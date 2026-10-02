package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/rs/zerolog"
)

// fakeAPI stands in for the Messages API. It records every request body so a
// test can assert on the shape of the conversation the client builds, which is
// the part that breaks silently: a malformed follow-up turn is a 400 from the
// real API and nothing at all from a mock that only checks the first call.
type fakeAPI struct {
	server   *httptest.Server
	requests []model.AnthropicRequest
	replies  []string
}

func newFakeAPI(t *testing.T, replies ...string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{replies: replies}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Errorf("anthropic-version = %q, want %q", got, anthropicVersion)
		}
		if r.Header.Get("x-api-key") == "" {
			t.Error("no x-api-key header")
		}

		raw, _ := io.ReadAll(r.Body)
		var req model.AnthropicRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("request is not a Messages payload: %v", err)
		}
		f.requests = append(f.requests, req)

		// budget_tokens is refused by the current models. Catching it here is
		// cheaper than catching it as a 400 in production.
		if strings.Contains(string(raw), "budget_tokens") {
			t.Error("request carries budget_tokens, which the current models reject")
		}

		i := len(f.requests) - 1
		if i >= len(f.replies) {
			t.Fatalf("the client made %d calls, the test scripted %d", len(f.requests), len(f.replies))
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test server
		io.WriteString(w, f.replies[i])
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAPI) client(t *testing.T) *LLMClient {
	t.Helper()
	cfg := LLMConfigFromEnv()
	cfg.BaseURL = f.server.URL
	return NewLLMClient("test-key", cfg, NewToolDispatcher(map[string]string{}), zerolog.Nop())
}

const thinkingThenToolUse = `{
  "id": "msg_1", "type": "message", "role": "assistant",
  "content": [
    {"type": "thinking", "thinking": "The analyst wants the current counts.", "signature": "sig-abc123"},
    {"type": "tool_use", "id": "toolu_1", "name": "query_platform_stats", "input": {}}
  ],
  "stop_reason": "tool_use",
  "usage": {"input_tokens": 100, "output_tokens": 50}
}`

const finalAnswer = `{
  "id": "msg_2", "type": "message", "role": "assistant",
  "content": [{"type": "text", "text": "Five alerts are open."}],
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 200, "output_tokens": 20}
}`

// A thinking block must come back on the next turn with its signature intact.
// Without that the API rejects the follow-up, so every conversation that used
// a tool would fail on its second call — and only in production, because the
// first call looks perfect.
func TestThinkingBlocksSurviveTheToolLoop(t *testing.T) {
	api := newFakeAPI(t, thinkingThenToolUse, finalAnswer)

	resp, err := api.client(t).Chat(context.Background(), nil, "How many alerts are open?")
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if resp.StopReason != "end_turn" {
		t.Fatalf("stop_reason = %q, want end_turn", resp.StopReason)
	}
	if len(api.requests) != 2 {
		t.Fatalf("%d calls, want 2", len(api.requests))
	}

	second := api.requests[1]
	// user question, assistant turn, tool results
	if len(second.Messages) != 3 {
		t.Fatalf("second call carries %d messages, want 3", len(second.Messages))
	}

	assistant := second.Messages[1]
	if assistant.Role != model.RoleAssistant {
		t.Fatalf("message 2 is %q, want assistant", assistant.Role)
	}
	var thinking *model.AnthropicContent
	for i := range assistant.Content {
		if assistant.Content[i].Type == "thinking" {
			thinking = &assistant.Content[i]
		}
	}
	if thinking == nil {
		t.Fatal("the thinking block was dropped from the assistant turn")
	}
	if thinking.Signature != "sig-abc123" {
		t.Errorf("signature = %q, want sig-abc123", thinking.Signature)
	}
	if thinking.Thinking == "" {
		t.Error("the thinking block came back empty")
	}

	results := second.Messages[2]
	if len(results.Content) != 1 || results.Content[0].Type != "tool_result" {
		t.Fatalf("the tool results turn is %#v", results.Content)
	}
	if results.Content[0].ToolUseID != "toolu_1" {
		t.Errorf("tool_use_id = %q, want toolu_1", results.Content[0].ToolUseID)
	}
}

// The default model is the one the platform is documented against, and it is
// never date-suffixed.
func TestDefaultRequestShape(t *testing.T) {
	api := newFakeAPI(t, finalAnswer)
	if _, err := api.client(t).Chat(context.Background(), nil, "hello"); err != nil {
		t.Fatalf("Chat: %v", err)
	}

	req := api.requests[0]
	if req.Model != defaultModel {
		t.Errorf("model = %q, want %q", req.Model, defaultModel)
	}
	if strings.Contains(req.Model, "-2024") || strings.Contains(req.Model, "-2025") {
		t.Errorf("model %q carries a date suffix", req.Model)
	}
	if req.MaxTokens != defaultMaxTokens {
		t.Errorf("max_tokens = %d, want %d", req.MaxTokens, defaultMaxTokens)
	}
	// No effort configured means the model's own default, not a guess.
	if req.OutputConfig != nil {
		t.Errorf("output_config = %#v, want it absent", req.OutputConfig)
	}
	if len(req.Tools) == 0 {
		t.Error("the request carries no tools")
	}
	if req.System == "" {
		t.Error("the request carries no system prompt")
	}
}

// Effort is how depth is asked for now; a token budget is refused.
func TestEffortIsSentAsOutputConfig(t *testing.T) {
	api := newFakeAPI(t, finalAnswer)
	cfg := LLMConfigFromEnv()
	cfg.BaseURL = api.server.URL
	cfg.Effort = "high"
	c := NewLLMClient("test-key", cfg, NewToolDispatcher(map[string]string{}), zerolog.Nop())

	if _, err := c.Chat(context.Background(), nil, "hello"); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if api.requests[0].OutputConfig == nil || api.requests[0].OutputConfig.Effort != "high" {
		t.Fatalf("output_config = %#v, want effort high", api.requests[0].OutputConfig)
	}
}

// Persisted history is text. A tool turn cannot be replayed as a tool_result,
// and one built anyway — with a tool name where a block id belongs — is
// rejected by the API.
func TestHistoryNeverReplaysAToolTurn(t *testing.T) {
	history := []*model.Message{
		{Role: model.RoleUser, Content: "what is open?"},
		{Role: model.RoleAssistant, Content: "Five alerts."},
		{Role: model.RoleTool, ToolName: "query_alerts", Content: `{"total":5}`},
	}

	msgs := buildAnthropicMessages(history)
	for _, m := range msgs {
		for _, block := range m.Content {
			if block.Type == "tool_result" {
				t.Fatalf("history rebuilt a tool_result: %#v", block)
			}
		}
	}
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2 (the user turn and the assistant turn)", len(msgs))
	}
}

// Every tool must carry a name, a description and an object schema: a tool
// with a malformed schema is refused for the whole request, so one bad entry
// disables all ten.
func TestToolDefinitionsAreWellFormed(t *testing.T) {
	tools := buildTools()
	if len(tools) == 0 {
		t.Fatal("no tools")
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if tool.Name == "" {
			t.Fatalf("a tool has no name: %#v", tool)
		}
		if seen[tool.Name] {
			t.Errorf("%s is defined twice", tool.Name)
		}
		seen[tool.Name] = true

		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
		if tool.InputSchema["type"] != "object" {
			t.Errorf("%s input_schema type = %v, want object", tool.Name, tool.InputSchema["type"])
		}
		props, ok := tool.InputSchema["properties"].(map[string]any)
		if !ok {
			t.Errorf("%s has no properties object", tool.Name)
			continue
		}
		required, _ := tool.InputSchema["required"].([]string)
		for _, field := range required {
			if _, ok := props[field]; !ok {
				t.Errorf("%s requires %q, which its schema does not describe", tool.Name, field)
			}
		}
		if _, err := json.Marshal(tool); err != nil {
			t.Errorf("%s does not marshal: %v", tool.Name, err)
		}
	}

	// Every name the model may return must be one the dispatcher routes.
	d := NewToolDispatcher(map[string]string{})
	for _, tool := range tools {
		if _, err := d.Dispatch(context.Background(), tool.Name, map[string]any{}); err != nil &&
			strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("%s is offered to the model and not routed by the dispatcher", tool.Name)
		}
	}
}

// An error from the API must not be reported as an empty answer.
func TestAPIErrorIsReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		//nolint:errcheck // test server
		io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`)
	}))
	defer server.Close()

	cfg := LLMConfigFromEnv()
	cfg.BaseURL = server.URL
	c := NewLLMClient("test-key", cfg, NewToolDispatcher(map[string]string{}), zerolog.Nop())

	_, err := c.Chat(context.Background(), nil, "hello")
	if err == nil {
		t.Fatal("a 429 was reported as success")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error = %v, want it to name the status", err)
	}
}
