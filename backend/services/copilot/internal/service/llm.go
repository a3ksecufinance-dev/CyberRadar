package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/rs/zerolog"
)

const (
	anthropicAPI   = "https://api.anthropic.com/v1/messages"
	anthropicModel = "claude-sonnet-4-6"
	maxTokens      = 4096
)

// systemPrompt is the security analyst persona injected on every call.
const systemPrompt = `You are CyberRadar Copilot, an expert AI security analyst embedded in the CyberRadar Platform (CRP) — a sovereign cybersecurity platform for banks, governments, and critical infrastructure.

Your role:
- Help security analysts investigate threats, triage alerts, and respond to incidents
- Query live platform data using available tools and synthesize findings into clear, actionable insights
- Apply MITRE ATT&CK framework knowledge when analyzing threats
- Prioritize brevity and precision; lead with the most critical finding
- When in doubt about scope or tenant data, ask for clarification

Platform domains you can query:
- SIEM/XDR: real-time alerts and correlation rules
- UEBA: behavioral anomalies and entity risk profiles
- Threat Intelligence: IOC lookups and threat actor attribution
- Vulnerability Management: CVE/EPSS data and SLA tracking
- Attack Path Analysis: lateral movement scenarios and choke points
- SOAR: active incidents and playbook status
- Knowledge Graph: entity relationships and attack surface

Always cite the tool call results that informed your answer.
Never hallucinate data — if a tool returns no results, say so explicitly.`

// LLMClient calls the Anthropic Messages API with tool use.
type LLMClient struct {
	apiKey     string
	httpClient *http.Client
	tools      []model.AnthropicTool
	dispatcher *ToolDispatcher
	logger     zerolog.Logger
}

// NewLLMClient creates an LLMClient with the security analyst toolset.
func NewLLMClient(apiKey string, dispatcher *ToolDispatcher, logger zerolog.Logger) *LLMClient {
	return &LLMClient{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 90 * time.Second},
		tools:      buildTools(),
		dispatcher: dispatcher,
		logger:     logger,
	}
}

// Chat sends a conversational message and returns the assistant reply.
// It implements the agentic loop: call Claude → dispatch tool use → call Claude again.
func (c *LLMClient) Chat(ctx context.Context, history []*model.Message, userContent string) (*model.AnthropicResponse, error) {
	// Build Anthropic message list from persisted history
	messages := buildAnthropicMessages(history)
	messages = append(messages, model.AnthropicMessage{
		Role:    model.RoleUser,
		Content: []model.AnthropicContent{{Type: "text", Text: userContent}},
	})

	// Agentic loop: keep calling until stop_reason is "end_turn"
	for iterations := 0; iterations < 10; iterations++ {
		resp, err := c.call(ctx, messages)
		if err != nil {
			return nil, err
		}

		// No tool use → done
		if resp.StopReason != "tool_use" {
			return resp, nil
		}

		// Append assistant message with tool_use blocks
		messages = append(messages, model.AnthropicMessage{
			Role:    model.RoleAssistant,
			Content: resp.Content,
		})

		// Dispatch each tool call and collect results
		toolResults := make([]model.AnthropicContent, 0, len(resp.Content))
		for _, block := range resp.Content {
			if block.Type != "tool_use" {
				continue
			}
			result, err := c.dispatcher.Dispatch(ctx, block.Name, block.Input)
			if err != nil {
				c.logger.Warn().Err(err).Str("tool", block.Name).Msg("tool_dispatch_error")
				toolResults = append(toolResults, model.AnthropicContent{
					Type:      "tool_result",
					ToolUseID: block.ID,
					Content:   fmt.Sprintf("Tool error: %s", err.Error()),
					IsError:   true,
				})
			} else {
				resultJSON, _ := json.Marshal(result)
				toolResults = append(toolResults, model.AnthropicContent{
					Type:      "tool_result",
					ToolUseID: block.ID,
					Content:   string(resultJSON),
				})
			}
		}

		// Append tool results as a user turn
		messages = append(messages, model.AnthropicMessage{
			Role:    model.RoleUser,
			Content: toolResults,
		})
	}

	return nil, fmt.Errorf("exceeded max tool-use iterations")
}

// Analyze sends a single-shot analysis prompt (used for async hunt jobs).
func (c *LLMClient) Analyze(ctx context.Context, prompt string) (*model.AnthropicResponse, error) {
	messages := []model.AnthropicMessage{
		{Role: model.RoleUser, Content: []model.AnthropicContent{{Type: "text", Text: prompt}}},
	}
	// Single call — allow tool use but don't loop more than 5 times
	for i := 0; i < 5; i++ {
		resp, err := c.call(ctx, messages)
		if err != nil {
			return nil, err
		}
		if resp.StopReason != "tool_use" {
			return resp, nil
		}
		messages = append(messages, model.AnthropicMessage{Role: model.RoleAssistant, Content: resp.Content})
		var results []model.AnthropicContent
		for _, block := range resp.Content {
			if block.Type != "tool_use" {
				continue
			}
			result, _ := c.dispatcher.Dispatch(ctx, block.Name, block.Input)
			resultJSON, _ := json.Marshal(result)
			results = append(results, model.AnthropicContent{
				Type: "tool_result", ToolUseID: block.ID, Content: string(resultJSON),
			})
		}
		messages = append(messages, model.AnthropicMessage{Role: model.RoleUser, Content: results})
	}
	return nil, fmt.Errorf("exceeded max iterations")
}

// call makes a single HTTP POST to the Anthropic Messages API.
func (c *LLMClient) call(ctx context.Context, messages []model.AnthropicMessage) (*model.AnthropicResponse, error) {
	req := model.AnthropicRequest{
		Model:     anthropicModel,
		MaxTokens: maxTokens,
		System:    systemPrompt,
		Messages:  messages,
		Tools:     c.tools,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPI, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic http: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read anthropic response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API error %d: %s", httpResp.StatusCode, string(respBody))
	}

	var resp model.AnthropicResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal anthropic response: %w", err)
	}
	return &resp, nil
}

// ─── Helper: build Anthropic message list from DB history ────────────────────

func buildAnthropicMessages(history []*model.Message) []model.AnthropicMessage {
	var msgs []model.AnthropicMessage
	for _, m := range history {
		switch m.Role {
		case model.RoleUser:
			msgs = append(msgs, model.AnthropicMessage{
				Role:    model.RoleUser,
				Content: []model.AnthropicContent{{Type: "text", Text: m.Content}},
			})
		case model.RoleAssistant:
			msgs = append(msgs, model.AnthropicMessage{
				Role:    model.RoleAssistant,
				Content: []model.AnthropicContent{{Type: "text", Text: m.Content}},
			})
		case model.RoleTool:
			// Reconstruct tool result block attached to previous assistant turn
			if len(msgs) > 0 && msgs[len(msgs)-1].Role == model.RoleUser {
				msgs[len(msgs)-1].Content = append(msgs[len(msgs)-1].Content, model.AnthropicContent{
					Type:      "tool_result",
					ToolUseID: m.ToolName,
					Content:   m.Content,
				})
			}
		}
	}
	return msgs
}

// ─── Tool definitions ─────────────────────────────────────────────────────────

func buildTools() []model.AnthropicTool {
	str := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	num := func(desc string) map[string]any {
		return map[string]any{"type": "number", "description": desc}
	}
	props := func(fields map[string]map[string]any) map[string]any {
		p := make(map[string]any, len(fields))
		for k, v := range fields {
			p[k] = v
		}
		return p
	}
	schema := func(required []string, properties map[string]map[string]any) map[string]any {
		return map[string]any{
			"type":       "object",
			"required":   required,
			"properties": props(properties),
		}
	}

	return []model.AnthropicTool{
		{
			Name:        model.ToolQueryAlerts,
			Description: "Query recent SIEM/XDR alerts. Returns a list of alerts matching filters.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"severity":  str("Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
				"status":    str("Filter by alert status: open, acknowledged, resolved"),
				"limit":     num("Max number of results (default 10)"),
				"rule_name": str("Filter by SIEM rule name (partial match)"),
			}),
		},
		{
			Name:        model.ToolLookupIOC,
			Description: "Look up an indicator of compromise (IP, domain, hash, URL, email) in the Threat Intelligence database.",
			InputSchema: schema([]string{"value"}, map[string]map[string]any{
				"value": str("The IOC value to look up"),
				"type":  str("Optional IOC type hint: ip, domain, url, hash_sha256, hash_md5, email"),
			}),
		},
		{
			Name:        model.ToolGetIncident,
			Description: "Retrieve a SOAR incident by ID or list recent open incidents.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"incident_id": str("UUID of a specific incident to retrieve"),
				"status":      str("Filter: open, in_progress, contained, resolved"),
				"severity":    str("Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
				"limit":       num("Max results (default 5)"),
			}),
		},
		{
			Name:        model.ToolQueryAnomalies,
			Description: "Query UEBA behavioral anomalies for entities or users.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"entity_id":    str("UUID of a specific entity"),
				"anomaly_type": str("OFF_HOURS_ACCESS, NEW_COUNTRY, NEW_IP_PREFIX, VELOCITY_SPIKE, PRIV_ESCALATION, LATERAL_MOVEMENT, DATA_EXFILTRATION, BRUTE_FORCE"),
				"status":       str("open, investigating, resolved"),
				"limit":        num("Max results (default 10)"),
			}),
		},
		{
			Name:        model.ToolQueryVulns,
			Description: "Query vulnerability findings. Returns CVE details, CVSS scores, EPSS, and affected assets.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"severity":     str("CRITICAL, HIGH, MEDIUM, LOW"),
				"asset_id":     str("Filter by asset UUID"),
				"cve_id":       str("Specific CVE ID (e.g. CVE-2024-1234)"),
				"sla_breached": str("true to return only SLA-breached findings"),
				"limit":        num("Max results (default 10)"),
			}),
		},
		{
			Name:        model.ToolAnalyzeAttackPath,
			Description: "Query attack path analysis results: discovered lateral movement paths, choke points, and scenario risk scores.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"scenario_id":  str("UUID of a specific scenario"),
				"min_score":    num("Minimum path risk score (0-10)"),
				"limit":        num("Max paths (default 5)"),
				"choke_points": str("Set to 'true' to return choke point summary instead of paths"),
			}),
		},
		{
			Name:        model.ToolSearchEntities,
			Description: "Search the Knowledge Graph for entities by name, type, or properties.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"name":        str("Entity name (partial match)"),
				"entity_type": str("asset, identity, ip, domain, url, hash, vulnerability, ioc, alert, incident, threat_actor, software"),
				"min_risk":    num("Minimum risk score (0-10)"),
				"limit":       num("Max results (default 10)"),
			}),
		},
		{
			Name:        model.ToolGetAsset,
			Description: "Retrieve asset details by ID or hostname/IP.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"asset_id": str("UUID of a specific asset"),
				"hostname": str("Hostname to search for"),
				"ip":       str("IP address to search for"),
			}),
		},
		{
			Name:        model.ToolQueryStats,
			Description: "Get aggregate platform statistics: open alerts, active anomalies, critical vulnerabilities, open incidents, and overall risk score.",
			InputSchema: schema([]string{}, map[string]map[string]any{
				"domain": str("Optional: filter to a specific domain — siem, ueba, ti, vuln, attackpath, soar"),
			}),
		},
		{
			Name:        model.ToolHuntThreats,
			Description: "Execute a structured threat hunt query across multiple data sources. Returns correlated findings.",
			InputSchema: schema([]string{"hypothesis"}, map[string]map[string]any{
				"hypothesis": str("Threat hunting hypothesis (e.g. 'Look for signs of credential stuffing from external IPs')"),
				"time_range": str("Time range: 1h, 6h, 24h, 7d (default 24h)"),
				"sources":    str("Comma-separated data sources to search: siem, ueba, ti, vuln, kg"),
			}),
		},
	}
}
