package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testDim = 4

type embeddingResult struct {
	Index     int       `json:"index"`
	Embedding []float32 `json:"embedding"`
}

// embeddingServer stands in for an OpenAI-compatible embeddings endpoint.
func embeddingServer(t *testing.T, reply func(inputs []string) any) (*httptest.Server, *[]string) {
	t.Helper()
	var models []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req embeddingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		models = append(models, req.Model)
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test stub
		json.NewEncoder(w).Encode(reply(req.Input))
	}))
	t.Cleanup(srv.Close)
	return srv, &models
}

// inOrder answers with one distinct vector per input, correctly indexed.
func inOrder(inputs []string) any {
	data := make([]embeddingResult, len(inputs))
	for i := range inputs {
		v := make([]float32, testDim)
		v[i%testDim] = 1
		data[i] = embeddingResult{Index: i, Embedding: v}
	}
	return map[string]any{"data": data}
}

func embedder(t *testing.T, url string) *HTTPEmbedder {
	t.Helper()
	e, err := NewHTTPEmbedder(EmbedderConfig{URL: url, Model: "bge-large", Dimension: testDim})
	if err != nil {
		t.Fatalf("NewHTTPEmbedder: %v", err)
	}
	return e
}

func TestEmbedReturnsOneVectorPerInput(t *testing.T) {
	srv, models := embeddingServer(t, inOrder)

	got, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("%d vectors, want 3", len(got))
	}
	for i, v := range got {
		if len(v) != testDim {
			t.Errorf("vector %d has %d dimensions, want %d", i, len(v), testDim)
		}
	}
	if len(*models) != 1 || (*models)[0] != "bge-large" {
		t.Errorf("models sent = %v, want one request naming bge-large", *models)
	}
}

func TestEmbedRestoresTheRequestOrder(t *testing.T) {
	// Not every server returns results in order. Silently pairing a vector
	// with the wrong document would only show up as retrieved context that
	// makes no sense — long after indexing.
	srv, _ := embeddingServer(t, func(inputs []string) any {
		data := make([]embeddingResult, 0, len(inputs))
		for i := len(inputs) - 1; i >= 0; i-- { // reversed
			v := make([]float32, testDim)
			v[i%testDim] = 1
			data = append(data, embeddingResult{Index: i, Embedding: v})
		}
		return map[string]any{"data": data}
	})

	got, err := embedder(t, srv.URL).Embed(context.Background(), []string{"first", "second", "third"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	for i, v := range got {
		if v[i%testDim] != 1 {
			t.Errorf("vector %d is not the one the server indexed as %d: %v", i, i, v)
		}
	}
}

func TestEmbedRejectsAWrongWidthModel(t *testing.T) {
	// A model whose output is a different width would be rejected row by row
	// at ingestion; naming it here says which model is wrong.
	srv, _ := embeddingServer(t, func(inputs []string) any {
		return map[string]any{"data": []embeddingResult{{Index: 0, Embedding: make([]float32, 99)}}}
	})

	_, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("a 99-dimension vector was accepted for a 4-dimension index")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error = %q, want it to name the width it got", err)
	}
}

func TestEmbedRejectsAShortResponse(t *testing.T) {
	srv, _ := embeddingServer(t, func(inputs []string) any {
		return map[string]any{"data": []embeddingResult{{Index: 0, Embedding: make([]float32, testDim)}}}
	})

	if _, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a", "b"}); err == nil {
		t.Error("two inputs answered with one vector was accepted")
	}
}

func TestEmbedRejectsADuplicateIndex(t *testing.T) {
	// Two results claiming the same slot means one input has no vector, and
	// taking the last would pair it with the wrong document.
	srv, _ := embeddingServer(t, func(inputs []string) any {
		return map[string]any{"data": []embeddingResult{
			{Index: 0, Embedding: make([]float32, testDim)},
			{Index: 0, Embedding: make([]float32, testDim)},
		}}
	})

	if _, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a", "b"}); err == nil {
		t.Error("a duplicated result index was accepted")
	}
}

func TestEmbedRejectsAnOutOfRangeIndex(t *testing.T) {
	srv, _ := embeddingServer(t, func(inputs []string) any {
		return map[string]any{"data": []embeddingResult{{Index: 7, Embedding: make([]float32, testDim)}}}
	})

	if _, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a"}); err == nil {
		t.Error("a result index outside the request was accepted")
	}
}

func TestEmbedRejectsEmptyInput(t *testing.T) {
	// Several servers answer an empty string with a zero vector, which the
	// store then refuses. Failing here names the offending input instead.
	srv, _ := embeddingServer(t, inOrder)

	_, err := embedder(t, srv.URL).Embed(context.Background(), []string{"fine", "   "})
	if err == nil {
		t.Fatal("an empty input was sent to the server")
	}
	if !strings.Contains(err.Error(), "[1]") {
		t.Errorf("error = %q, want it to name which input was empty", err)
	}
}

func TestEmbedSurfacesAServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a"}); err == nil {
		t.Error("a 503 produced no error")
	}
}

func TestEmbedSurfacesAnErrorInTheBody(t *testing.T) {
	srv, _ := embeddingServer(t, func(inputs []string) any {
		return map[string]any{"error": map[string]any{"message": "model not loaded"}}
	})

	_, err := embedder(t, srv.URL).Embed(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("an error body with HTTP 200 produced no error")
	}
	if !strings.Contains(err.Error(), "model not loaded") {
		t.Errorf("error = %q, want the server's own message", err)
	}
}

func TestEmbedSendsTheAPIKeyOnlyWhenSet(t *testing.T) {
	var headers []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = append(headers, r.Header.Get("Authorization"))
		//nolint:errcheck // test stub
		json.NewEncoder(w).Encode(inOrder([]string{"a"}))
	}))
	defer srv.Close()

	plain, _ := NewHTTPEmbedder(EmbedderConfig{URL: srv.URL, Model: "m", Dimension: testDim})
	if _, err := plain.Embed(context.Background(), []string{"a"}); err != nil {
		t.Fatalf("Embed: %v", err)
	}
	keyed, _ := NewHTTPEmbedder(EmbedderConfig{URL: srv.URL, Model: "m", Dimension: testDim, APIKey: "s3cret"})
	if _, err := keyed.Embed(context.Background(), []string{"a"}); err != nil {
		t.Fatalf("Embed: %v", err)
	}

	if headers[0] != "" {
		t.Errorf("a self-hosted server with no key got Authorization %q", headers[0])
	}
	if headers[1] != "Bearer s3cret" {
		t.Errorf("Authorization = %q, want the bearer token", headers[1])
	}
}

func TestIncompleteConfigurationIsRefused(t *testing.T) {
	for name, cfg := range map[string]EmbedderConfig{
		"no url":       {Model: "m", Dimension: 4},
		"no model":     {URL: "http://x", Dimension: 4},
		"no dimension": {URL: "http://x", Model: "m"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHTTPEmbedder(cfg); err == nil {
				t.Error("accepted, want an error")
			}
		})
	}
}

func TestEmbedOneReturnsASingleVector(t *testing.T) {
	srv, _ := embeddingServer(t, inOrder)

	got, err := EmbedOne(context.Background(), embedder(t, srv.URL), "a question")
	if err != nil {
		t.Fatalf("EmbedOne: %v", err)
	}
	if len(got) != testDim {
		t.Errorf("%d dimensions, want %d", len(got), testDim)
	}
}

func TestEmbedNothingCallsNothing(t *testing.T) {
	srv, models := embeddingServer(t, inOrder)

	got, err := embedder(t, srv.URL).Embed(context.Background(), nil)
	if err != nil || got != nil {
		t.Errorf("Embed(nil) = %v, %v; want nil, nil", got, err)
	}
	if len(*models) != 0 {
		t.Error("an empty batch still called the server")
	}
}
