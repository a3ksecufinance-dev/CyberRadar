package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Embedder turns text into a vector the knowledge index can compare.
//
// It is an interface because where embeddings come from is a deployment
// decision, not a code one. Anthropic has no embeddings endpoint, so the model
// behind this is never the one answering the question.
type Embedder interface {
	// Embed returns one vector per input, in the same order.
	Embed(ctx context.Context, inputs []string) ([][]float32, error)
	// Dimension is the width every returned vector has, checked once at
	// startup against the column the index is built on.
	Dimension() int
}

// HTTPEmbedder calls an OpenAI-compatible /v1/embeddings endpoint.
//
// That shape is deliberate: it is what a self-hosted server speaks — text-
// embeddings-inference, vLLM, Ollama, LocalAI — as well as the hosted
// providers. A bank that may not send incident text off its own premises
// points EMBEDDINGS_URL at its own server and nothing leaves the estate; an
// operator who accepts a hosted provider points it there instead. The platform
// imposes neither.
type HTTPEmbedder struct {
	url       string
	model     string
	apiKey    string
	dimension int
	client    *http.Client
}

// EmbedderConfig configures an HTTPEmbedder.
type EmbedderConfig struct {
	// URL is the full endpoint, e.g. http://embeddings:8080/v1/embeddings.
	URL string
	// Model is the model name the server expects, e.g. BAAI/bge-large-en-v1.5.
	Model string
	// APIKey is sent as a bearer token when set. A self-hosted server on a
	// private network usually needs none.
	APIKey string
	// Dimension must match the width of the embedding column.
	Dimension int

	HTTPClient *http.Client
}

// NewHTTPEmbedder builds an HTTPEmbedder.
func NewHTTPEmbedder(cfg EmbedderConfig) (*HTTPEmbedder, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("embeddings: URL is required")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("embeddings: model is required")
	}
	if cfg.Dimension <= 0 {
		return nil, fmt.Errorf("embeddings: dimension must be positive")
	}

	client := cfg.HTTPClient
	if client == nil {
		// Embedding a batch on CPU is not fast; the default is generous.
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &HTTPEmbedder{
		url: cfg.URL, model: cfg.Model, apiKey: cfg.APIKey,
		dimension: cfg.Dimension, client: client,
	}, nil
}

// Dimension is the width of every vector this embedder returns.
func (e *HTTPEmbedder) Dimension() int { return e.dimension }

type embeddingsRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embeddingsResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Embed returns one vector per input, in the order the inputs were given.
func (e *HTTPEmbedder) Embed(ctx context.Context, inputs []string) ([][]float32, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	for i, in := range inputs {
		if strings.TrimSpace(in) == "" {
			// Several servers answer an empty string with a zero vector, which
			// the store then refuses. Failing here names the offending input.
			return nil, fmt.Errorf("embeddings: input[%d] is empty", i)
		}
	}

	body, err := json.Marshal(embeddingsRequest{Model: e.model, Input: inputs})
	if err != nil {
		return nil, fmt.Errorf("embeddings: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embeddings: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embeddings: call %s: %w", e.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("embeddings: %s answered %s", e.url, resp.Status)
	}

	var parsed embeddingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("embeddings: decode response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("embeddings: %s", parsed.Error.Message)
	}
	if len(parsed.Data) != len(inputs) {
		return nil, fmt.Errorf("embeddings: asked for %d vectors, got %d", len(inputs), len(parsed.Data))
	}

	// The spec says results carry their index; not every server returns them
	// in order, and silently mismatching a vector to the wrong document would
	// be invisible until the retrieved context made no sense.
	out := make([][]float32, len(inputs))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(out) {
			return nil, fmt.Errorf("embeddings: result index %d is outside the request", d.Index)
		}
		if len(d.Embedding) != e.dimension {
			return nil, fmt.Errorf("embeddings: model returned %d dimensions, the index is built on %d",
				len(d.Embedding), e.dimension)
		}
		if out[d.Index] != nil {
			return nil, fmt.Errorf("embeddings: result index %d appeared twice", d.Index)
		}
		out[d.Index] = d.Embedding
	}
	for i, v := range out {
		if v == nil {
			return nil, fmt.Errorf("embeddings: no vector returned for input[%d]", i)
		}
	}
	return out, nil
}

// EmbedOne is the single-input case, which is what a query is.
func EmbedOne(ctx context.Context, e Embedder, input string) ([]float32, error) {
	vectors, err := e.Embed(ctx, []string{input})
	if err != nil {
		return nil, err
	}
	if len(vectors) != 1 {
		return nil, fmt.Errorf("embeddings: expected one vector, got %d", len(vectors))
	}
	return vectors[0], nil
}
