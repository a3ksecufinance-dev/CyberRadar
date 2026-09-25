package model

import (
	"time"

	"github.com/google/uuid"
)

// Knowledge source types. They mirror the CHECK constraint on the table: a new
// one needs a migration, so the database and this list cannot drift apart.
const (
	KnowledgeSourceIncident = "incident"
	KnowledgeSourceAlert    = "alert"
	KnowledgeSourcePlaybook = "playbook"
	KnowledgeSourceRule     = "rule"
	KnowledgeSourceRunbook  = "runbook"
	KnowledgeSourceNote     = "note"
)

// KnowledgeChunk is one retrievable piece of a tenant's own history.
type KnowledgeChunk struct {
	ID         uuid.UUID      `json:"id"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	SourceType string         `json:"source_type"`
	SourceRef  string         `json:"source_ref"`
	Title      string         `json:"title"`
	Content    string         `json:"content"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`

	// Similarity is set only on search results: 1 is identical, 0 unrelated.
	Similarity float64 `json:"similarity,omitempty"`
}

// IndexKnowledgeRequest adds or replaces one document in a tenant's corpus.
type IndexKnowledgeRequest struct {
	SourceType string         `json:"source_type" validate:"required,oneof=incident alert playbook rule runbook note"`
	SourceRef  string         `json:"source_ref"  validate:"required,max=255"`
	Title      string         `json:"title"       validate:"required,max=512"`
	Content    string         `json:"content"     validate:"required"`
	Metadata   map[string]any `json:"metadata"`
}
