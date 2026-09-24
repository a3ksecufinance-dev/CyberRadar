package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/google/uuid"
)

// EmbeddingDimension reads the declared width of the embedding column.
//
// The service checks its embedder against this at startup. A model whose
// output is a different width would otherwise be rejected row by row at write
// time — or worse, silently indexed alongside vectors it cannot be compared
// with, if the column were ever made dimensionless.
func (r *CopilotRepository) EmbeddingDimension(ctx context.Context) (int, error) {
	var dim int
	err := r.db.QueryRow(ctx, `
		SELECT atttypmod
		FROM pg_attribute
		WHERE attrelid = 'copilot_knowledge'::regclass AND attname = 'embedding'`).Scan(&dim)
	if err != nil {
		return 0, fmt.Errorf("read embedding dimension: %w", err)
	}
	return dim, nil
}

// UpsertKnowledge adds or replaces one document in a tenant's corpus.
//
// It is keyed on (tenant, source type, source ref) so re-indexing a document
// replaces it. Without that, an incident edited three times would sit in the
// index three times and crowd out everything else for the queries it matches.
func (r *CopilotRepository) UpsertKnowledge(ctx context.Context, tenantID uuid.UUID, req *model.IndexKnowledgeRequest, embedding []float32) (*model.KnowledgeChunk, error) {
	literal, err := vectorLiteral(embedding)
	if err != nil {
		return nil, err
	}

	metadata := req.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	var c model.KnowledgeChunk
	err = r.db.QueryRow(ctx, `
		INSERT INTO copilot_knowledge (tenant_id, source_type, source_ref, title, content, embedding, metadata)
		VALUES ($1, $2, $3, $4, $5, $6::vector, $7)
		ON CONFLICT (tenant_id, source_type, source_ref) DO UPDATE SET
			title      = EXCLUDED.title,
			content    = EXCLUDED.content,
			embedding  = EXCLUDED.embedding,
			metadata   = EXCLUDED.metadata,
			updated_at = NOW()
		RETURNING id, tenant_id, source_type, source_ref, title, content, created_at`,
		tenantID, req.SourceType, req.SourceRef, req.Title, req.Content, literal, raw).
		Scan(&c.ID, &c.TenantID, &c.SourceType, &c.SourceRef, &c.Title, &c.Content, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert knowledge: %w", err)
	}
	c.Metadata = metadata
	return &c, nil
}

// SearchKnowledge returns a tenant's most similar chunks to a query vector.
//
// minSimilarity drops weak matches rather than always returning k rows: an
// unrelated question should retrieve nothing and let the model say it has
// nothing, instead of being handed the least-unrelated document in the corpus
// and treating it as evidence.
func (r *CopilotRepository) SearchKnowledge(ctx context.Context, tenantID uuid.UUID, embedding []float32, limit int, minSimilarity float64) ([]*model.KnowledgeChunk, error) {
	literal, err := vectorLiteral(embedding)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 5
	}

	// The tenant filter is in the WHERE clause, not applied after the fact:
	// an ORDER BY over the index followed by a filter would return another
	// customer's documents whenever they are the closest match.
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, source_type, source_ref, title, content, metadata, created_at,
		       1 - (embedding <=> $2::vector) AS similarity
		FROM copilot_knowledge
		WHERE tenant_id = $1
		ORDER BY embedding <=> $2::vector
		LIMIT $3`, tenantID, literal, limit)
	if err != nil {
		return nil, fmt.Errorf("search knowledge: %w", err)
	}
	defer rows.Close()

	var out []*model.KnowledgeChunk
	for rows.Next() {
		var c model.KnowledgeChunk
		var raw []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.SourceType, &c.SourceRef,
			&c.Title, &c.Content, &raw, &c.CreatedAt, &c.Similarity); err != nil {
			return nil, fmt.Errorf("scan knowledge: %w", err)
		}
		// A stored zero vector makes cosine similarity NaN. Such a row can
		// never be a real match, and a NaN would slip past a > comparison.
		if math.IsNaN(c.Similarity) || c.Similarity < minSimilarity {
			continue
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &c.Metadata)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// DeleteKnowledge removes one document from a tenant's corpus.
func (r *CopilotRepository) DeleteKnowledge(ctx context.Context, tenantID uuid.UUID, sourceType, sourceRef string) error {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM copilot_knowledge WHERE tenant_id = $1 AND source_type = $2 AND source_ref = $3`,
		tenantID, sourceType, sourceRef)
	if err != nil {
		return fmt.Errorf("delete knowledge: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("knowledge not found")
	}
	return nil
}

// vectorLiteral renders an embedding as the text form pgvector parses.
//
// Sending the literal and casting keeps the driver free of a pgvector-specific
// type registration, which would otherwise have to be repeated on every pool.
func vectorLiteral(embedding []float32) (string, error) {
	if len(embedding) == 0 {
		return "", fmt.Errorf("embedding is empty")
	}

	var b strings.Builder
	b.Grow(len(embedding) * 8)
	b.WriteByte('[')

	allZero := true
	for i, v := range embedding {
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			// Postgres would accept these and every later comparison with the
			// row would be NaN, which sorts unpredictably rather than failing.
			return "", fmt.Errorf("embedding[%d] is not a finite number", i)
		}
		if v != 0 {
			allZero = false
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(v), 'g', -1, 32))
	}
	b.WriteByte(']')

	if allZero {
		// Cosine distance divides by the norm, so a zero vector makes every
		// similarity involving this row NaN. Some embedding servers return one
		// for empty or unparseable input; storing it poisons the index quietly.
		return "", fmt.Errorf("embedding is all zeros, which has no direction to compare")
	}
	return b.String(), nil
}
