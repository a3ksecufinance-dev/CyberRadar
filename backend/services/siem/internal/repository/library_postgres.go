package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/siem/internal/model"
)

// LibraryRepository reads the detection content the platform ships and the
// lineage that links a tenant's rules back to it.
type LibraryRepository struct {
	db *pgxpool.Pool
}

// NewLibraryRepository creates a LibraryRepository.
func NewLibraryRepository(db *pgxpool.Pool) *LibraryRepository {
	return &LibraryRepository{db: db}
}

// ErrNoSuchEntry is returned for a code the catalogue does not carry, so the
// answer can name it rather than being a bare 500.
var ErrNoSuchEntry = errors.New("no such detection in the library")

// ErrAlreadyAdopted is returned when a tenant already runs this entry. Adopting
// twice would double every alert it raises, and the copies would drift apart.
var ErrAlreadyAdopted = errors.New("this detection is already adopted")

const contentColumns = `
	id, code, version, title, description, category, severity,
	COALESCE(mitre_tactic, ''), COALESCE(mitre_technique, ''),
	conditions, actions, dedup_window_s,
	rationale, COALESCE(false_positives, ''), COALESCE(response, ''),
	frameworks, controls, requires, enabled_by_default, tags, created_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanContent(row rowScanner) (*model.ContentEntry, error) {
	var (
		e        model.ContentEntry
		condJSON []byte
		actJSON  []byte
	)
	if err := row.Scan(
		&e.ID, &e.Code, &e.Version, &e.Title, &e.Description, &e.Category, &e.Severity,
		&e.MitreTactic, &e.MitreTechnique,
		&condJSON, &actJSON, &e.DedupWindowS,
		&e.Rationale, &e.FalsePositives, &e.Response,
		&e.Frameworks, &e.Controls, &e.Requires, &e.EnabledByDefault, &e.Tags, &e.CreatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(condJSON, &e.Conditions); err != nil {
		return nil, fmt.Errorf("conditions of %s: %w", e.Code, err)
	}
	// An entry with no actions is legitimate: it raises the alert and nothing
	// more. An empty slice rather than nil, so a client never has to tell "no
	// actions" from "this field was not populated".
	e.Actions = []model.RuleAction{}
	if len(actJSON) > 0 {
		if err := json.Unmarshal(actJSON, &e.Actions); err != nil {
			return nil, fmt.Errorf("actions of %s: %w", e.Code, err)
		}
	}
	return &e, nil
}

// Catalogue is every current entry.
func (r *LibraryRepository) Catalogue(ctx context.Context) ([]*model.ContentEntry, error) {
	rows, err := r.db.Query(ctx, `SELECT `+contentColumns+`
		FROM detection_content WHERE retired_at IS NULL ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("read the detection library: %w", err)
	}
	defer rows.Close()

	var out []*model.ContentEntry
	for rows.Next() {
		e, err := scanContent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Entry is the current version of one code.
func (r *LibraryRepository) Entry(ctx context.Context, code string) (*model.ContentEntry, error) {
	row := r.db.QueryRow(ctx, `SELECT `+contentColumns+`
		FROM detection_content WHERE code = $1 AND retired_at IS NULL`, code)
	e, err := scanContent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchEntry, code)
	}
	if err != nil {
		return nil, fmt.Errorf("library entry %s: %w", code, err)
	}
	return e, nil
}

// EntryVersion is one specific version, retired or not.
//
// It is what makes "what did you change" answerable: a tenant on v1 has to be
// compared against v1, not against whatever ships today.
func (r *LibraryRepository) EntryVersion(ctx context.Context, code string, version int) (*model.ContentEntry, error) {
	row := r.db.QueryRow(ctx, `SELECT `+contentColumns+`
		FROM detection_content WHERE code = $1 AND version = $2`, code, version)
	e, err := scanContent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s v%d", ErrNoSuchEntry, code, version)
	}
	if err != nil {
		return nil, fmt.Errorf("library entry %s v%d: %w", code, version, err)
	}
	return e, nil
}

// Adoption is a tenant rule that came from the catalogue: its lineage, and the
// shape it has now so the caller can compare the two.
type Adoption struct {
	Lineage *model.AdoptedRule
	// Current is the rule as it stands in this tenant, which may have been
	// edited since it was adopted.
	Current *model.DetectionRule
}

// Adoptions are the tenant's rules that came from the catalogue, by code.
func (r *LibraryRepository) Adoptions(ctx context.Context, tenantID uuid.UUID) (map[string]*Adoption, error) {
	rows, err := r.db.Query(ctx, `
		SELECT content_code, content_version, COALESCE(adopted_at, created_at),
		       id, name, enabled, alerts_total,
		       severity, conditions, actions, dedup_window_s
		FROM detection_rules
		WHERE tenant_id = $1 AND content_code IS NOT NULL`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read adoptions: %w", err)
	}
	defer rows.Close()

	out := map[string]*Adoption{}
	for rows.Next() {
		var (
			code     string
			lineage  model.AdoptedRule
			current  model.DetectionRule
			condJSON []byte
			actJSON  []byte
		)
		if err := rows.Scan(&code, &lineage.AtVersion, &lineage.AdoptedAt,
			&lineage.RuleID, &lineage.Name, &lineage.Enabled, &lineage.AlertsTotal,
			&current.Severity, &condJSON, &actJSON, &current.DedupWindowS); err != nil {
			return nil, fmt.Errorf("scan adoption: %w", err)
		}
		if err := json.Unmarshal(condJSON, &current.Conditions); err != nil {
			return nil, fmt.Errorf("conditions of rule %s: %w", lineage.RuleID, err)
		}
		current.Actions = []model.RuleAction{}
		if len(actJSON) > 0 {
			if err := json.Unmarshal(actJSON, &current.Actions); err != nil {
				return nil, fmt.Errorf("actions of rule %s: %w", lineage.RuleID, err)
			}
		}
		current.ID = lineage.RuleID
		current.Name = lineage.Name

		out[code] = &Adoption{Lineage: &lineage, Current: &current}
	}
	return out, rows.Err()
}

// Adopt creates a tenant rule from a catalogue entry, recording the lineage.
func (r *LibraryRepository) Adopt(
	ctx context.Context,
	tenantID uuid.UUID,
	createdBy *uuid.UUID,
	entry *model.ContentEntry,
	rule *model.DetectionRule,
) (uuid.UUID, error) {
	condJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal conditions: %w", err)
	}
	actJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal actions: %w", err)
	}

	id := uuid.New()
	err = r.db.QueryRow(ctx, `
		INSERT INTO detection_rules
			(id, tenant_id, name, description, category, severity, conditions,
			 mitre_tactic, mitre_technique, actions, dedup_window_s, enabled,
			 is_system, content_code, content_version, adopted_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true,$13,$14,NOW(),$15)
		RETURNING id`,
		id, tenantID, rule.Name, entry.Description, entry.Category, rule.Severity,
		condJSON, nvl(entry.MitreTactic), nvl(entry.MitreTechnique), actJSON,
		rule.DedupWindowS, rule.Enabled, entry.Code, entry.Version, createdBy,
	).Scan(&id)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return uuid.Nil, fmt.Errorf("%w: %s", ErrAlreadyAdopted, entry.Code)
		}
		return uuid.Nil, fmt.Errorf("adopt %s: %w", entry.Code, err)
	}
	return id, nil
}

// OwnRuleCount is how many rules this tenant wrote rather than adopted.
func (r *LibraryRepository) OwnRuleCount(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM detection_rules WHERE tenant_id = $1 AND content_code IS NULL`,
		tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count own rules: %w", err)
	}
	return n, nil
}
