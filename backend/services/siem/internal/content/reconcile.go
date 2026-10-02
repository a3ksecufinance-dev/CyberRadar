package content

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/siem/internal/model"
)

// Change is what the reconciliation would do, or did, to one code.
type Change struct {
	Code string
	// Action is one of "publish", "retire" or "unchanged".
	Action string
	// From and To are the version numbers. From is zero for a new detection.
	From int
	To   int
	// Why is the one-line reason, for an operator reading a dry run.
	Why string
}

// Plan is the whole reconciliation, decided before anything is written.
//
// Separated from applying it because a content load changes what a platform
// detects, and an operator is entitled to see that before it happens rather
// than afterwards in a log.
type Plan struct {
	Pack    *Pack
	Source  string
	Changes []Change

	// SignedBy and Digest are what vouched for the pack, carried through to the
	// load record. Empty when it came from a directory or was loaded unsigned —
	// which is exactly what the record has to be able to say.
	SignedBy string
	Digest   string
}

// Counts are the three numbers the load record keeps.
func (p *Plan) Counts() (published, retired, unchanged int) {
	for _, c := range p.Changes {
		switch c.Action {
		case "publish":
			published++
		case "retire":
			retired++
		default:
			unchanged++
		}
	}
	return
}

// Moves reports whether anything would actually change.
func (p *Plan) Moves() bool {
	published, retired, _ := p.Counts()
	return published+retired > 0
}

// currentRow is a published entry as the database holds it.
type currentRow struct {
	version int
	hash    string
	entry   *Entry
}

// Reconcile decides what the pack means for the catalogue already in place.
//
// The comparison is on the content fingerprint, not on a version in the file.
// Three cases matter and each is a decision somebody would otherwise get wrong:
//
//   - a code the catalogue has never seen is published at version 1;
//   - a code whose fingerprint matches is left entirely alone, including its
//     version — so a load that changes nothing tells no tenant that an update
//     is available;
//   - a code whose fingerprint differs is retired and republished one version
//     higher, which is what makes "you adopted v1, v2 is out" true.
//
// A code the catalogue holds and the pack no longer carries is retired, never
// deleted: tenants have adopted it, their rules point at it by code, and the
// difference from the version they took is computed by reading that version
// back. Deleting it would turn their lineage into "the version you adopted is
// no longer on record".
func Reconcile(ctx context.Context, db *pgxpool.Pool, pack *Pack, entries []*Entry, source string) (*Plan, error) {
	current, err := currentCatalogue(ctx, db)
	if err != nil {
		return nil, err
	}

	plan := &Plan{Pack: pack, Source: source}
	inPack := make(map[string]bool, len(entries))

	for _, e := range entries {
		inPack[e.Code] = true
		hash := e.Hash()

		row, known := current[e.Code]
		switch {
		case !known:
			plan.Changes = append(plan.Changes, Change{
				Code: e.Code, Action: "publish", From: 0, To: 1,
				Why: "not in the catalogue",
			})
		case row.hash == hash:
			plan.Changes = append(plan.Changes, Change{
				Code: e.Code, Action: "unchanged", From: row.version, To: row.version,
				Why: "same content",
			})
		default:
			plan.Changes = append(plan.Changes, Change{
				Code: e.Code, Action: "publish", From: row.version, To: row.version + 1,
				Why: changedFields(row.entry, e),
			})
		}
	}

	for code, row := range current {
		if !inPack[code] {
			plan.Changes = append(plan.Changes, Change{
				Code: code, Action: "retire", From: row.version, To: row.version,
				Why: "no longer in the pack",
			})
		}
	}

	sort.Slice(plan.Changes, func(i, j int) bool { return plan.Changes[i].Code < plan.Changes[j].Code })
	return plan, nil
}

// changedFields names what moved, so a dry run says why a version is being
// published rather than only that one is.
func changedFields(was, now *Entry) string {
	if was == nil {
		return "content differs"
	}
	var moved []string
	cmp := func(name string, a, b any) {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if string(x) != string(y) {
			moved = append(moved, name)
		}
	}
	cmp("title", was.Title, now.Title)
	cmp("description", was.Description, now.Description)
	cmp("category", was.Category, now.Category)
	cmp("severity", was.Severity, now.Severity)
	cmp("mitre", was.Mitre, now.Mitre)
	cmp("conditions", was.Conditions, now.Conditions)
	cmp("actions", was.Actions, now.Actions)
	cmp("dedup_window_s", was.DedupWindowS, now.DedupWindowS)
	cmp("rationale", was.Rationale, now.Rationale)
	cmp("false_positives", was.FalsePositives, now.FalsePositives)
	cmp("response", was.Response, now.Response)
	cmp("frameworks", sortedCopy(was.Frameworks), sortedCopy(now.Frameworks))
	cmp("controls", sortedCopy(was.Controls), sortedCopy(now.Controls))
	cmp("requires", sortedCopy(was.Requires), sortedCopy(now.Requires))
	cmp("enabled_by_default", was.EnabledByDefault, now.EnabledByDefault)
	cmp("tags", sortedCopy(was.Tags), sortedCopy(now.Tags))
	if len(moved) == 0 {
		return "content differs"
	}
	return fmt.Sprintf("%v", moved)
}

// currentCatalogue is every published entry, as an Entry so it can be hashed
// and compared with one from a file.
//
// Rows seeded before fingerprints existed carry none. Rather than treating a
// missing fingerprint as "different" — which would republish the whole
// catalogue on first load and tell every tenant that fifteen updates were
// available — the row is rebuilt into an Entry and hashed the same way a file
// is. Identical content therefore converges silently, which is the only
// acceptable behaviour for a migration of where content lives.
func currentCatalogue(ctx context.Context, db *pgxpool.Pool) (map[string]currentRow, error) {
	rows, err := db.Query(ctx, `
		SELECT code, version, COALESCE(content_hash, ''),
		       title, description, category, severity,
		       COALESCE(mitre_tactic, ''), COALESCE(mitre_technique, ''),
		       conditions, actions, dedup_window_s,
		       rationale, COALESCE(false_positives, ''), COALESCE(response, ''),
		       frameworks, controls, requires, enabled_by_default, tags
		FROM detection_content WHERE retired_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("read the catalogue: %w", err)
	}
	defer rows.Close()

	out := map[string]currentRow{}
	for rows.Next() {
		var (
			r        currentRow
			e        Entry
			condJSON []byte
			actJSON  []byte
		)
		if err := rows.Scan(&e.Code, &r.version, &r.hash,
			&e.Title, &e.Description, &e.Category, &e.Severity,
			&e.Mitre.Tactic, &e.Mitre.Technique,
			&condJSON, &actJSON, &e.DedupWindowS,
			&e.Rationale, &e.FalsePositives, &e.Response,
			&e.Frameworks, &e.Controls, &e.Requires, &e.EnabledByDefault, &e.Tags,
		); err != nil {
			return nil, fmt.Errorf("scan a catalogue row: %w", err)
		}
		if err := json.Unmarshal(condJSON, &e.Conditions); err != nil {
			return nil, fmt.Errorf("conditions of %s: %w", e.Code, err)
		}
		e.Actions = []model.RuleAction{}
		if len(actJSON) > 0 {
			if err := json.Unmarshal(actJSON, &e.Actions); err != nil {
				return nil, fmt.Errorf("actions of %s: %w", e.Code, err)
			}
		}
		if r.hash == "" {
			r.hash = e.Hash()
		}
		r.entry = &e
		out[e.Code] = r
	}
	return out, rows.Err()
}

// Apply writes the plan.
//
// One transaction for the whole pack: a catalogue half-updated is worse than
// one not updated, because the half that moved would be reported to tenants as
// available while the rest silently did not.
func Apply(ctx context.Context, db *pgxpool.Pool, pack *Pack, entries []*Entry, plan *Plan) error {
	byCode := make(map[string]*Entry, len(entries))
	for _, e := range entries {
		byCode[e.Code] = e
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	for _, c := range plan.Changes {
		switch c.Action {
		case "unchanged":
			// Backfill the fingerprint on a row that predates them, so the next
			// load compares a stored hash rather than recomputing one.
			if _, err := tx.Exec(ctx, `
				UPDATE detection_content
				SET content_hash = $1, pack_version = COALESCE(pack_version, $2)
				WHERE code = $3 AND retired_at IS NULL AND content_hash IS NULL`,
				byCode[c.Code].Hash(), pack.Version, c.Code); err != nil {
				return fmt.Errorf("record the fingerprint of %s: %w", c.Code, err)
			}

		case "retire":
			if _, err := tx.Exec(ctx,
				`UPDATE detection_content SET retired_at = NOW()
				 WHERE code = $1 AND retired_at IS NULL`, c.Code); err != nil {
				return fmt.Errorf("retire %s: %w", c.Code, err)
			}

		case "publish":
			// Retire first: one current row per code is a unique index, and it
			// is what makes "which one ships today" unambiguous.
			if c.From > 0 {
				if _, err := tx.Exec(ctx,
					`UPDATE detection_content SET retired_at = NOW()
					 WHERE code = $1 AND retired_at IS NULL`, c.Code); err != nil {
					return fmt.Errorf("retire the previous %s: %w", c.Code, err)
				}
			}
			if err := insert(ctx, tx, pack, byCode[c.Code], c.To); err != nil {
				return err
			}
		}
	}

	published, retired, unchanged := plan.Counts()
	if _, err := tx.Exec(ctx, `
		INSERT INTO detection_content_loads
			(pack_name, pack_version, source, published, retired, unchanged,
			 signed_by, pack_digest)
		VALUES ($1,$2,$3,$4,$5,$6, NULLIF($7,''), NULLIF($8,''))`,
		pack.Name, pack.Version, plan.Source, published, retired, unchanged,
		plan.SignedBy, plan.Digest); err != nil {
		return fmt.Errorf("record the load: %w", err)
	}

	return tx.Commit(ctx)
}

func insert(ctx context.Context, tx pgx.Tx, pack *Pack, e *Entry, version int) error {
	condJSON, err := json.Marshal(e.Conditions)
	if err != nil {
		return fmt.Errorf("conditions of %s: %w", e.Code, err)
	}
	actJSON, err := json.Marshal(e.Actions)
	if err != nil {
		return fmt.Errorf("actions of %s: %w", e.Code, err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO detection_content
			(code, version, title, description, category, severity,
			 mitre_tactic, mitre_technique, conditions, actions, dedup_window_s,
			 rationale, false_positives, response,
			 frameworks, controls, requires, enabled_by_default, tags,
			 content_hash, pack_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		e.Code, version, e.Title, e.Description, e.Category, e.Severity,
		nilIfEmpty(e.Mitre.Tactic), nilIfEmpty(e.Mitre.Technique),
		condJSON, actJSON, e.DedupWindowS,
		e.Rationale, nilIfEmpty(e.FalsePositives), nilIfEmpty(e.Response),
		orEmpty(e.Frameworks), orEmpty(e.Controls), orEmpty(e.Requires),
		e.EnabledByDefault, orEmpty(e.Tags),
		e.Hash(), pack.Version,
	)
	if err != nil {
		return fmt.Errorf("publish %s v%d: %w", e.Code, version, err)
	}
	return nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// orEmpty turns a nil list into an empty one: the columns are NOT NULL arrays,
// and a client should never have to tell "none" from "not populated".
func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
