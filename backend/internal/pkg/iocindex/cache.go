package iocindex

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Snapshot is an immutable view of every active indicator, keyed for lookup.
//
// Immutable on purpose: the ingest path reads it without a lock, and a refresh
// replaces the pointer rather than mutating the map. A reader holding the old
// snapshot finishes its event against a consistent set, which matters more here
// than being a few seconds fresher.
type Snapshot struct {
	byKey     map[string]Entry
	loadedAt  time.Time
	truncated bool
}

// key is tenant, type and normalised value. The tenant is part of it because
// one process serves every tenant and an indicator belongs to exactly one:
// a shared key would let one customer's feed raise alerts in another's estate.
func key(tenantID uuid.UUID, iocType, normalized string) string {
	return tenantID.String() + "\x00" + iocType + "\x00" + normalized
}

// Lookup reports whether value is a known indicator for this tenant.
func (s *Snapshot) Lookup(tenantID uuid.UUID, iocType, value string) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	e, ok := s.byKey[key(tenantID, iocType, Normalize(iocType, value))]
	return e, ok
}

// Match runs every candidate of an event against the snapshot.
func (s *Snapshot) Match(tenantID uuid.UUID, candidates []Candidate) []Hit {
	if s == nil || len(s.byKey) == 0 {
		return nil
	}
	var hits []Hit
	for _, c := range candidates {
		if e, ok := s.Lookup(tenantID, c.Type, c.Value); ok {
			hits = append(hits, Hit{Candidate: c, Entry: e})
		}
	}
	return hits
}

// Size is how many indicators the snapshot holds.
func (s *Snapshot) Size() int {
	if s == nil {
		return 0
	}
	return len(s.byKey)
}

// Age is how long ago the snapshot was loaded — the staleness an operator has
// to reason about when an indicator does not seem to be matching yet.
func (s *Snapshot) Age() time.Duration {
	if s == nil || s.loadedAt.IsZero() {
		return 0
	}
	return time.Since(s.loadedAt)
}

// Truncated reports that the feed held more indicators than the cap allowed,
// so some are not being matched.
func (s *Snapshot) Truncated() bool { return s != nil && s.truncated }

// Hit is one candidate that matched.
type Hit struct {
	Candidate Candidate
	Entry     Entry
}

// Label is the form written into NormalizedEvent.IOCMatched: the kind, the
// value, and the field it was found in. A bare value would leave an analyst
// asking where it came from.
func (h Hit) Label() string {
	return fmt.Sprintf("%s:%s@%s", h.Candidate.Type, Normalize(h.Candidate.Type, h.Candidate.Value), h.Candidate.Field)
}

// ─── Loading ─────────────────────────────────────────────────────────────────

// Config configures a Cache.
type Config struct {
	// Interval between refreshes. The indicator added now takes at most this
	// long to affect detection.
	Interval time.Duration

	// MaxEntries bounds memory on the ingest path. A feed that suddenly
	// delivers ten million indicators must not take the pipeline down with it;
	// matching fewer of them is the lesser failure, and it is reported.
	MaxEntries int
}

// Defaults chosen so that a deployment that sets nothing still behaves: a
// minute of staleness is well inside the window in which an analyst would
// notice, and a million indicators is roughly 150 MB of map.
const (
	DefaultInterval   = time.Minute
	DefaultMaxEntries = 1_000_000
)

// Cache keeps a Snapshot current.
type Cache struct {
	pool    *pgxpool.Pool
	cfg     Config
	logger  zerolog.Logger
	current atomic.Pointer[Snapshot]
}

// NewCache builds a Cache. It does not load anything yet; call Start.
func NewCache(pool *pgxpool.Pool, cfg Config, logger zerolog.Logger) *Cache {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	c := &Cache{pool: pool, cfg: cfg, logger: logger}
	// An empty snapshot rather than nil, so a lookup before the first load
	// answers "not an indicator" instead of panicking.
	c.current.Store(&Snapshot{byKey: map[string]Entry{}})
	return c
}

// Start loads the index once, then refreshes it until ctx is done.
//
// The first load is synchronous and its failure is returned: starting an
// ingest path that silently matches nothing is how a platform reports zero
// threats and is believed.
func (c *Cache) Start(ctx context.Context) error {
	snap, err := c.load(ctx)
	if err != nil {
		return fmt.Errorf("initial indicator load: %w", err)
	}
	c.current.Store(snap)
	c.logger.Info().
		Int("indicators", snap.Size()).
		Dur("refresh", c.cfg.Interval).
		Bool("truncated", snap.Truncated()).
		Msg("ioc_index_loaded")

	go c.refreshLoop(ctx)
	return nil
}

// Current is the snapshot to match against.
func (c *Cache) Current() *Snapshot { return c.current.Load() }

// Match is the whole job in one call: pull the candidates out of an event and
// look each one up. It is what the ingest path uses.
func (c *Cache) Match(tenantID uuid.UUID, ev *event.NormalizedEvent) []Hit {
	return c.Current().Match(tenantID, Candidates(ev))
}

func (c *Cache) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := c.load(ctx)
			if err != nil {
				// Keep serving the old snapshot: stale matching beats none.
				// Worth an error line — the age of what is being matched
				// against is now growing without bound.
				c.logger.Error().Err(err).
					Dur("serving_age", c.Current().Age()).
					Msg("ioc_index_refresh_failed")
				continue
			}
			previous := c.Current().Size()
			c.current.Store(snap)
			if snap.Size() != previous {
				c.logger.Info().
					Int("indicators", snap.Size()).
					Int("previous", previous).
					Msg("ioc_index_refreshed")
			}
		}
	}
}

// load reads every active indicator. The query is the same predicate the
// threat intelligence service's own lookup uses, so the index and a direct
// lookup cannot disagree about which indicators count.
func (c *Cache) load(ctx context.Context) (*Snapshot, error) {
	const q = `
		SELECT id, tenant_id, ioc_type, normalized, severity, confidence,
		       COALESCE(mitre_tactic, ''), COALESCE(mitre_technique, ''),
		       COALESCE(threat_actor, ''), COALESCE(malware_family, ''),
		       COALESCE(campaign, '')
		FROM ti_iocs
		WHERE is_active = true
		  AND (valid_until IS NULL OR valid_until > NOW())
		ORDER BY severity, created_at DESC
		LIMIT $1`

	// One more than the cap, so the extra row is what tells us the feed
	// overflowed rather than happening to hold exactly the cap.
	rows, err := c.pool.Query(ctx, q, c.cfg.MaxEntries+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byKey := make(map[string]Entry, c.cfg.MaxEntries/4)
	truncated := false
	for rows.Next() {
		var (
			e          Entry
			tenantID   uuid.UUID
			normalized string
		)
		if err := rows.Scan(&e.ID, &tenantID, &e.Type, &normalized, &e.Severity, &e.Confidence,
			&e.MitreTactic, &e.MitreTechnique, &e.ThreatActor, &e.MalwareFamily, &e.Campaign); err != nil {
			return nil, err
		}
		if len(byKey) >= c.cfg.MaxEntries {
			truncated = true
			break
		}
		byKey[key(tenantID, e.Type, strings.TrimSpace(normalized))] = e
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if truncated {
		c.logger.Warn().
			Int("cap", c.cfg.MaxEntries).
			Msg("the indicator feed is larger than the cap: the rest is not being matched")
	}

	return &Snapshot{byKey: byKey, loadedAt: time.Now(), truncated: truncated}, nil
}
