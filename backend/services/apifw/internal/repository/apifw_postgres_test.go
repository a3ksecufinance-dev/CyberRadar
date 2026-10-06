package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/apifw/internal/model"
)

// The API firewall repository: the first test this service has ever had.
//
// This is the service that decides whether an inbound request carrying an API
// key is allowed in, so it holds the only credential in the platform that is
// not a JWT. Three properties are worth a database to prove: the raw key is
// never stored, a key that has been revoked or has expired stops
// authenticating, and rotation really invalidates what it replaced. Each of
// those is a one-line change away from being wrong, and none of them fails
// loudly — a key that still works after revocation works exactly as well as
// one that should.

func repo(t *testing.T) (*APIFWRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewAPIFWRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func newKey(t *testing.T, r *APIFWRepository, tenant uuid.UUID, name string) *model.APIKey {
	t.Helper()
	k, err := r.CreateAPIKey(context.Background(), tenant, nil, &model.CreateAPIKeyRequest{
		Name: name, Description: "clé de test", Scopes: []string{model.ScopeRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey(%s): %v", name, err)
	}
	return k
}

func hashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ─── The credential ──────────────────────────────────────────────────────────

// The raw key is handed back exactly once, and what the database holds is its
// digest. A table that held the key itself would turn one read of one row into
// every customer's API access.
func TestTheRawKeyIsReturnedOnceAndStoredAsADigest(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)

	made := newKey(t, r, tenant, "intégration SIEM")
	if made.PlainKey == "" {
		t.Fatal("the creation returned no key, so nobody can use it")
	}
	if !strings.HasPrefix(made.PlainKey, "crp_") || len(made.PlainKey) != 68 {
		t.Errorf("the key is %q — want crp_ plus 64 hex characters", made.PlainKey)
	}
	if made.KeyPrefix == made.PlainKey {
		t.Error("the prefix shown in the interface is the whole key")
	}
	if !strings.HasPrefix(made.PlainKey, strings.TrimSuffix(made.KeyPrefix, "...")) {
		t.Errorf("the prefix %q does not belong to the key", made.KeyPrefix)
	}

	// What is on disk: the digest, and nothing resembling the key.
	var storedHash, storedPrefix string
	if err := pool.QueryRow(ctx,
		`SELECT key_hash, key_prefix FROM apifw_api_keys WHERE id=$1`, made.ID).
		Scan(&storedHash, &storedPrefix); err != nil {
		t.Fatalf("read the stored row: %v", err)
	}
	if storedHash == made.PlainKey {
		t.Fatal("the raw key is stored in the database")
	}
	if storedHash != hashOf(made.PlainKey) {
		t.Errorf("the stored digest is not the key's SHA-256")
	}

	// And reading the key back never returns it again.
	again, err := r.GetAPIKey(ctx, tenant, made.ID)
	if err != nil {
		t.Fatalf("GetAPIKey: %v", err)
	}
	if again == nil {
		t.Fatal("GetAPIKey found nothing")
	}
	if again.PlainKey != "" {
		t.Error("a later read handed the raw key back")
	}
	if again.RateLimitRPM != 60 || again.RateLimitRPD != 10000 {
		t.Errorf("the default rate limits are %d/%d, want 60 and 10000",
			again.RateLimitRPM, again.RateLimitRPD)
	}
	if !again.IsActive {
		t.Error("a fresh key is not active")
	}
	if len(again.Scopes) != 1 || again.Scopes[0] != model.ScopeRead {
		t.Errorf("scopes are %v", again.Scopes)
	}
}

// Two keys are never the same, which is what makes the digest a credential
// rather than a label.
func TestTwoKeysAreNeverTheSame(t *testing.T) {
	r, _, tenant := repo(t)

	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		k := newKey(t, r, tenant, "clé")
		if seen[k.PlainKey] {
			t.Fatalf("the same key was generated twice: %s", k.KeyPrefix)
		}
		seen[k.PlainKey] = true
	}
}

// Authentication: the key works, and every reason it should stop working does.
func TestAuthenticationAcceptsOnlyALiveKey(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	live := newKey(t, r, tenant, "vivante")
	got, err := r.GetAPIKeyByHash(ctx, live.PlainKey)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if got == nil || got.ID != live.ID {
		t.Fatalf("a live key did not authenticate: %+v", got)
	}

	// A key nobody issued.
	if got, err := r.GetAPIKeyByHash(ctx, "crp_"+strings.Repeat("0", 64)); err != nil || got != nil {
		t.Errorf("an unissued key authenticated: %v / %v", got, err)
	}
	// The prefix alone, which is the part shown in the interface.
	if got, err := r.GetAPIKeyByHash(ctx, live.KeyPrefix); err != nil || got != nil {
		t.Errorf("the prefix shown in the interface authenticated: %v / %v", got, err)
	}
	// The stored digest presented as if it were the key.
	if got, err := r.GetAPIKeyByHash(ctx, hashOf(live.PlainKey)); err != nil || got != nil {
		t.Errorf("the stored digest authenticated as a key: %v / %v", got, err)
	}
	// An empty key.
	if got, err := r.GetAPIKeyByHash(ctx, ""); err != nil || got != nil {
		t.Errorf("an empty key authenticated: %v / %v", got, err)
	}

	// Revoked: this is the one an operator reaches for when a key has leaked,
	// so it has to take effect on the next request.
	revoked := newKey(t, r, tenant, "révoquée")
	if err := r.RevokeAPIKey(ctx, tenant, revoked.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if got, err := r.GetAPIKeyByHash(ctx, revoked.PlainKey); err != nil || got != nil {
		t.Errorf("a revoked key still authenticates: %v / %v", got, err)
	}

	// Expired.
	past := time.Now().UTC().Add(-time.Hour)
	expired, err := r.CreateAPIKey(ctx, tenant, nil, &model.CreateAPIKeyRequest{
		Name: "expirée", Scopes: []string{model.ScopeRead}, ExpiresAt: &past,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if got, err := r.GetAPIKeyByHash(ctx, expired.PlainKey); err != nil || got != nil {
		t.Errorf("an expired key still authenticates: %v / %v", got, err)
	}

	// A key expiring in the future still works, or every key with a lifetime
	// would be dead on arrival.
	future := time.Now().UTC().Add(time.Hour)
	dated, err := r.CreateAPIKey(ctx, tenant, nil, &model.CreateAPIKeyRequest{
		Name: "datée", Scopes: []string{model.ScopeRead}, ExpiresAt: &future,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if got, err := r.GetAPIKeyByHash(ctx, dated.PlainKey); err != nil || got == nil {
		t.Errorf("a key valid for another hour did not authenticate: %v / %v", got, err)
	}
}

// Rotation hands back a new key and the old one stops working. A rotation that
// left the old key valid would be the opposite of what it is for.
func TestRotationInvalidatesWhatItReplaced(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	old := newKey(t, r, tenant, "à faire tourner")
	rotated, err := r.RotateAPIKey(ctx, tenant, old.ID)
	if err != nil {
		t.Fatalf("RotateAPIKey: %v", err)
	}
	if rotated == nil {
		t.Fatal("the rotation returned nothing")
	}
	if rotated.ID != old.ID {
		t.Errorf("the rotation changed the key's identity: %s then %s", old.ID, rotated.ID)
	}
	if rotated.PlainKey == "" {
		t.Fatal("the rotation returned no new key")
	}
	if rotated.PlainKey == old.PlainKey {
		t.Fatal("the rotation returned the same key")
	}
	if rotated.KeyPrefix == old.KeyPrefix {
		t.Error("the prefix did not move, so the interface still shows the old key")
	}

	if got, err := r.GetAPIKeyByHash(ctx, old.PlainKey); err != nil || got != nil {
		t.Errorf("the rotated-out key still authenticates: %v / %v", got, err)
	}
	if got, err := r.GetAPIKeyByHash(ctx, rotated.PlainKey); err != nil || got == nil {
		t.Errorf("the new key does not authenticate: %v / %v", got, err)
	}
}

// Using a key records when it was last used, which is what tells an operator a
// key is dormant and can be withdrawn.
func TestUsingAKeyRecordsThatItWasUsed(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	k := newKey(t, r, tenant, "clé")
	if k.LastUsedAt != nil {
		t.Errorf("a key that has never been used carries %v", k.LastUsedAt)
	}
	if _, err := r.GetAPIKeyByHash(ctx, k.PlainKey); err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}

	// The touch is asynchronous and best-effort, so wait for it rather than
	// assuming either way.
	var seen bool
	for i := 0; i < 50; i++ {
		got, err := r.GetAPIKey(ctx, tenant, k.ID)
		if err != nil {
			t.Fatalf("GetAPIKey: %v", err)
		}
		if got != nil && got.LastUsedAt != nil {
			seen = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seen {
		t.Error("using a key never recorded that it was used")
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	key := newKey(t, r, mine, "ma clé")
	wh, err := r.CreateWebhook(ctx, mine, nil, &model.CreateWebhookRequest{
		Name: "mon webhook", URL: "https://banque.example/hook",
		Events: []string{model.EventAlertCreated}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}

	// Reads
	if got, err := r.GetAPIKey(ctx, theirs, key.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the key: %v / %v", got, err)
	}
	if got, err := r.GetWebhook(ctx, theirs, wh.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the webhook: %v / %v", got, err)
	}
	if rows, total, err := r.ListAPIKeys(ctx, model.APIKeyFilter{TenantID: theirs, Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d keys (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListWebhooks(ctx, model.WebhookFilter{TenantID: theirs, Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d webhooks (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListActiveWebhooksForEvent(ctx, theirs, model.EventAlertCreated); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d webhooks for the event: %v", len(rows), err)
	}
	if rows, total, err := r.ListDeliveries(ctx, theirs, wh.ID, 50, 0); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d deliveries (total=%d): %v", len(rows), total, err)
	}
	if stats, err := r.UsageStats(ctx, theirs, key.ID); err != nil || len(stats) != 0 {
		t.Errorf("the neighbour read %d usage rows: %v", len(stats), err)
	}

	// A filter with no tenant at all must match nothing rather than everything.
	if rows, total, err := r.ListAPIKeys(ctx, model.APIKeyFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("a filter with no tenant listed %d keys (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListWebhooks(ctx, model.WebhookFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("a filter with no tenant listed %d webhooks (total=%d): %v", len(rows), total, err)
	}

	// Writes
	if got, err := r.UpdateAPIKey(ctx, theirs, key.ID, &model.UpdateAPIKeyRequest{Name: strp("volée")}); err != nil || got != nil {
		t.Errorf("the neighbour renamed the key: %v / %v", got, err)
	}
	if got, err := r.RotateAPIKey(ctx, theirs, key.ID); err != nil || got != nil {
		t.Errorf("the neighbour rotated the key: %v / %v", got, err)
	}
	if got, err := r.UpdateWebhook(ctx, theirs, wh.ID, &model.UpdateWebhookRequest{Name: strp("volé")}); err != nil || got != nil {
		t.Errorf("the neighbour renamed the webhook: %v / %v", got, err)
	}
	if err := r.RevokeAPIKey(ctx, theirs, key.ID); err != nil {
		t.Errorf("RevokeAPIKey by the neighbour: %v", err)
	}
	if err := r.SetWebhookActive(ctx, theirs, wh.ID, false); err != nil {
		t.Errorf("SetWebhookActive by the neighbour: %v", err)
	}
	if err := r.DeleteWebhook(ctx, theirs, wh.ID); err != nil {
		t.Errorf("DeleteWebhook by the neighbour: %v", err)
	}

	// None of it landed: the key still authenticates and the webhook is still
	// there and still active.
	if got, err := r.GetAPIKeyByHash(ctx, key.PlainKey); err != nil || got == nil {
		t.Errorf("the neighbour's revocation took effect: %v / %v", got, err)
	}
	live, err := r.GetWebhook(ctx, mine, wh.ID)
	if err != nil {
		t.Fatalf("re-read the webhook: %v", err)
	}
	if live == nil {
		t.Fatal("the neighbour deleted the webhook")
	}
	if !live.IsActive {
		t.Error("the neighbour disabled the webhook")
	}
	if live.Name != "mon webhook" {
		t.Errorf("the webhook is now named %q", live.Name)
	}
}

// ─── Webhooks ────────────────────────────────────────────────────────────────

// A webhook's signing secret is never part of what a read returns: it is the
// shared secret that lets the far end trust a delivery, so showing it in an API
// response would let anyone who can read the configuration forge one.
func TestTheSigningSecretIsNotPartOfAWebhookRead(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	wh, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "hook", URL: "https://banque.example/hook",
		Events: []string{model.EventIncidentCreated}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}

	// The internal read does hand it over, because the delivery has to sign.
	got, secret, err := r.GetWebhookWithSecret(ctx, wh.ID)
	if err != nil {
		t.Fatalf("GetWebhookWithSecret: %v", err)
	}
	if got == nil || secret != "s3cr3t" {
		t.Fatalf("the signing path did not get the secret: %v / %q", got, secret)
	}
	if direct, err := r.GetWebhookSecret(ctx, wh.ID); err != nil || direct != "s3cr3t" {
		t.Errorf("GetWebhookSecret gave %q: %v", direct, err)
	}

	// A webhook created with no secret reads back as empty rather than failing.
	bare, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "sans secret", URL: "https://banque.example/nu",
		Events: []string{model.EventIOCMatched},
	})
	if err != nil {
		t.Fatalf("CreateWebhook with no secret: %v", err)
	}
	if s, err := r.GetWebhookSecret(ctx, bare.ID); err != nil || s != "" {
		t.Errorf("a webhook with no secret gave %q: %v", s, err)
	}

	// An inactive webhook is not handed to the signing path at all: a delivery
	// to a webhook the customer switched off must not happen.
	if err := r.SetWebhookActive(ctx, tenant, wh.ID, false); err != nil {
		t.Fatalf("SetWebhookActive: %v", err)
	}
	if got, _, err := r.GetWebhookWithSecret(ctx, wh.ID); err != nil || got != nil {
		t.Errorf("a disabled webhook was handed to the signing path: %v / %v", got, err)
	}
}

// Only the webhooks subscribed to an event, and only the active ones, are
// returned for it — a fan-out that ignored the subscription would send every
// customer's hook every event in the platform.
func TestOnlyTheSubscribedAndActiveWebhooksGetAnEvent(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	subscribed, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "alertes", URL: "https://banque.example/alertes",
		Events: []string{model.EventAlertCreated, model.EventIOCMatched},
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	other, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "vulnérabilités", URL: "https://banque.example/vulns",
		Events: []string{model.EventVulnFound},
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	disabled, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "coupé", URL: "https://banque.example/coupe",
		Events: []string{model.EventAlertCreated},
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	if err := r.SetWebhookActive(ctx, tenant, disabled.ID, false); err != nil {
		t.Fatalf("SetWebhookActive: %v", err)
	}

	got, err := r.ListActiveWebhooksForEvent(ctx, tenant, model.EventAlertCreated)
	if err != nil {
		t.Fatalf("ListActiveWebhooksForEvent: %v", err)
	}
	if len(got) != 1 || got[0].ID != subscribed.ID {
		t.Fatalf("%d webhooks for alert.created, want only the subscribed and active one", len(got))
	}
	_ = other

	// An event nobody subscribed to reaches nobody.
	if got, err := r.ListActiveWebhooksForEvent(ctx, tenant, model.EventAnomalyDetected); err != nil || len(got) != 0 {
		t.Errorf("%d webhooks for an event nobody subscribed to: %v", len(got), err)
	}
}

// A delivery is recorded and moves the webhook's own counters, which is what
// tells an operator a far end has stopped answering.
func TestADeliveryMovesTheWebhookCounters(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	wh, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "hook", URL: "https://banque.example/hook",
		Events: []string{model.EventAlertCreated},
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}

	status := 500
	if err := r.RecordDelivery(ctx, &model.WebhookDelivery{
		TenantID: tenant, WebhookID: wh.ID, EventType: model.EventAlertCreated,
		Payload: map[string]any{"alert_id": "a-1"}, ResponseStatus: &status,
		ResponseBody: "boom", Attempt: 1, Success: false,
	}); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}

	failing, err := r.GetWebhook(ctx, tenant, wh.ID)
	if err != nil || failing == nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if failing.FailureCount != 1 {
		t.Errorf("failure_count is %d after one failure", failing.FailureCount)
	}
	if failing.LastStatusCode == nil || *failing.LastStatusCode != 500 {
		t.Errorf("last_status_code is %v", failing.LastStatusCode)
	}
	if failing.LastTriggeredAt == nil {
		t.Error("last_triggered_at was not set")
	}

	// The counter is cumulative, not consecutive: a success records itself and
	// leaves it where it was. Pinned as it is, because the two readings lead to
	// different products — a consecutive counter can retire a webhook that has
	// stopped answering, a cumulative one only reports a total — and because
	// nothing in this service reads the column at all today. No webhook is
	// therefore ever retired for failing, however long the far end has been
	// gone; the deliveries keep being attempted and recorded.
	ok := 200
	if err := r.RecordDelivery(ctx, &model.WebhookDelivery{
		TenantID: tenant, WebhookID: wh.ID, EventType: model.EventAlertCreated,
		Payload: map[string]any{"alert_id": "a-2"}, ResponseStatus: &ok,
		Attempt: 1, Success: true,
	}); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}
	healthy, err := r.GetWebhook(ctx, tenant, wh.ID)
	if err != nil || healthy == nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if healthy.FailureCount != 1 {
		t.Errorf("failure_count is %d, want the cumulative 1", healthy.FailureCount)
	}
	if healthy.LastStatusCode == nil || *healthy.LastStatusCode != 200 {
		t.Errorf("last_status_code is %v after a success", healthy.LastStatusCode)
	}
	if !healthy.IsActive {
		t.Error("the webhook was disabled by a delivery")
	}

	rows, total, err := r.ListDeliveries(ctx, tenant, wh.ID, 50, 0)
	if err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("ListDeliveries gave total=%d, %d rows", total, len(rows))
	}
	// Newest first, and the payload survived the round trip.
	if rows[0].Payload["alert_id"] != "a-2" {
		t.Errorf("the first delivery is %v, want the newest", rows[0].Payload)
	}
}

// ─── The numbers ─────────────────────────────────────────────────────────────

func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	live := newKey(t, r, tenant, "vivante")
	dead := newKey(t, r, tenant, "révoquée")
	if err := r.RevokeAPIKey(ctx, tenant, dead.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	// Four requests on two endpoints, one of them an error.
	now := time.Now().UTC()
	for _, u := range []model.APIKeyUsage{
		{TenantID: tenant, KeyID: live.ID, Endpoint: "/api/v1/alerts", Method: "GET", StatusCode: 200, LatencyMS: 10, RequestedAt: now},
		{TenantID: tenant, KeyID: live.ID, Endpoint: "/api/v1/alerts", Method: "GET", StatusCode: 200, LatencyMS: 30, RequestedAt: now},
		{TenantID: tenant, KeyID: live.ID, Endpoint: "/api/v1/alerts", Method: "GET", StatusCode: 500, LatencyMS: 20, RequestedAt: now},
		{TenantID: tenant, KeyID: live.ID, Endpoint: "/api/v1/assets", Method: "POST", StatusCode: 201, LatencyMS: 40, RequestedAt: now},
	} {
		if err := r.RecordUsage(ctx, &u); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
	}

	wh, err := r.CreateWebhook(ctx, tenant, nil, &model.CreateWebhookRequest{
		Name: "hook", URL: "https://banque.example/hook",
		Events: []string{model.EventAlertCreated},
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	ok, bad := 200, 500
	for _, d := range []model.WebhookDelivery{
		{TenantID: tenant, WebhookID: wh.ID, EventType: model.EventAlertCreated, ResponseStatus: &ok, Success: true, Attempt: 1},
		{TenantID: tenant, WebhookID: wh.ID, EventType: model.EventAlertCreated, ResponseStatus: &ok, Success: true, Attempt: 1},
		{TenantID: tenant, WebhookID: wh.ID, EventType: model.EventAlertCreated, ResponseStatus: &bad, Success: false, Attempt: 1},
		{TenantID: tenant, WebhookID: wh.ID, EventType: model.EventAlertCreated, ResponseStatus: &bad, Success: false, Attempt: 2},
	} {
		d := d
		if err := r.RecordDelivery(ctx, &d); err != nil {
			t.Fatalf("RecordDelivery: %v", err)
		}
	}

	// The neighbour's traffic, which must change nothing below.
	nbKey := newKey(t, r, other, "voisine")
	if err := r.RecordUsage(ctx, &model.APIKeyUsage{
		TenantID: other, KeyID: nbKey.ID, Endpoint: "/api/v1/alerts",
		Method: "GET", StatusCode: 200, LatencyMS: 5, RequestedAt: now,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.ActiveKeys != 1 {
		t.Errorf("active_keys is %d, want 1 — the revoked one is counted", stats.ActiveKeys)
	}
	if stats.TotalRequestsToday != 4 {
		t.Errorf("total_requests_today is %d, want 4", stats.TotalRequestsToday)
	}
	if stats.ActiveWebhooks != 1 {
		t.Errorf("active_webhooks is %d, want 1", stats.ActiveWebhooks)
	}
	if stats.DeliverySuccessRate != 50 {
		t.Errorf("delivery_success_rate is %v, want 50", stats.DeliverySuccessRate)
	}
	if len(stats.TopEndpoints) != 2 {
		t.Fatalf("%d endpoints, want 2: %+v", len(stats.TopEndpoints), stats.TopEndpoints)
	}
	// Busiest first, and its averages are of this tenant's traffic only.
	top := stats.TopEndpoints[0]
	if top.Endpoint != "/api/v1/alerts" || top.Count != 3 {
		t.Errorf("the busiest endpoint is %s with %d calls", top.Endpoint, top.Count)
	}
	if top.AvgLatency != 20 {
		t.Errorf("average latency is %v, want 20", top.AvgLatency)
	}
	if top.ErrorRate < 33 || top.ErrorRate > 34 {
		t.Errorf("error rate is %v, want one error in three", top.ErrorRate)
	}

	// Per-key usage agrees with the aggregate.
	perKey, err := r.UsageStats(ctx, tenant, live.ID)
	if err != nil {
		t.Fatalf("UsageStats: %v", err)
	}
	if len(perKey) != 2 {
		t.Errorf("%d endpoints for the key, want 2", len(perKey))
	}
}

// A tenant with nothing gets zeros, and the success rate is zero rather than a
// division by no deliveries.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if stats.ActiveKeys != 0 || stats.TotalRequestsToday != 0 || stats.ActiveWebhooks != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	if stats.DeliverySuccessRate != 0 {
		t.Errorf("delivery_success_rate is %v with no delivery at all", stats.DeliverySuccessRate)
	}
	if stats.TopEndpoints == nil {
		t.Error("top_endpoints came back nil rather than empty")
	}
	if got, err := r.UsageStats(ctx, tenant, uuid.New()); err != nil || len(got) != 0 {
		t.Errorf("UsageStats for an unknown key gave %d rows: %v", len(got), err)
	}
}

// ─── Filters ─────────────────────────────────────────────────────────────────

func TestTheActiveFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	newKey(t, r, tenant, "vivante")
	dead := newKey(t, r, tenant, "révoquée")
	if err := r.RevokeAPIKey(ctx, tenant, dead.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	yes, no := true, false
	for _, c := range []struct {
		what   string
		filter model.APIKeyFilter
		want   int
	}{
		{"all", model.APIKeyFilter{TenantID: tenant, Limit: 50}, 2},
		{"active only", model.APIKeyFilter{TenantID: tenant, IsActive: &yes, Limit: 50}, 1},
		{"revoked only", model.APIKeyFilter{TenantID: tenant, IsActive: &no, Limit: 50}, 1},
	} {
		rows, total, err := r.ListAPIKeys(ctx, c.filter)
		if err != nil {
			t.Fatalf("ListAPIKeys %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
		for _, k := range rows {
			if k.PlainKey != "" {
				t.Error("a listing handed back a raw key")
			}
		}
	}
}

func strp(s string) *string { return &s }
