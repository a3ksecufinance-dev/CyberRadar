package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/apifw/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIFWRepository handles all API Framework persistence.
type APIFWRepository struct {
	db *pgxpool.Pool
}

// NewAPIFWRepository creates an APIFWRepository.
func NewAPIFWRepository(db *pgxpool.Pool) *APIFWRepository {
	return &APIFWRepository{db: db}
}

// ─── API Keys ─────────────────────────────────────────────────────────────────

const keySelect = `
    id, tenant_id, name, key_prefix, COALESCE(description,''), COALESCE(scopes,'{}'),
    rate_limit_rpm, rate_limit_rpd, is_active, last_used_at, expires_at,
    created_by, created_at, updated_at`

// generateRawKey creates a random key "crp_<32 hex chars>".
func generateRawKey() (rawKey, prefix, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return
	}
	hex32 := hex.EncodeToString(buf)
	rawKey = "crp_" + hex32
	// prefix = first 12 chars of rawKey (crp_ + 8 hex) + "..."
	prefix = rawKey[:12] + "..."
	sum := sha256.Sum256([]byte(rawKey))
	hash = hex.EncodeToString(sum[:])
	return
}

// CreateAPIKey generates a new key, stores hash+prefix, returns the model with
// PlainKey set (the ONLY time the raw key is available).
func (r *APIFWRepository) CreateAPIKey(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateAPIKeyRequest) (*model.APIKey, error) {
	rawKey, prefix, hash, err := generateRawKey()
	if err != nil {
		return nil, err
	}

	rpm := req.RateLimitRPM
	if rpm <= 0 {
		rpm = 60
	}
	rpd := req.RateLimitRPD
	if rpd <= 0 {
		rpd = 10000
	}
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	key, err := scanKey(r.db.QueryRow(ctx, `
		INSERT INTO apifw_api_keys
		    (tenant_id, name, key_prefix, key_hash, description, scopes,
		     rate_limit_rpm, rate_limit_rpd, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING `+keySelect,
		tenantID, req.Name, prefix, hash, req.Description, scopes,
		rpm, rpd, req.ExpiresAt, callerID))
	if err != nil {
		return nil, err
	}
	key.PlainKey = rawKey
	return key, nil
}

func (r *APIFWRepository) GetAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) (*model.APIKey, error) {
	key, err := scanKey(r.db.QueryRow(ctx,
		`SELECT `+keySelect+` FROM apifw_api_keys WHERE id=$1 AND tenant_id=$2`,
		keyID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return key, err
}

// GetAPIKeyByHash is used for authenticating inbound requests with a raw key.
// It returns nil if not found or inactive/expired.
func (r *APIFWRepository) GetAPIKeyByHash(ctx context.Context, rawKey string) (*model.APIKey, error) {
	sum := sha256.Sum256([]byte(rawKey))
	hash := hex.EncodeToString(sum[:])
	key, err := scanKey(r.db.QueryRow(ctx,
		`SELECT `+keySelect+` FROM apifw_api_keys WHERE key_hash=$1 AND is_active=TRUE
		 AND (expires_at IS NULL OR expires_at > NOW())`,
		hash))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Touch last_used_at asynchronously — best effort.
	_, _ = r.db.Exec(context.Background(),
		`UPDATE apifw_api_keys SET last_used_at=NOW(), updated_at=NOW() WHERE id=$1`, key.ID)
	return key, nil
}

func (r *APIFWRepository) ListAPIKeys(ctx context.Context, f model.APIKeyFilter) ([]*model.APIKey, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.IsActive != nil {
		where = append(where, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *f.IsActive)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM apifw_api_keys WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+keySelect+` FROM apifw_api_keys WHERE `+whereStr+
			` ORDER BY created_at DESC`+
			fmt.Sprintf(` LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var keys []*model.APIKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, 0, err
		}
		keys = append(keys, k)
	}
	return keys, total, rows.Err()
}

// RevokeAPIKey sets is_active=false.
func (r *APIFWRepository) RevokeAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE apifw_api_keys SET is_active=FALSE, updated_at=NOW() WHERE id=$1 AND tenant_id=$2`,
		keyID, tenantID)
	return err
}

// RotateAPIKey generates a new key, updates hash+prefix, and returns the model
// with PlainKey set to the new raw key (only time it's available).
func (r *APIFWRepository) RotateAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) (*model.APIKey, error) {
	rawKey, prefix, hash, err := generateRawKey()
	if err != nil {
		return nil, err
	}
	key, err := scanKey(r.db.QueryRow(ctx, `
		UPDATE apifw_api_keys
		SET key_prefix=$1, key_hash=$2, updated_at=NOW()
		WHERE id=$3 AND tenant_id=$4
		RETURNING `+keySelect,
		prefix, hash, keyID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key.PlainKey = rawKey
	return key, nil
}

func (r *APIFWRepository) UpdateAPIKey(ctx context.Context, tenantID, keyID uuid.UUID, req *model.UpdateAPIKeyRequest) (*model.APIKey, error) {
	setClauses := []string{"updated_at = NOW()"}
	args := []any{keyID, tenantID}
	idx := 3

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", idx))
		args = append(args, *req.Name)
		idx++
	}
	if req.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", idx))
		args = append(args, *req.Description)
		idx++
	}
	if req.Scopes != nil {
		setClauses = append(setClauses, fmt.Sprintf("scopes = $%d", idx))
		args = append(args, req.Scopes)
		idx++
	}
	if req.RateLimitRPM != nil {
		setClauses = append(setClauses, fmt.Sprintf("rate_limit_rpm = $%d", idx))
		args = append(args, *req.RateLimitRPM)
		idx++
	}
	if req.RateLimitRPD != nil {
		setClauses = append(setClauses, fmt.Sprintf("rate_limit_rpd = $%d", idx))
		args = append(args, *req.RateLimitRPD)
		idx++
	}
	if req.ExpiresAt != nil {
		setClauses = append(setClauses, fmt.Sprintf("expires_at = $%d", idx))
		args = append(args, *req.ExpiresAt)
		idx++
	}

	q := fmt.Sprintf(`UPDATE apifw_api_keys SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), keySelect)
	key, err := scanKey(r.db.QueryRow(ctx, q, args...))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return key, err
}

// ─── Usage ────────────────────────────────────────────────────────────────────

func (r *APIFWRepository) RecordUsage(ctx context.Context, u *model.APIKeyUsage) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO apifw_key_usage
		    (tenant_id, key_id, endpoint, method, status_code, latency_ms, ip_address, user_agent, requested_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		u.TenantID, u.KeyID, u.Endpoint, u.Method, u.StatusCode, u.LatencyMS,
		nvlS(u.IPAddress), nvlS(u.UserAgent), u.RequestedAt)
	return err
}

// UsageStats returns aggregated endpoint stats for a key over the last 24 hours.
func (r *APIFWRepository) UsageStats(ctx context.Context, tenantID, keyID uuid.UUID) ([]model.EndpointStat, error) {
	since := time.Now().UTC().Add(-24 * time.Hour)
	rows, err := r.db.Query(ctx, `
		SELECT endpoint, method,
		       COUNT(*)                                                  AS count,
		       AVG(latency_ms)                                          AS avg_latency,
		       COUNT(*) FILTER (WHERE status_code >= 400) * 100.0 / COUNT(*) AS error_rate
		FROM apifw_key_usage
		WHERE key_id=$1 AND tenant_id=$2 AND requested_at >= $3
		GROUP BY endpoint, method
		ORDER BY count DESC
		LIMIT 50`,
		keyID, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []model.EndpointStat
	for rows.Next() {
		var s model.EndpointStat
		if err := rows.Scan(&s.Endpoint, &s.Method, &s.Count, &s.AvgLatency, &s.ErrorRate); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

const webhookSelect = `
    id, tenant_id, name, url, COALESCE(events,'{}'),
    is_active, failure_count, last_triggered_at, last_status_code,
    created_by, created_at, updated_at`

func (r *APIFWRepository) CreateWebhook(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateWebhookRequest) (*model.Webhook, error) {
	events := req.Events
	if events == nil {
		events = []string{}
	}
	wh, err := scanWebhook(r.db.QueryRow(ctx, `
		INSERT INTO apifw_webhooks
		    (tenant_id, name, url, secret, events, created_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+webhookSelect,
		tenantID, req.Name, req.URL, nvlS(req.Secret), events, callerID))
	if err != nil {
		return nil, err
	}
	return wh, nil
}

func (r *APIFWRepository) GetWebhook(ctx context.Context, tenantID, webhookID uuid.UUID) (*model.Webhook, error) {
	wh, err := scanWebhook(r.db.QueryRow(ctx,
		`SELECT `+webhookSelect+` FROM apifw_webhooks WHERE id=$1 AND tenant_id=$2`,
		webhookID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return wh, err
}

// GetWebhookWithSecret fetches the webhook including its signing secret for
// internal use (delivery signing). Secret is never returned to API callers.
func (r *APIFWRepository) GetWebhookWithSecret(ctx context.Context, webhookID uuid.UUID) (wh *model.Webhook, secret string, err error) {
	wh = &model.Webhook{}
	var sc *string
	err = r.db.QueryRow(ctx, `
		SELECT `+webhookSelect+`, secret
		FROM apifw_webhooks WHERE id=$1 AND is_active=TRUE`,
		webhookID,
	).Scan(&wh.ID, &wh.TenantID, &wh.Name, &wh.URL, &wh.Events,
		&wh.IsActive, &wh.FailureCount, &wh.LastTriggeredAt, &wh.LastStatusCode,
		&wh.CreatedBy, &wh.CreatedAt, &wh.UpdatedAt, &sc)
	if err == pgx.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if sc != nil {
		secret = *sc
	}
	return wh, secret, nil
}

func (r *APIFWRepository) ListWebhooks(ctx context.Context, f model.WebhookFilter) ([]*model.Webhook, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.IsActive != nil {
		where = append(where, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *f.IsActive)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM apifw_webhooks WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+webhookSelect+` FROM apifw_webhooks WHERE `+whereStr+
			` ORDER BY created_at DESC`+
			fmt.Sprintf(` LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var webhooks []*model.Webhook
	for rows.Next() {
		wh, err := scanWebhook(rows)
		if err != nil {
			return nil, 0, err
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, total, rows.Err()
}

func (r *APIFWRepository) UpdateWebhook(ctx context.Context, tenantID, webhookID uuid.UUID, req *model.UpdateWebhookRequest) (*model.Webhook, error) {
	setClauses := []string{"updated_at = NOW()"}
	args := []any{webhookID, tenantID}
	idx := 3

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", idx))
		args = append(args, *req.Name)
		idx++
	}
	if req.URL != nil {
		setClauses = append(setClauses, fmt.Sprintf("url = $%d", idx))
		args = append(args, *req.URL)
		idx++
	}
	if req.Secret != nil {
		setClauses = append(setClauses, fmt.Sprintf("secret = $%d", idx))
		args = append(args, nvlS(*req.Secret))
		idx++
	}
	if req.Events != nil {
		setClauses = append(setClauses, fmt.Sprintf("events = $%d", idx))
		args = append(args, req.Events)
		idx++
	}

	q := fmt.Sprintf(`UPDATE apifw_webhooks SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), webhookSelect)
	wh, err := scanWebhook(r.db.QueryRow(ctx, q, args...))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return wh, err
}

func (r *APIFWRepository) DeleteWebhook(ctx context.Context, tenantID, webhookID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM apifw_webhooks WHERE id=$1 AND tenant_id=$2`, webhookID, tenantID)
	return err
}

func (r *APIFWRepository) SetWebhookActive(ctx context.Context, tenantID, webhookID uuid.UUID, active bool) error {
	_, err := r.db.Exec(ctx,
		`UPDATE apifw_webhooks SET is_active=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		active, webhookID, tenantID)
	return err
}

// ListActiveWebhooksForEvent returns all active webhooks subscribed to eventType for a tenant.
// Secrets are not returned here; callers must use GetWebhookSecret per webhook.
func (r *APIFWRepository) ListActiveWebhooksForEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*model.Webhook, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+webhookSelect+`
		 FROM apifw_webhooks
		 WHERE tenant_id=$1 AND is_active=TRUE AND events @> $2::TEXT[]`,
		tenantID, []string{eventType})
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*model.Webhook
	for rows.Next() {
		wh, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, rows.Err()
}

// GetWebhookSecrets returns a map of webhookID -> secret for a set of webhooks.
func (r *APIFWRepository) GetWebhookSecret(ctx context.Context, webhookID uuid.UUID) (string, error) {
	var secret *string
	err := r.db.QueryRow(ctx,
		`SELECT secret FROM apifw_webhooks WHERE id=$1`, webhookID).Scan(&secret)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", nil
	}
	return *secret, nil
}

// ─── Webhook Deliveries ───────────────────────────────────────────────────────

// RecordDelivery inserts a delivery record and updates the webhook stats.
func (r *APIFWRepository) RecordDelivery(ctx context.Context, d *model.WebhookDelivery) error {
	payloadJSON, _ := json.Marshal(d.Payload)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO apifw_webhook_deliveries
		    (tenant_id, webhook_id, event_type, payload, response_status, response_body,
		     attempt, success, delivered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		d.TenantID, d.WebhookID, d.EventType, payloadJSON,
		d.ResponseStatus, nvlS(d.ResponseBody), d.Attempt, d.Success, d.DeliveredAt)
	if err != nil {
		return err
	}

	if d.Success {
		_, err = tx.Exec(ctx, `
			UPDATE apifw_webhooks
			SET last_triggered_at=NOW(), last_status_code=$1, updated_at=NOW()
			WHERE id=$2`,
			d.ResponseStatus, d.WebhookID)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE apifw_webhooks
			SET last_triggered_at=NOW(), last_status_code=$1,
			    failure_count=failure_count+1, updated_at=NOW()
			WHERE id=$2`,
			d.ResponseStatus, d.WebhookID)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListDeliveries returns delivery history for a webhook.
func (r *APIFWRepository) ListDeliveries(ctx context.Context, tenantID, webhookID uuid.UUID, limit, offset int) ([]*model.WebhookDelivery, int, error) {
	if limit <= 0 {
		limit = 50
	}
	var total int
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM apifw_webhook_deliveries WHERE webhook_id=$1 AND tenant_id=$2`,
		webhookID, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, webhook_id, event_type, payload, response_status,
		       COALESCE(response_body,''), attempt, success, delivered_at, created_at
		FROM apifw_webhook_deliveries
		WHERE webhook_id=$1 AND tenant_id=$2
		ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		webhookID, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var deliveries []*model.WebhookDelivery
	for rows.Next() {
		var d model.WebhookDelivery
		var payRaw []byte
		if err := rows.Scan(&d.ID, &d.TenantID, &d.WebhookID, &d.EventType, &payRaw,
			&d.ResponseStatus, &d.ResponseBody, &d.Attempt, &d.Success, &d.DeliveredAt, &d.CreatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(payRaw, &d.Payload)
		deliveries = append(deliveries, &d)
	}
	return deliveries, total, rows.Err()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *APIFWRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.APIFWStats, error) {
	s := &model.APIFWStats{}
	today := time.Now().UTC().Truncate(24 * time.Hour)

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM apifw_api_keys WHERE tenant_id=$1 AND is_active=TRUE`,
		tenantID).Scan(&s.ActiveKeys)

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM apifw_key_usage WHERE tenant_id=$1 AND requested_at >= $2`,
		tenantID, today).Scan(&s.TotalRequestsToday)

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM apifw_webhooks WHERE tenant_id=$1 AND is_active=TRUE`,
		tenantID).Scan(&s.ActiveWebhooks)

	// Delivery success rate over last 24h
	var delivered, succeeded int
	r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE success)
		FROM apifw_webhook_deliveries WHERE tenant_id=$1 AND created_at >= $2`,
		tenantID, today).Scan(&delivered, &succeeded)
	if delivered > 0 {
		s.DeliverySuccessRate = float64(succeeded) * 100.0 / float64(delivered)
	}

	// Top endpoints last 24h
	since := time.Now().UTC().Add(-24 * time.Hour)
	rows, err := r.db.Query(ctx, `
		SELECT endpoint, method,
		       COUNT(*)                                                        AS count,
		       AVG(latency_ms)                                                AS avg_latency,
		       COUNT(*) FILTER (WHERE status_code >= 400) * 100.0 / COUNT(*) AS error_rate
		FROM apifw_key_usage
		WHERE tenant_id=$1 AND requested_at >= $2
		GROUP BY endpoint, method
		ORDER BY count DESC
		LIMIT 10`,
		tenantID, since)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ep model.EndpointStat
			if err := rows.Scan(&ep.Endpoint, &ep.Method, &ep.Count, &ep.AvgLatency, &ep.ErrorRate); err == nil {
				s.TopEndpoints = append(s.TopEndpoints, ep)
			}
		}
	}
	if s.TopEndpoints == nil {
		s.TopEndpoints = []model.EndpointStat{}
	}
	return s, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(...any) error
}

func scanKey(row scannable) (*model.APIKey, error) {
	var k model.APIKey
	err := row.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.KeyPrefix, &k.Description, &k.Scopes,
		&k.RateLimitRPM, &k.RateLimitRPD, &k.IsActive,
		&k.LastUsedAt, &k.ExpiresAt, &k.CreatedBy, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if k.Scopes == nil {
		k.Scopes = []string{}
	}
	return &k, nil
}

func scanWebhook(row scannable) (*model.Webhook, error) {
	var wh model.Webhook
	err := row.Scan(
		&wh.ID, &wh.TenantID, &wh.Name, &wh.URL, &wh.Events,
		&wh.IsActive, &wh.FailureCount, &wh.LastTriggeredAt, &wh.LastStatusCode,
		&wh.CreatedBy, &wh.CreatedAt, &wh.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if wh.Events == nil {
		wh.Events = []string{}
	}
	return &wh, nil
}

func nvlS(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
