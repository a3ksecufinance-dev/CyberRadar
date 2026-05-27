package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/apifw/internal/model"
	"github.com/cyberradar/platform/services/apifw/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// APIFWService orchestrates API key and webhook management.
type APIFWService struct {
	repo   *repository.APIFWRepository
	logger zerolog.Logger
	http   *http.Client
}

// NewAPIFWService creates an APIFWService.
func NewAPIFWService(repo *repository.APIFWRepository, logger zerolog.Logger) *APIFWService {
	return &APIFWService{
		repo:   repo,
		logger: logger,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ─── API Keys ─────────────────────────────────────────────────────────────────

func (s *APIFWService) CreateAPIKey(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateAPIKeyRequest) (*model.APIKey, error) {
	key, err := s.repo.CreateAPIKey(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create api key", err)
	}
	s.logger.Info().
		Str("key_id", key.ID.String()).
		Str("name", key.Name).
		Msg("api_key_created")
	return key, nil
}

func (s *APIFWService) GetAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) (*model.APIKey, error) {
	key, err := s.repo.GetAPIKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, apierrors.Internal("get api key", err)
	}
	if key == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "api key not found")
	}
	return key, nil
}

func (s *APIFWService) ListAPIKeys(ctx context.Context, f model.APIKeyFilter) ([]*model.APIKey, int, error) {
	keys, total, err := s.repo.ListAPIKeys(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list api keys", err)
	}
	return keys, total, nil
}

func (s *APIFWService) UpdateAPIKey(ctx context.Context, tenantID, keyID uuid.UUID, req *model.UpdateAPIKeyRequest) (*model.APIKey, error) {
	key, err := s.repo.UpdateAPIKey(ctx, tenantID, keyID, req)
	if err != nil {
		return nil, apierrors.Internal("update api key", err)
	}
	if key == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "api key not found")
	}
	return key, nil
}

// RevokeAPIKey marks a key inactive. Once revoked it cannot authenticate.
func (s *APIFWService) RevokeAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) error {
	// Confirm exists first.
	if _, err := s.GetAPIKey(ctx, tenantID, keyID); err != nil {
		return err
	}
	if err := s.repo.RevokeAPIKey(ctx, tenantID, keyID); err != nil {
		return apierrors.Internal("revoke api key", err)
	}
	s.logger.Info().Str("key_id", keyID.String()).Msg("api_key_revoked")
	return nil
}

// RotateAPIKey generates a new key material and returns the new plain key.
func (s *APIFWService) RotateAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) (*model.APIKey, error) {
	if _, err := s.GetAPIKey(ctx, tenantID, keyID); err != nil {
		return nil, err
	}
	key, err := s.repo.RotateAPIKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, apierrors.Internal("rotate api key", err)
	}
	if key == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "api key not found")
	}
	s.logger.Info().Str("key_id", keyID.String()).Msg("api_key_rotated")
	return key, nil
}

// ValidateAPIKey authenticates a raw key string and returns the active APIKey.
// Used by other services for external API key authentication.
func (s *APIFWService) ValidateAPIKey(ctx context.Context, rawKey string) (*model.APIKey, error) {
	if len(rawKey) < 4 {
		return nil, apierrors.New(apierrors.KindForbidden, "invalid api key")
	}
	key, err := s.repo.GetAPIKeyByHash(ctx, rawKey)
	if err != nil {
		return nil, apierrors.Internal("validate api key", err)
	}
	if key == nil {
		return nil, apierrors.New(apierrors.KindForbidden, "api key invalid or expired")
	}
	return key, nil
}

// UsageStats returns aggregated usage for a key.
func (s *APIFWService) UsageStats(ctx context.Context, tenantID, keyID uuid.UUID) ([]model.EndpointStat, error) {
	if _, err := s.GetAPIKey(ctx, tenantID, keyID); err != nil {
		return nil, err
	}
	stats, err := s.repo.UsageStats(ctx, tenantID, keyID)
	if err != nil {
		return nil, apierrors.Internal("usage stats", err)
	}
	if stats == nil {
		stats = []model.EndpointStat{}
	}
	return stats, nil
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

func (s *APIFWService) CreateWebhook(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateWebhookRequest) (*model.Webhook, error) {
	wh, err := s.repo.CreateWebhook(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create webhook", err)
	}
	s.logger.Info().Str("webhook_id", wh.ID.String()).Str("url", wh.URL).Msg("webhook_created")
	return wh, nil
}

func (s *APIFWService) GetWebhook(ctx context.Context, tenantID, webhookID uuid.UUID) (*model.Webhook, error) {
	wh, err := s.repo.GetWebhook(ctx, tenantID, webhookID)
	if err != nil {
		return nil, apierrors.Internal("get webhook", err)
	}
	if wh == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "webhook not found")
	}
	return wh, nil
}

func (s *APIFWService) ListWebhooks(ctx context.Context, f model.WebhookFilter) ([]*model.Webhook, int, error) {
	whs, total, err := s.repo.ListWebhooks(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list webhooks", err)
	}
	return whs, total, nil
}

func (s *APIFWService) UpdateWebhook(ctx context.Context, tenantID, webhookID uuid.UUID, req *model.UpdateWebhookRequest) (*model.Webhook, error) {
	wh, err := s.repo.UpdateWebhook(ctx, tenantID, webhookID, req)
	if err != nil {
		return nil, apierrors.Internal("update webhook", err)
	}
	if wh == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "webhook not found")
	}
	return wh, nil
}

func (s *APIFWService) DeleteWebhook(ctx context.Context, tenantID, webhookID uuid.UUID) error {
	if _, err := s.GetWebhook(ctx, tenantID, webhookID); err != nil {
		return err
	}
	if err := s.repo.DeleteWebhook(ctx, tenantID, webhookID); err != nil {
		return apierrors.Internal("delete webhook", err)
	}
	return nil
}

func (s *APIFWService) SetWebhookActive(ctx context.Context, tenantID, webhookID uuid.UUID, active bool) error {
	if _, err := s.GetWebhook(ctx, tenantID, webhookID); err != nil {
		return err
	}
	if err := s.repo.SetWebhookActive(ctx, tenantID, webhookID, active); err != nil {
		return apierrors.Internal("set webhook active", err)
	}
	return nil
}

// TestWebhook sends a synthetic ping event to a webhook.
func (s *APIFWService) TestWebhook(ctx context.Context, tenantID, webhookID uuid.UUID) error {
	wh, err := s.GetWebhook(ctx, tenantID, webhookID)
	if err != nil {
		return err
	}
	secret, err := s.repo.GetWebhookSecret(ctx, webhookID)
	if err != nil {
		return apierrors.Internal("get webhook secret", err)
	}

	payload := map[string]any{
		"event_type": "webhook.test",
		"tenant_id":  tenantID.String(),
		"webhook_id": webhookID.String(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"message":    "This is a test delivery from CyberRadar Platform.",
	}

	delivery := s.deliverWebhook(ctx, wh, secret, "webhook.test", payload, 1)
	_ = s.repo.RecordDelivery(ctx, delivery)
	if !delivery.Success {
		return apierrors.New(apierrors.KindBadInput, fmt.Sprintf("test delivery failed with status %v", delivery.ResponseStatus))
	}
	return nil
}

// ListDeliveries returns paginated delivery history for a webhook.
func (s *APIFWService) ListDeliveries(ctx context.Context, tenantID, webhookID uuid.UUID, limit, offset int) ([]*model.WebhookDelivery, int, error) {
	if _, err := s.GetWebhook(ctx, tenantID, webhookID); err != nil {
		return nil, 0, err
	}
	deliveries, total, err := s.repo.ListDeliveries(ctx, tenantID, webhookID, limit, offset)
	if err != nil {
		return nil, 0, apierrors.Internal("list deliveries", err)
	}
	return deliveries, total, nil
}

// GetStats returns platform-wide API usage stats for a tenant.
func (s *APIFWService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.APIFWStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("apifw stats", err)
	}
	return stats, nil
}

// ─── Webhook Delivery (Kafka-driven) ─────────────────────────────────────────

// DeliverWebhook is called by the Kafka consumer to fan-out a platform event to
// all matching active webhooks for the tenant. Retries up to 3 times with 1s
// backoff. Records every attempt.
func (s *APIFWService) DeliverWebhook(ctx context.Context, tenantID uuid.UUID, eventType string, payload map[string]any) {
	webhooks, err := s.repo.ListActiveWebhooksForEvent(ctx, tenantID, eventType)
	if err != nil {
		s.logger.Warn().Err(err).Str("event_type", eventType).Msg("webhook_lookup_error")
		return
	}

	for _, wh := range webhooks {
		secret, err := s.repo.GetWebhookSecret(ctx, wh.ID)
		if err != nil {
			s.logger.Warn().Err(err).Str("webhook_id", wh.ID.String()).Msg("webhook_secret_error")
			continue
		}

		var delivery *model.WebhookDelivery
		for attempt := 1; attempt <= 3; attempt++ {
			delivery = s.deliverWebhook(ctx, wh, secret, eventType, payload, attempt)
			_ = s.repo.RecordDelivery(ctx, delivery)
			if delivery.Success {
				break
			}
			s.logger.Warn().
				Str("webhook_id", wh.ID.String()).
				Int("attempt", attempt).
				Msg("webhook_delivery_retry")
			if attempt < 3 {
				time.Sleep(time.Second)
			}
		}
	}
}

// deliverWebhook performs one HTTP POST delivery attempt and returns the result.
func (s *APIFWService) deliverWebhook(ctx context.Context, wh *model.Webhook, secret, eventType string, payload map[string]any, attempt int) *model.WebhookDelivery {
	now := time.Now().UTC()
	d := &model.WebhookDelivery{
		TenantID:  wh.TenantID,
		WebhookID: wh.ID,
		EventType: eventType,
		Payload:   payload,
		Attempt:   attempt,
		CreatedAt: now,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		d.ResponseBody = "json marshal error: " + err.Error()
		return d
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		d.ResponseBody = "request build error: " + err.Error()
		return d
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CRP-Event-Type", eventType)
	req.Header.Set("X-CRP-Delivery-ID", uuid.New().String())

	// HMAC-SHA256 signature if secret is set.
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-CRP-Signature", "sha256="+sig)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		d.ResponseBody = "http error: " + err.Error()
		return d
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	d.ResponseStatus = &statusCode

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	d.ResponseBody = string(respBody)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.Success = true
		d.DeliveredAt = &now
	}
	return d
}

