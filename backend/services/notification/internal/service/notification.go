package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/notification/internal/model"
	"github.com/rs/zerolog"
)

// NotificationService dispatches notifications across multiple channels.
type NotificationService struct {
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewNotificationService creates a NotificationService.
func NewNotificationService(logger zerolog.Logger) *NotificationService {
	return &NotificationService{
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Send dispatches a notification to all configured channels.
func (s *NotificationService) Send(ctx context.Context, req *model.SendNotificationRequest) error {
	var errs []error

	for _, ch := range req.Channels {
		if err := s.dispatch(ctx, ch, req); err != nil {
			s.logger.Error().Err(err).
				Str("channel", string(ch.Type)).
				Str("tenant_id", req.TenantID).
				Msg("notification_dispatch_failed")
			errs = append(errs, err)
		} else {
			s.logger.Info().
				Str("channel", string(ch.Type)).
				Str("tenant_id", req.TenantID).
				Str("title", req.Title).
				Msg("notification_sent")
		}
	}

	if len(errs) == len(req.Channels) {
		return apierrors.Internal("all channels failed", errs[0])
	}
	return nil
}

// dispatch routes to the correct channel implementation.
func (s *NotificationService) dispatch(ctx context.Context, ch model.ChannelConfig, req *model.SendNotificationRequest) error {
	switch ch.Type {
	case model.ChannelSlack:
		return s.sendSlack(ctx, ch.Config, req)
	case model.ChannelWebhook:
		return s.sendWebhook(ctx, ch.Config, req)
	case model.ChannelTeams:
		return s.sendTeams(ctx, ch.Config, req)
	case model.ChannelEmail:
		return s.sendEmail(ctx, ch.Config, req)
	default:
		return fmt.Errorf("unsupported channel: %s", ch.Type)
	}
}

// sendSlack sends a Slack message via incoming webhook.
func (s *NotificationService) sendSlack(ctx context.Context, cfg map[string]any, req *model.SendNotificationRequest) error {
	webhookURL, ok := cfg["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("slack: missing webhook_url")
	}

	emoji := severityEmoji(req.Severity)
	payload := map[string]any{
		"text": fmt.Sprintf("%s *[%s] %s*\n%s", emoji, req.Severity, req.Title, req.Body),
		"attachments": []map[string]any{{
			"color": severityColor(req.Severity),
			"fields": []map[string]string{
				{"title": "Severity", "value": string(req.Severity), "short": "true"},
				{"title": "Resource", "value": req.ResourceType + "/" + req.ResourceID, "short": "true"},
				{"title": "Tenant", "value": req.TenantID, "short": "true"},
			},
		}},
	}

	return s.postJSON(ctx, webhookURL, payload)
}

// sendWebhook sends an HTTP POST to a generic webhook URL.
func (s *NotificationService) sendWebhook(ctx context.Context, cfg map[string]any, req *model.SendNotificationRequest) error {
	url, ok := cfg["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("webhook: missing url")
	}

	payload := map[string]any{
		"event":         "crp.notification",
		"tenant_id":    req.TenantID,
		"title":        req.Title,
		"body":         req.Body,
		"severity":     req.Severity,
		"resource_type": req.ResourceType,
		"resource_id":  req.ResourceID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}

	return s.postJSON(ctx, url, payload)
}

// sendTeams sends a Microsoft Teams adaptive card message.
func (s *NotificationService) sendTeams(ctx context.Context, cfg map[string]any, req *model.SendNotificationRequest) error {
	webhookURL, ok := cfg["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("teams: missing webhook_url")
	}

	payload := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": severityColor(req.Severity),
		"summary":    req.Title,
		"sections": []map[string]any{{
			"activityTitle":    req.Title,
			"activitySubtitle": fmt.Sprintf("Severity: %s | Tenant: %s", req.Severity, req.TenantID),
			"activityText":     req.Body,
		}},
	}

	return s.postJSON(ctx, webhookURL, payload)
}

// sendEmail is a stub — implement with SMTP or SendGrid in production.
func (s *NotificationService) sendEmail(_ context.Context, cfg map[string]any, req *model.SendNotificationRequest) error {
	to, _ := cfg["to"].(string)
	s.logger.Info().
		Str("to", to).
		Str("subject", req.Title).
		Msg("email_notification_stub")
	// TODO: implement SMTP sender
	return nil
}

// postJSON sends a JSON payload to a URL.
func (s *NotificationService) postJSON(ctx context.Context, url string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return nil
}

func severityEmoji(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	default:
		return "🟢"
	}
}

func severityColor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "#FF0000"
	case model.SeverityHigh:
		return "#FF8C00"
	case model.SeverityMedium:
		return "#FFD700"
	default:
		return "#008000"
	}
}
