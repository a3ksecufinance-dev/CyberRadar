package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/notification/internal/model"
	"github.com/cyberradar/platform/services/notification/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// NotificationHandler exposes notification endpoints.
type NotificationHandler struct {
	svc      *service.NotificationService
	validate *validator.Validate
}

// NewNotificationHandler creates a NotificationHandler.
func NewNotificationHandler(svc *service.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		svc:      svc,
		validate: validator.New(),
	}
}

// RegisterRoutes mounts notification routes.
func (h *NotificationHandler) RegisterRoutes(r chi.Router) {
	r.Post("/notifications/send", h.Send)
	r.Get("/notifications/rules", h.ListRules)
	r.Post("/notifications/rules", h.CreateRule)
	r.Post("/notifications/test", h.Test)
}

// Send handles POST /notifications/send
func (h *NotificationHandler) Send(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.SendNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	// Enforce tenant isolation
	req.TenantID = tenantID.String()

	if err := h.svc.Send(r.Context(), &req); err != nil {
		response.InternalError(w)
		return
	}

	response.OK(w, map[string]string{"message": "notification dispatched"})
}

// ListRules handles GET /notifications/rules
func (h *NotificationHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	response.OK(w, map[string]string{"message": "notification rules — DB-backed implementation in Sprint 4"})
}

// CreateRule handles POST /notifications/rules
func (h *NotificationHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	response.OK(w, map[string]string{"message": "notification rule creation — DB-backed implementation in Sprint 4"})
}

// Test handles POST /notifications/test — sends a test notification.
func (h *NotificationHandler) Test(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var body struct {
		Channel model.ChannelConfig `json:"channel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}

	err := h.svc.Send(r.Context(), &model.SendNotificationRequest{
		TenantID:  tenantID.String(),
		Title:     "CyberRadar — Test Notification",
		Body:      "This is a test notification from Cyber Radar Platform.",
		Severity:  model.SeverityLow,
		Channels:  []model.ChannelConfig{body.Channel},
	})
	if err != nil {
		response.InternalError(w)
		return
	}

	response.OK(w, map[string]string{"message": "test notification sent"})
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

type contextKey string

func mustTenantID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value(contextKey("tenant_id")).(string)
	id, _ := uuid.Parse(v)
	return id
}

var _ = apierrors.IsKind   // ensure import used
var _ = fmt.Sprintf        // ensure import used
