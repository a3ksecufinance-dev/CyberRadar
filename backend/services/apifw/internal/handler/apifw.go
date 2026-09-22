package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/apifw/internal/model"
	"github.com/cyberradar/platform/services/apifw/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// APIFWHandler exposes the API Framework API.
type APIFWHandler struct {
	svc      *service.APIFWService
	validate *validator.Validate
}

// NewAPIFWHandler creates an APIFWHandler.
func NewAPIFWHandler(svc *service.APIFWService) *APIFWHandler {
	return &APIFWHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all API Framework routes.
func (h *APIFWHandler) RegisterRoutes(r chi.Router) {
	// API Keys
	r.Get("/apifw/keys", h.ListAPIKeys)
	r.Post("/apifw/keys", h.CreateAPIKey)
	r.Get("/apifw/keys/{keyID}", h.GetAPIKey)
	r.Patch("/apifw/keys/{keyID}", h.UpdateAPIKey)
	r.Post("/apifw/keys/{keyID}/rotate", h.RotateAPIKey)
	r.Delete("/apifw/keys/{keyID}", h.RevokeAPIKey)
	r.Get("/apifw/keys/{keyID}/usage", h.KeyUsageStats)

	// Webhooks
	r.Get("/apifw/webhooks", h.ListWebhooks)
	r.Post("/apifw/webhooks", h.CreateWebhook)
	r.Get("/apifw/webhooks/{webhookID}", h.GetWebhook)
	r.Patch("/apifw/webhooks/{webhookID}", h.UpdateWebhook)
	r.Delete("/apifw/webhooks/{webhookID}", h.DeleteWebhook)
	r.Post("/apifw/webhooks/{webhookID}/enable", h.EnableWebhook)
	r.Post("/apifw/webhooks/{webhookID}/disable", h.DisableWebhook)
	r.Post("/apifw/webhooks/{webhookID}/test", h.TestWebhook)
	r.Get("/apifw/webhooks/{webhookID}/deliveries", h.ListDeliveries)

	// Stats
	r.Get("/apifw/stats", h.Stats)
}

// ─── API Keys ─────────────────────────────────────────────────────────────────

func (h *APIFWHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.APIKeyFilter{
		TenantID: tenantID,
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("active"); v != "" {
		b := v == "true"
		f.IsActive = &b
	}

	keys, total, err := h.svc.ListAPIKeys(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"keys": keys, "total": total})
}

func (h *APIFWHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	key, err := h.svc.CreateAPIKey(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	// plain_key is set on the returned model only at creation.
	response.Created(w, key)
}

func (h *APIFWHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "keyID")
	if !ok {
		return
	}
	key, err := h.svc.GetAPIKey(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	// Never return plain key or hash on GET.
	key.PlainKey = ""
	response.OK(w, key)
}

func (h *APIFWHandler) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "keyID")
	if !ok {
		return
	}
	var req model.UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	key, err := h.svc.UpdateAPIKey(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	key.PlainKey = ""
	response.OK(w, key)
}

func (h *APIFWHandler) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "keyID")
	if !ok {
		return
	}
	key, err := h.svc.RotateAPIKey(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	// plain_key set only on rotate — expose it once.
	response.OK(w, key)
}

func (h *APIFWHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "keyID")
	if !ok {
		return
	}
	if err := h.svc.RevokeAPIKey(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "revoked", "key_id": id})
}

func (h *APIFWHandler) KeyUsageStats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "keyID")
	if !ok {
		return
	}
	stats, err := h.svc.UsageStats(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"key_id": id, "endpoints": stats})
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

func (h *APIFWHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.WebhookFilter{
		TenantID: tenantID,
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("active"); v != "" {
		b := v == "true"
		f.IsActive = &b
	}

	whs, total, err := h.svc.ListWebhooks(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"webhooks": whs, "total": total})
}

func (h *APIFWHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	wh, err := h.svc.CreateWebhook(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, wh)
}

func (h *APIFWHandler) GetWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	wh, err := h.svc.GetWebhook(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, wh)
}

func (h *APIFWHandler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	var req model.UpdateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	wh, err := h.svc.UpdateWebhook(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, wh)
}

func (h *APIFWHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	if err := h.svc.DeleteWebhook(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "deleted", "webhook_id": id})
}

func (h *APIFWHandler) EnableWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	if err := h.svc.SetWebhookActive(r.Context(), tenantID, id, true); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "enabled"})
}

func (h *APIFWHandler) DisableWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	if err := h.svc.SetWebhookActive(r.Context(), tenantID, id, false); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "disabled"})
}

func (h *APIFWHandler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	if err := h.svc.TestWebhook(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "test_sent", "webhook_id": id})
}

func (h *APIFWHandler) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "webhookID")
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := queryInt(q.Get("limit"), 50)
	offset := queryInt(q.Get("offset"), 0)

	deliveries, total, err := h.svc.ListDeliveries(r.Context(), tenantID, id, limit, offset)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"deliveries": deliveries, "total": total})
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *APIFWHandler) Stats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, stats)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
}

func mustCallerID(r *http.Request) uuid.UUID {
	return authctx.UserID(r.Context())
}

func parseUUID(w http.ResponseWriter, r *http.Request, param string) (uuid.UUID, bool) {
	raw := chi.URLParam(r, param)
	id, err := uuid.Parse(raw)
	if err != nil {
		response.BadRequest(w, "INVALID_ID", param+" must be a valid UUID")
		return uuid.Nil, false
	}
	return id, true
}

func mapError(w http.ResponseWriter, err error) {
	switch {
	case apierrors.IsKind(err, apierrors.KindNotFound):
		response.NotFound(w, "resource")
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, "access denied")
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}
