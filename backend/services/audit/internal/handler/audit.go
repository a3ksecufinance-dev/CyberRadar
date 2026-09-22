package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/audit/internal/model"
	"github.com/cyberradar/platform/services/audit/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// AuditHandler exposes audit log endpoints.
type AuditHandler struct {
	svc      *service.AuditService
	validate *validator.Validate
}

// NewAuditHandler creates an AuditHandler.
func NewAuditHandler(svc *service.AuditService) *AuditHandler {
	return &AuditHandler{
		svc:      svc,
		validate: validator.New(),
	}
}

// RegisterRoutes mounts audit routes.
func (h *AuditHandler) RegisterRoutes(r chi.Router) {
	r.Route("/audit", func(r chi.Router) {
		r.Post("/events", h.Write)       // Write a single event (service-to-service)
		r.Get("/events", h.Search)       // Search audit events
		r.Get("/events/{id}", h.GetByID) // Get a specific event
		r.Post("/export", h.Export)      // Export audit log
	})
}

// Write handles POST /audit/events
// This endpoint is called by other CRP services, not end users.
// SECURITY: tenant_id in the payload is validated against the JWT tenant_id.
func (h *AuditHandler) Write(w http.ResponseWriter, r *http.Request) {
	jwtTenantID := mustTenantID(r)

	var req model.WriteAuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	// Enforce tenant isolation: payload tenant_id must match JWT tenant_id
	// Super admins (system services) can write on behalf of any tenant
	if req.TenantID != jwtTenantID.String() && !mustIsSuperAdmin(r) {
		response.Forbidden(w, "tenant_id mismatch")
		return
	}

	event, svcErr := h.svc.Write(r.Context(), &req)
	if mapError(w, svcErr) != nil {
		return
	}

	response.Created(w, event)
}

// Search handles GET /audit/events
func (h *AuditHandler) Search(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := &model.AuditEventFilter{
		TenantID:     tenantID.String(),
		ActorID:      q.Get("actor_id"),
		Action:       q.Get("action"),
		ResourceType: q.Get("resource_type"),
		ResourceID:   q.Get("resource_id"),
		Result:       q.Get("result"),
		Page:         queryInt(q.Get("page"), 1),
		Limit:        queryInt(q.Get("limit"), 50),
	}

	if fromStr := q.Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			f.From = &t
		}
	}
	if toStr := q.Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			f.To = &t
		}
	}

	list, svcErr := h.svc.Search(r.Context(), f)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OKWithMeta(w, list.Events, &response.Meta{
		Page:     list.Page,
		Limit:    list.Limit,
		Total:    list.Total,
		TenantID: tenantID.String(),
	})
}

// GetByID handles GET /audit/events/{id}
// Stub — ClickHouse lookup by ID requires full partition key; implement when needed.
func (h *AuditHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if _, err := uuid.Parse(idStr); err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid event ID")
		return
	}
	response.OK(w, map[string]string{"message": "lookup by ID requires timestamp range — use /audit/events?resource_id=" + idStr})
}

// Export handles POST /audit/export — returns events as JSON for forensic use.
func (h *AuditHandler) Export(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var body struct {
		From   *time.Time `json:"from"`
		To     *time.Time `json:"to"`
		Action string     `json:"action"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	f := &model.AuditEventFilter{
		TenantID: tenantID.String(),
		From:     body.From,
		To:       body.To,
		Action:   body.Action,
		Page:     1,
		Limit:    10000,
	}

	list, svcErr := h.svc.Search(r.Context(), f)
	if mapError(w, svcErr) != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="audit_export_%s.json"`, time.Now().Format("20060102_150405")))
	_ = json.NewEncoder(w).Encode(list.Events)
}

// ─── Context helpers ─────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
}

func mustIsSuperAdmin(r *http.Request) bool {
	return authctx.IsSuperAdmin(r.Context())
}

func mapError(w http.ResponseWriter, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, err.Error())
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
	return err
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}
