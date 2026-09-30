package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/service"
)

// LibraryHandler exposes the detection content the platform ships.
type LibraryHandler struct {
	svc      *service.LibraryService
	validate *validator.Validate
}

// NewLibraryHandler creates a LibraryHandler.
func NewLibraryHandler(svc *service.LibraryService) *LibraryHandler {
	return &LibraryHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts the library routes.
//
// Reading the catalogue needs rules:read; adopting from it writes a detection
// rule, so it needs rules:write. Same authority as writing a rule by hand,
// which is what adopting is.
func (h *LibraryHandler) RegisterRoutes(r chi.Router) {
	r.Route("/siem/rule-library", func(r chi.Router) {
		r.With(authmw.RequirePermission("rules:read")).Get("/", h.Catalogue)
		r.With(authmw.RequirePermission("rules:read")).Get("/coverage", h.Coverage)
		r.With(authmw.RequirePermission("rules:read")).Get("/{code}", h.Entry)
		r.With(authmw.RequirePermission("rules:write")).Post("/{code}/adopt", h.Adopt)
	})
}

// Catalogue handles GET /siem/rule-library.
func (h *LibraryHandler) Catalogue(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entries, err := h.svc.Catalogue(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OKWithMeta(w, entries, &response.Meta{Total: int64(len(entries))})
}

// Entry handles GET /siem/rule-library/{code}.
func (h *LibraryHandler) Entry(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entry, err := h.svc.Entry(r.Context(), tenantID, chi.URLParam(r, "code"))
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, entry)
}

// Coverage handles GET /siem/rule-library/coverage.
func (h *LibraryHandler) Coverage(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	coverage, err := h.svc.Coverage(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, coverage)
}

// Adopt handles POST /siem/rule-library/{code}/adopt.
func (h *LibraryHandler) Adopt(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	// An empty body is the common case and the best one: adopt the detection
	// exactly as it ships, so the difference afterwards means something.
	var req model.AdoptRequest
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		response.BadRequest(w, "INVALID_BODY", "Could not read the request body")
		return
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			response.BadRequest(w, "INVALID_JSON", "Invalid request body")
			return
		}
		if err := h.validate.Struct(&req); err != nil {
			response.UnprocessableEntity(w, err.Error())
			return
		}
	}

	var callerID *uuid.UUID
	if id, ok := authctx.From(r.Context()); ok && id.UserID != uuid.Nil {
		caller := id.UserID
		callerID = &caller
	}

	rule, err := h.svc.Adopt(r.Context(), tenantID, callerID, chi.URLParam(r, "code"), &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, rule)
}
