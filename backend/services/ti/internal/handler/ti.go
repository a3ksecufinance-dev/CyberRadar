package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/ti/internal/model"
	"github.com/cyberradar/platform/services/ti/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// TIHandler exposes the Threat Intelligence API.
type TIHandler struct {
	svc      *service.TIService
	validate *validator.Validate
}

// NewTIHandler creates a TIHandler.
func NewTIHandler(svc *service.TIService) *TIHandler {
	return &TIHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all TI routes.
func (h *TIHandler) RegisterRoutes(r chi.Router) {
	// Feeds
	r.Get("/ti/feeds", h.ListFeeds)
	r.Post("/ti/feeds", h.CreateFeed)
	r.Get("/ti/feeds/{feedID}", h.GetFeed)
	r.Put("/ti/feeds/{feedID}", h.UpdateFeed)
	r.Delete("/ti/feeds/{feedID}", h.DeleteFeed)

	// IOCs
	r.Get("/ti/iocs", h.ListIOCs)
	r.Post("/ti/iocs", h.CreateIOC)
	r.Post("/ti/iocs/bulk", h.BulkCreateIOCs)
	r.Post("/ti/iocs/lookup", h.Lookup)

	// IOC Hits
	r.Get("/ti/hits", h.ListHits)

	// Threat Actors
	r.Get("/ti/actors", h.ListThreatActors)
	r.Post("/ti/actors", h.CreateThreatActor)

	// Stats
	r.Get("/ti/stats", h.Stats)
}

// ─── Feeds ────────────────────────────────────────────────────────────────────

func (h *TIHandler) ListFeeds(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	feeds, err := h.svc.ListFeeds(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"feeds": feeds, "total": len(feeds)})
}

func (h *TIHandler) CreateFeed(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	f, err := h.svc.CreateFeed(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, f)
}

func (h *TIHandler) GetFeed(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "feedID")
	if !ok {
		return
	}
	f, err := h.svc.GetFeed(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, f)
}

func (h *TIHandler) UpdateFeed(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "feedID")
	if !ok {
		return
	}
	var req model.UpdateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	f, err := h.svc.UpdateFeed(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, f)
}

func (h *TIHandler) DeleteFeed(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "feedID")
	if !ok {
		return
	}
	if err := h.svc.DeleteFeed(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

// ─── IOCs ─────────────────────────────────────────────────────────────────────

func (h *TIHandler) ListIOCs(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.IOCFilter{
		TenantID: tenantID,
		IOCType:  q.Get("type"),
		Severity: q.Get("severity"),
		Search:   q.Get("q"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("feed_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.FeedID = &id
		}
	}
	if v := q.Get("active"); v != "" {
		active := v == "true"
		f.IsActive = &active
	}

	iocs, total, err := h.svc.ListIOCs(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"iocs": iocs, "total": total})
}

func (h *TIHandler) CreateIOC(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	ioc, err := h.svc.CreateIOC(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, ioc)
}

func (h *TIHandler) BulkCreateIOCs(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.BulkCreateIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	count, err := h.svc.BulkCreateIOCs(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, map[string]any{"imported": count, "total": len(req.IOCs)})
}

func (h *TIHandler) Lookup(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.LookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	result, err := h.svc.Lookup(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, result)
}

// ─── Hits ─────────────────────────────────────────────────────────────────────

func (h *TIHandler) ListHits(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	limit := queryInt(r.URL.Query().Get("limit"), 50)
	hits, err := h.svc.ListHits(r.Context(), tenantID, limit)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"hits": hits, "total": len(hits)})
}

// ─── Threat Actors ────────────────────────────────────────────────────────────

func (h *TIHandler) ListThreatActors(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	bankingOnly := r.URL.Query().Get("banking_only") == "true"
	actors, err := h.svc.ListThreatActors(r.Context(), tenantID, bankingOnly)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"actors": actors, "total": len(actors)})
}

func (h *TIHandler) CreateThreatActor(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateThreatActorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	ta, err := h.svc.CreateThreatActor(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, ta)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *TIHandler) Stats(w http.ResponseWriter, r *http.Request) {
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
