package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/httperr"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/ir/internal/model"
	"github.com/cyberradar/platform/services/ir/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type IRHandler struct {
	svc    *service.IRService
	logger zerolog.Logger
}

func NewIRHandler(svc *service.IRService, logger zerolog.Logger) *IRHandler {
	return &IRHandler{svc: svc, logger: logger}
}

func (h *IRHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Playbooks — authoring a response procedure is a separate authority from
	// working an incident, so it carries its own permission.
	r.Route("/playbooks", func(r chi.Router) {
		r.Use(authmw.RequirePermissionByMethod("playbooks"))
		r.Post("/", h.CreatePlaybook)
		r.Get("/", h.ListPlaybooks)
		r.Get("/{playbookID}", h.GetPlaybook)
		r.Patch("/{playbookID}", h.UpdatePlaybook)
	})

	// Incidents, with their timeline, tasks and evidence.
	r.Route("/incidents", func(r chi.Router) {
		r.Use(authmw.RequirePermissionByMethod("incidents"))
		r.Post("/", h.CreateIncident)
		r.Get("/", h.ListIncidents)
		r.Get("/{incidentID}", h.GetIncident)
		r.Patch("/{incidentID}", h.UpdateIncident)

		r.Post("/{incidentID}/timeline", h.AddTimelineEvent)
		r.Get("/{incidentID}/timeline", h.GetTimeline)

		r.Post("/{incidentID}/tasks", h.CreateTask)
		r.Get("/{incidentID}/tasks", h.ListTasks)
		r.Patch("/{incidentID}/tasks/{taskID}", h.UpdateTask)

		r.Post("/{incidentID}/evidence", h.CreateEvidence)
		r.Get("/{incidentID}/evidence", h.ListEvidence)
		r.Patch("/{incidentID}/evidence/{evidenceID}", h.UpdateEvidence)
	})

	// Stats
	r.With(authmw.RequirePermission("incidents:read")).Get("/stats", h.GetStats)

	return r
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) (uuid.UUID, bool) {
	id := authctx.TenantID(r.Context())
	return id, id != uuid.Nil
}

func userFromCtx(r *http.Request) *uuid.UUID {
	if id := authctx.UserID(r.Context()); id != uuid.Nil {
		return &id
	}
	return nil
}

func parseUUID(r *http.Request, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, param))
	return id, err == nil
}

// ─── Playbooks ────────────────────────────────────────────────────────────────

func (h *IRHandler) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreatePlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	pb, err := h.svc.CreatePlaybook(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreatePlaybook")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, pb)
}

func (h *IRHandler) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentType := r.URL.Query().Get("incident_type")
	pbs, err := h.svc.ListPlaybooks(r.Context(), tenantID, incidentType)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if pbs == nil {
		pbs = []model.IRPlaybook{}
	}
	response.OKWithMeta(w, pbs, &response.Meta{Total: int64(len(pbs))})
}

func (h *IRHandler) GetPlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "playbookID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	pb, err := h.svc.GetPlaybook(r.Context(), tenantID, id)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if pb == nil {
		response.NotFound(w, "not found")
		return
	}
	response.OK(w, pb)
}

func (h *IRHandler) UpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "playbookID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdatePlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	pb, err := h.svc.UpdatePlaybook(r.Context(), tenantID, id, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, pb)
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (h *IRHandler) CreateIncident(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Title == "" || req.IncidentType == "" || req.Severity == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "title, incident_type and severity are required")
		return
	}
	inc, err := h.svc.CreateIncident(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateIncident")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, inc)
}

func (h *IRHandler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit == 0 {
		limit = 50
	}
	f := model.ListIncidentsFilter{
		Status:       q.Get("status"),
		Severity:     q.Get("severity"),
		IncidentType: q.Get("incident_type"),
		Limit:        limit,
		Offset:       offset,
	}
	incs, total, err := h.svc.ListIncidents(r.Context(), tenantID, f)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if incs == nil {
		incs = []model.IRIncident{}
	}
	response.OKWithMeta(w, incs, &response.Meta{Total: int64(total), Limit: limit})
}

func (h *IRHandler) GetIncident(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	inc, err := h.svc.GetIncident(r.Context(), tenantID, id)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if inc == nil {
		response.NotFound(w, "not found")
		return
	}
	response.OK(w, inc)
}

func (h *IRHandler) UpdateIncident(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	inc, err := h.svc.UpdateIncident(r.Context(), tenantID, id, &req, userFromCtx(r))
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, inc)
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

func (h *IRHandler) AddTimelineEvent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	var req model.CreateTimelineEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Title == "" || req.EventType == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "title and event_type are required")
		return
	}
	ev, err := h.svc.AddTimelineEvent(r.Context(), tenantID, incidentID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("AddTimelineEvent")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, ev)
}

func (h *IRHandler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	evs, err := h.svc.GetTimeline(r.Context(), tenantID, incidentID)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if evs == nil {
		evs = []model.IRTimeline{}
	}
	response.OKWithMeta(w, evs, &response.Meta{Total: int64(len(evs))})
}

// ─── Tasks ────────────────────────────────────────────────────────────────────

func (h *IRHandler) CreateTask(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	var req model.CreateTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Title == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "title is required")
		return
	}
	t, err := h.svc.CreateTask(r.Context(), tenantID, incidentID, &req, userFromCtx(r))
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, t)
}

func (h *IRHandler) ListTasks(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	tasks, err := h.svc.ListTasks(r.Context(), tenantID, incidentID)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if tasks == nil {
		tasks = []model.IRTask{}
	}
	response.OKWithMeta(w, tasks, &response.Meta{Total: int64(len(tasks))})
}

func (h *IRHandler) UpdateTask(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	taskID, ok := parseUUID(r, "taskID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid task id")
		return
	}
	var req model.UpdateTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	t, err := h.svc.UpdateTask(r.Context(), tenantID, incidentID, taskID, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, t)
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

func (h *IRHandler) CreateEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	var req model.CreateEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Name == "" || req.EvidenceType == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "name and evidence_type are required")
		return
	}
	ev, err := h.svc.CreateEvidence(r.Context(), tenantID, incidentID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateEvidence")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, ev)
}

func (h *IRHandler) ListEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	evs, err := h.svc.ListEvidence(r.Context(), tenantID, incidentID)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if evs == nil {
		evs = []model.IREvidence{}
	}
	response.OKWithMeta(w, evs, &response.Meta{Total: int64(len(evs))})
}

func (h *IRHandler) UpdateEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	incidentID, ok := parseUUID(r, "incidentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid incident id")
		return
	}
	evidenceID, ok := parseUUID(r, "evidenceID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid evidence id")
		return
	}
	var req model.UpdateEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	ev, err := h.svc.UpdateEvidence(r.Context(), tenantID, incidentID, evidenceID, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, ev)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *IRHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, stats)
}
