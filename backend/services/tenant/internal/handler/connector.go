package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/cyberradar/platform/internal/pkg/authmw"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/service"
)

// ConnectorHandler exposes the connector registry.
type ConnectorHandler struct {
	svc *service.ConnectorService
}

func NewConnectorHandler(svc *service.ConnectorService) *ConnectorHandler {
	return &ConnectorHandler{svc: svc}
}

// RegisterRoutes mounts the registry.
//
// Gated on connectors:* — the authority to declare where a bank's telemetry
// comes from, which is neither the authority to administer tenants nor the
// one to ingest events. The tenant comes from the token and never from the
// path, so one customer cannot register a source for another.
//
// Health is deliberately not here. What a connector *did* is answered by the
// collector from the events; serving it from this registry would mean copying
// counts into a second place, and the copy that disagreed would be the one on
// the screen.
func (h *ConnectorHandler) RegisterRoutes(r chi.Router) {
	r.Route("/connectors", func(r chi.Router) {
		r.With(authmw.RequirePermission("connectors:read")).Get("/", h.List)
		r.With(authmw.RequirePermission("connectors:read")).Get("/{connectorID}", h.Get)
		r.With(authmw.RequirePermission("connectors:write")).Post("/", h.Register)
		r.With(authmw.RequirePermission("connectors:write")).Patch("/{connectorID}", h.Update)
		r.With(authmw.RequirePermission("connectors:delete")).Delete("/{connectorID}", h.Delete)
	})
}

func (h *ConnectorHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	list, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, list, &response.Meta{Total: int64(len(list))})
}

func (h *ConnectorHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, err := connectorID(r)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	c, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OK(w, c)
}

func (h *ConnectorHandler) Register(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.CreateConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mapError(w, apierrors.BadInput("the request body is not valid JSON")) //nolint:errcheck // written
		return
	}
	c, err := h.svc.Register(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.Created(w, c)
}

func (h *ConnectorHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, err := connectorID(r)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}

	var req model.UpdateConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mapError(w, apierrors.BadInput("the request body is not valid JSON")) //nolint:errcheck // written
		return
	}
	c, err := h.svc.Update(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OK(w, c)
}

func (h *ConnectorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, err := connectorID(r)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	if err := h.svc.Delete(r.Context(), tenantID, id); err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.NoContent(w)
}

func connectorID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "connectorID"))
	if err != nil {
		return uuid.Nil, apierrors.BadInput("the connector id is not a uuid")
	}
	return id, nil
}
