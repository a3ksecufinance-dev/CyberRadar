package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/fraud/internal/model"
	"github.com/cyberradar/platform/services/fraud/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// FraudHandler exposes the Fraud Detection API.
type FraudHandler struct {
	svc      *service.FraudService
	validate *validator.Validate
}

// NewFraudHandler creates a FraudHandler.
func NewFraudHandler(svc *service.FraudService) *FraudHandler {
	return &FraudHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all fraud routes under the provided router.
func (h *FraudHandler) RegisterRoutes(r chi.Router) {
	// Detection rules
	r.Post("/fraud/rules", h.CreateRule)
	r.Get("/fraud/rules", h.ListRules)
	r.Get("/fraud/rules/{ruleID}", h.GetRule)
	r.Patch("/fraud/rules/{ruleID}", h.UpdateRule)

	// Transactions
	r.Post("/fraud/transactions/ingest", h.IngestTransaction)
	r.Get("/fraud/transactions", h.ListTransactions)
	r.Get("/fraud/transactions/{txnID}", h.GetTransaction)
	r.Patch("/fraud/transactions/{txnID}/status", h.UpdateTransactionStatus)

	// Cases
	r.Post("/fraud/cases", h.CreateCase)
	r.Get("/fraud/cases", h.ListCases)
	r.Get("/fraud/cases/{caseID}", h.GetCase)
	r.Patch("/fraud/cases/{caseID}", h.UpdateCase)

	// Watchlist
	r.Post("/fraud/watchlist", h.AddWatchlistEntry)
	r.Get("/fraud/watchlist", h.ListWatchlist)
	r.Delete("/fraud/watchlist/{entryID}", h.RemoveWatchlistEntry)

	// Stats
	r.Get("/fraud/stats", h.GetStats)
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (h *FraudHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	rule, err := h.svc.CreateRule(r.Context(), tenantID, &req, callerID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, rule)
}

func (h *FraudHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	activeOnly := r.URL.Query().Get("active") == "true"
	rules, total, err := h.svc.ListRules(r.Context(), tenantID,
		queryString(r, "category"), activeOnly,
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": rules, "total": total})
}

func (h *FraudHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	ruleID, err := parseUUID(chi.URLParam(r, "ruleID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid rule id")
		return
	}
	rule, err := h.svc.GetRule(r.Context(), tenantID, ruleID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, rule)
}

func (h *FraudHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	ruleID, err := parseUUID(chi.URLParam(r, "ruleID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid rule id")
		return
	}
	var req model.UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	rule, err := h.svc.UpdateRule(r.Context(), tenantID, ruleID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, rule)
}

// ─── Transactions ─────────────────────────────────────────────────────────────

func (h *FraudHandler) IngestTransaction(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.IngestTransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	txn, err := h.svc.IngestAndScore(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	// Return 202 — scoring is async
	response.JSON(w, http.StatusAccepted, txn)
}

func (h *FraudHandler) ListTransactions(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.ListTransactionsFilter{
		Channel:      queryString(r, "channel"),
		Status:       queryString(r, "status"),
		SenderAcct:   queryString(r, "sender_account"),
		ReceiverAcct: queryString(r, "receiver_account"),
		Page:         queryInt(r, "page", 1),
		PageSize:     queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.MinScore = &n
		}
	}
	txns, total, err := h.svc.ListTransactions(r.Context(), tenantID, f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": txns, "total": total})
}

func (h *FraudHandler) GetTransaction(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	txnID, err := parseUUID(chi.URLParam(r, "txnID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid transaction id")
		return
	}
	txn, err := h.svc.GetTransaction(r.Context(), tenantID, txnID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, txn)
}

func (h *FraudHandler) UpdateTransactionStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	txnID, err := parseUUID(chi.URLParam(r, "txnID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid transaction id")
		return
	}
	var body model.UpdateTransactionStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	txn, err := h.svc.UpdateTransactionStatus(r.Context(), tenantID, txnID, body.Status)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, txn)
}

// ─── Cases ────────────────────────────────────────────────────────────────────

func (h *FraudHandler) CreateCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	c, err := h.svc.CreateCase(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, c)
}

func (h *FraudHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.ListCasesFilter{
		Category: queryString(r, "category"),
		Status:   queryString(r, "status"),
		Severity: queryString(r, "severity"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	cases, total, err := h.svc.ListCases(r.Context(), tenantID, f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": cases, "total": total})
}

func (h *FraudHandler) GetCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	caseID, err := parseUUID(chi.URLParam(r, "caseID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid case id")
		return
	}
	c, err := h.svc.GetCase(r.Context(), tenantID, caseID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, c)
}

func (h *FraudHandler) UpdateCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	caseID, err := parseUUID(chi.URLParam(r, "caseID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid case id")
		return
	}
	var req model.UpdateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	c, err := h.svc.UpdateCase(r.Context(), tenantID, caseID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, c)
}

// ─── Watchlist ────────────────────────────────────────────────────────────────

func (h *FraudHandler) AddWatchlistEntry(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.AddWatchlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	e, err := h.svc.AddWatchlistEntry(r.Context(), tenantID, &req, callerID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, e)
}

func (h *FraudHandler) ListWatchlist(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	activeOnly := r.URL.Query().Get("active") != "false"
	entries, total, err := h.svc.ListWatchlist(r.Context(), tenantID,
		queryString(r, "entity_type"), queryString(r, "list_type"),
		activeOnly, queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": entries, "total": total})
}

func (h *FraudHandler) RemoveWatchlistEntry(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entryID, err := parseUUID(chi.URLParam(r, "entryID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid entry id")
		return
	}
	if err := h.svc.RemoveWatchlistEntry(r.Context(), tenantID, entryID); err != nil {
		mapError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *FraudHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.Stats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, stats)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("tenant_id").(string)
	id, _ := uuid.Parse(v)
	return id
}

func mustCallerID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("user_id").(string)
	id, _ := uuid.Parse(v)
	return id
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func queryString(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func mapError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	de, ok := err.(*apierrors.DomainError)
	if !ok {
		response.InternalError(w)
		return
	}
	switch de.Kind {
	case apierrors.KindNotFound:
		response.NotFound(w, de.Message)
	case apierrors.KindConflict:
		response.Conflict(w, de.Message)
	case apierrors.KindBadInput:
		response.BadRequest(w, "VALIDATION_ERROR", de.Message)
	case apierrors.KindUnauth:
		response.Unauthorized(w, de.Message)
	case apierrors.KindForbidden:
		response.Forbidden(w, de.Message)
	default:
		response.InternalError(w)
	}
}
