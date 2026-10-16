package handler

import (
	"net/http"
	"strconv"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/siem/internal/model"
)

// ─── Event search ─────────────────────────────────────────────────────────────
//
// The analyst's first move after an alert: what else happened around it.
//
// Every value here arrives as a string from a query parameter, and the whole
// job of this file is to turn those into a typed filter or into a 400. A
// malformed date must not become a 500 — the caller would read "internal
// error" and have no idea they wrote the time wrong.

// SearchEvents answers GET /api/v1/siem/events.
func (h *SIEMHandler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	f, err := eventFilterFrom(r)
	if err != nil {
		mapError(w, err)
		return
	}
	f.TenantID = mustTenantID(r)

	events, total, err := h.svc.SearchEvents(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	limit, _ := pageOf(f)
	response.OKWithMeta(w, events, &response.Meta{
		Total:    total,
		Limit:    limit,
		TenantID: f.TenantID.String(),
	})
}

// GetEvent answers GET /api/v1/siem/events/{eventID}.
func (h *SIEMHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "eventID")
	if !ok {
		return
	}
	event, err := h.svc.GetEvent(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, event)
}

// pageOf reports the page size that will actually be applied, so the response
// meta states the truth rather than what the caller asked for.
func pageOf(f model.EventFilter) (limit, offset int) {
	limit = f.Limit
	if limit <= 0 {
		limit = model.DefaultEventLimit
	}
	if limit > model.MaxEventLimit {
		limit = model.MaxEventLimit
	}
	offset = f.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// eventFilterFrom reads the query string into a filter.
//
// TenantID is deliberately not read here. It is set by the caller of this
// function from the authenticated context, so that no query parameter can
// ever name a tenant.
func eventFilterFrom(r *http.Request) (model.EventFilter, error) {
	q := r.URL.Query()
	f := model.EventFilter{
		Text:          q.Get("q"),
		Category:      q.Get("category"),
		Severity:      q.Get("severity"),
		Outcome:       q.Get("outcome"),
		SourceType:    q.Get("source_type"),
		Source:        q.Get("source"),
		Action:        q.Get("action"),
		UserID:        q.Get("user_id"),
		IPSource:      q.Get("ip_source"),
		IPDestination: q.Get("ip_destination"),
		GeoCountry:    q.Get("geo_country"),
		MitreTactic:   q.Get("mitre_tactic"),
		IOCOnly:       q.Get("ioc") == "true",
	}

	to, err := parseTimeParam(q.Get("to"), "to")
	if err != nil {
		return f, err
	}
	from, err := parseTimeParam(q.Get("from"), "from")
	if err != nil {
		return f, err
	}
	f.To, f.From = to, from

	// window is the shorthand an analyst actually types: window=15m beats
	// computing two RFC3339 stamps by hand. It only fills a From that was not
	// given, so an explicit from always wins.
	if w := q.Get("window"); w != "" && f.From == nil {
		d, err := time.ParseDuration(w)
		if err != nil {
			return f, apierrors.BadInput(
				"window must be a duration such as 15m, 6h or 7d-equivalent 168h")
		}
		if d <= 0 {
			return f, apierrors.BadInput("window must be positive")
		}
		end := time.Now().UTC()
		if f.To != nil {
			end = *f.To
		}
		start := end.Add(-d)
		f.From = &start
	}

	if f.MinRiskScore, err = parseFloatParam(q.Get("min_risk_score"), "min_risk_score"); err != nil {
		return f, err
	}
	if f.MinThreatScore, err = parseFloatParam(q.Get("min_threat_score"), "min_threat_score"); err != nil {
		return f, err
	}
	if f.CBSImpact, err = parseFlagParam(q.Get("cbs_impact"), "cbs_impact"); err != nil {
		return f, err
	}
	if f.SWIFTImpact, err = parseFlagParam(q.Get("swift_impact"), "swift_impact"); err != nil {
		return f, err
	}
	if f.Limit, err = parseIntParam(q.Get("limit"), "limit"); err != nil {
		return f, err
	}
	if f.Offset, err = parseIntParam(q.Get("offset"), "offset"); err != nil {
		return f, err
	}
	return f, nil
}

func parseTimeParam(raw, name string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, apierrors.BadInput(name + " must be an RFC3339 timestamp, such as 2026-03-02T11:30:00Z")
	}
	u := t.UTC()
	return &u, nil
}

func parseFloatParam(raw, name string) (*float32, error) {
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseFloat(raw, 32)
	if err != nil {
		return nil, apierrors.BadInput(name + " must be a number")
	}
	f := float32(v)
	return &f, nil
}

// parseFlagParam reads a 0/1 banking impact flag.
func parseFlagParam(raw, name string) (*uint8, error) {
	switch raw {
	case "":
		return nil, nil
	case "0", "false":
		v := uint8(0)
		return &v, nil
	case "1", "true":
		v := uint8(1)
		return &v, nil
	default:
		return nil, apierrors.BadInput(name + " must be 0 or 1")
	}
}

func parseIntParam(raw, name string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apierrors.BadInput(name + " must be a whole number")
	}
	if v < 0 {
		return 0, apierrors.BadInput(name + " may not be negative")
	}
	return v, nil
}
