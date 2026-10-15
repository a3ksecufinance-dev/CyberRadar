package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cyberradar/platform/internal/pkg/db"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/google/uuid"
)

// EventRepository reads the normalized events the pipeline wrote.
type EventRepository struct {
	conn driver.Conn
}

// NewEventRepository creates an EventRepository.
func NewEventRepository(conn driver.Conn) *EventRepository {
	return &EventRepository{conn: conn}
}

// eventColumns is the projection, in the order Scan expects.
//
// raw_event is last and is the widest column by far. It is selected because an
// analyst reading one event wants the original line; if a caller ever needs a
// cheaper listing, dropping it from here is the lever.
const eventColumns = `event_id, tenant_id, timestamp, ingested_at,
	source, source_type, connector_id,
	user_id, user_name, asset_hostname, ip_source, ip_destination, geo_country,
	action, category, severity, outcome,
	threat_score, risk_score, mitre_tactic, mitre_technique, ioc_matched,
	business_service, cbs_impact, swift_impact, raw_event`

// query is a WHERE clause and the parameters that fill it.
type query struct {
	where  string
	params []any
	from   time.Time
	to     time.Time
}

// buildQuery turns a filter into a WHERE clause.
//
// Separated from the call to ClickHouse so it can be tested without one. What
// it has to get right is not the SQL — it is the two properties below, and
// both of them fail silently.
//
//   - Every value reaches the server as a named parameter. Nothing a caller
//     typed is ever concatenated into the statement. An analyst searching for
//     an apostrophe is a normal day; a search box that builds SQL by hand is a
//     way to read another tenant's events.
//   - The tenant predicate is written first and unconditionally, from the
//     filter's TenantID and never from anything the caller sent.
func buildQuery(f model.EventFilter) (query, error) {
	if f.TenantID == uuid.Nil {
		// Not a validation message for a user: it means a caller reached the
		// repository without an authenticated tenant, and the right outcome
		// is no query at all rather than a query across every tenant.
		return query{}, apierrors.Internal("event search",
			fmt.Errorf("no tenant in filter"))
	}

	to := time.Now().UTC()
	if f.To != nil {
		to = f.To.UTC()
	}
	from := to.Add(-model.DefaultEventWindow)
	if f.From != nil {
		from = f.From.UTC()
	}
	if !from.Before(to) {
		return query{}, apierrors.BadInput("from must be before to")
	}
	if to.Sub(from) > model.MaxEventWindow {
		return query{}, apierrors.BadInput(fmt.Sprintf(
			"the window may not exceed %d days; narrow it or page through it",
			int(model.MaxEventWindow.Hours()/24)))
	}

	where := []string{
		"tenant_id = {tenant:String}",
		"timestamp >= {from:DateTime64(3,'UTC')}",
		"timestamp <= {to:DateTime64(3,'UTC')}",
	}
	params := []any{
		clickhouse.Named("tenant", f.TenantID.String()),
		clickhouse.Named("from", db.CHTime64(from)),
		clickhouse.Named("to", db.CHTime64(to)),
	}

	eq := func(column, name, value string) {
		if value == "" {
			return
		}
		where = append(where, fmt.Sprintf("%s = {%s:String}", column, name))
		params = append(params, clickhouse.Named(name, value))
	}
	eq("category", "category", f.Category)
	eq("severity", "severity", f.Severity)
	eq("outcome", "outcome", f.Outcome)
	eq("source_type", "stype", f.SourceType)
	eq("source", "source", f.Source)
	eq("action", "action", f.Action)
	eq("user_id", "uid", f.UserID)
	eq("ip_source", "ipsrc", f.IPSource)
	eq("ip_destination", "ipdst", f.IPDestination)
	eq("geo_country", "geo", f.GeoCountry)
	eq("mitre_tactic", "tactic", f.MitreTactic)

	if f.Text != "" {
		// positionCaseInsensitive rather than LIKE: no escaping of % and _ to
		// get wrong, and a caller searching for "100%" means those characters.
		where = append(where, "positionCaseInsensitive(raw_event, {text:String}) > 0")
		params = append(params, clickhouse.Named("text", f.Text))
	}
	if f.MinRiskScore != nil {
		where = append(where, "risk_score >= {minrisk:Float32}")
		params = append(params, clickhouse.Named("minrisk", *f.MinRiskScore))
	}
	if f.MinThreatScore != nil {
		where = append(where, "threat_score >= {minthreat:Float32}")
		params = append(params, clickhouse.Named("minthreat", *f.MinThreatScore))
	}
	if f.CBSImpact != nil {
		where = append(where, "cbs_impact = {cbs:UInt8}")
		params = append(params, clickhouse.Named("cbs", *f.CBSImpact))
	}
	if f.SWIFTImpact != nil {
		where = append(where, "swift_impact = {swift:UInt8}")
		params = append(params, clickhouse.Named("swift", *f.SWIFTImpact))
	}
	if f.IOCOnly {
		where = append(where, "notEmpty(ioc_matched)")
	}

	return query{
		where:  "WHERE " + strings.Join(where, " AND "),
		params: params,
		from:   from,
		to:     to,
	}, nil
}

// page clamps the limit and offset a caller asked for.
//
// A page size of a million is not a search, it is an outage with a user behind
// it. A negative offset is a caller bug that ClickHouse would answer with a
// syntax error nobody can read.
func page(f model.EventFilter) (limit, offset int) {
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

// Search returns the events matching the filter, most recent first, and how
// many matched in total.
func (r *EventRepository) Search(ctx context.Context, f model.EventFilter) ([]*model.Event, int64, error) {
	q, err := buildQuery(f)
	if err != nil {
		return nil, 0, err
	}
	limit, offset := page(f)

	var total uint64
	if err := r.conn.QueryRow(ctx,
		"SELECT COUNT(*) FROM crp_audit.cyber_events "+q.where,
		q.params...,
	).Scan(&total); err != nil {
		return nil, 0, apierrors.Internal("event count", err)
	}

	// ORDER BY timestamp DESC follows the table's own sorting key,
	// (tenant_id, timestamp, event_id), so the newest page is read from the
	// end of the parts rather than sorted out of all of them.
	rows, err := r.conn.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM crp_audit.cyber_events %s ORDER BY timestamp DESC, event_id LIMIT %d OFFSET %d",
		eventColumns, q.where, limit, offset), q.params...)
	if err != nil {
		return nil, 0, apierrors.Internal("event search", err)
	}
	defer rows.Close()

	events, err := scanEvents(rows)
	if err != nil {
		return nil, 0, err
	}
	return events, int64(total), nil
}

// Get returns one event by id, scoped to the tenant.
//
// The id alone would be enough to find the row; the tenant is in the predicate
// anyway, so that guessing an identifier from another tenant returns nothing
// rather than that tenant's event.
func (r *EventRepository) Get(ctx context.Context, tenantID, eventID uuid.UUID) (*model.Event, error) {
	rows, err := r.conn.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM crp_audit.cyber_events WHERE tenant_id = {tenant:String} AND event_id = {id:UUID} LIMIT 1",
		eventColumns),
		clickhouse.Named("tenant", tenantID.String()),
		clickhouse.Named("id", eventID.String()),
	)
	if err != nil {
		return nil, apierrors.Internal("event get", err)
	}
	defer rows.Close()

	events, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, apierrors.New(apierrors.KindNotFound, "event not found")
	}
	return events[0], nil
}

func scanEvents(rows driver.Rows) ([]*model.Event, error) {
	events := []*model.Event{}
	for rows.Next() {
		e := &model.Event{}
		var eventID uuid.UUID
		if err := rows.Scan(
			&eventID, &e.TenantID, &e.Timestamp, &e.IngestedAt,
			&e.Source, &e.SourceType, &e.ConnectorID,
			&e.UserID, &e.UserName, &e.AssetHostname, &e.IPSource, &e.IPDestination, &e.GeoCountry,
			&e.Action, &e.Category, &e.Severity, &e.Outcome,
			&e.ThreatScore, &e.RiskScore, &e.MitreTactic, &e.MitreTechnique, &e.IOCMatched,
			&e.BusinessService, &e.CBSImpact, &e.SWIFTImpact, &e.RawEvent,
		); err != nil {
			return nil, apierrors.Internal("event scan", err)
		}
		e.EventID = eventID
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apierrors.Internal("event rows", err)
	}
	return events, nil
}
