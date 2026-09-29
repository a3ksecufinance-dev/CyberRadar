package httperr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
)

type body struct {
	Data  any `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details any    `json:"details"`
	} `json:"error"`
}

func answer(t *testing.T, err error) (int, body) {
	t.Helper()
	rec := httptest.NewRecorder()
	Write(rec, err)
	var b body
	if e := json.Unmarshal(rec.Body.Bytes(), &b); e != nil {
		t.Fatalf("response is not the envelope: %v (%s)", e, rec.Body.String())
	}
	return rec.Code, b
}

// A value outside a CHECK list is the database rejecting the request. Before
// this package it surfaced as 500, so a caller posting incident_type:"foo" was
// told the server had failed.
func TestCheckViolationIsUnprocessable(t *testing.T) {
	err := &pgconn.PgError{
		Code:           sqlStateCheckViolation,
		TableName:      "ir_incidents",
		ConstraintName: "ir_incidents_incident_type_check",
		Message:        `new row for relation "ir_incidents" violates check constraint`,
	}

	code, b := answer(t, err)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", code)
	}
	if b.Error == nil {
		t.Fatal("no error object in the envelope")
	}
	details, ok := b.Error.Details.(map[string]any)
	if !ok {
		t.Fatalf("details = %#v, want an object", b.Error.Details)
	}
	if details["field"] != "incident_type" {
		t.Errorf("field = %v, want incident_type", details["field"])
	}
	// The driver's own message names the relation and the SQL; it must not be
	// forwarded.
	if b.Error.Message == err.Message {
		t.Error("the driver message reached the caller")
	}
}

func TestConstraintFieldExtraction(t *testing.T) {
	cases := []struct {
		constraint, table, want string
	}{
		{"ir_incidents_incident_type_check", "ir_incidents", "incident_type"},
		{"ot_events_event_type_check", "ot_events", "event_type"},
		{"scs_vendors_vendor_type_check", "scs_vendors", "vendor_type"},
		{"assets_tenant_id_fkey", "assets", "tenant_id"},
		// A constraint the schema named itself carries no column to recover.
		{"sensible_dates", "ir_incidents", ""},
		{"", "ir_incidents", ""},
	}
	for _, c := range cases {
		if got := fieldFromConstraint(c.constraint, c.table); got != c.want {
			t.Errorf("fieldFromConstraint(%q, %q) = %q, want %q", c.constraint, c.table, got, c.want)
		}
	}
}

func TestDatabaseStatusMapping(t *testing.T) {
	cases := []struct {
		name  string
		state string
		want  int
	}{
		{"unique violation is a conflict", sqlStateUniqueViolation, http.StatusConflict},
		{"missing reference is unprocessable", sqlStateForeignKeyViolation, http.StatusUnprocessableEntity},
		{"null in a required column is unprocessable", sqlStateNotNullViolation, http.StatusUnprocessableEntity},
		{"unparseable literal is a bad request", sqlStateInvalidTextRepr, http.StatusBadRequest},
		{"overlong value is unprocessable", sqlStateStringDataTruncation, http.StatusUnprocessableEntity},
		// Anything else really is the server's problem.
		{"deadlock is ours", "40P01", http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _ := answer(t, &pgconn.PgError{Code: c.state})
			if code != c.want {
				t.Errorf("SQLSTATE %s → %d, want %d", c.state, code, c.want)
			}
		})
	}
}

func TestNoRowsIsNotFound(t *testing.T) {
	code, _ := answer(t, fmt.Errorf("load incident: %w", pgx.ErrNoRows))
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", code)
	}
}

func TestDomainErrorWins(t *testing.T) {
	// A service that classified the failure itself has more context than the
	// driver, even when a driver error is wrapped underneath.
	err := apierrors.Wrap(apierrors.KindNotFound, "incident not found", &pgconn.PgError{Code: sqlStateUniqueViolation})
	code, b := answer(t, err)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
	if b.Error.Message != "incident not found" {
		t.Errorf("message = %q, want the domain message alone", b.Error.Message)
	}
}

// Error() renders as "[KIND] message"; that prefix is for logs.
func TestDomainKindPrefixIsNotSent(t *testing.T) {
	_, b := answer(t, apierrors.New(apierrors.KindBadInput, "severity must be one of low, medium, high"))
	if b.Error.Message != "severity must be one of low, medium, high" {
		t.Errorf("message = %q, want it without the kind prefix", b.Error.Message)
	}
}

func TestUnclassifiedErrorLeaksNothing(t *testing.T) {
	code, b := answer(t, errors.New("dial tcp 10.0.0.5:5432: connection refused"))
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	if b.Error.Message != "An internal error occurred" {
		t.Errorf("message = %q, want the generic text", b.Error.Message)
	}
}

// A service that cannot classify a failure wraps it as Internal. The wrapper
// must not hide a database error the driver classified perfectly well: the
// asset service wrapped a not-null violation this way, and every create that
// left an optional field out was answered "an internal error occurred".
func TestInternalWrapperDoesNotHideADatabaseError(t *testing.T) {
	pgErr := &pgconn.PgError{
		Code:       sqlStateNotNullViolation,
		ColumnName: "mac_addresses",
		TableName:  "assets",
	}
	status, b := answer(t, apierrors.Internal("create asset", pgErr))

	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
	if b.Error == nil {
		t.Fatal("no error in the envelope")
	}
	details, ok := b.Error.Details.(map[string]any)
	if !ok {
		t.Fatalf("details = %#v, want the field and the reason", b.Error.Details)
	}
	if details["field"] != "mac_addresses" {
		t.Errorf("field = %v, want mac_addresses", details["field"])
	}
}

// An internal error with nothing classifiable underneath is still a 500.
func TestInternalWithoutADatabaseErrorIsStillFiveHundred(t *testing.T) {
	status, _ := answer(t, apierrors.Internal("compute score", errors.New("divide by zero")))
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", status, http.StatusInternalServerError)
	}
}
