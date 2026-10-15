package model

import (
	"encoding/json"
	"testing"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
)

// A refusal has to carry its kind, because httperr classifies by kind and an
// unclassified error becomes "an internal error occurred". Telling an operator
// the server failed when they mistyped a format sends them to support for
// something they could have fixed in a second — and that is what this
// endpoint did until the live API was asked.
func TestEveryRefusalIsBadInputAndNotAnInternalError(t *testing.T) {
	cases := []struct {
		name string
		req  CreateConnectorRequest
	}{
		{"no name", CreateConnectorRequest{SourceType: "firewall"}},
		{"a blank name", CreateConnectorRequest{Name: "   ", SourceType: "firewall"}},
		{"no source type", CreateConnectorRequest{Name: "pare-feu"}},
		{"a format nothing parses", CreateConnectorRequest{Name: "pare-feu", SourceType: "firewall", Format: "xml"}},
		{"a negative silence threshold", CreateConnectorRequest{Name: "pare-feu", SourceType: "firewall", SilentAfter: -1}},
		{"config that is not JSON", CreateConnectorRequest{Name: "pare-feu", SourceType: "firewall", Config: json.RawMessage(`{nope`)}},
	}
	for _, c := range cases {
		err := c.req.Validate()
		if err == nil {
			t.Errorf("%s was accepted", c.name)
			continue
		}
		if !apierrors.IsKind(err, apierrors.KindBadInput) {
			t.Errorf("%s produced %v, which httperr answers 500 — the caller is told the server failed", c.name, err)
		}
	}
}

func TestTheSameHoldsWhenChangingAConnector(t *testing.T) {
	blank, bad, zero := "  ", "xml", 0
	cases := []struct {
		name string
		req  UpdateConnectorRequest
	}{
		{"emptying the name", UpdateConnectorRequest{Name: &blank}},
		{"emptying the source type", UpdateConnectorRequest{SourceType: &blank}},
		{"a format nothing parses", UpdateConnectorRequest{Format: &bad}},
		{"a silence threshold of zero", UpdateConnectorRequest{SilentAfter: &zero}},
	}
	for _, c := range cases {
		err := c.req.Validate()
		if err == nil {
			t.Errorf("%s was accepted", c.name)
			continue
		}
		if !apierrors.IsKind(err, apierrors.KindBadInput) {
			t.Errorf("%s produced %v, which httperr answers 500", c.name, err)
		}
	}
}

// json is the format a connector gets when it does not say, because the
// collector's own ingest endpoint takes JSON and most connectors send it.
func TestAConnectorThatNamesNoFormatGetsJSON(t *testing.T) {
	req := CreateConnectorRequest{Name: "pare-feu", SourceType: "firewall"}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if req.Format != "json" {
		t.Errorf("format defaulted to %q, want json", req.Format)
	}
}
