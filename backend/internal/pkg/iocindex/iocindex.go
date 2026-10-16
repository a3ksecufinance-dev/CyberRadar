// Package iocindex answers "is this value a known indicator of compromise?"
// fast enough to ask on every event.
//
// The question has to be answered inside enrichment, before the rule engine
// sees the event, because the most valuable detection a platform like this can
// make is "something here talked to an address the feed knows". Until now the
// enricher returned an empty list with a comment saying so, and the only
// component that matched indicators was a second consumer of the same topic —
// running beside the rule engine, not before it. So a rule could never be
// written against a match, and the estate's indicators had no effect on
// detection at all.
//
// It is an in-process index rather than a call to the threat intelligence
// service, and that is a throughput decision, not a shortcut. A single event
// carries up to half a dozen candidate values; at the ingest rates this
// platform is sold on that is hundreds of thousands of lookups a second, which
// no database and no network cache will serve. The cost is that the index is a
// snapshot: an indicator added now takes until the next refresh to affect
// detection. The window is bounded and reported, which is the honest trade.
package iocindex

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/google/uuid"
)

// Indicator types, as stored in ti_iocs.ioc_type.
const (
	TypeIP         = "ip"
	TypeDomain     = "domain"
	TypeURL        = "url"
	TypeHashMD5    = "hash_md5"
	TypeHashSHA1   = "hash_sha1"
	TypeHashSHA256 = "hash_sha256"
	TypeEmail      = "email"
	TypeCVE        = "cve"
	TypeASN        = "asn"
)

// Normalize puts a value in the form the index and the ti_iocs.normalized
// column both use.
//
// It lives here, and the threat intelligence repository calls it, because the
// two have to agree exactly: a lookup normalised differently from the stored
// value misses every time, and misses silently — the answer "not a known
// indicator" is indistinguishable from a bug.
func Normalize(iocType, value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if iocType == TypeDomain || iocType == TypeURL {
		v = strings.TrimPrefix(v, "http://")
		v = strings.TrimPrefix(v, "https://")
		v = strings.TrimRight(v, "/")
	}
	return v
}

// Entry is what the index knows about one indicator.
//
// It carries the attribution as well as the identifier because the enricher
// uses it: an event that matched an indicator tied to a technique should carry
// that technique, and deriving it from a keyword in the action — which is what
// happens otherwise — is a guess where the feed has an answer.
type Entry struct {
	ID             uuid.UUID
	Type           string
	Severity       string
	Confidence     int
	MitreTactic    string
	MitreTechnique string
	ThreatActor    string
	MalwareFamily  string
	Campaign       string
}

// Candidate is one value from an event that might be an indicator, and the
// field it came from — which is what makes a hit explicable afterwards.
type Candidate struct {
	Type  string
	Value string
	Field string
}

// Candidates lists what is worth looking up for one event.
//
// One implementation, used by everything that matches indicators. There were
// two, and they disagreed: one looked at user_name, the other would have
// looked at user_email, so which indicators could ever match depended on which
// component you asked.
func Candidates(ev *event.NormalizedEvent) []Candidate {
	var out []Candidate
	seen := make(map[string]bool, 8)

	add := func(iocType, value, field string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		// The same value can arrive under two fields — user_name and
		// user_email are often the address. Looking it up twice would also
		// record the hit twice.
		key := iocType + "\x00" + Normalize(iocType, value)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Candidate{Type: iocType, Value: value, Field: field})
	}

	if ev.IPSource != nil {
		// A private address is never in a feed, and looking it up on every
		// event is the most common lookup there is.
		if ip := net.ParseIP(*ev.IPSource); ip != nil && !isPrivate(ip) {
			add(TypeIP, *ev.IPSource, "ip_source")
		}
	}
	if ev.IPDestination != nil {
		if ip := net.ParseIP(*ev.IPDestination); ip != nil && !isPrivate(ip) {
			add(TypeIP, *ev.IPDestination, "ip_destination")
		}
	}
	if ev.UserEmail != nil {
		add(TypeEmail, *ev.UserEmail, "user_email")
	}
	if ev.UserName != nil && strings.Contains(*ev.UserName, "@") {
		add(TypeEmail, *ev.UserName, "user_name")
	}

	// The fields a connector could not map into the schema stay in the raw
	// payload. Hashes, domains and URLs are there and nowhere else, and they
	// are exactly what a feed is mostly made of.
	//
	// The payload is decoded once, not once per field: this runs on every
	// event, and a raw event that is not JSON — syslog, CEF — must cost
	// nothing beyond the failed decode.
	if ev.RawEvent != "" && strings.HasPrefix(strings.TrimSpace(ev.RawEvent), "{") {
		var raw map[string]any
		if json.Unmarshal([]byte(ev.RawEvent), &raw) == nil {
			for field, iocType := range rawFields {
				if v, ok := raw[field].(string); ok {
					add(iocType, v, field)
				}
			}
		}
	}

	return out
}

// rawFields names the keys worth reading out of a JSON raw payload, and what
// kind of indicator each holds.
var rawFields = map[string]string{
	"file_hash_sha256": TypeHashSHA256,
	"file_hash_sha1":   TypeHashSHA1,
	"file_hash_md5":    TypeHashMD5,
	"domain":           TypeDomain,
	"dns_query":        TypeDomain,
	"url":              TypeURL,
	"http_host":        TypeDomain,
	"sender_email":     TypeEmail,
}

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
