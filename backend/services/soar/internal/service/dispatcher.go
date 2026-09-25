package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cyberradar/platform/internal/pkg/svcauth"
	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// defaultActionTimeout bounds one remediation call when the step does not set
// TimeoutSec. A playbook step that hangs holds up every step behind it.
const defaultActionTimeout = 15 * time.Second

// maxErrorBody caps how much of a failing response is quoted back into the
// execution record, which is read by analysts and stored per step.
const maxErrorBody = 512

// Dispatcher performs one playbook action. The executor owns sequencing,
// retries and persistence; a Dispatcher only knows how to carry out a step.
type Dispatcher interface {
	Do(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, event map[string]any) (map[string]any, error)
}

// Endpoints holds the base URL of each service the SOAR can act through.
// An empty URL disables the actions that need it, and they fail with a message
// saying which service is unconfigured rather than pretending to have run.
type Endpoints struct {
	Netsec       string
	Identity     string
	Asset        string
	ThreatIntel  string
	Vuln         string
	Notification string
	SIEM         string
	IR           string
	AttackPath   string
}

// HTTPDispatcher carries out playbook actions by calling the platform's own
// services, authenticated as the SOAR's platform-scoped service account.
//
// It replaces a switch that returned fixed maps — `{"status":"blocked"}` —
// without contacting anything. Every step therefore succeeded, which made
// on_failure: abort dead code and every execution record a work of fiction.
type HTTPDispatcher struct {
	endpoints Endpoints
	tokens    *svcauth.Pool
	client    *http.Client
	logger    zerolog.Logger
}

// NewHTTPDispatcher creates an HTTPDispatcher.
func NewHTTPDispatcher(endpoints Endpoints, tokens *svcauth.Pool, logger zerolog.Logger) *HTTPDispatcher {
	return &HTTPDispatcher{
		endpoints: endpoints,
		tokens:    tokens,
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    logger,
	}
}

// call is one HTTP request to one platform service.
type call struct {
	service string // for the error message and the execution record
	baseURL string
	method  string
	path    string
	query   url.Values
	body    any
}

// Do carries out one step.
func (d *HTTPDispatcher) Do(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	timeout := defaultActionTimeout
	if step.TimeoutSec > 0 {
		timeout = time.Duration(step.TimeoutSec) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch step.ActionType {
	case model.ActionBlockIP:
		return d.blockIP(ctx, tenantID, step, ev)
	case model.ActionUnblockIP:
		return d.unblockIP(ctx, tenantID, step, ev)
	case model.ActionDisableUser:
		return d.setUserEnabled(ctx, tenantID, step, ev, false)
	case model.ActionEnableUser:
		return d.setUserEnabled(ctx, tenantID, step, ev, true)
	case model.ActionIsolateHost:
		return d.setHostIsolated(ctx, tenantID, step, ev, true)
	case model.ActionUnisolateHost:
		return d.setHostIsolated(ctx, tenantID, step, ev, false)
	case model.ActionEnrichIOC:
		return d.enrichIOC(ctx, tenantID, step, ev)
	case model.ActionAddToBlocklist:
		return d.addToBlocklist(ctx, tenantID, step, ev)
	case model.ActionCreateTicket:
		return d.createTicket(ctx, tenantID, step, ev)
	case model.ActionCloseTicket:
		return d.closeTicket(ctx, tenantID, step, ev)
	case model.ActionSendNotification:
		return d.sendNotification(ctx, tenantID, step, ev)
	case model.ActionRunSIEMQuery:
		return d.runSIEMQuery(ctx, tenantID, step, ev)
	case model.ActionTagEntity:
		return d.tagEntity(ctx, tenantID, step, ev)
	case model.ActionMarkCompromised:
		return d.markCompromised(ctx, tenantID, step, ev)
	case model.ActionCreateIncident:
		return d.createIncident(ctx, tenantID, step, ev)
	case model.ActionWait:
		// Handled by the executor, which owns the clock between steps.
		return map[string]any{"action": model.ActionWait}, nil
	default:
		return nil, fmt.Errorf("unknown action type: %s", step.ActionType)
	}
}

// ─── Actions ──────────────────────────────────────────────────────────────────

// blockIP installs a deny policy for the address, in both directions.
func (d *HTTPDispatcher) blockIP(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	ip := resolveParam(step.ActionParams, "ip", ev, "ip_source")
	if ip == "" {
		return nil, fmt.Errorf("block_ip: no IP address in the step params or the trigger event")
	}
	cidr := asCIDR(ip)

	return d.send(ctx, tenantID, call{
		service: "netsec", baseURL: d.endpoints.Netsec,
		method: http.MethodPost, path: "/api/v1/netsec/policies",
		body: map[string]any{
			"name":        "soar-block-" + ip,
			"description": "Blocked by SOAR playbook step " + step.Name,
			"src_cidr":    cidr,
			"action":      "deny",
			// Above any allow rule an operator is likely to have written; a
			// containment policy that loses to a standing allow contains nothing.
			"priority": 1,
		},
	})
}

// unblockIP retires the deny policy by name. netsec has no delete route, so
// the policy is set to log rather than removed, which also leaves the trail.
func (d *HTTPDispatcher) unblockIP(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	policyID := resolveParam(step.ActionParams, "policy_id", ev, "policy_id")
	if policyID == "" {
		return nil, fmt.Errorf("unblock_ip: policy_id is required — it is returned by the block_ip step that created the policy")
	}

	return d.send(ctx, tenantID, call{
		service: "netsec", baseURL: d.endpoints.Netsec,
		method: http.MethodPatch, path: "/api/v1/netsec/policies/" + policyID,
		body: map[string]any{"action": "log", "description": "Unblocked by SOAR playbook step " + step.Name},
	})
}

// setUserEnabled disables or re-enables an identity.
func (d *HTTPDispatcher) setUserEnabled(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any, enabled bool) (map[string]any, error) {
	action := model.ActionDisableUser
	if enabled {
		action = model.ActionEnableUser
	}

	userID := resolveParam(step.ActionParams, "user_id", ev, "user_id")
	if userID == "" {
		return nil, fmt.Errorf("%s: no user_id in the step params or the trigger event", action)
	}

	if !enabled {
		// identity exposes disable as DELETE on the user; it is a soft disable.
		return d.send(ctx, tenantID, call{
			service: "identity", baseURL: d.endpoints.Identity,
			method: http.MethodDelete, path: "/api/v1/users/" + userID,
		})
	}
	return d.send(ctx, tenantID, call{
		service: "identity", baseURL: d.endpoints.Identity,
		method: http.MethodPut, path: "/api/v1/users/" + userID,
		body: map[string]any{"status": "active"},
	})
}

// setHostIsolated contains a host at the network layer.
//
// Isolation is a deny policy on the host's address, not an asset status: the
// asset and device vocabularies have no "isolated" state, and marking a host
// "inactive" would record a containment that never happened.
func (d *HTTPDispatcher) setHostIsolated(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any, isolate bool) (map[string]any, error) {
	action := model.ActionIsolateHost
	if !isolate {
		action = model.ActionUnisolateHost
	}

	if !isolate {
		policyID := resolveParam(step.ActionParams, "policy_id", ev, "policy_id")
		if policyID == "" {
			return nil, fmt.Errorf("%s: policy_id is required — it is returned by the isolate_host step", action)
		}
		return d.send(ctx, tenantID, call{
			service: "netsec", baseURL: d.endpoints.Netsec,
			method: http.MethodPatch, path: "/api/v1/netsec/policies/" + policyID,
			body: map[string]any{"action": "log", "description": "Host released by SOAR step " + step.Name},
		})
	}

	ip := resolveParam(step.ActionParams, "ip", ev, "ip_source")
	assetID := resolveParam(step.ActionParams, "asset_id", ev, "asset_id")
	if ip == "" && assetID == "" {
		return nil, fmt.Errorf("%s: needs an ip or an asset_id", action)
	}
	if ip == "" {
		resolved, err := d.assetAddress(ctx, tenantID, assetID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", action, err)
		}
		ip = resolved
	}

	out, err := d.send(ctx, tenantID, call{
		service: "netsec", baseURL: d.endpoints.Netsec,
		method: http.MethodPost, path: "/api/v1/netsec/policies",
		body: map[string]any{
			"name":        "soar-isolate-" + ip,
			"description": "Host isolated by SOAR playbook step " + step.Name,
			"src_cidr":    asCIDR(ip),
			"dst_cidr":    asCIDR(ip),
			"action":      "deny",
			"priority":    1,
		},
	})
	if out != nil {
		out["isolated_ip"] = ip
		if assetID != "" {
			out["asset_id"] = assetID
		}
	}
	return out, err
}

// assetAddress resolves an asset to its first known address.
func (d *HTTPDispatcher) assetAddress(ctx context.Context, tenantID uuid.UUID, assetID string) (string, error) {
	out, err := d.send(ctx, tenantID, call{
		service: "asset", baseURL: d.endpoints.Asset,
		method: http.MethodGet, path: "/api/v1/assets/" + assetID,
	})
	if err != nil {
		return "", err
	}

	addresses, _ := dig(out, "response", "data", "ip_addresses").([]any)
	for _, a := range addresses {
		if s, ok := a.(string); ok && s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("asset %s has no IP address recorded, so it cannot be isolated by address", assetID)
}

func (d *HTTPDispatcher) enrichIOC(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	value := resolveParam(step.ActionParams, "ioc_value", ev, "ioc_value")
	if value == "" {
		value = resolveParam(step.ActionParams, "ip", ev, "ip_source")
	}
	if value == "" {
		return nil, fmt.Errorf("enrich_ioc: no ioc_value in the step params or the trigger event")
	}

	iocType := resolveParam(step.ActionParams, "ioc_type", ev, "ioc_type")
	if iocType == "" {
		iocType = guessIOCType(value)
	}

	return d.send(ctx, tenantID, call{
		service: "threat-intel", baseURL: d.endpoints.ThreatIntel,
		method: http.MethodPost, path: "/api/v1/ti/iocs/lookup",
		body: map[string]any{"type": iocType, "value": value},
	})
}

func (d *HTTPDispatcher) addToBlocklist(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	value := resolveParam(step.ActionParams, "ioc_value", ev, "ioc_value")
	if value == "" {
		value = resolveParam(step.ActionParams, "ip", ev, "ip_source")
	}
	if value == "" {
		return nil, fmt.Errorf("add_to_blocklist: no ioc_value in the step params or the trigger event")
	}

	iocType := resolveParam(step.ActionParams, "ioc_type", ev, "ioc_type")
	if iocType == "" {
		iocType = guessIOCType(value)
	}
	severity := strings.ToUpper(resolveParam(step.ActionParams, "severity", ev, "severity"))
	if severity == "" {
		severity = "HIGH"
	}

	return d.send(ctx, tenantID, call{
		service: "threat-intel", baseURL: d.endpoints.ThreatIntel,
		method: http.MethodPost, path: "/api/v1/ti/iocs",
		body: map[string]any{
			"ioc_type":    iocType,
			"value":       value,
			"severity":    severity,
			"confidence":  90,
			"tlp":         2,
			"description": "Added by SOAR playbook step " + step.Name,
			"tags":        []string{"soar", "auto-blocklist"},
		},
	})
}

func (d *HTTPDispatcher) createTicket(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	title := resolveParam(step.ActionParams, "title", ev, "title")
	if title == "" {
		return nil, fmt.Errorf("create_ticket: no title in the step params or the trigger event")
	}

	priority := 2
	if p, ok := numericParam(step.ActionParams, "priority"); ok {
		priority = p
	}

	return d.send(ctx, tenantID, call{
		service: "vuln", baseURL: d.endpoints.Vuln,
		method: http.MethodPost, path: "/api/v1/vuln/tickets",
		body: map[string]any{
			"title":       title,
			"description": resolveParam(step.ActionParams, "description", ev, "description"),
			"priority":    priority,
			"tags":        []string{"soar"},
		},
	})
}

func (d *HTTPDispatcher) closeTicket(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	ticketID := resolveParam(step.ActionParams, "ticket_id", ev, "ticket_id")
	if ticketID == "" {
		return nil, fmt.Errorf("close_ticket: no ticket_id in the step params or the trigger event")
	}

	return d.send(ctx, tenantID, call{
		service: "vuln", baseURL: d.endpoints.Vuln,
		method: http.MethodPut, path: "/api/v1/vuln/tickets/" + ticketID,
		body: map[string]any{"status": "resolved"},
	})
}

func (d *HTTPDispatcher) sendNotification(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	message := resolveParam(step.ActionParams, "message", ev, "message")
	if message == "" {
		return nil, fmt.Errorf("send_notification: no message in the step params or the trigger event")
	}
	title := resolveParam(step.ActionParams, "title", ev, "title")
	if title == "" {
		title = "SOAR: " + step.Name
	}
	severity := strings.ToUpper(resolveParam(step.ActionParams, "severity", ev, "severity"))
	if severity == "" {
		severity = "HIGH"
	}

	channel := resolveParam(step.ActionParams, "channel", ev, "channel")
	if channel == "" {
		return nil, fmt.Errorf("send_notification: no channel in the step params — there is no safe default recipient")
	}
	channelConfig, _ := step.ActionParams["channel_config"].(map[string]any)
	if channelConfig == nil {
		channelConfig = map[string]any{}
	}

	return d.send(ctx, tenantID, call{
		service: "notification", baseURL: d.endpoints.Notification,
		method: http.MethodPost, path: "/api/v1/notifications/send",
		body: map[string]any{
			"tenant_id": tenantID.String(),
			"title":     title,
			"body":      message,
			"severity":  severity,
			"channels":  []any{map[string]any{"type": channel, "config": channelConfig}},
		},
	})
}

func (d *HTTPDispatcher) runSIEMQuery(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	q := url.Values{}
	for _, field := range []string{"severity", "status", "rule_id", "entity_value", "from", "to", "limit"} {
		if v := resolveParam(step.ActionParams, field, ev, field); v != "" {
			q.Set(field, v)
		}
	}
	if len(q) == 0 {
		return nil, fmt.Errorf("run_siem_query: no filters given — an unfiltered alert query is not a useful playbook step")
	}

	return d.send(ctx, tenantID, call{
		service: "siem", baseURL: d.endpoints.SIEM,
		method: http.MethodGet, path: "/api/v1/siem/alerts", query: q,
	})
}

func (d *HTTPDispatcher) tagEntity(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	assetID := resolveParam(step.ActionParams, "asset_id", ev, "asset_id")
	if assetID == "" {
		assetID = resolveParam(step.ActionParams, "entity_id", ev, "entity_id")
	}
	tag := resolveParam(step.ActionParams, "tag", ev, "tag")
	if assetID == "" || tag == "" {
		return nil, fmt.Errorf("tag_entity: needs an asset_id and a tag")
	}

	// Read the asset first: the update replaces the tag list, so writing only
	// the new tag would drop every tag the asset already carries.
	current, err := d.send(ctx, tenantID, call{
		service: "asset", baseURL: d.endpoints.Asset,
		method: http.MethodGet, path: "/api/v1/assets/" + assetID,
	})
	if err != nil {
		return nil, fmt.Errorf("tag_entity: %w", err)
	}

	tags := []any{}
	if existing, ok := dig(current, "response", "data", "tags").([]any); ok {
		tags = existing
	}
	for _, t := range tags {
		if s, ok := t.(string); ok && strings.EqualFold(s, tag) {
			// Already tagged: a replayed playbook must not be an error.
			return map[string]any{"action": model.ActionTagEntity, "asset_id": assetID, "tag": tag, "already_tagged": true}, nil
		}
	}

	return d.send(ctx, tenantID, call{
		service: "asset", baseURL: d.endpoints.Asset,
		method: http.MethodPut, path: "/api/v1/assets/" + assetID,
		body: map[string]any{"tags": append(tags, tag)},
	})
}

func (d *HTTPDispatcher) markCompromised(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	nodeID := resolveParam(step.ActionParams, "node_id", ev, "node_id")
	if nodeID == "" {
		return nil, fmt.Errorf("mark_compromised: no node_id in the step params or the trigger event")
	}

	return d.send(ctx, tenantID, call{
		service: "attackpath", baseURL: d.endpoints.AttackPath,
		method: http.MethodPut, path: "/api/v1/attack/nodes/" + nodeID + "/compromise",
		body: map[string]any{"compromised": true},
	})
}

func (d *HTTPDispatcher) createIncident(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	title := resolveParam(step.ActionParams, "title", ev, "title")
	if title == "" {
		return nil, fmt.Errorf("create_incident: no title in the step params or the trigger event")
	}
	severity := strings.ToUpper(resolveParam(step.ActionParams, "severity", ev, "severity"))
	if severity == "" {
		severity = "HIGH"
	}

	return d.send(ctx, tenantID, call{
		service: "ir", baseURL: d.endpoints.IR,
		method: http.MethodPost, path: "/api/v1/incidents",
		body: map[string]any{
			"title":         title,
			"description":   resolveParam(step.ActionParams, "description", ev, "description"),
			"severity":      severity,
			"incident_type": resolveParam(step.ActionParams, "incident_type", ev, "incident_type"),
			"source":        "soar",
			"source_ref":    step.ID.String(),
			"tags":          []string{"soar"},
		},
	})
}

// ─── Transport ────────────────────────────────────────────────────────────────

// send performs one call and reports what actually happened.
//
// A non-2xx answer is an error. That is the point of this file: while every
// action returned a fixed success map, on_failure: abort could never fire and
// an execution record showed containment that had not occurred.
func (d *HTTPDispatcher) send(ctx context.Context, tenantID uuid.UUID, c call) (map[string]any, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("%s service has no URL configured, so this action cannot run", c.service)
	}

	endpoint := strings.TrimSuffix(c.baseURL, "/") + c.path
	if len(c.query) > 0 {
		endpoint += "?" + c.query.Encode()
	}

	var payload io.Reader
	if c.body != nil {
		encoded, err := json.Marshal(c.body)
		if err != nil {
			return nil, fmt.Errorf("%s: encode request: %w", c.service, err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, c.method, endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", c.service, err)
	}
	if c.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// The token names the tenant this playbook is acting for. The SOAR's
	// account is platform-scoped, so this is the only thing confining the call
	// to one customer.
	if err := d.tokens.Authorize(ctx, tenantID.String(), req); err != nil {
		return nil, fmt.Errorf("%s: authenticate as the SOAR service account: %w", c.service, err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s %s: %w", c.service, c.method, c.path, err)
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s %s: %s: %s",
			c.service, c.method, c.path, resp.Status, truncate(string(raw), maxErrorBody))
	}
	if readErr != nil {
		return nil, fmt.Errorf("%s: read response: %w", c.service, readErr)
	}

	out := map[string]any{
		"service": c.service,
		"method":  c.method,
		"path":    c.path,
		"status":  resp.StatusCode,
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err == nil {
			out["response"] = decoded
		} else {
			out["response_raw"] = truncate(string(raw), maxErrorBody)
		}
	}

	d.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("service", c.service).
		Str("method", c.method).
		Str("path", c.path).
		Int("status", resp.StatusCode).
		Msg("soar_action_performed")

	return out, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// dig walks nested maps, returning nil if any step is missing or not a map.
func dig(m map[string]any, keys ...string) any {
	var current any = m
	for _, k := range keys {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = asMap[k]
	}
	return current
}

// asCIDR turns a bare address into a single-host CIDR, leaving a range alone.
func asCIDR(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	if strings.Contains(ip, ":") {
		return ip + "/128" // IPv6
	}
	return ip + "/32"
}

// guessIOCType infers the indicator type from its shape, so a playbook author
// need not repeat what is obvious from the value.
func guessIOCType(value string) string {
	switch {
	case strings.HasPrefix(value, "http://"), strings.HasPrefix(value, "https://"):
		return "url"
	case strings.Contains(value, "@"):
		return "email"
	case strings.HasPrefix(strings.ToUpper(value), "CVE-"):
		return "cve"
	case isHex(value, 64):
		return "hash_sha256"
	case isHex(value, 40):
		return "hash_sha1"
	case isHex(value, 32):
		return "hash_md5"
	case strings.Count(value, ".") == 3 && !strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyz"):
		return "ip"
	case strings.Contains(value, ":"):
		return "ip" // IPv6
	default:
		return "domain"
	}
}

func isHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// numericParam reads a param that JSON decoding may have given as a float.
func numericParam(params map[string]any, key string) (int, bool) {
	switch v := params[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
