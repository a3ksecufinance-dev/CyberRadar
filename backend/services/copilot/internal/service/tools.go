package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cyberradar/platform/internal/pkg/authctx"
)

// ToolDispatcher routes Claude's tool calls to the appropriate platform service.
// Each Dispatch call reaches the target microservice over HTTP carrying the
// asking user's own bearer token, so a tool can never read more than that user
// could read directly.
type ToolDispatcher struct {
	serviceURLs map[string]string
}

// NewToolDispatcher creates a ToolDispatcher.
func NewToolDispatcher(serviceURLs map[string]string) *ToolDispatcher {
	return &ToolDispatcher{serviceURLs: serviceURLs}
}

// Dispatch routes a tool call by name and returns structured results.
func (d *ToolDispatcher) Dispatch(ctx context.Context, toolName string, input map[string]any) (map[string]any, error) {
	switch toolName {
	case "query_alerts":
		return d.queryAlerts(ctx, input)
	case "lookup_ioc":
		return d.lookupIOC(ctx, input)
	case "get_incident":
		return d.getIncident(ctx, input)
	case "query_anomalies":
		return d.queryAnomalies(ctx, input)
	case "query_vulnerabilities":
		return d.queryVulns(ctx, input)
	case "analyze_attack_path":
		return d.analyzeAttackPath(ctx, input)
	case "search_entities":
		return d.searchEntities(ctx, input)
	case "get_asset":
		return d.getAsset(ctx, input)
	case "query_platform_stats":
		return d.queryPlatformStats(ctx, input)
	case "hunt_threats":
		return d.huntThreats(ctx, input)
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

// ─── Tool implementations ─────────────────────────────────────────────────────

func (d *ToolDispatcher) queryAlerts(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["siem"]
	if !ok {
		return unavailable("siem"), nil
	}
	p := buildQueryParams(input, map[string]string{
		"severity":  "severity",
		"status":    "status",
		"limit":     "limit",
		"rule_name": "rule_name",
	})
	return httpGET(ctx, u+"/api/v1/alerts?"+p)
}

func (d *ToolDispatcher) lookupIOC(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["ti"]
	if !ok {
		return unavailable("ti"), nil
	}
	value, _ := input["value"].(string)
	iocType, _ := input["type"].(string)
	q := "value=" + url.QueryEscape(value)
	if iocType != "" {
		q += "&type=" + iocType
	}
	return httpGET(ctx, u+"/api/v1/iocs/lookup?"+q)
}

func (d *ToolDispatcher) getIncident(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["soar"]
	if !ok {
		return unavailable("soar"), nil
	}
	if id, ok := input["incident_id"].(string); ok && id != "" {
		return httpGET(ctx, u+"/api/v1/soar/incidents/"+id)
	}
	p := buildQueryParams(input, map[string]string{
		"status": "status", "severity": "severity", "limit": "limit",
	})
	return httpGET(ctx, u+"/api/v1/soar/incidents?"+p)
}

func (d *ToolDispatcher) queryAnomalies(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["ueba"]
	if !ok {
		return unavailable("ueba"), nil
	}
	p := buildQueryParams(input, map[string]string{
		"entity_id": "entity_id", "anomaly_type": "type",
		"status": "status", "limit": "limit",
	})
	return httpGET(ctx, u+"/api/v1/ueba/anomalies?"+p)
}

func (d *ToolDispatcher) queryVulns(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["vuln"]
	if !ok {
		return unavailable("vuln"), nil
	}
	p := buildQueryParams(input, map[string]string{
		"severity": "severity", "asset_id": "asset_id",
		"cve_id": "cve_id", "sla_breached": "sla_breached", "limit": "limit",
	})
	return httpGET(ctx, u+"/api/v1/findings?"+p)
}

func (d *ToolDispatcher) analyzeAttackPath(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["attackpath"]
	if !ok {
		return unavailable("attackpath"), nil
	}
	if cp, _ := input["choke_points"].(string); cp == "true" {
		p := buildQueryParams(input, map[string]string{"scenario_id": "scenario_id", "limit": "limit"})
		return httpGET(ctx, u+"/api/v1/attack/choke-points?"+p)
	}
	p := buildQueryParams(input, map[string]string{
		"scenario_id": "scenario_id", "min_score": "min_score", "limit": "limit",
	})
	return httpGET(ctx, u+"/api/v1/attack/paths?"+p)
}

func (d *ToolDispatcher) searchEntities(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["kg"]
	if !ok {
		return unavailable("kg"), nil
	}
	p := buildQueryParams(input, map[string]string{
		"name": "search", "entity_type": "type",
		"min_risk": "min_risk", "limit": "limit",
	})
	return httpGET(ctx, u+"/api/v1/kg/entities?"+p)
}

func (d *ToolDispatcher) getAsset(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["asset"]
	if !ok {
		return unavailable("asset"), nil
	}
	if id, ok := input["asset_id"].(string); ok && id != "" {
		return httpGET(ctx, u+"/api/v1/assets/"+id)
	}
	p := buildQueryParams(input, map[string]string{"hostname": "hostname", "ip": "ip"})
	return httpGET(ctx, u+"/api/v1/assets?"+p)
}

func (d *ToolDispatcher) queryPlatformStats(ctx context.Context, input map[string]any) (map[string]any, error) {
	u, ok := d.serviceURLs["dashboard"]
	if !ok {
		return unavailable("dashboard"), nil
	}
	if domain, ok := input["domain"].(string); ok && domain != "" {
		return httpGET(ctx, u+"/api/v1/dashboard/kpi/snapshot?domain="+domain)
	}
	return httpGET(ctx, u+"/api/v1/dashboard/overview")
}

func (d *ToolDispatcher) huntThreats(ctx context.Context, input map[string]any) (map[string]any, error) {
	hypothesis, _ := input["hypothesis"].(string)
	timeRange, _ := input["time_range"].(string)
	if timeRange == "" {
		timeRange = "24h"
	}
	results := map[string]any{
		"hypothesis": hypothesis,
		"time_range": timeRange,
		"note":       "Threat hunt dispatched across siem, ueba, and ti sources.",
	}
	if u, ok := d.serviceURLs["siem"]; ok {
		if stats, err := httpGET(ctx, u+"/api/v1/alerts/stats"); err == nil {
			results["siem_stats"] = stats
		}
	}
	if u, ok := d.serviceURLs["ueba"]; ok {
		if data, err := httpGET(ctx, u+"/api/v1/ueba/anomalies?status=open&limit=5"); err == nil {
			results["ueba_anomalies"] = data
		}
	}
	if u, ok := d.serviceURLs["ti"]; ok {
		if data, err := httpGET(ctx, u+"/api/v1/iocs?limit=5"); err == nil {
			results["active_iocs"] = data
		}
	}
	return results, nil
}

// ─── HTTP / query helpers ─────────────────────────────────────────────────────

func httpGET(ctx context.Context, rawURL string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// Forward the caller's own token. The downstream service derives the tenant
	// from it, so the copilot cannot read outside what the asking user may see,
	// and no header can assert a tenant the token does not carry.
	token := authctx.Token(ctx)
	if token == "" {
		return nil, fmt.Errorf("no caller token in context: cannot query a service on the user's behalf")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("service call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]any{"raw": string(body), "status_code": resp.StatusCode}, nil
	}
	return result, nil
}

func buildQueryParams(input map[string]any, mapping map[string]string) string {
	vals := url.Values{}
	for inputKey, paramKey := range mapping {
		if v, ok := input[inputKey]; ok && v != nil {
			vals.Set(paramKey, fmt.Sprintf("%v", v))
		}
	}
	return vals.Encode()
}

func unavailable(svc string) map[string]any {
	return map[string]any{
		"error":   "service_unavailable",
		"service": svc,
		"message": fmt.Sprintf("The %s service URL is not configured", svc),
	}
}
