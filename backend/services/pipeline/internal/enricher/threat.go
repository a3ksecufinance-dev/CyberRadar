package enricher

import (
	"strings"

	"github.com/cyberradar/platform/internal/pkg/event"
)

// ThreatEnricher adds threat intelligence context to normalized events.
// Production: connect to D6 Threat Intel service via gRPC or Redis cache.
type ThreatEnricher struct{}

// NewThreatEnricher creates a ThreatEnricher.
func NewThreatEnricher() *ThreatEnricher {
	return &ThreatEnricher{}
}

// ThreatResult is the output of threat enrichment.
type ThreatResult struct {
	ThreatScore    float32
	MitreTactic    string
	MitreTechnique string
	IOCMatched     []string
	RiskScore      float32
}

// Enrich derives threat metadata from a normalized event.
// Stub: applies heuristic rules. Replace with D6 Threat Intel API call in Sprint 3+.
func (t *ThreatEnricher) Enrich(e *event.NormalizedEvent) ThreatResult {
	var result ThreatResult

	result.ThreatScore = baseThreatScore(e)
	result.RiskScore = result.ThreatScore

	// Heuristic MITRE ATT&CK mapping based on action keywords
	result.MitreTactic, result.MitreTechnique = heuristicMITRE(e)

	// IOC matching stub — D6 will replace with real IOC feed lookups
	result.IOCMatched = stubIOCMatch(e)

	// Boost risk for sanctioned geo
	if e.GeoCountry != nil && IsSanctioned(*e.GeoCountry) {
		result.RiskScore += 2.0
		result.ThreatScore += 1.5
	}

	// Cap scores
	if result.ThreatScore > 10.0 {
		result.ThreatScore = 10.0
	}
	if result.RiskScore > 10.0 {
		result.RiskScore = 10.0
	}

	return result
}

func baseThreatScore(e *event.NormalizedEvent) float32 {
	switch e.Severity {
	case event.SeverityCritical:
		return 8.0
	case event.SeverityHigh:
		return 6.0
	case event.SeverityMedium:
		return 4.0
	default:
		return 1.0
	}
}

func heuristicMITRE(e *event.NormalizedEvent) (tactic, technique string) {
	action := strings.ToLower(e.Action)

	switch {
	case contains(action, "login", "logon", "authentication", "signin"):
		if e.Outcome == event.OutcomeFailure {
			return "TA0006", "T1110" // Credential Access / Brute Force
		}
		return "TA0001", "T1078" // Initial Access / Valid Accounts

	case contains(action, "privilege", "escalat", "sudo", "runas"):
		return "TA0004", "T1548" // Privilege Escalation / Abuse Elevation Control

	case contains(action, "lateral", "rdp", "wmi", "psexec", "ssh"):
		return "TA0008", "T1021" // Lateral Movement / Remote Services

	case contains(action, "exfil", "upload", "transfer", "ftp", "scp"):
		return "TA0010", "T1041" // Exfiltration / Over C2 Channel

	case contains(action, "powershell", "cmd", "bash", "script"):
		return "TA0002", "T1059" // Execution / Command and Scripting Interpreter

	case contains(action, "scan", "recon", "nmap", "probe"):
		return "TA0007", "T1046" // Discovery / Network Service Scanning

	case e.Category == event.CategoryTransaction:
		return "TA0011", "T1657" // Impact / Financial Theft

	default:
		return "", ""
	}
}

func stubIOCMatch(e *event.NormalizedEvent) []string {
	// TODO: Query D6 Threat Intel IOC cache (Redis) with IPs, domains, hashes
	// For now: return empty — no false positives from stubs
	return []string{}
}

func contains(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
