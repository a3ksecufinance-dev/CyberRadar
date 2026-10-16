package enricher

import (
	"strings"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/iocindex"
)

// ThreatEnricher adds threat intelligence context to normalized events.
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

// Enrich derives threat metadata from a normalized event and whatever
// indicators it matched.
//
// The hits come from the caller because looking them up is a shared index, not
// this type's business. What is this type's business is what a match is worth:
// an event that reached an address a feed calls a command-and-control server
// is not a medium-severity event, whatever severity the connector put on it.
func (t *ThreatEnricher) Enrich(e *event.NormalizedEvent, hits []iocindex.Hit) ThreatResult {
	var result ThreatResult

	result.ThreatScore = baseThreatScore(e)
	result.RiskScore = result.ThreatScore

	// Heuristic MITRE ATT&CK mapping based on action keywords
	result.MitreTactic, result.MitreTechnique = heuristicMITRE(e)

	// A matched indicator is evidence, not a hint. It raises the score to a
	// floor rather than adding to it: adding would let two weak matches
	// outweigh one certain one, and would make the threshold a rule has to
	// compare against depend on how many fields happened to match.
	for _, hit := range hits {
		result.IOCMatched = append(result.IOCMatched, hit.Label())
		if floor := iocSeverityFloor(hit.Entry.Severity); floor > result.ThreatScore {
			result.ThreatScore = floor
		}
		if floor := iocSeverityFloor(hit.Entry.Severity); floor > result.RiskScore {
			result.RiskScore = floor
		}
		// The feed's attribution beats a keyword in the action string.
		if hit.Entry.MitreTactic != "" {
			result.MitreTactic = hit.Entry.MitreTactic
		}
		if hit.Entry.MitreTechnique != "" {
			result.MitreTechnique = hit.Entry.MitreTechnique
		}
	}
	if result.IOCMatched == nil {
		// An empty list, never nil: a consumer reading this field should not
		// have to tell "no matches" from "this field was not populated".
		result.IOCMatched = []string{}
	}

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

// iocSeverityFloor is the score an event cannot fall below once it has matched
// an indicator of that severity.
func iocSeverityFloor(severity string) float32 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 8.0
	case "MEDIUM":
		return 6.0
	case "LOW":
		return 4.0
	default:
		return 0.0
	}
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

func contains(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
