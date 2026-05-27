package normalizer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
)

// ─── JSON parser ─────────────────────────────────────────────────────────────
// Accepts a flexible JSON event with well-known field names.
// Unknown fields are preserved in RawEvent.

type jsonEvent struct {
	Timestamp   string  `json:"timestamp"`
	Action      string  `json:"action"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Outcome     string  `json:"outcome"`
	UserID      string  `json:"user_id"`
	UserName    string  `json:"user_name"`
	UserEmail   string  `json:"user_email"`
	AssetID     string  `json:"asset_id"`
	Hostname    string  `json:"hostname"`
	AssetType   string  `json:"asset_type"`
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     uint16  `json:"src_port"`
	DstPort     uint16  `json:"dst_port"`
	RiskScore   float32 `json:"risk_score"`
}

func fromJSON(raw event.RawEvent) (*event.NormalizedEvent, error) {
	var je jsonEvent
	if err := json.Unmarshal([]byte(raw.Raw), &je); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}

	e := base(raw)
	e.Action = je.Action
	e.Category = mapCategory(je.Category)
	e.Severity = mapSeverity(je.Severity)
	e.Outcome = mapOutcome(je.Outcome)
	e.RiskScore = je.RiskScore

	if ts, err := time.Parse(time.RFC3339, je.Timestamp); err == nil {
		e.Timestamp = ts.UTC()
	}

	e.UserID = strPtr(je.UserID)
	e.UserName = strPtr(je.UserName)
	e.UserEmail = strPtr(je.UserEmail)
	e.AssetID = strPtr(je.AssetID)
	e.AssetHostname = strPtr(je.Hostname)
	e.AssetType = strPtr(je.AssetType)
	e.IPSource = strPtr(je.SrcIP)
	e.IPDestination = strPtr(je.DstIP)

	if je.SrcPort > 0 {
		p := je.SrcPort
		e.PortSource = &p
	}
	if je.DstPort > 0 {
		p := je.DstPort
		e.PortDest = &p
	}

	return e, nil
}

// ─── CEF parser ──────────────────────────────────────────────────────────────
// Common Event Format: CEF:Version|Device Vendor|Device Product|Device Version|
//                       Signature ID|Name|Severity|Extensions

func fromCEF(raw event.RawEvent) (*event.NormalizedEvent, error) {
	line := strings.TrimSpace(raw.Raw)
	if !strings.HasPrefix(line, "CEF:") {
		return nil, fmt.Errorf("cef: not a CEF event")
	}

	// Split on '|' — first 8 fields are mandatory (7 pipes)
	// Extensions may contain | inside quoted values; naive split on first 7 |
	parts := strings.SplitN(line, "|", 8)
	if len(parts) < 7 {
		return nil, fmt.Errorf("cef: malformed header (got %d fields)", len(parts))
	}

	e := base(raw)
	// parts[0] = "CEF:0", parts[5] = name, parts[6] = severity
	e.Action = parts[5]
	e.Severity = cefSeverity(parts[6])

	// Parse extensions (key=value pairs)
	if len(parts) == 8 {
		ext := parseCEFExtensions(parts[7])

		if ts := ext["rt"]; ts != "" {
			if t, err := time.Parse("Jan 02 2006 15:04:05", ts); err == nil {
				e.Timestamp = t.UTC()
			}
		}
		e.IPSource = strPtr(ext["src"])
		e.IPDestination = strPtr(ext["dst"])
		e.UserName = strPtr(ext["suser"])
		e.AssetHostname = strPtr(ext["dhost"])
		if p, err := strconv.ParseUint(ext["spt"], 10, 16); err == nil {
			port := uint16(p)
			e.PortSource = &port
		}
		if p, err := strconv.ParseUint(ext["dpt"], 10, 16); err == nil {
			port := uint16(p)
			e.PortDest = &port
		}
		if out := ext["outcome"]; out != "" {
			e.Outcome = mapOutcome(out)
		}
	}

	e.Category = categoryFromSourceType(raw.SourceType)
	return e, nil
}

func parseCEFExtensions(ext string) map[string]string {
	m := make(map[string]string)
	// Simple key=value parser (handles escaped \=)
	pairs := strings.Fields(ext)
	for _, pair := range pairs {
		idx := strings.Index(pair, "=")
		if idx <= 0 {
			continue
		}
		k := pair[:idx]
		v := strings.ReplaceAll(pair[idx+1:], "\\=", "=")
		m[k] = v
	}
	return m
}

func cefSeverity(s string) event.Severity {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return mapSeverity(s)
	}
	switch {
	case n >= 9:
		return event.SeverityCritical
	case n >= 7:
		return event.SeverityHigh
	case n >= 4:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

// ─── Syslog parser ───────────────────────────────────────────────────────────
// Supports RFC 3164 and RFC 5424 syslog formats.

func fromSyslog(raw event.RawEvent) (*event.NormalizedEvent, error) {
	line := strings.TrimSpace(raw.Raw)
	e := base(raw)

	// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	if strings.HasPrefix(line, "<") {
		priEnd := strings.Index(line, ">")
		if priEnd > 0 {
			priStr := line[1:priEnd]
			if pri, err := strconv.Atoi(priStr); err == nil {
				e.Severity = syslogSeverity(pri & 0x07)
				e.Category = syslogFacility(pri >> 3)
			}
			line = line[priEnd+1:]
		}
	}

	// Best-effort: use the whole message as the action
	parts := strings.Fields(line)
	if len(parts) >= 4 {
		// Try to parse timestamp (RFC 3164: "Jan  2 15:04:05")
		if len(parts) >= 3 {
			tsStr := strings.Join(parts[:3], " ")
			if ts, err := time.Parse("Jan  2 15:04:05", tsStr); err == nil {
				e.Timestamp = ts.UTC()
			}
		}
		if len(parts) >= 4 {
			e.AssetHostname = strPtr(parts[3])
		}
		if len(parts) >= 5 {
			e.Action = strings.Join(parts[4:], " ")
		}
	}

	return e, nil
}

func syslogSeverity(pri int) event.Severity {
	// 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
	switch pri {
	case 0, 1, 2:
		return event.SeverityCritical
	case 3:
		return event.SeverityHigh
	case 4:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

func syslogFacility(fac int) event.Category {
	// 4=auth, 10=authpriv, 1=user, 3=daemon
	switch fac {
	case 4, 10:
		return event.CategoryIAM
	case 16, 17, 18, 19, 20, 21, 22, 23: // local0-7
		return event.CategorySecurity
	default:
		return event.CategoryOther
	}
}

// ─── LEEF parser ─────────────────────────────────────────────────────────────
// Log Event Extended Format (IBM QRadar): LEEF:Version|Vendor|Product|Version|EventID|ext

func fromLEEF(raw event.RawEvent) (*event.NormalizedEvent, error) {
	line := strings.TrimSpace(raw.Raw)
	if !strings.HasPrefix(line, "LEEF:") {
		return nil, fmt.Errorf("leef: not a LEEF event")
	}

	parts := strings.SplitN(line, "|", 6)
	if len(parts) < 5 {
		return nil, fmt.Errorf("leef: malformed header")
	}

	e := base(raw)
	if len(parts) >= 5 {
		e.Action = parts[4] // EventID
	}

	if len(parts) == 6 {
		// Parse tab-delimited extensions
		ext := make(map[string]string)
		fields := strings.Split(parts[5], "\t")
		for _, f := range fields {
			kv := strings.SplitN(f, "=", 2)
			if len(kv) == 2 {
				ext[kv[0]] = kv[1]
			}
		}
		e.IPSource = strPtr(ext["src"])
		e.IPDestination = strPtr(ext["dst"])
		e.UserName = strPtr(ext["usrName"])
		e.Severity = mapSeverity(ext["sev"])
	}

	e.Category = categoryFromSourceType(raw.SourceType)
	return e, nil
}

// ─── Windows Event Log parser ─────────────────────────────────────────────────
// Expects JSON-encoded Windows Event (from Winlogbeat or NXLog).

type winEvent struct {
	TimeCreated  string `json:"TimeCreated"`
	EventID      int    `json:"EventId"`
	Channel      string `json:"Channel"`
	Computer     string `json:"Computer"`
	UserData     struct {
		SubjectUserName string `json:"SubjectUserName"`
		TargetUserName  string `json:"TargetUserName"`
		IpAddress       string `json:"IpAddress"`
	} `json:"UserData"`
	Level string `json:"Level"`
}

func fromWinEvent(raw event.RawEvent) (*event.NormalizedEvent, error) {
	var we winEvent
	if err := json.Unmarshal([]byte(raw.Raw), &we); err != nil {
		return nil, fmt.Errorf("winevent parse: %w", err)
	}

	e := base(raw)
	e.Action = fmt.Sprintf("EventID:%d", we.EventID)
	e.AssetHostname = strPtr(we.Computer)
	e.Category = winEventCategory(we.Channel)
	e.Severity = mapSeverity(we.Level)
	e.UserName = strPtr(we.UserData.TargetUserName)
	e.IPSource = strPtr(we.UserData.IpAddress)

	if ts, err := time.Parse(time.RFC3339, we.TimeCreated); err == nil {
		e.Timestamp = ts.UTC()
	}

	return e, nil
}

func winEventCategory(channel string) event.Category {
	ch := strings.ToLower(channel)
	if strings.Contains(ch, "security") {
		return event.CategoryIAM
	}
	if strings.Contains(ch, "system") || strings.Contains(ch, "application") {
		return event.CategorySecurity
	}
	return event.CategoryOther
}

// ─── Common Log Format parser (Apache/Nginx) ─────────────────────────────────
// 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326

func fromCLF(raw event.RawEvent) (*event.NormalizedEvent, error) {
	line := strings.TrimSpace(raw.Raw)
	e := base(raw)
	e.Category = event.CategoryNetwork

	parts := strings.Fields(line)
	if len(parts) < 7 {
		e.Action = line
		return e, nil
	}

	e.IPSource = strPtr(parts[0])
	// parts[3] = [10/Oct/2000:13:55:36, parts[4] = -0700]
	tsRaw := strings.TrimPrefix(parts[3], "[")
	tz := strings.TrimSuffix(parts[4], "]")
	if ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", tsRaw+" "+tz); err == nil {
		e.Timestamp = ts.UTC()
	}

	// Method + path
	method := strings.Trim(parts[5], "\"")
	path := parts[6]
	e.Action = method + " " + path

	// Status code → severity
	if len(parts) >= 9 {
		if code, err := strconv.Atoi(parts[8]); err == nil {
			e.Severity = httpSeverity(code)
			if code >= 400 {
				e.Outcome = event.OutcomeFailure
			} else {
				e.Outcome = event.OutcomeSuccess
			}
		}
	}

	return e, nil
}

func httpSeverity(code int) event.Severity {
	switch {
	case code >= 500:
		return event.SeverityHigh
	case code >= 400:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func mapSeverity(s string) event.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "EMERGENCY", "ALERT", "FATAL", "10", "9":
		return event.SeverityCritical
	case "HIGH", "ERROR", "8", "7":
		return event.SeverityHigh
	case "MEDIUM", "WARN", "WARNING", "5", "6", "4":
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

func mapCategory(s string) event.Category {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "security":
		return event.CategorySecurity
	case "fraud":
		return event.CategoryFraud
	case "network":
		return event.CategoryNetwork
	case "iam", "identity", "authentication", "authorization":
		return event.CategoryIAM
	case "compliance":
		return event.CategoryCompliance
	case "transaction", "payment":
		return event.CategoryTransaction
	default:
		return event.CategoryOther
	}
}

func mapOutcome(s string) event.Outcome {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "success", "allow", "allowed", "permit", "permitted":
		return event.OutcomeSuccess
	case "failure", "fail", "deny", "denied", "block", "blocked":
		return event.OutcomeFailure
	default:
		return event.OutcomeUnknown
	}
}

func categoryFromSourceType(st string) event.Category {
	switch strings.ToLower(st) {
	case "firewall", "ids", "ips", "proxy", "dns", "vpn", "netflow":
		return event.CategoryNetwork
	case "iam", "pam", "mfa", "sso", "ldap", "ad":
		return event.CategoryIAM
	case "edr", "av", "dlp", "siem":
		return event.CategorySecurity
	case "cbs", "banking", "payment", "atm", "swift", "monetique":
		return event.CategoryTransaction
	default:
		return event.CategoryOther
	}
}
