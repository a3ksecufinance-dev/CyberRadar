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
	Timestamp string  `json:"timestamp"`
	Action    string  `json:"action"`
	Category  string  `json:"category"`
	Severity  string  `json:"severity"`
	Outcome   string  `json:"outcome"`
	UserID    string  `json:"user_id"`
	UserName  string  `json:"user_name"`
	UserEmail string  `json:"user_email"`
	AssetID   string  `json:"asset_id"`
	Hostname  string  `json:"hostname"`
	AssetType string  `json:"asset_type"`
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	SrcPort   uint16  `json:"src_port"`
	DstPort   uint16  `json:"dst_port"`
	RiskScore float32 `json:"risk_score"`
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

		if t, ok := cefTime(ext["rt"]); ok {
			e.Timestamp = t
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
		// A sender that leaves the header name empty puts the text in msg.
		if e.Action == "" {
			e.Action = ext["msg"]
		}
	}

	e.Category = categoryFromSourceType(raw.SourceType)
	return e, nil
}

// parseCEFExtensions reads the key=value tail of a CEF event.
//
// A value may contain spaces — rt=Mar 14 2026 08:00:00 and msg=Connexion
// refusée par la règle 12 are both ordinary CEF — so the delimiter is not
// whitespace but the start of the next key. Splitting on whitespace kept only
// the first word of every value, which silently lost the event's own timestamp
// and its message.
//
// An escaped \= is part of the value, as the CEF specification says, and a
// key is a bare identifier, so a value containing a word with an = in it does
// not start a new pair.
func parseCEFExtensions(ext string) map[string]string {
	m := make(map[string]string)
	for _, kv := range splitCEFPairs(ext) {
		idx := indexUnescaped(kv, '=')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(kv[:idx])
		v := strings.TrimSpace(kv[idx+1:])
		v = strings.ReplaceAll(v, "\\=", "=")
		v = strings.ReplaceAll(v, "\\n", "\n")
		v = strings.ReplaceAll(v, "\\r", "\r")
		v = strings.ReplaceAll(v, "\\\\", "\\")
		m[k] = v
	}
	return m
}

// splitCEFPairs cuts the extension string before each key that starts a new
// pair.
func splitCEFPairs(ext string) []string {
	var pairs []string
	start := 0
	for i := 1; i < len(ext); i++ {
		if ext[i] != ' ' && ext[i] != '\t' {
			continue
		}
		// A space only ends a pair when what follows is "<key>=".
		j := i
		for j < len(ext) && (ext[j] == ' ' || ext[j] == '\t') {
			j++
		}
		k := j
		for k < len(ext) && isCEFKeyByte(ext[k]) {
			k++
		}
		if k > j && k < len(ext) && ext[k] == '=' && (k == 0 || ext[k-1] != '\\') {
			pairs = append(pairs, ext[start:i])
			start = j
			i = j
		}
	}
	if start < len(ext) {
		pairs = append(pairs, ext[start:])
	}
	return pairs
}

func isCEFKeyByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '.', b == '-':
		return true
	}
	return false
}

// indexUnescaped finds the first c that is not preceded by a backslash.
func indexUnescaped(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c && (i == 0 || s[i-1] != '\\') {
			return i
		}
	}
	return -1
}

// cefTime reads the rt extension, which a sender writes either as the textual
// form the specification gives or as milliseconds since the epoch. Both are
// common enough that accepting one and ignoring the other means half the
// senders have their events stamped with their arrival time.
func cefTime(rt string) (time.Time, bool) {
	if rt == "" {
		return time.Time{}, false
	}
	if ms, err := strconv.ParseInt(rt, 10, 64); err == nil {
		// Milliseconds, per the specification. A plausible second-based value
		// would be in 1970 read as milliseconds, so anything below the year
		// 2001 in milliseconds is read as seconds instead.
		if ms < 1_000_000_000_000 {
			return time.Unix(ms, 0).UTC(), true
		}
		return time.UnixMilli(ms).UTC(), true
	}
	for _, layout := range []string{
		"Jan 02 2006 15:04:05.000 MST",
		"Jan 02 2006 15:04:05.000",
		"Jan 02 2006 15:04:05 MST",
		"Jan 02 2006 15:04:05",
		"Jan 02 2006 15:04:05 -0700",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, rt); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
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

	// ─── PRI ─────────────────────────────────────────────────────────────────
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

	// ─── RFC 5424 ────────────────────────────────────────────────────────────
	//
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	//
	// It has to be recognised before falling through to RFC 3164, because the
	// two put the hostname in different places: reading a 5424 message
	// positionally as a 3164 one records the application name as the host, so
	// every event from a modern sender is attributed to the wrong asset.
	if ts, rest, ok := splitRFC5424(line); ok {
		if !ts.IsZero() {
			e.Timestamp = ts
		}
		fields := strings.SplitN(rest, " ", 5) // HOST APP PROCID MSGID SD+MSG
		if len(fields) >= 1 && fields[0] != "-" {
			e.AssetHostname = strPtr(fields[0])
		}
		if len(fields) >= 5 {
			e.Action = strings.TrimSpace(stripStructuredData(fields[4]))
		} else if len(fields) >= 2 {
			e.Action = strings.Join(fields[1:], " ")
		}
		return e, nil
	}

	// ─── RFC 3164 ────────────────────────────────────────────────────────────
	//
	// "Mmm dd hh:mm:ss HOSTNAME TAG: MSG". The timestamp carries no year, so
	// it is anchored on when the event was received rather than parsed on its
	// own — time.Parse of "Jan  2 15:04:05" yields year 0000, which puts every
	// event from an RFC 3164 sender outside every retention window and every
	// dashboard range. The syslog service's own listener already does this;
	// the two parsers now agree.
	parts := strings.Fields(line)
	if len(parts) >= 4 {
		if ts, ok := parseRFC3164Time(strings.Join(parts[:3], " "), raw.ReceivedAt); ok {
			e.Timestamp = ts
		}
		e.AssetHostname = strPtr(parts[3])
		if len(parts) >= 5 {
			e.Action = strings.Join(parts[4:], " ")
		}
	}

	return e, nil
}

// splitRFC5424 recognises the "VERSION TIMESTAMP ..." head of an RFC 5424
// message and returns the timestamp and what follows the timestamp.
//
// The version is a single digit and the timestamp is RFC 3339, so the shape is
// unambiguous: no RFC 3164 message starts with a digit followed by a date in
// that form. A nil timestamp ("-", which 5424 allows) still counts as 5424 —
// the positions are what matter.
func splitRFC5424(line string) (time.Time, string, bool) {
	parts := strings.SplitN(strings.TrimLeft(line, " "), " ", 3)
	if len(parts) < 3 {
		return time.Time{}, "", false
	}
	if len(parts[0]) != 1 || parts[0][0] < '1' || parts[0][0] > '9' {
		return time.Time{}, "", false
	}
	if parts[1] == "-" {
		return time.Time{}, parts[2], true
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return time.Time{}, "", false
	}
	return ts.UTC(), parts[2], true
}

// stripStructuredData drops the structured-data element RFC 5424 puts before
// the message, so the action is the message a person would read.
func stripStructuredData(s string) string {
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, "-") {
		return strings.TrimLeft(s[1:], " ")
	}
	if !strings.HasPrefix(s, "[") {
		return s
	}
	// Walk the elements: each is [...] and a ] inside a quoted value does not
	// close one.
	inQuote := false
	depth := 0
	for i, r := range s {
		switch r {
		case '"':
			inQuote = !inQuote
		case '[':
			if !inQuote {
				depth++
			}
		case ']':
			if !inQuote {
				depth--
				if depth == 0 && (i+1 == len(s) || s[i+1] != '[') {
					return strings.TrimLeft(s[i+1:], " ")
				}
			}
		}
	}
	return s
}

// parseRFC3164Time reads "Mmm dd hh:mm:ss" and gives it the year it must have
// had, which the format does not carry.
//
// A message received on 1 January that is stamped 31 December belongs to the
// previous year: anchoring on the received time and stepping back when the
// result lands in the future is what the syslog listener does, and the two must
// not disagree about the same line.
func parseRFC3164Time(stamp string, receivedAt time.Time) (time.Time, bool) {
	t, err := time.Parse("Jan  2 15:04:05", stamp)
	if err != nil {
		// Some senders pad the day with a zero rather than a space.
		t, err = time.Parse("Jan 02 15:04:05", stamp)
		if err != nil {
			return time.Time{}, false
		}
	}
	anchor := receivedAt
	if anchor.IsZero() {
		anchor = time.Now().UTC()
	}
	ts := time.Date(anchor.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	if ts.After(anchor.Add(24 * time.Hour)) {
		ts = ts.AddDate(-1, 0, 0)
	}
	return ts, true
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
	TimeCreated string `json:"TimeCreated"`
	EventID     int    `json:"EventId"`
	Channel     string `json:"Channel"`
	Computer    string `json:"Computer"`
	UserData    struct {
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
