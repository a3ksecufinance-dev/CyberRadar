package parser

// parser.go — main entry point for syslog message detection and parsing.
// Supports: RFC 3164, RFC 5424, CEF-over-syslog.
// Output is a Parsed struct that the publisher converts to event.NormalizedEvent.

import (
	"strings"
	"time"
)

// SyslogFormat identifies the detected wire format.
type SyslogFormat string

const (
	FormatRFC3164    SyslogFormat = "rfc3164"
	FormatRFC5424    SyslogFormat = "rfc5424"
	FormatCEFSyslog  SyslogFormat = "cef_syslog"
	FormatUnknown    SyslogFormat = "unknown"
)

// Syslog severity values (RFC 5424 Table 2).
const (
	SevEmergency = 0 // System is unusable
	SevAlert     = 1 // Action must be taken immediately
	SevCritical  = 2 // Critical conditions
	SevError     = 3 // Error conditions
	SevWarning   = 4 // Warning conditions
	SevNotice    = 5 // Normal but significant condition
	SevInfo      = 6 // Informational messages
	SevDebug     = 7 // Debug-level messages
)

// Syslog facility codes (RFC 5424 Table 1, partial).
const (
	FacKernel  = 0
	FacUser    = 1
	FacMail    = 2
	FacDaemon  = 3
	FacAuth    = 4
	FacSyslog  = 5
	FacAuthpriv = 10
	FacLocal0  = 16
)

// Parsed is the output of the syslog parser — format-agnostic intermediate.
type Parsed struct {
	Format         SyslogFormat
	Timestamp      time.Time
	Hostname       string
	AppName        string
	ProcID         string
	MsgID          string
	Priority       int
	Facility       int
	Severity       int
	Message        string
	StructuredData map[string]map[string]string // RFC 5424 SD elements
	CEFExtensions  map[string]string            // populated when Format == FormatCEFSyslog
	CEFVendor      string
	CEFProduct     string
	CEFVersion     string
	CEFSignatureID string
	CEFName        string
	CEFSeverity    string
}

// Parse auto-detects the syslog format and parses the raw line.
// defaultHostname is used for RFC 3164 messages that omit the HOSTNAME field.
func Parse(raw []byte, defaultHostname string) (*Parsed, error) {
	line := strings.TrimRight(string(raw), "\r\n\x00")

	switch detect(line) {
	case FormatRFC5424:
		return parseRFC5424(line)
	case FormatCEFSyslog:
		return parseCEFSyslog(line, defaultHostname)
	default:
		return parseRFC3164(line, defaultHostname)
	}
}

// detect inspects the beginning of the message to determine its format.
func detect(line string) SyslogFormat {
	// Syslog with PRI prefix
	if strings.HasPrefix(line, "<") {
		priEnd := strings.Index(line, ">")
		if priEnd < 2 {
			return FormatUnknown
		}
		afterPRI := line[priEnd+1:]

		// RFC 5424: version digit "1" immediately after PRI
		if len(afterPRI) > 0 && afterPRI[0] == '1' && (len(afterPRI) == 1 || afterPRI[1] == ' ') {
			return FormatRFC5424
		}

		// CEF-over-syslog: MSG contains CEF: header
		// After PRI, skip RFC 3164 timestamp (15 chars) + space + hostname + space
		if isCEFBody(afterPRI) {
			return FormatCEFSyslog
		}

		return FormatRFC3164
	}

	// Raw CEF (no syslog wrapper)
	if strings.HasPrefix(line, "CEF:") {
		return FormatCEFSyslog
	}

	return FormatRFC3164
}

// isCEFBody checks whether the MSG body of a syslog message contains a CEF header.
func isCEFBody(s string) bool {
	// Skip RFC 3164 header: "Mmm dd hh:mm:ss hostname " (~26 chars)
	// Search for "CEF:" anywhere in the first 128 bytes to handle variations
	limit := len(s)
	if limit > 128 {
		limit = 128
	}
	return strings.Contains(s[:limit], "CEF:")
}
