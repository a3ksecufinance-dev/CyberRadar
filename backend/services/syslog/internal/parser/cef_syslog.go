package parser

// cef_syslog.go — CEF-over-Syslog parser.
// ArcSight CEF messages are often wrapped in an RFC 3164 or RFC 5424 syslog envelope.
// This parser strips the syslog header, then parses the inner CEF payload.
//
// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func parseCEFSyslog(line string, defaultHostname string) (*Parsed, error) {
	// First, strip the syslog envelope to get hostname + timestamp.
	// We do a light RFC 3164 parse to extract the header, then find "CEF:" in the body.
	p := &Parsed{
		Format:        FormatCEFSyslog,
		CEFExtensions: make(map[string]string),
	}

	// ─── Strip syslog PRI + header ───────────────────────────
	rest := line
	if strings.HasPrefix(line, "<") {
		priEnd := strings.Index(line, ">")
		if priEnd >= 2 {
			pri, _ := strconv.Atoi(line[1:priEnd])
			p.Priority = pri
			p.Facility = pri >> 3
			p.Severity = pri & 0x07
			rest = line[priEnd+1:]
		}
	}

	// Try to extract RFC 3164 timestamp + hostname before "CEF:"
	cefIdx := strings.Index(rest, "CEF:")
	if cefIdx < 0 {
		return nil, fmt.Errorf("cef_syslog: no CEF: header found")
	}

	header := rest[:cefIdx]
	cefLine := rest[cefIdx:]

	// Parse header for timestamp and hostname
	headerParts := strings.Fields(header)
	switch {
	case len(headerParts) >= 4:
		// "Mmm dd hh:mm:ss hostname"
		tsStr := strings.Join(headerParts[:3], " ")
		now := time.Now()
		for month, val := range rfc3164Months {
			if strings.HasPrefix(headerParts[0], month) {
				_ = month
				_ = val
			}
		}
		if ts, err := parseRFC3164Timestamp(tsStr, now.Year()); err == nil {
			p.Timestamp = ts
		}
		p.Hostname = headerParts[3]
	case len(headerParts) >= 1:
		p.Hostname = headerParts[len(headerParts)-1]
	default:
		p.Hostname = defaultHostname
	}

	if p.Hostname == "" {
		p.Hostname = defaultHostname
	}

	// ─── Parse CEF body ──────────────────────────────────────
	// CEF:Version|Vendor|Product|DevVer|SigID|Name|Severity|Extension
	parts := strings.SplitN(cefLine, "|", 8)
	if len(parts) < 7 {
		return nil, fmt.Errorf("cef_syslog: malformed CEF header, got %d fields", len(parts))
	}

	// parts[0] = "CEF:0"
	cefVerStr := strings.TrimPrefix(parts[0], "CEF:")
	p.CEFVersion = cefVerStr
	p.CEFVendor = parts[1]
	p.CEFProduct = parts[2]
	// parts[3] = device version (skip)
	p.CEFSignatureID = parts[4]
	p.CEFName = parts[5]
	p.CEFSeverity = parts[6]

	// Update parsed severity from CEF severity
	p.Severity = cefSeverityToSyslog(parts[6])

	// Action from CEF name
	p.Message = p.CEFName

	// Parse CEF extension key=value pairs
	if len(parts) == 8 {
		p.CEFExtensions = parseCEFExt(parts[7])

		// Extract timestamp from CEF extension "rt" (receipt time, epoch ms) or "end"/"start"
		if rt := p.CEFExtensions["rt"]; rt != "" && p.Timestamp.IsZero() {
			if ms, err := strconv.ParseInt(rt, 10, 64); err == nil {
				p.Timestamp = time.UnixMilli(ms).UTC()
			} else if ts, err := time.Parse("Jan 02 2006 15:04:05", rt); err == nil {
				p.Timestamp = ts.UTC()
			}
		}

		// Extract source/dest from CEF standard keys
		if p.Hostname == "" || p.Hostname == defaultHostname {
			if dhost := p.CEFExtensions["dhost"]; dhost != "" {
				p.Hostname = dhost
			}
		}
	}

	// Fill timestamp if still empty
	if p.Timestamp.IsZero() {
		p.Timestamp = time.Now().UTC()
	}

	return p, nil
}

// parseCEFExt parses CEF extension key=value pairs.
// Values may contain escaped characters (\=, \\, \n, \r).
func parseCEFExt(ext string) map[string]string {
	m := make(map[string]string)
	if ext == "" {
		return m
	}

	i := 0
	for i < len(ext) {
		// Skip whitespace
		for i < len(ext) && ext[i] == ' ' {
			i++
		}
		if i >= len(ext) {
			break
		}

		// Find key (up to '=')
		keyStart := i
		for i < len(ext) && ext[i] != '=' {
			i++
		}
		if i >= len(ext) {
			break
		}
		key := strings.TrimSpace(ext[keyStart:i])
		i++ // skip '='

		// Find value: extends until next "key=" pattern or end of string.
		// CEF spec says values use backslash escaping.
		var val strings.Builder
		for i < len(ext) {
			if ext[i] == '\\' && i+1 < len(ext) {
				switch ext[i+1] {
				case '=':
					val.WriteByte('=')
				case '\\':
					val.WriteByte('\\')
				case 'n':
					val.WriteByte('\n')
				case 'r':
					val.WriteByte('\r')
				default:
					val.WriteByte(ext[i+1])
				}
				i += 2
				continue
			}
			// Detect next key: look for " word=" pattern
			if ext[i] == ' ' {
				// Peek ahead to see if this is "key=" start
				j := i + 1
				for j < len(ext) && ext[j] != '=' && ext[j] != ' ' {
					j++
				}
				if j < len(ext) && ext[j] == '=' {
					// Yes — this is the start of the next key=value pair
					break
				}
			}
			val.WriteByte(ext[i])
			i++
		}

		if key != "" {
			m[key] = strings.TrimSpace(val.String())
		}
	}
	return m
}

func cefSeverityToSyslog(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		// String severity
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "critical", "emergency":
			return SevCritical
		case "high", "error":
			return SevError
		case "medium", "warning":
			return SevWarning
		case "low", "notice":
			return SevNotice
		default:
			return SevInfo
		}
	}
	switch {
	case n >= 9:
		return SevCritical
	case n >= 7:
		return SevError
	case n >= 4:
		return SevWarning
	default:
		return SevNotice
	}
}

func parseRFC3164Timestamp(s string, year int) (time.Time, error) {
	// "Jan  2 15:04:05" or "Jan 02 15:04:05"
	s = strings.TrimSpace(s)
	formats := []string{
		"Jan _2 15:04:05",
		"Jan 02 15:04:05",
		"Jan  2 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp %q", s)
}
