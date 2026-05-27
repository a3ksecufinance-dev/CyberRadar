package parser

// RFC 5424 — The Syslog Protocol
// Format: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD MSG
//
// Examples:
//   <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry
//   <34>1 2003-10-11T22:14:15.003Z mymachine su - - - 'su root' failed

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseRFC5424 parses an RFC 5424 syslog message.
func parseRFC5424(line string) (*Parsed, error) {
	p := &Parsed{Format: FormatRFC5424}

	if !strings.HasPrefix(line, "<") {
		return nil, fmt.Errorf("rfc5424: missing PRI")
	}

	// ─── Priority ───────────────────────────────────────────
	priEnd := strings.Index(line, ">")
	if priEnd < 2 {
		return nil, fmt.Errorf("rfc5424: malformed PRI bracket")
	}
	pri, err := strconv.Atoi(line[1:priEnd])
	if err != nil {
		return nil, fmt.Errorf("rfc5424: invalid PRI value: %w", err)
	}
	p.Priority = pri
	p.Facility = pri >> 3
	p.Severity = pri & 0x07

	// After ">", next char should be VERSION ("1")
	rest := line[priEnd+1:]
	parts := strings.SplitN(rest, " ", 7) // VERSION TS HOST APP PROCID MSGID SD+MSG
	if len(parts) < 6 {
		return nil, fmt.Errorf("rfc5424: too few fields (%d)", len(parts))
	}

	// parts[0] = version (skip)
	// parts[1] = TIMESTAMP
	if parts[1] != "-" {
		ts, err := time.Parse(time.RFC3339Nano, parts[1])
		if err == nil {
			p.Timestamp = ts.UTC()
		}
	}

	// parts[2] = HOSTNAME
	if parts[2] != "-" {
		p.Hostname = parts[2]
	}

	// parts[3] = APP-NAME
	if parts[3] != "-" {
		p.AppName = parts[3]
	}

	// parts[4] = PROCID
	if parts[4] != "-" {
		p.ProcID = parts[4]
	}

	// parts[5] = MSGID
	if parts[5] != "-" {
		p.MsgID = parts[5]
	}

	// parts[6] = SD + optional MSG
	if len(parts) < 7 {
		return p, nil
	}

	sdAndMsg := parts[6]

	// ─── Structured Data ────────────────────────────────────
	p.StructuredData = make(map[string]map[string]string)

	if strings.HasPrefix(sdAndMsg, "-") {
		// No SD
		if len(sdAndMsg) > 2 {
			p.Message = strings.TrimSpace(sdAndMsg[1:])
		}
	} else if strings.HasPrefix(sdAndMsg, "[") {
		// Parse one or more SD-ELEMENTs
		msgStart, sd := parseStructuredData(sdAndMsg)
		p.StructuredData = sd
		if msgStart < len(sdAndMsg) {
			p.Message = strings.TrimSpace(sdAndMsg[msgStart:])
		}
	} else {
		p.Message = sdAndMsg
	}

	return p, nil
}

// parseStructuredData parses RFC 5424 structured data.
// Returns the index where the MSG starts (after all SD elements) and the parsed SD map.
func parseStructuredData(s string) (int, map[string]map[string]string) {
	sd := make(map[string]map[string]string)
	i := 0

	for i < len(s) && s[i] == '[' {
		i++ // skip '['

		// Read SD-ID (up to first space or ']')
		sdIDEnd := i
		for sdIDEnd < len(s) && s[sdIDEnd] != ' ' && s[sdIDEnd] != ']' {
			sdIDEnd++
		}
		sdID := s[i:sdIDEnd]
		i = sdIDEnd
		params := make(map[string]string)

		// Read PARAM-NAME="PARAM-VALUE" pairs
		for i < len(s) && s[i] != ']' {
			if s[i] == ' ' {
				i++
				continue
			}

			// PARAM-NAME
			nameEnd := i
			for nameEnd < len(s) && s[nameEnd] != '=' {
				nameEnd++
			}
			if nameEnd >= len(s) {
				break
			}
			name := s[i:nameEnd]
			i = nameEnd + 1 // skip '='

			// PARAM-VALUE (quoted)
			if i >= len(s) || s[i] != '"' {
				break
			}
			i++ // skip opening '"'

			var value strings.Builder
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					// Escaped character: \\, \", \]
					value.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '"' {
					i++ // skip closing '"'
					break
				}
				value.WriteByte(s[i])
				i++
			}
			params[name] = value.String()
		}

		if i < len(s) && s[i] == ']' {
			i++ // skip ']'
		}
		sd[sdID] = params
	}

	// Skip BOM or space before MSG
	if i < len(s) && s[i] == ' ' {
		i++
	}
	// Skip UTF-8 BOM if present (0xEF 0xBB 0xBF)
	if i+2 < len(s) && s[i] == '\xef' && s[i+1] == '\xbb' && s[i+2] == '\xbf' {
		i += 3
	}

	return i, sd
}
