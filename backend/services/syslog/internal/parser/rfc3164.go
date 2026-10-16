package parser

// RFC 3164 — The BSD Syslog Protocol
// Format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
//
// Examples:
//   <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
//   <13>Feb  5 17:32:18 10.0.0.99 Use the BFG!

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// rfc3164Months maps abbreviated month names to their numeric value.
var rfc3164Months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// parseRFC3164 parses an RFC 3164 syslog message.
// It returns a Parsed struct and the detected priority/facility/severity integers.
func parseRFC3164(line string, defaultHostname string) (*Parsed, error) {
	p := &Parsed{Format: FormatRFC3164}

	// ─── Priority ───────────────────────────────────────────
	if len(line) < 3 || line[0] != '<' {
		// No PRI — treat the whole line as MSG
		p.Hostname = defaultHostname
		p.Message = line
		p.Severity = SevNotice
		return p, nil
	}
	priEnd := strings.Index(line, ">")
	if priEnd < 2 {
		return nil, fmt.Errorf("rfc3164: malformed PRI")
	}
	pri, err := strconv.Atoi(line[1:priEnd])
	if err != nil {
		return nil, fmt.Errorf("rfc3164: invalid PRI %q", line[1:priEnd])
	}
	p.Priority = pri
	p.Facility = pri >> 3
	p.Severity = pri & 0x07

	rest := line[priEnd+1:]

	// ─── Timestamp (RFC 3164: "Mmm dd hh:mm:ss") ────────────
	// Month is 3 chars, day is 2 chars (space-padded), time is 8 chars → total 15
	if len(rest) >= 16 {
		monthStr := rest[0:3]
		if _, ok := rfc3164Months[monthStr]; ok {
			tsStr := rest[0:15]
			rest = strings.TrimLeft(rest[15:], " ")

			now := time.Now()
			month := rfc3164Months[monthStr]
			day := 0
			hour, min, sec := 0, 0, 0
			fmt.Sscanf(tsStr[4:6], "%d", &day)
			fmt.Sscanf(tsStr[7:9], "%d", &hour)
			fmt.Sscanf(tsStr[10:12], "%d", &min)
			fmt.Sscanf(tsStr[13:15], "%d", &sec)

			p.Timestamp = time.Date(now.Year(), month, day, hour, min, sec, 0, time.UTC)
			// Handle year wrap: if parsed timestamp is more than 30 days in the future, subtract 1 year
			if p.Timestamp.After(now.Add(30 * 24 * time.Hour)) {
				p.Timestamp = p.Timestamp.AddDate(-1, 0, 0)
			}
		}
	}

	// ─── Hostname ────────────────────────────────────────────
	if idx := strings.IndexByte(rest, ' '); idx > 0 {
		p.Hostname = rest[:idx]
		rest = rest[idx+1:]
	} else {
		p.Hostname = defaultHostname
	}

	// ─── Tag (PROCESS[PID]: ) ────────────────────────────────
	// '[' must not terminate the tag: the PID is part of it, and stopping at
	// the bracket left ProcID empty and prefixed the message with "[1234]: ".
	if idx := strings.IndexAny(rest, ": "); idx > 0 {
		tag := rest[:idx]
		rest = rest[idx:]

		// Extract PID from tag[pid]
		if pidStart := strings.IndexByte(tag, '['); pidStart > 0 {
			if pidEnd := strings.IndexByte(tag, ']'); pidEnd > pidStart {
				p.ProcID = tag[pidStart+1 : pidEnd]
				tag = tag[:pidStart]
			}
		}
		p.AppName = tag

		// Skip ": " separator
		if strings.HasPrefix(rest, ": ") {
			rest = rest[2:]
		} else if strings.HasPrefix(rest, ":") {
			rest = rest[1:]
		}
	}

	p.Message = strings.TrimSpace(rest)
	return p, nil
}
