package parser

import (
	"strings"
	"testing"
	"time"
)

// The RFC 5424 §6.5 and RFC 3164 §5.4 examples are normative, so they are used
// here in preference to messages invented for the test.

func TestDetect(t *testing.T) {
	cases := map[string]struct {
		line string
		want SyslogFormat
	}{
		"rfc5424 with version digit": {
			`<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - msg`, FormatRFC5424},
		"rfc3164 timestamp after pri": {
			`<34>Oct 11 22:14:15 mymachine su: failed`, FormatRFC3164},
		"cef wrapped in syslog": {
			`<34>Oct 11 22:14:15 host CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1`, FormatCEFSyslog},
		"bare cef": {
			`CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1`, FormatCEFSyslog},
		"no pri at all": {
			`plain text line`, FormatRFC3164},
		"malformed pri bracket": {
			`<>1 2003-10-11T22:14:15.003Z h a - - - m`, FormatUnknown},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := detect(c.line); got != c.want {
				t.Errorf("detect(%q) = %s, want %s", c.line, got, c.want)
			}
		})
	}
}

func TestPriorityDecoding(t *testing.T) {
	// PRI = facility*8 + severity (RFC 5424 §6.2.1)
	cases := []struct {
		pri             int
		facility, sever int
		line            string
	}{
		{34, 4, 2, `<34>1 2003-10-11T22:14:15.003Z mymachine su - ID47 - msg`},
		{165, 20, 5, `<165>1 2003-10-11T22:14:15.003Z mymachine evntslog - ID47 - msg`},
		{0, 0, 0, `<0>1 2003-10-11T22:14:15.003Z mymachine x - - - msg`},
		{191, 23, 7, `<191>1 2003-10-11T22:14:15.003Z mymachine x - - - msg`},
	}

	for _, c := range cases {
		p, err := Parse([]byte(c.line), "fallback")
		if err != nil {
			t.Fatalf("PRI %d: %v", c.pri, err)
		}
		if p.Priority != c.pri || p.Facility != c.facility || p.Severity != c.sever {
			t.Errorf("PRI %d: got priority=%d facility=%d severity=%d, want %d/%d/%d",
				c.pri, p.Priority, p.Facility, p.Severity, c.pri, c.facility, c.sever)
		}
	}
}

func TestRFC5424Example1(t *testing.T) {
	line := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Format != FormatRFC5424 {
		t.Errorf("Format = %s, want %s", p.Format, FormatRFC5424)
	}
	if p.Hostname != "mymachine.example.com" {
		t.Errorf("Hostname = %q", p.Hostname)
	}
	if p.AppName != "su" {
		t.Errorf("AppName = %q, want su", p.AppName)
	}
	if p.ProcID != "" {
		t.Errorf("ProcID = %q, want empty (NILVALUE)", p.ProcID)
	}
	if p.MsgID != "ID47" {
		t.Errorf("MsgID = %q, want ID47", p.MsgID)
	}
	want := time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC)
	if !p.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %s, want %s", p.Timestamp, want)
	}
	if p.Message != `'su root' failed for lonvick on /dev/pts/8` {
		t.Errorf("Message = %q", p.Message)
	}
}

func TestRFC5424StructuredData(t *testing.T) {
	line := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 ` +
		`[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sd, ok := p.StructuredData["exampleSDID@32473"]
	if !ok {
		t.Fatalf("SD element missing, got %v", p.StructuredData)
	}
	for k, want := range map[string]string{"iut": "3", "eventSource": "Application", "eventID": "1011"} {
		if sd[k] != want {
			t.Errorf("SD[%s] = %q, want %q", k, sd[k], want)
		}
	}
	if p.Message != "An application event log entry" {
		t.Errorf("Message = %q", p.Message)
	}
}

func TestRFC5424MultipleSDElements(t *testing.T) {
	line := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 ` +
		`[exampleSDID@32473 iut="3"][examplePriority@32473 class="high"] msg here`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.StructuredData) != 2 {
		t.Fatalf("got %d SD elements, want 2: %v", len(p.StructuredData), p.StructuredData)
	}
	if p.StructuredData["examplePriority@32473"]["class"] != "high" {
		t.Errorf("second SD element not parsed: %v", p.StructuredData)
	}
	if p.Message != "msg here" {
		t.Errorf("Message = %q, want %q", p.Message, "msg here")
	}
}

func TestRFC5424EscapedSDValue(t *testing.T) {
	// RFC 5424 §6.3.3: ", \ and ] are escaped inside PARAM-VALUE.
	line := `<165>1 2003-10-11T22:14:15.003Z h app - - [id@1 k="a\"b\]c\\d"] msg`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := p.StructuredData["id@1"]["k"], `a"b]c\d`; got != want {
		t.Errorf("escaped value = %q, want %q", got, want)
	}
}

func TestRFC5424NilValues(t *testing.T) {
	line := `<34>1 - - - - - - message body`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Timestamp.IsZero() {
		t.Errorf("Timestamp = %s, want zero for NILVALUE", p.Timestamp)
	}
	if p.Hostname != "" || p.AppName != "" || p.ProcID != "" || p.MsgID != "" {
		t.Errorf("NILVALUE fields not empty: host=%q app=%q proc=%q msgid=%q",
			p.Hostname, p.AppName, p.ProcID, p.MsgID)
	}
}

func TestRFC3164Example(t *testing.T) {
	line := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Format != FormatRFC3164 {
		t.Errorf("Format = %s", p.Format)
	}
	if p.Hostname != "mymachine" {
		t.Errorf("Hostname = %q, want mymachine", p.Hostname)
	}
	if p.AppName != "su" {
		t.Errorf("AppName = %q, want su", p.AppName)
	}
	if p.Message != `'su root' failed for lonvick on /dev/pts/8` {
		t.Errorf("Message = %q", p.Message)
	}
	if p.Timestamp.Month() != time.October || p.Timestamp.Day() != 11 ||
		p.Timestamp.Hour() != 22 || p.Timestamp.Minute() != 14 || p.Timestamp.Second() != 15 {
		t.Errorf("Timestamp = %s, want Oct 11 22:14:15", p.Timestamp)
	}
}

func TestRFC3164TagWithPID(t *testing.T) {
	line := `<34>Oct 11 22:14:15 mymachine sshd[1234]: Accepted publickey for root`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.AppName != "sshd" {
		t.Errorf("AppName = %q, want sshd", p.AppName)
	}
	if p.ProcID != "1234" {
		t.Errorf("ProcID = %q, want 1234", p.ProcID)
	}
	if p.Message != "Accepted publickey for root" {
		t.Errorf("Message = %q", p.Message)
	}
}

func TestRFC3164SpacePaddedDay(t *testing.T) {
	// RFC 3164 §4.1.2: single-digit days are space-padded, e.g. "Feb  5".
	line := `<13>Feb  5 17:32:18 10.0.0.99 app: Use the BFG!`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Timestamp.Month() != time.February || p.Timestamp.Day() != 5 {
		t.Errorf("Timestamp = %s, want Feb 5", p.Timestamp)
	}
	if p.Hostname != "10.0.0.99" {
		t.Errorf("Hostname = %q, want 10.0.0.99", p.Hostname)
	}
}

func TestRFC3164NoPRIFallsBackToDefaults(t *testing.T) {
	p, err := Parse([]byte("just a bare line"), "fallback-host")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Hostname != "fallback-host" {
		t.Errorf("Hostname = %q, want the supplied default", p.Hostname)
	}
	if p.Message != "just a bare line" {
		t.Errorf("Message = %q", p.Message)
	}
	if p.Severity != SevNotice {
		t.Errorf("Severity = %d, want %d", p.Severity, SevNotice)
	}
}

func TestParseTrimsTransportFraming(t *testing.T) {
	// Framing leftovers must not end up in the message body.
	for _, suffix := range []string{"\n", "\r\n", "\x00"} {
		p, err := Parse([]byte(`<34>Oct 11 22:14:15 h su: body`+suffix), "fallback")
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if p.Message != "body" {
			t.Errorf("suffix %q: Message = %q, want %q", suffix, p.Message, "body")
		}
	}
}

func TestCEFOverSyslog(t *testing.T) {
	line := `<34>Oct 11 22:14:15 gw CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`

	p, err := Parse([]byte(line), "fallback")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Format != FormatCEFSyslog {
		t.Fatalf("Format = %s, want %s", p.Format, FormatCEFSyslog)
	}
	if p.CEFVendor != "Security" {
		t.Errorf("CEFVendor = %q, want Security", p.CEFVendor)
	}
	if p.CEFProduct != "threatmanager" {
		t.Errorf("CEFProduct = %q, want threatmanager", p.CEFProduct)
	}
	if p.CEFSignatureID != "100" {
		t.Errorf("CEFSignatureID = %q, want 100", p.CEFSignatureID)
	}
	if p.CEFName != "worm successfully stopped" {
		t.Errorf("CEFName = %q", p.CEFName)
	}
	for k, want := range map[string]string{"src": "10.0.0.1", "dst": "2.1.2.2", "spt": "1232"} {
		if p.CEFExtensions[k] != want {
			t.Errorf("CEF extension %s = %q, want %q", k, p.CEFExtensions[k], want)
		}
	}
}

func TestParseNeverPanics(t *testing.T) {
	// A syslog listener takes bytes straight off the network: malformed input
	// must return an error, never take the process down.
	inputs := []string{
		"", "<", "<>", "<34", "<34>", "<999999999999999999999>x",
		"<34>1", "<34>1 ", "<165>1 - - - - - [", `<165>1 - - - - - [id@1 k="`,
		"CEF:", "CEF:0|", "CEF:0|a|b|c|d|e|f|", strings.Repeat("A", 70000),
		"<34>Oct 11 22:14:15", "<-1>x", "<34>\x00\x00\x00",
	}

	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Parse(%q) panicked: %v", in, r)
				}
			}()
			_, _ = Parse([]byte(in), "fallback")
		}()
	}
}
