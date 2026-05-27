package publisher

// kafka.go — converts a Parsed syslog message to a NormalizedEvent and publishes to Kafka.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/services/syslog/internal/parser"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// Publisher writes normalized syslog events to Kafka.
type Publisher struct {
	writer *kafka.Writer
	logger zerolog.Logger
}

// NewPublisher creates a new Kafka publisher for syslog events.
func NewPublisher(brokers []string, topic string, logger zerolog.Logger) *Publisher {
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		BatchTimeout: 10 * time.Millisecond,
		BatchSize:    100,
		RequiredAcks: kafka.RequireOne,
		Async:        true,
		ErrorLogger:  kafka.LoggerFunc(func(msg string, args ...any) { logger.Error().Msgf(msg, args...) }),
	}
	return &Publisher{writer: w, logger: logger}
}

// Publish converts a parsed syslog message to a NormalizedEvent and writes it to Kafka.
func (p *Publisher) Publish(ctx context.Context, parsed *parser.Parsed, sourceIP string, tenantID string) error {
	ne := toNormalizedEvent(parsed, sourceIP, tenantID)

	payload, err := json.Marshal(ne)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return p.writer.WriteMessages(ctx, kafka.Message{
		Key:   []byte(ne.EventID.String()),
		Value: payload,
		Headers: []kafka.Header{
			{Key: "tenant_id", Value: []byte(tenantID)},
			{Key: "source", Value: []byte("syslog-connector")},
			{Key: "format", Value: []byte(string(parsed.Format))},
		},
	})
}

// Close gracefully shuts down the Kafka writer.
func (p *Publisher) Close() error {
	return p.writer.Close()
}

// toNormalizedEvent maps a Parsed syslog message to the CRP NormalizedEvent schema.
func toNormalizedEvent(p *parser.Parsed, sourceIP string, tenantID string) *event.NormalizedEvent {
	now := time.Now().UTC()
	ts := p.Timestamp
	if ts.IsZero() {
		ts = now
	}

	ne := &event.NormalizedEvent{
		EventID:       uuid.New(),
		TenantID:      tenantID,
		Timestamp:     ts,
		IngestedAt:    now,
		SchemaVersion: 1,
		ConnectorID:   "syslog-connector",
		Source:        coalesce(p.Hostname, sourceIP, "unknown"),
		SourceType:    inferSourceType(p),
		Category:      mapFacilityToCategory(p.Facility),
		Severity:      mapSyslogSeverity(p.Severity),
		Outcome:       event.OutcomeUnknown,
		Action:        buildAction(p),
		IOCMatched:    []string{},
	}

	// Hostname → AssetHostname
	if p.Hostname != "" {
		ne.AssetHostname = &p.Hostname
	}

	// Source IP
	if sourceIP != "" {
		ne.IPSource = &sourceIP
	}

	// CEF-specific enrichment
	if p.Format == parser.FormatCEFSyslog && p.CEFExtensions != nil {
		ext := p.CEFExtensions

		if src := ext["src"]; src != "" {
			ne.IPSource = &src
		}
		if dst := ext["dst"]; dst != "" {
			ne.IPDestination = &dst
		}
		if user := coalesce(ext["suser"], ext["duser"]); user != "" {
			ne.UserName = &user
		}
		if dhost := ext["dhost"]; dhost != "" {
			ne.AssetHostname = &dhost
		}
		if outcome := ext["outcome"]; outcome != "" {
			ne.Outcome = mapOutcomeStr(outcome)
		}
	}

	// RFC 5424 structured data enrichment
	if p.Format == parser.FormatRFC5424 && p.StructuredData != nil {
		for _, params := range p.StructuredData {
			if src, ok := params["src"]; ok && ne.IPSource == nil {
				ne.IPSource = &src
			}
			if user, ok := params["user"]; ok && ne.UserName == nil {
				ne.UserName = &user
			}
		}
	}

	// App name → tag the source type
	if p.AppName != "" {
		ne.SourceType = coalesce(inferAppSourceType(p.AppName), ne.SourceType)
	}

	// Raw payload
	ne.RawEvent = buildRawRepresentation(p)

	return ne
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func mapFacilityToCategory(fac int) event.Category {
	switch fac {
	case parser.FacAuth, parser.FacAuthpriv:
		return event.CategoryIAM
	case parser.FacKernel, parser.FacDaemon:
		return event.CategorySecurity
	case parser.FacLocal0, 17, 18, 19, 20, 21, 22, 23: // local0-7
		return event.CategorySecurity
	default:
		return event.CategoryOther
	}
}

func mapSyslogSeverity(sev int) event.Severity {
	switch sev {
	case parser.SevEmergency, parser.SevAlert, parser.SevCritical:
		return event.SeverityCritical
	case parser.SevError:
		return event.SeverityHigh
	case parser.SevWarning:
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

func mapOutcomeStr(s string) event.Outcome {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "success", "allow", "allowed", "permit", "0":
		return event.OutcomeSuccess
	case "failure", "fail", "deny", "denied", "block", "blocked":
		return event.OutcomeFailure
	default:
		return event.OutcomeUnknown
	}
}

func buildAction(p *parser.Parsed) string {
	if p.Format == parser.FormatCEFSyslog && p.CEFName != "" {
		return p.CEFName
	}
	if p.AppName != "" && p.Message != "" {
		return p.AppName + ": " + truncate(p.Message, 256)
	}
	return truncate(p.Message, 256)
}

// inferSourceType guesses the source type from the app name or CEF product.
func inferSourceType(p *parser.Parsed) string {
	if p.Format == parser.FormatCEFSyslog {
		prod := strings.ToLower(p.CEFProduct)
		switch {
		case strings.Contains(prod, "firewall") || strings.Contains(prod, "fortigate") || strings.Contains(prod, "palo"):
			return "firewall"
		case strings.Contains(prod, "ids") || strings.Contains(prod, "ips") || strings.Contains(prod, "snort") || strings.Contains(prod, "suricata"):
			return "ids"
		case strings.Contains(prod, "proxy") || strings.Contains(prod, "bluecoat") || strings.Contains(prod, "squid"):
			return "proxy"
		case strings.Contains(prod, "edr") || strings.Contains(prod, "endpoint") || strings.Contains(prod, "crowdstrike") || strings.Contains(prod, "sentinel"):
			return "edr"
		case strings.Contains(prod, "dlp"):
			return "dlp"
		case strings.Contains(prod, "pam") || strings.Contains(prod, "cyberark") || strings.Contains(prod, "vault"):
			return "pam"
		}
	}
	return inferAppSourceType(p.AppName)
}

func inferAppSourceType(appName string) string {
	app := strings.ToLower(appName)
	switch {
	case app == "sshd" || app == "su" || app == "sudo" || strings.Contains(app, "pam"):
		return "iam"
	case strings.Contains(app, "nginx") || strings.Contains(app, "apache") || strings.Contains(app, "httpd"):
		return "web"
	case strings.Contains(app, "postfix") || strings.Contains(app, "sendmail") || strings.Contains(app, "dovecot"):
		return "mail"
	case strings.Contains(app, "cron"):
		return "scheduler"
	case strings.Contains(app, "kernel"):
		return "os"
	default:
		return "syslog"
	}
}

func buildRawRepresentation(p *parser.Parsed) string {
	if p.Format == parser.FormatCEFSyslog {
		return fmt.Sprintf("[%s] %s|%s", p.Format, p.CEFVendor, p.CEFName)
	}
	return p.Message
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
