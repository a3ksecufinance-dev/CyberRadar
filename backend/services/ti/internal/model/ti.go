package model

import (
	"time"

	"github.com/google/uuid"
)

// IOC types
const (
	IOCTypeIP         = "ip"
	IOCTypeDomain     = "domain"
	IOCTypeURL        = "url"
	IOCTypeHashMD5    = "hash_md5"
	IOCTypeHashSHA1   = "hash_sha1"
	IOCTypeHashSHA256 = "hash_sha256"
	IOCTypeEmail      = "email"
	IOCTypeCVE        = "cve"
	IOCTypeASN        = "asn"
)

// Feed types
const (
	FeedTypeSTIX     = "stix"
	FeedTypeTAXII    = "taxii"
	FeedTypeMISP     = "misp"
	FeedTypeCSV      = "csv"
	FeedTypeInternal = "internal"
)

// TLP levels (Traffic Light Protocol)
const (
	TLPWhite = 0
	TLPGreen = 1
	TLPAmber = 2
	TLPRed   = 3
	TLPBlack = 4
)

// Threat actor motivations
const (
	MotivationFinancial   = "financial"
	MotivationEspionage   = "espionage"
	MotivationHacktivism  = "hacktivism"
	MotivationDisruption  = "disruption"
)

// Feed is a configured threat intelligence source.
type Feed struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	FeedType       string     `json:"feed_type"`
	URL            string     `json:"url,omitempty"`
	ApiKeyRef      string     `json:"api_key_ref,omitempty"`  // Vault path
	CollectionID   string     `json:"collection_id,omitempty"`
	PollIntervalS  int        `json:"poll_interval_s"`
	Enabled        bool       `json:"enabled"`
	TLP            int        `json:"tlp"`
	Confidence     int        `json:"confidence"`
	LastPolledAt   *time.Time `json:"last_polled_at,omitempty"`
	LastIOCCount   int        `json:"last_ioc_count"`
	ErrorCount     int        `json:"error_count"`
	LastError      string     `json:"last_error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// IOC is a single indicator of compromise.
type IOC struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	FeedID         *uuid.UUID `json:"feed_id,omitempty"`
	IOCType        string     `json:"ioc_type"`
	Value          string     `json:"value"`
	Normalized     string     `json:"normalized"`
	TLP            int        `json:"tlp"`
	Confidence     int        `json:"confidence"`
	Severity       string     `json:"severity"`
	IsActive       bool       `json:"is_active"`
	MitreTactic    string     `json:"mitre_tactic,omitempty"`
	MitreTechnique string     `json:"mitre_technique,omitempty"`
	ThreatActor    string     `json:"threat_actor,omitempty"`
	MalwareFamily  string     `json:"malware_family,omitempty"`
	Campaign       string     `json:"campaign,omitempty"`
	ValidFrom      time.Time  `json:"valid_from"`
	ValidUntil     *time.Time `json:"valid_until,omitempty"`
	HitCount       int        `json:"hit_count"`
	LastHitAt      *time.Time `json:"last_hit_at,omitempty"`
	ExternalID     string     `json:"external_id,omitempty"`
	StixID         string     `json:"stix_id,omitempty"`
	Tags           []string   `json:"tags"`
	Description    string     `json:"description,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ThreatActor is a known threat group or individual.
type ThreatActor struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	Name            string     `json:"name"`
	Aliases         []string   `json:"aliases"`
	Description     string     `json:"description,omitempty"`
	Motivation      string     `json:"motivation,omitempty"`
	Sophistication  string     `json:"sophistication"`
	OriginCountry   string     `json:"origin_country,omitempty"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	MitreGroups     []string   `json:"mitre_groups"`
	TTPs            []string   `json:"ttps"`
	TargetsCBS      bool       `json:"targets_cbs"`
	TargetsSWIFT    bool       `json:"targets_swift"`
	TargetsATM      bool       `json:"targets_atm"`
	StixID          string     `json:"stix_id,omitempty"`
	Tags            []string   `json:"tags"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// IOCHit records a single IOC match event.
type IOCHit struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	IOCID         uuid.UUID  `json:"ioc_id"`
	SourceEventID *uuid.UUID `json:"source_event_id,omitempty"`
	AlertID       *uuid.UUID `json:"alert_id,omitempty"`
	MatchedValue  string     `json:"matched_value"`
	MatchedField  string     `json:"matched_field"`
	Severity      string     `json:"severity"`
	AutoBlocked   bool       `json:"auto_blocked"`
	HitAt         time.Time  `json:"hit_at"`
}

// MatchResult is returned by the IOC lookup API.
type MatchResult struct {
	Matched bool   `json:"matched"`
	IOC     *IOC   `json:"ioc,omitempty"`
	HitID   string `json:"hit_id,omitempty"`
}

// TIStats is the dashboard summary.
type TIStats struct {
	TotalIOCs      int            `json:"total_iocs"`
	ActiveIOCs     int            `json:"active_iocs"`
	TotalFeeds     int            `json:"total_feeds"`
	EnabledFeeds   int            `json:"enabled_feeds"`
	HitsLast24h    int            `json:"hits_last_24h"`
	HitsLast7d     int            `json:"hits_last_7d"`
	ByType         map[string]int `json:"by_type"`
	BySeverity     map[string]int `json:"by_severity"`
	TopIOCs        []*IOC         `json:"top_iocs"`
	ThreatActors   int            `json:"threat_actors"`
	BankingThreats int            `json:"banking_threats"`
}

// ─── Request / filter models ──────────────────────────────────────────────────

type IOCFilter struct {
	TenantID  uuid.UUID
	IOCType   string
	Severity  string
	FeedID    *uuid.UUID
	IsActive  *bool
	Search    string
	Limit     int
	Offset    int
}

type CreateFeedRequest struct {
	Name          string `json:"name"            validate:"required,min=2,max=100"`
	Description   string `json:"description"`
	FeedType      string `json:"feed_type"       validate:"required,oneof=stix taxii misp csv internal"`
	URL           string `json:"url"`
	ApiKeyRef     string `json:"api_key_ref"`
	CollectionID  string `json:"collection_id"`
	PollIntervalS int    `json:"poll_interval_s"`
	TLP           int    `json:"tlp"             validate:"min=0,max=4"`
	Confidence    int    `json:"confidence"      validate:"min=0,max=100"`
}

type UpdateFeedRequest struct {
	Enabled       *bool   `json:"enabled"`
	PollIntervalS *int    `json:"poll_interval_s"`
	Confidence    *int    `json:"confidence"  validate:"omitempty,min=0,max=100"`
	Description   *string `json:"description"`
}

type CreateIOCRequest struct {
	IOCType        string     `json:"ioc_type"   validate:"required,oneof=ip domain url hash_md5 hash_sha1 hash_sha256 email cve asn"`
	Value          string     `json:"value"      validate:"required"`
	FeedID         *uuid.UUID `json:"feed_id"`
	TLP            int        `json:"tlp"        validate:"min=0,max=4"`
	Confidence     int        `json:"confidence" validate:"min=0,max=100"`
	Severity       string     `json:"severity"   validate:"omitempty,oneof=CRITICAL HIGH MEDIUM LOW INFO"`
	MitreTactic    string     `json:"mitre_tactic"`
	MitreTechnique string     `json:"mitre_technique"`
	ThreatActor    string     `json:"threat_actor"`
	MalwareFamily  string     `json:"malware_family"`
	Campaign       string     `json:"campaign"`
	ValidUntil     *time.Time `json:"valid_until"`
	Tags           []string   `json:"tags"`
	Description    string     `json:"description"`
	ExternalID     string     `json:"external_id"`
	StixID         string     `json:"stix_id"`
}

type BulkCreateIOCRequest struct {
	FeedID *uuid.UUID         `json:"feed_id"`
	IOCs   []CreateIOCRequest `json:"iocs" validate:"required,min=1,max=10000"`
}

type LookupRequest struct {
	Type  string `json:"type"  validate:"required,oneof=ip domain url hash_md5 hash_sha1 hash_sha256 email cve asn"`
	Value string `json:"value" validate:"required"`
}

type CreateThreatActorRequest struct {
	Name           string   `json:"name"           validate:"required,min=2,max=100"`
	Aliases        []string `json:"aliases"`
	Description    string   `json:"description"`
	Motivation     string   `json:"motivation"     validate:"omitempty,oneof=financial espionage hacktivism disruption"`
	Sophistication string   `json:"sophistication" validate:"omitempty,oneof=minimal low medium high advanced"`
	OriginCountry  string   `json:"origin_country"`
	MitreGroups    []string `json:"mitre_groups"`
	TTPs           []string `json:"ttps"`
	TargetsCBS     bool     `json:"targets_cbs"`
	TargetsSWIFT   bool     `json:"targets_swift"`
	TargetsATM     bool     `json:"targets_atm"`
	Tags           []string `json:"tags"`
	StixID         string   `json:"stix_id"`
}
