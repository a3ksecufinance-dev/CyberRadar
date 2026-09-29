package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// ─── Threat intelligence ──────────────────────────────────────────────────────

var demoActors = []map[string]any{
	{
		"name": "Lazarus Group", "aliases": []string{"HIDDEN COBRA", "APT38", "Diamond Sleet"},
		"description": "Acteur étatique, connu pour le détournement de virements SWIFT et le vol d'actifs numériques.",
		"motivation":  "financial", "sophistication": "advanced", "origin_country": "KP",
		"mitre_groups": []string{"G0032", "G0082"},
		"ttps":         []string{"T1566.001", "T1059.003", "T1486", "T1071.001"},
		"targets_cbs":  true, "targets_swift": true, "targets_atm": true,
		"tags": []string{"demo", "apt", "swift"},
	},
	{
		"name": "FIN7", "aliases": []string{"Carbanak", "Sangria Tempest"},
		"description": "Groupe criminel spécialisé dans la monétique et les systèmes de paiement.",
		"motivation":  "financial", "sophistication": "high", "origin_country": "RU",
		"mitre_groups": []string{"G0046"},
		"ttps":         []string{"T1566.002", "T1204.002", "T1055", "T1005"},
		"targets_cbs":  true, "targets_swift": false, "targets_atm": true,
		"tags": []string{"demo", "ecrime", "monetique"},
	},
	{
		"name": "TA505", "aliases": []string{"Hive0065", "Spandex Tempest"},
		"description": "Distributeur de chargeurs et de rançongiciels, point d'entrée fréquent des incidents bancaires.",
		"motivation":  "financial", "sophistication": "high", "origin_country": "RU",
		"mitre_groups": []string{"G0092"},
		"ttps":         []string{"T1566.001", "T1204.002", "T1486"},
		"targets_cbs":  false, "targets_swift": false, "targets_atm": false,
		"tags": []string{"demo", "ecrime", "ransomware"},
	},
}

type demoIOC struct {
	Type       string
	Value      string
	Severity   string
	Confidence int
	Actor      string
	Malware    string
	Campaign   string
	Tactic     string
	Technique  string
	Note       string
}

// The addresses are documentation ranges (RFC 5737) and the domains are
// reserved for examples (RFC 2606). A demonstration dataset must not name a
// third party as hostile, and must never be mistaken for a live blocklist.
var demoIOCs = []demoIOC{
	{"ip", "198.51.100.23", "CRITICAL", 92, "Lazarus Group", "AppleJeus", "Hidden Cobra 2026", "command-and-control", "T1071.001", "Serveur de commande observé après compromission de la passerelle SWIFT."},
	{"ip", "198.51.100.77", "HIGH", 85, "FIN7", "Carbanak", "Monétique FR", "command-and-control", "T1071.001", "Balise HTTPS depuis le réseau monétique."},
	{"ip", "203.0.113.66", "HIGH", 78, "TA505", "Get2", "", "initial-access", "T1190", "Scan massif du portail VPN."},
	{"ip", "192.0.2.155", "MEDIUM", 60, "", "", "", "discovery", "T1046", "Balayage de ports sortant vers la DMZ."},
	{"domain", "update-swift-secure.example", "CRITICAL", 95, "Lazarus Group", "AppleJeus", "Hidden Cobra 2026", "command-and-control", "T1071.001", "Domaine de typosquatting imitant un portail de paiement."},
	{"domain", "cdn-metrics.example.net", "HIGH", 80, "FIN7", "Carbanak", "Monétique FR", "exfiltration", "T1567", "Exfiltration déguisée en télémétrie."},
	{"domain", "invoice-portal.example.org", "MEDIUM", 65, "TA505", "Get2", "", "initial-access", "T1566.002", "Hameçonnage sur le thème de la facturation."},
	{"url", "https://update-swift-secure.example/patch/win32.bin", "CRITICAL", 93, "Lazarus Group", "AppleJeus", "Hidden Cobra 2026", "execution", "T1204.002", "Charge utile de second niveau."},
	{"hash_sha256", "9f2b6c1d5a4e3f8b7c0d9e2a1b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c", "CRITICAL", 90, "Lazarus Group", "AppleJeus", "", "execution", "T1059.003", "Implant déposé sur la passerelle."},
	{"hash_sha256", "1a3c5e7092b4d6f8001a3c5e7092b4d6f8001a3c5e7092b4d6f8001a3c5e7092", "HIGH", 82, "TA505", "Get2", "", "execution", "T1204.002", "Chargeur reçu par courriel."},
	{"email", "tresorerie@invoice-portal.example.org", "HIGH", 75, "TA505", "", "", "initial-access", "T1566.001", "Expéditeur du courriel d'hameçonnage."},
}

func (s *seeder) seedThreatIntel(ctx context.Context) error {
	step("Threat intelligence")

	feeds, err := s.index(ctx, "ti", "/api/v1/ti/feeds")
	if err != nil {
		return err
	}
	feedID, err := s.ensure(ctx, feeds, "Renseignement interne CSIRT", "ti", "/api/v1/ti/feeds", map[string]any{
		"name":        "Renseignement interne CSIRT",
		"description": "Indicateurs produits par le CSIRT de la banque et par ses pairs sectoriels.",
		"feed_type":   "internal",
		"tlp":         2,
		"confidence":  85,
	})
	if err != nil {
		return err
	}

	actors, err := s.index(ctx, "ti", "/api/v1/ti/actors")
	if err != nil {
		return err
	}
	for _, a := range demoActors {
		if _, err := s.ensure(ctx, actors, a["name"].(string), "ti", "/api/v1/ti/actors", a); err != nil {
			return err
		}
	}

	idx, err := s.index(ctx, "ti", "/api/v1/ti/iocs")
	if err != nil {
		return err
	}
	s.iocs = idx

	validUntil := time.Now().UTC().AddDate(0, 6, 0)
	for _, i := range demoIOCs {
		body := map[string]any{
			"ioc_type":        i.Type,
			"value":           i.Value,
			"feed_id":         feedID,
			"tlp":             2,
			"confidence":      i.Confidence,
			"severity":        i.Severity,
			"mitre_tactic":    i.Tactic,
			"mitre_technique": i.Technique,
			"threat_actor":    i.Actor,
			"malware_family":  i.Malware,
			"campaign":        i.Campaign,
			"valid_until":     validUntil,
			"tags":            []string{"demo"},
			"description":     i.Note,
		}
		if _, err := s.ensure(ctx, s.iocs, i.Value, "ti", "/api/v1/ti/iocs", body); err != nil {
			return err
		}
	}

	fmt.Printf("   %d actors, %d indicators on one internal feed\n", len(actors), len(s.iocs))
	return nil
}

// ─── Detection rules ──────────────────────────────────────────────────────────

// The rules are written against the fields the engine actually reads
// (services/siem/internal/service/engine.go, getField). A rule naming a field
// the engine does not know would load, match nothing, and look like a working
// detection — which is worse than no rule at all.
//
// The MITRE fields carry identifiers, not names: detection_rules.mitre_tactic
// is varchar(10), which fits "TA0006" and not "credential-access".
//
// They compare threat_score rather than risk_score because the pipeline
// enricher derives both from the event's severity and overwrites whatever the
// connector sent. A rule keyed on the connector's own risk_score would
// therefore never fire, however plausible it reads.
var demoRules = []map[string]any{
	{
		"name":        "Bourrage d'identifiants sur la banque en ligne",
		"description": "Cinq échecs d'authentification ou plus depuis une même adresse en cinq minutes.",
		"category":    "IAM", "severity": "HIGH",
		"mitre_tactic": "TA0006", "mitre_technique": "T1110.004",
		"dedup_window_s": 300,
		"conditions": map[string]any{
			"field_matches": []map[string]any{
				{"field": "category", "op": "eq", "value": "IAM"},
				{"field": "outcome", "op": "eq", "value": "failure"},
			},
			"threshold": map[string]any{"count": 5, "window_seconds": 300, "group_by": []string{"ip_source"}},
		},
		"actions": []map[string]any{{"type": "notify"}},
	},
	{
		"name":        "Authentification administrateur réussie depuis Internet",
		"description": "Une session privilégiée ouverte depuis une adresse hors du plan d'adressage interne.",
		"category":    "IAM", "severity": "CRITICAL",
		"mitre_tactic": "TA0001", "mitre_technique": "T1078",
		"dedup_window_s": 600,
		"conditions": map[string]any{
			"field_matches": []map[string]any{
				{"field": "action", "op": "contains", "value": "admin_login"},
				{"field": "outcome", "op": "eq", "value": "success"},
			},
		},
		"actions": []map[string]any{{"type": "notify"}, {"type": "create_case"}},
	},
	{
		"name":        "Exécution suspecte sur la passerelle SWIFT",
		"description": "Tout lancement d'interpréteur sur un actif du périmètre SWIFT.",
		"category":    "Security", "severity": "CRITICAL",
		"mitre_tactic": "TA0002", "mitre_technique": "T1059",
		"dedup_window_s": 300,
		"conditions": map[string]any{
			"field_matches": []map[string]any{
				{"field": "action", "op": "contains", "value": "process_exec"},
				{"field": "threat_score", "op": "gte", "value": "8"},
			},
		},
		"actions": []map[string]any{{"type": "notify"}, {"type": "create_case"}},
	},
	{
		"name":        "Contact avec un indicateur de compromission connu",
		"description": "Un flux sortant dont la destination figure au renseignement.",
		"category":    "Network", "severity": "CRITICAL",
		"mitre_tactic": "TA0011", "mitre_technique": "T1071.001",
		"dedup_window_s": 300,
		"conditions": map[string]any{
			"field_matches": []map[string]any{
				{"field": "category", "op": "eq", "value": "Network"},
				{"field": "threat_score", "op": "gte", "value": "6"},
			},
		},
		"actions": []map[string]any{{"type": "notify"}, {"type": "block_ip"}},
	},
	{
		"name":        "Volume de transfert anormal depuis le socle de sauvegarde",
		"description": "Une session dont le score de risque dépasse le seuil d'exfiltration.",
		"category":    "Security", "severity": "HIGH",
		"mitre_tactic": "TA0010", "mitre_technique": "T1567",
		"dedup_window_s": 900,
		"conditions": map[string]any{
			"field_matches": []map[string]any{
				{"field": "action", "op": "contains", "value": "file_transfer"},
				{"field": "threat_score", "op": "gte", "value": "6"},
			},
		},
		"actions": []map[string]any{{"type": "notify"}},
	},
}

func (s *seeder) seedRules(ctx context.Context) error {
	step("Detection rules")
	idx, err := s.index(ctx, "siem", "/api/v1/siem/rules")
	if err != nil {
		return err
	}
	for _, r := range demoRules {
		if _, err := s.ensure(ctx, idx, r["name"].(string), "siem", "/api/v1/siem/rules", r); err != nil {
			return err
		}
	}
	fmt.Printf("   %d rules loaded in the engine\n", len(idx))
	return nil
}

// ─── Events ───────────────────────────────────────────────────────────────────

// seedEvents feeds the pipeline rather than writing alerts.
//
// There is no endpoint that creates an alert, and that is the right design:
// an alert is what the rule engine concluded, not something a client asserts.
// So the demonstration sends the events a connector would send, and the alerts
// on screen are alerts this platform decided to raise — which is the thing
// worth demonstrating.
func (s *seeder) seedEvents(ctx context.Context) error {
	step("Events through the pipeline")

	// The ingest endpoint validates connector_id as a version-4 UUID, so a
	// name-derived one (version 5) is refused. It is lineage, not a key, so a
	// fixed literal keeps every run attributable to the same connector.
	const connector = "d3f4a1c2-5b6e-4f7a-9c8d-1e2f3a4b5c6d"
	now := time.Now().UTC()

	var events []string

	// 1. Credential stuffing: eight failures from one address, inside the
	//    five-minute window the rule declares.
	for i := 0; i < 8; i++ {
		events = append(events, jsonEventLine(map[string]any{
			"timestamp": now.Add(time.Duration(-i*20) * time.Second).Format(time.RFC3339),
			"action":    "user_login", "category": "authentication", "severity": "MEDIUM",
			"outcome": "failure", "user_name": "m.durand", "user_email": "m.durand@bnf.fr",
			"hostname": "web-ebank-01.bnf.fr", "asset_type": "server",
			"src_ip": "203.0.113.66", "dst_ip": "10.20.1.11", "dst_port": 443,
			"risk_score": 4.5,
		}))
	}

	// 2. A privileged session opened from outside.
	events = append(events, jsonEventLine(map[string]any{
		"timestamp": now.Add(-3 * time.Minute).Format(time.RFC3339),
		"action":    "admin_login", "category": "authentication", "severity": "HIGH",
		"outcome": "success", "user_name": "svc-admin", "user_email": "svc-admin@bnf.fr",
		"hostname": "jump-adm-01.bnf.fr", "asset_type": "server",
		"src_ip": "198.51.100.23", "dst_ip": "10.10.0.50", "dst_port": 3389,
		"risk_score": 8.7,
	}))

	// 3. Outbound traffic to an address the feed carries.
	for i := 0; i < 3; i++ {
		events = append(events, jsonEventLine(map[string]any{
			"timestamp": now.Add(time.Duration(-i*90) * time.Second).Format(time.RFC3339),
			"action":    "network_connection", "category": "network", "severity": "HIGH",
			"outcome": "success", "hostname": "swift-gw-01.bnf.fr", "asset_type": "server",
			"src_ip": "10.40.3.41", "dst_ip": "198.51.100.23", "dst_port": 443,
			"risk_score": 9.1,
		}))
	}

	// 4. An interpreter launched on the SWIFT gateway.
	events = append(events, jsonEventLine(map[string]any{
		"timestamp": now.Add(-6 * time.Minute).Format(time.RFC3339),
		"action":    "process_exec powershell.exe -enc", "category": "security", "severity": "CRITICAL",
		"outcome": "success", "user_name": "svc-swift", "hostname": "swift-gw-01.bnf.fr",
		"asset_type": "server", "src_ip": "10.40.3.41", "risk_score": 9.4,
	}))

	// 5. A transfer out of the backup estate.
	events = append(events, jsonEventLine(map[string]any{
		"timestamp": now.Add(-12 * time.Minute).Format(time.RFC3339),
		"action":    "file_transfer outbound 42GB", "category": "security", "severity": "HIGH",
		"outcome": "success", "user_name": "svc-backup", "hostname": "backup-nas-01.bnf.fr",
		"asset_type": "storage", "src_ip": "10.10.0.90", "dst_ip": "198.51.100.77",
		"dst_port": 443, "risk_score": 8.2,
	}))

	// 6. Ordinary traffic, so the estate is not made of nothing but alerts.
	for i := 0; i < 25; i++ {
		events = append(events, jsonEventLine(map[string]any{
			"timestamp": now.Add(time.Duration(-i*40) * time.Second).Format(time.RFC3339),
			"action":    "user_login", "category": "authentication", "severity": "LOW",
			"outcome": "success", "user_name": fmt.Sprintf("agent%02d", i%7),
			"hostname": "web-ebank-02.bnf.fr", "asset_type": "server",
			"src_ip": fmt.Sprintf("10.60.5.%d", 20+i%30), "dst_ip": "10.20.1.12",
			"dst_port": 443, "risk_score": 1.0,
		}))
	}

	agent, err := s.connectorClient(ctx)
	if err != nil {
		return err
	}

	var result struct {
		Received  int      `json:"received"`
		Published int      `json:"published"`
		Failed    int      `json:"failed"`
		Errors    []string `json:"errors"`
	}
	err = agent.post(ctx, "collector", "/api/v1/events/ingest", map[string]any{
		"connector_id": connector,
		"source":       "demo-connector",
		"source_type":  "application",
		"format":       "json",
		"events":       events,
	}, &result)
	if err != nil {
		return err
	}
	if result.Failed > 0 {
		return fmt.Errorf("%d of %d events were rejected: %v", result.Failed, result.Received, result.Errors)
	}

	fmt.Printf("   %d events published; waiting %s for the pipeline and the rule engine\n",
		result.Published, s.settle)
	select {
	case <-time.After(s.settle):
	case <-ctx.Done():
		return ctx.Err()
	}

	alerts, err := s.c.count(ctx, "siem", "/api/v1/siem/alerts?limit=1")
	if err != nil {
		return fmt.Errorf("count alerts: %w", err)
	}
	fmt.Printf("   %d alerts raised by the engine\n", alerts)
	return nil
}

// connectorClient returns a client holding the demonstration connector's own
// token, onboarding it the first time.
//
// Ingestion is for machines, and rightly so. So the connector gets what a
// deployed agent gets: a service account, a secret shown exactly once, and a
// credentials file it keeps. Re-running reuses that file rather than issuing a
// second credential — the client id carries a unique index that a revoked
// account still occupies, so "revoke and recreate under the same name" is not
// something an operator can do either.
func (s *seeder) connectorClient(ctx context.Context) (*client, error) {
	if s.collectorRole == uuid.Nil {
		return nil, fmt.Errorf("no role grants events:ingest, so no connector can be onboarded")
	}

	if cred, err := readConnectorCredential(s.credentialPath); err == nil {
		if c, terr := s.exchange(ctx, cred); terr == nil {
			s.note("· %s (credential from %s)", cred.ClientID, s.credentialPath)
			return c, nil
		}
		// The stored credential no longer works — revoked, expired, or from a
		// database that has since been reset. Onboard again below rather than
		// stopping: the file is a cache, not the record.
	}

	cred, err := s.onboard(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeConnectorCredential(s.credentialPath, cred); err != nil {
		// Worth saying: without the file the next run onboards a second
		// credential, and the operator ends up with a list of them.
		s.softFail("store the connector credential", err)
	}
	return s.exchange(ctx, cred)
}

// connectorCredential is what a connector keeps on disk.
type connectorCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// onboard creates the service account and returns its one-time secret.
func (s *seeder) onboard(ctx context.Context) (connectorCredential, error) {
	create := func(clientID string) (connectorCredential, error) {
		var created struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		err := s.c.post(ctx, "identity", "/api/v1/service-accounts", map[string]any{
			"client_id":       clientID,
			"description":     "Connector of the demonstration dataset.",
			"scope":           "tenant",
			"role_ids":        []uuid.UUID{s.collectorRole},
			"expires_in_days": 30,
		}, &created)
		if err != nil {
			return connectorCredential{}, err
		}
		if created.ClientSecret == "" {
			return connectorCredential{}, fmt.Errorf("%s was created without a secret", clientID)
		}
		return connectorCredential{ClientID: clientID, ClientSecret: created.ClientSecret}, nil
	}

	cred, err := create("demo-connector")
	if err == nil {
		s.note("+ demo-connector (service account, events:ingest)")
		s.written++
		return cred, nil
	}
	if !isConflict(err) {
		return connectorCredential{}, fmt.Errorf("create the demo-connector service account: %w", err)
	}

	// The name is taken by an account whose secret is gone. Take the next one
	// rather than leaving the estate without events.
	alt := fmt.Sprintf("demo-connector-%d", time.Now().UTC().Unix())
	cred, err = create(alt)
	if err != nil {
		return connectorCredential{}, fmt.Errorf("create the %s service account: %w", alt, err)
	}
	s.note("+ %s (service account, events:ingest)", alt)
	s.written++
	return cred, nil
}

func (s *seeder) exchange(ctx context.Context, cred connectorCredential) (*client, error) {
	var granted struct {
		AccessToken string `json:"access_token"`
	}
	if err := s.c.post(ctx, "identity", "/api/v1/auth/service-token", map[string]any{
		"client_id":     cred.ClientID,
		"client_secret": cred.ClientSecret,
	}, &granted); err != nil {
		return nil, fmt.Errorf("exchange the %s credential for a token: %w", cred.ClientID, err)
	}
	return newClient(granted.AccessToken, s.c.base), nil
}

func readConnectorCredential(path string) (connectorCredential, error) {
	var cred connectorCredential
	raw, err := os.ReadFile(path)
	if err != nil {
		return cred, err
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		return cred, err
	}
	if cred.ClientID == "" || cred.ClientSecret == "" {
		return cred, fmt.Errorf("%s holds no credential", path)
	}
	return cred, nil
}

func writeConnectorCredential(path string, cred connectorCredential) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}
	// 0600: it is a live credential for writing into the detection pipeline.
	return os.WriteFile(path, raw, 0o600)
}
