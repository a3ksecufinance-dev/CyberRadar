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

// ─── Detection rules ─────────────────────────────────────────────────────────

// demoAdoptions are the library entries this estate runs, and what it changed
// about them.
//
// The rules are adopted rather than written, because that is what a customer
// does: the platform ships detection content, the tenant takes what fits and
// tunes it, and the difference from the standard is what it defends to an
// auditor. A demonstration that hand-writes its rules would demonstrate the
// wrong workflow — and would leave the library looking like documentation
// nobody uses.
//
// Two of them are deliberately adjusted, so the lineage has something to show.
var demoAdoptions = []struct {
	Code string
	// Override is sent as the adoption body; nil adopts the detection exactly
	// as it ships, which is the common and better case.
	Override map[string]any
	Why      string
}{
	{Code: "CRP-IAM-0001"},
	{
		Code: "CRP-IAM-0003",
		// A bank with a small administration team can afford to hear about
		// every privileged session; the standard window batches them.
		Override: map[string]any{"dedup_window_s": 120},
		Why:      "fenêtre de déduplication resserrée",
	},
	{Code: "CRP-EXE-0001"},
	{Code: "CRP-C2-0001"},
	{Code: "CRP-C2-0002"},
	{
		Code: "CRP-EXF-0001",
		// This estate's backup service account transfers at night, so the
		// severity is raised rather than the condition widened: the intent is
		// to page, not to match more.
		Override: map[string]any{"severity": "CRITICAL"},
		Why:      "sévérité relevée",
	},
	{Code: "CRP-LAT-0001"},
	{Code: "CRP-DIS-0001"},
	{Code: "CRP-IAM-0002"},
	{Code: "CRP-IAM-0004"},
	{Code: "CRP-IAM-0005"},
	{Code: "CRP-C2-0003"},
	{Code: "CRP-EXF-0002"},
	{Code: "CRP-GEO-0001"},
	// CRP-FRD-0001 et CRP-LAT-0001 restent volontairement non adoptées : un
	// client ne prend pas tout, et l'écran de couverture n'a d'intérêt que s'il
	// a un écart à montrer. C'est aussi la question qu'un auditeur pose —
	// « pourquoi celle-là n'est pas active » — et elle doit avoir une réponse.
}

func (s *seeder) seedRules(ctx context.Context) error {
	step("Detection rules, adopted from the library")

	// The library as this tenant sees it: every entry, and whether it is
	// already adopted. Re-running then changes nothing, and the count below is
	// the real coverage rather than what this file hoped for.
	var library []struct {
		Content struct {
			Code             string   `json:"code"`
			Title            string   `json:"title"`
			Requires         []string `json:"requires"`
			EnabledByDefault bool     `json:"enabled_by_default"`
		} `json:"content"`
		Adopted *struct {
			RuleID uuid.UUID `json:"rule_id"`
		} `json:"adopted"`
	}
	if err := s.c.get(ctx, "siem", "/api/v1/siem/rule-library", nil, &library); err != nil {
		return fmt.Errorf("read the rule library: %w", err)
	}
	adopted := map[string]bool{}
	available := map[string]bool{}
	for _, entry := range library {
		available[entry.Content.Code] = true
		if entry.Adopted != nil {
			adopted[entry.Content.Code] = true
		}
	}

	taken, reused := 0, 0
	for _, want := range demoAdoptions {
		if !available[want.Code] {
			return fmt.Errorf("the library has no %s: has migration 000040 been applied?", want.Code)
		}
		if adopted[want.Code] {
			reused++
			s.note("· %s", want.Code)
			continue
		}
		body := want.Override
		if body == nil {
			body = map[string]any{}
		}
		if err := s.c.post(ctx, "siem",
			fmt.Sprintf("/api/v1/siem/rule-library/%s/adopt", want.Code), body, nil); err != nil {
			return fmt.Errorf("adopt %s: %w", want.Code, err)
		}
		taken++
		s.written++
		if want.Why != "" {
			s.note("+ %s (%s)", want.Code, want.Why)
		} else {
			s.note("+ %s", want.Code)
		}
	}
	s.reused += reused

	var coverage struct {
		CatalogueSize int `json:"catalogue_size"`
		AdoptedTotal  int `json:"adopted_total"`
		EnabledTotal  int `json:"enabled_total"`
		OwnRules      int `json:"own_rules"`
	}
	if err := s.c.get(ctx, "siem", "/api/v1/siem/rule-library/coverage", nil, &coverage); err != nil {
		return fmt.Errorf("read coverage: %w", err)
	}

	fmt.Printf("   %d adopted (%d already there) of %d in the library, %d enabled",
		taken+reused, reused, coverage.CatalogueSize, coverage.EnabledTotal)
	if coverage.OwnRules > 0 {
		fmt.Printf(", plus %d written by this tenant", coverage.OwnRules)
	}
	fmt.Println()
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
			"outcome": "failure", "user_name": "m.durand", "user_email": "m.durand@almassira.ma",
			"hostname": "web-ebank-01.almassira.ma", "asset_type": "server",
			"src_ip": "203.0.113.66", "dst_ip": "10.20.1.11", "dst_port": 443,
			"risk_score": 4.5,
		}))
	}

	// 2. A privileged session opened from outside.
	events = append(events, jsonEventLine(map[string]any{
		"timestamp": now.Add(-3 * time.Minute).Format(time.RFC3339),
		"action":    "admin_login", "category": "authentication", "severity": "HIGH",
		"outcome": "success", "user_name": "svc-admin", "user_email": "svc-admin@almassira.ma",
		"hostname": "jump-adm-01.almassira.ma", "asset_type": "server",
		"src_ip": "198.51.100.23", "dst_ip": "10.10.0.50", "dst_port": 3389,
		"risk_score": 8.7,
	}))

	// 3. Outbound traffic to an address the feed carries.
	for i := 0; i < 3; i++ {
		events = append(events, jsonEventLine(map[string]any{
			"timestamp": now.Add(time.Duration(-i*90) * time.Second).Format(time.RFC3339),
			"action":    "network_connection", "category": "network", "severity": "HIGH",
			"outcome": "success", "hostname": "swift-gw-01.almassira.ma", "asset_type": "server",
			"src_ip": "10.40.3.41", "dst_ip": "198.51.100.23", "dst_port": 443,
			"risk_score": 9.1,
		}))
	}

	// 4. An interpreter launched on the SWIFT gateway.
	events = append(events, jsonEventLine(map[string]any{
		"timestamp": now.Add(-6 * time.Minute).Format(time.RFC3339),
		"action":    "process_exec powershell.exe -enc", "category": "security", "severity": "CRITICAL",
		"outcome": "success", "user_name": "svc-swift", "hostname": "swift-gw-01.almassira.ma",
		"asset_type": "server", "src_ip": "10.40.3.41", "risk_score": 9.4,
	}))

	// 5. A transfer out of the backup estate.
	events = append(events, jsonEventLine(map[string]any{
		"timestamp": now.Add(-12 * time.Minute).Format(time.RFC3339),
		"action":    "file_transfer outbound 42GB", "category": "security", "severity": "HIGH",
		"outcome": "success", "user_name": "svc-backup", "hostname": "backup-nas-01.almassira.ma",
		"asset_type": "storage", "src_ip": "10.10.0.90", "dst_ip": "198.51.100.77",
		"dst_port": 443, "risk_score": 8.2,
	}))

	// 6. The week across the branch network.
	//
	// Why this is here. A bank with 125 assets whose alert screen shows ten
	// rows reads as a laboratory, and the dashboards' trend charts have nothing
	// to draw. The threshold counter keys on (tenant, rule, source address), so
	// alert volume comes from distinct attackers rather than from more events:
	// sixty addresses each failing six times is sixty alerts, which is what a
	// retail bank's console looks like on a Monday morning.
	//
	// The events carry timestamps spread over seven days, so the volume graphs
	// have a shape. The alerts themselves are stamped when the engine raises
	// them — the platform has just ingested the week, and saying so is more
	// honest than back-dating a detection that did not happen then.
	for a := 0; a < 60; a++ {
		branch := branches[a%len(branches)]
		host := fmt.Sprintf("agence-%s-srv.almassira.ma", branch.Slug)
		// 185.x and 196.x: the ranges a Moroccan bank actually sees knocking.
		attacker := fmt.Sprintf("185.%d.%d.%d", 100+a%80, 10+a%200, 2+a%250)
		day := time.Duration(-(a % 7)) * 24 * time.Hour
		for i := 0; i < 6; i++ {
			events = append(events, jsonEventLine(map[string]any{
				"timestamp": now.Add(day + time.Duration(-i*25)*time.Second).Format(time.RFC3339),
				"action":    "user_login", "category": "authentication", "severity": "MEDIUM",
				"outcome":   "failure",
				"user_name": fmt.Sprintf("client%04d", 1000+a),
				"hostname":  host, "asset_type": "server",
				"src_ip": attacker, "dst_ip": "10.20.1.11", "dst_port": 443,
				"risk_score": 4.8,
			}))
		}
	}

	// 7. Five transfers leaving the estate, from five different hosts, so the
	//    exfiltration rule has more than one row to its name.
	for i, h := range []string{"agence-cas-cfc-srv", "agence-rab-agd-srv", "agence-mar-gue-srv",
		"file-srv-01", "backup-nas-01"} {
		events = append(events, jsonEventLine(map[string]any{
			"timestamp": now.Add(time.Duration(-i*7) * time.Hour).Format(time.RFC3339),
			"action":    fmt.Sprintf("file_transfer outbound %dGB", 3+i*4), "category": "security",
			"severity": "HIGH", "outcome": "success", "user_name": "svc-report",
			"hostname": h + ".almassira.ma", "asset_type": "server",
			"src_ip": "10.70.10.10", "dst_ip": fmt.Sprintf("196.200.%d.%d", 10+i, 40+i),
			"dst_port": 443, "risk_score": 8.0,
		}))
	}

	// 8. Ordinary traffic, so the estate is not made of nothing but alerts.
	for i := 0; i < 300; i++ {
		branch := branches[i%len(branches)]
		events = append(events, jsonEventLine(map[string]any{
			"timestamp": now.Add(time.Duration(-(i % 7)) * 24 * time.Hour).
				Add(time.Duration(-i*11) * time.Minute).Format(time.RFC3339),
			"action": "user_login", "category": "authentication", "severity": "LOW",
			"outcome":    "success",
			"user_name":  fmt.Sprintf("agent.%s%02d", branch.Slug[:3], i%9),
			"hostname":   fmt.Sprintf("poste-%s-%02d.almassira.ma", branch.Slug, 1+i%2),
			"asset_type": "workstation",
			"src_ip":     fmt.Sprintf("10.70.%d.%d", 10+i%24, 101+i%2),
			"dst_ip":     "10.20.1.12", "dst_port": 443, "risk_score": 1.0,
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
