package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The estate is a retail bank with an internet-facing channel, a core banking
// system, a SWIFT gateway and an ATM network: the four things a European
// supervisor asks about first. Everything below hangs off it.

type demoAsset struct {
	Name        string
	Hostname    string
	IP          string
	Type        string
	OS          string
	Criticality int
	Environment string
	Zone        string
	Department  string
	Service     string
	Internet    bool
	CBS         bool
	SWIFT       bool
	PCI         bool
	Tags        []string
}

var demoAssets = []demoAsset{
	{"waf-dmz-01", "waf-dmz-01.bnf.fr", "203.0.113.10", "proxy", "PAN-OS 11.1", 3, "production", "dmz", "Infrastructure", "Banque en ligne", true, false, false, true, []string{"demo", "dmz", "edge"}},
	{"vpn-gw-01", "vpn-gw-01.bnf.fr", "203.0.113.11", "vpn", "FortiOS 7.2", 3, "production", "dmz", "Infrastructure", "Accès distant", true, false, false, false, []string{"demo", "dmz", "remote-access"}},
	{"web-ebank-01", "web-ebank-01.bnf.fr", "10.20.1.11", "server", "RHEL 9.3", 4, "production", "dmz", "Canaux digitaux", "Banque en ligne", true, false, false, true, []string{"demo", "web", "pci"}},
	{"web-ebank-02", "web-ebank-02.bnf.fr", "10.20.1.12", "server", "RHEL 9.3", 4, "production", "dmz", "Canaux digitaux", "Banque en ligne", true, false, false, true, []string{"demo", "web", "pci"}},
	{"app-core-01", "app-core-01.bnf.fr", "10.30.2.21", "cbs_server", "RHEL 9.3", 4, "production", "core", "Systèmes centraux", "Core banking", false, true, false, false, []string{"demo", "cbs"}},
	{"db-core-01", "db-core-01.bnf.fr", "10.30.2.31", "database", "Oracle Linux 8", 4, "production", "core", "Systèmes centraux", "Core banking", false, true, false, true, []string{"demo", "database", "cbs"}},
	{"swift-gw-01", "swift-gw-01.bnf.fr", "10.40.3.41", "swift_gateway", "RHEL 8.9", 4, "production", "swift", "Paiements", "Paiements internationaux", false, false, true, false, []string{"demo", "swift", "cscf"}},
	{"hsm-pay-01", "hsm-pay-01.bnf.fr", "10.40.3.45", "hsm", "Thales payShield", 4, "production", "swift", "Paiements", "Paiements internationaux", false, false, true, true, []string{"demo", "hsm", "pci"}},
	{"ad-dc-01", "ad-dc-01.bnf.fr", "10.10.0.5", "server", "Windows Server 2022", 4, "production", "internal", "Infrastructure", "Annuaire", false, false, false, false, []string{"demo", "active-directory"}},
	{"jump-adm-01", "jump-adm-01.bnf.fr", "10.10.0.50", "server", "Windows Server 2022", 4, "production", "admin", "Infrastructure", "Administration", false, false, false, false, []string{"demo", "bastion", "tier0"}},
	{"atm-switch-01", "atm-switch-01.bnf.fr", "10.50.4.10", "monetique", "RHEL 8.9", 4, "production", "monetique", "Monétique", "Réseau GAB", false, false, false, true, []string{"demo", "atm", "pci"}},
	{"backup-nas-01", "backup-nas-01.bnf.fr", "10.10.0.90", "storage", "TrueNAS 13", 3, "production", "internal", "Infrastructure", "Sauvegarde", false, false, false, false, []string{"demo", "backup"}},
	{"k8s-node-03", "k8s-node-03.bnf.fr", "10.20.1.53", "container", "Ubuntu 22.04", 2, "production", "dmz", "Canaux digitaux", "Banque en ligne", false, false, false, false, []string{"demo", "kubernetes"}},
	{"poste-soc-014", "poste-soc-014.bnf.fr", "10.60.5.14", "workstation", "Windows 11 23H2", 2, "production", "internal", "Sécurité", "Poste de travail", false, false, false, false, []string{"demo", "workstation"}},
}

func (s *seeder) seedAssets(ctx context.Context) error {
	step("Assets")
	idx, err := s.index(ctx, "asset", "/api/v1/assets")
	if err != nil {
		return err
	}
	s.assets = idx

	for _, a := range demoAssets {
		body := map[string]any{
			"name":               a.Name,
			"hostname":           a.Hostname,
			"fqdn":               a.Hostname,
			"ip_addresses":       []string{a.IP},
			"asset_type":         a.Type,
			"os":                 a.OS,
			"criticality":        a.Criticality,
			"environment":        a.Environment,
			"department":         a.Department,
			"location":           "Paris — La Défense",
			"business_service":   a.Service,
			"is_cbs_connected":   a.CBS,
			"is_swift_connected": a.SWIFT,
			"is_pci_scope":       a.PCI,
			"tags":               a.Tags,
			"metadata": map[string]any{
				"network_zone": a.Zone,
				"origin":       "demonstration dataset",
			},
		}
		if _, err := s.ensure(ctx, s.assets, a.Name, "asset", "/api/v1/assets", body); err != nil {
			return err
		}
	}
	fmt.Printf("   %d assets\n", len(s.assets))
	return nil
}

// assetLinks are the dependencies that make the estate a graph rather than an
// inventory: they are what the attack path analysis and the blast radius on
// the asset page both read.
var assetLinks = []struct {
	From, To, Type string
}{
	{"waf-dmz-01", "web-ebank-01", "CONNECTS_TO"},
	{"waf-dmz-01", "web-ebank-02", "CONNECTS_TO"},
	{"web-ebank-01", "app-core-01", "DEPENDS_ON"},
	{"web-ebank-02", "app-core-01", "DEPENDS_ON"},
	{"app-core-01", "db-core-01", "DEPENDS_ON"},
	{"k8s-node-03", "web-ebank-01", "HOSTS"},
	{"jump-adm-01", "swift-gw-01", "MANAGED_BY"},
	{"jump-adm-01", "db-core-01", "MANAGED_BY"},
	{"swift-gw-01", "hsm-pay-01", "DEPENDS_ON"},
	{"atm-switch-01", "app-core-01", "DEPENDS_ON"},
	{"backup-nas-01", "db-core-01", "BACKS_UP"},
	{"vpn-gw-01", "jump-adm-01", "CONNECTS_TO"},
	{"ad-dc-01", "jump-adm-01", "CONNECTS_TO"},
}

func (s *seeder) seedAssetLinks(ctx context.Context) error {
	step("Asset dependencies")
	n := 0
	for _, l := range assetLinks {
		src, ok := s.assets[l.From]
		dst, ok2 := s.assets[l.To]
		if !ok || !ok2 {
			continue
		}
		path := fmt.Sprintf("/api/v1/assets/%s/relationships", src)
		body := map[string]any{
			"target_id":         dst,
			"relationship_type": l.Type,
			"properties":        map[string]any{"origin": "demonstration dataset"},
		}
		if err := s.c.post(ctx, "asset", path, body, nil); err != nil {
			// The relationship table has a uniqueness constraint; a second run
			// is expected to land on it.
			if isConflict(err) {
				continue
			}
			return fmt.Errorf("%s -%s-> %s: %w", l.From, l.Type, l.To, err)
		}
		n++
	}
	fmt.Printf("   %d dependencies (%d already there)\n", n, len(assetLinks)-n)
	return nil
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

type demoVuln struct {
	CVE       string
	Title     string
	CVSS      float64
	EPSS      float64
	Exploited bool
	Exploit   bool
	CWE       string
	CWEName   string
	Technique string
	Products  []string
	Patch     bool
	PatchURL  string
	Published string
	OnAssets  []string
	Port      int
	Service   string
	Vector    string
}

var demoVulns = []demoVuln{
	{
		CVE: "CVE-2024-3400", Title: "PAN-OS GlobalProtect — injection de commande non authentifiée",
		CVSS: 10.0, EPSS: 0.9427, Exploited: true, Exploit: true,
		CWE: "CWE-77", CWEName: "Command Injection", Technique: "T1190",
		Products: []string{"PAN-OS 11.1", "PAN-OS 10.2"}, Patch: true,
		PatchURL:  "https://security.paloaltonetworks.com/CVE-2024-3400",
		Published: "2024-04-12", OnAssets: []string{"waf-dmz-01"}, Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2024-21762", Title: "FortiOS SSL-VPN — écriture hors limites",
		CVSS: 9.6, EPSS: 0.9381, Exploited: true, Exploit: true,
		CWE: "CWE-787", CWEName: "Out-of-bounds Write", Technique: "T1190",
		Products: []string{"FortiOS 7.2", "FortiOS 7.0"}, Patch: true,
		PatchURL:  "https://fortiguard.com/psirt/FG-IR-24-015",
		Published: "2024-02-09", OnAssets: []string{"vpn-gw-01"}, Port: 443, Service: "sslvpn",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2021-44228", Title: "Log4Shell — exécution de code à distance via JNDI",
		CVSS: 10.0, EPSS: 0.9441, Exploited: true, Exploit: true,
		CWE: "CWE-502", CWEName: "Deserialization of Untrusted Data", Technique: "T1190",
		Products: []string{"Apache Log4j 2.x"}, Patch: true,
		PatchURL:  "https://logging.apache.org/log4j/2.x/security.html",
		Published: "2021-12-10", OnAssets: []string{"web-ebank-01", "web-ebank-02", "app-core-01"},
		Port: 8080, Service: "http",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2020-1472", Title: "Zerologon — élévation de privilèges Netlogon",
		CVSS: 10.0, EPSS: 0.9752, Exploited: true, Exploit: true,
		CWE: "CWE-330", CWEName: "Use of Insufficiently Random Values", Technique: "T1068",
		Products: []string{"Windows Server 2022", "Windows Server 2019"}, Patch: true,
		PatchURL:  "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
		Published: "2020-08-11", OnAssets: []string{"ad-dc-01"}, Port: 445, Service: "netlogon",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-34362", Title: "MOVEit Transfer — injection SQL menant à l'exécution de code",
		CVSS: 9.8, EPSS: 0.9438, Exploited: true, Exploit: true,
		CWE: "CWE-89", CWEName: "SQL Injection", Technique: "T1190",
		Products: []string{"MOVEit Transfer"}, Patch: true,
		PatchURL:  "https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability",
		Published: "2023-06-02", OnAssets: []string{"backup-nas-01"}, Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2022-26134", Title: "Confluence — injection OGNL non authentifiée",
		CVSS: 9.8, EPSS: 0.9740, Exploited: true, Exploit: true,
		CWE: "CWE-917", CWEName: "Expression Language Injection", Technique: "T1190",
		Products: []string{"Atlassian Confluence Server"}, Patch: true,
		Published: "2022-06-02", OnAssets: []string{"k8s-node-03"}, Port: 8090, Service: "http",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-23397", Title: "Outlook — fuite de l'empreinte NTLM sans interaction",
		CVSS: 9.8, EPSS: 0.9182, Exploited: true, Exploit: true,
		CWE: "CWE-294", CWEName: "Authentication Bypass by Capture-replay", Technique: "T1187",
		Products: []string{"Microsoft Outlook"}, Patch: true,
		Published: "2023-03-14", OnAssets: []string{"poste-soc-014"}, Port: 0, Service: "smtp",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
	},
	{
		CVE: "CVE-2023-4966", Title: "Citrix Bleed — fuite mémoire permettant le vol de session",
		CVSS: 9.4, EPSS: 0.9412, Exploited: true, Exploit: true,
		CWE: "CWE-119", CWEName: "Buffer Overflow", Technique: "T1078",
		Products: []string{"NetScaler ADC", "NetScaler Gateway"}, Patch: true,
		Published: "2023-10-10", OnAssets: []string{"waf-dmz-01"}, Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
	{
		CVE: "CVE-2024-1086", Title: "Noyau Linux netfilter — use-after-free, élévation locale",
		CVSS: 7.8, EPSS: 0.1204, Exploited: true, Exploit: true,
		CWE: "CWE-416", CWEName: "Use After Free", Technique: "T1068",
		Products: []string{"Linux kernel 5.14 — 6.6"}, Patch: true,
		Published: "2024-01-31", OnAssets: []string{"web-ebank-01", "k8s-node-03"}, Port: 0, Service: "kernel",
		Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-48795", Title: "Terrapin — troncature du protocole SSH",
		CVSS: 5.9, EPSS: 0.0231, Exploited: false, Exploit: true,
		CWE: "CWE-354", CWEName: "Improper Validation of Integrity Check Value", Technique: "T1557",
		Products: []string{"OpenSSH < 9.6"}, Patch: true,
		Published: "2023-12-18", OnAssets: []string{"swift-gw-01", "jump-adm-01", "db-core-01"},
		Port: 22, Service: "ssh",
		Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
	},
}

func (s *seeder) seedVulnerabilities(ctx context.Context) error {
	step("Vulnerabilities and findings")
	idx, err := s.index(ctx, "vuln", "/api/v1/vuln/vulnerabilities")
	if err != nil {
		return err
	}
	s.vulns = idx

	type finding struct {
		AssetID     uuid.UUID      `json:"asset_id"`
		VulnID      uuid.UUID      `json:"vuln_id"`
		Port        *int           `json:"port,omitempty"`
		Protocol    string         `json:"protocol,omitempty"`
		ServiceName string         `json:"service_name,omitempty"`
		Evidence    map[string]any `json:"evidence,omitempty"`
	}
	var findings []finding

	for _, v := range demoVulns {
		published, _ := time.Parse("2006-01-02", v.Published)
		body := map[string]any{
			"cve_id":            v.CVE,
			"title":             v.Title,
			"description":       v.Title + " — entrée du jeu de démonstration, alignée sur l'avis public.",
			"cvss_score":        v.CVSS,
			"cvss_vector":       v.Vector,
			"is_exploited":      v.Exploited,
			"exploit_available": v.Exploit,
			"epss_score":        v.EPSS,
			"cwe_id":            v.CWE,
			"cwe_name":          v.CWEName,
			"mitre_technique":   v.Technique,
			"affected_products": v.Products,
			"patch_available":   v.Patch,
			"patch_url":         v.PatchURL,
			"published_at":      published.UTC(),
			"tags":              []string{"demo"},
		}
		vulnID, err := s.ensure(ctx, s.vulns, v.CVE, "vuln", "/api/v1/vuln/vulnerabilities", body)
		if err != nil {
			return err
		}

		for _, name := range v.OnAssets {
			assetID, ok := s.assets[name]
			if !ok {
				continue
			}
			f := finding{
				AssetID:     assetID,
				VulnID:      vulnID,
				Protocol:    "tcp",
				ServiceName: v.Service,
				Evidence: map[string]any{
					"detected_by": "demonstration dataset",
					"banner":      v.Service + " on " + name,
				},
			}
			if v.Port > 0 {
				port := v.Port
				f.Port = &port
			}
			findings = append(findings, f)
		}
	}

	// One bulk call, the way a scanner's importer would do it. Re-running lands
	// on the (asset, vuln) uniqueness the schema declares, which the service
	// treats as an update rather than an error.
	var result map[string]any
	err = s.c.post(ctx, "vuln", "/api/v1/vuln/findings/bulk",
		map[string]any{"findings": findings}, &result)
	if err != nil {
		return fmt.Errorf("bulk findings: %w", err)
	}
	fmt.Printf("   %d vulnerabilities, %d findings across %d assets\n",
		len(s.vulns), len(findings), len(s.assets))
	return nil
}
