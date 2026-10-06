package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The estate is a retail bank with an internet-facing channel, a core banking
// system, a SWIFT gateway and a cash-machine network: the four things a
// supervisor asks about first. Everything below hangs off it.
//
// **Banque Al Massira is invented.** The name, the domain almassira.ma and
// every figure here are a demonstration dataset; no resemblance to any
// existing institution is intended, and none should be read into it. It is
// placed in Morocco — Casa Finance City for the head office, twenty-four
// branches from Tanger to Laâyoune — because a reviewer judges a dataset by
// whether it looks like their own estate, and a French bank shown to the
// Casablanca market answers a question nobody asked.
//
// Two consequences worth knowing before presenting: the compliance frameworks
// are the ones that actually bind a Moroccan bank (see demoFrameworks in
// analysis.go — DORA is not one of them), and the branch cities are real while
// the bank is not.

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
	Location    string
	Tags        []string
}

// headOffice is where the fourteen named assets sit. A branch carries its own
// city instead: the asset screen shows the field, and every asset of a
// twenty-four-branch network located in La Défense is the kind of detail that
// makes a reviewer stop trusting the rest.
const headOffice = "Casablanca — Casa Finance City"

var demoAssets = []demoAsset{
	{"waf-dmz-01", "waf-dmz-01.almassira.ma", "203.0.113.10", "proxy", "PAN-OS 11.1", 3, "production", "dmz", "Infrastructure", "Banque en ligne", true, false, false, true, headOffice, []string{"demo", "dmz", "edge"}},
	{"vpn-gw-01", "vpn-gw-01.almassira.ma", "203.0.113.11", "vpn", "FortiOS 7.2", 3, "production", "dmz", "Infrastructure", "Accès distant", true, false, false, false, headOffice, []string{"demo", "dmz", "remote-access"}},
	{"web-ebank-01", "web-ebank-01.almassira.ma", "10.20.1.11", "server", "RHEL 9.3", 4, "production", "dmz", "Canaux digitaux", "Banque en ligne", true, false, false, true, headOffice, []string{"demo", "web", "pci"}},
	{"web-ebank-02", "web-ebank-02.almassira.ma", "10.20.1.12", "server", "RHEL 9.3", 4, "production", "dmz", "Canaux digitaux", "Banque en ligne", true, false, false, true, headOffice, []string{"demo", "web", "pci"}},
	{"app-core-01", "app-core-01.almassira.ma", "10.30.2.21", "cbs_server", "RHEL 9.3", 4, "production", "core", "Systèmes centraux", "Core banking", false, true, false, false, headOffice, []string{"demo", "cbs"}},
	{"db-core-01", "db-core-01.almassira.ma", "10.30.2.31", "database", "Oracle Linux 8", 4, "production", "core", "Systèmes centraux", "Core banking", false, true, false, true, headOffice, []string{"demo", "database", "cbs"}},
	{"swift-gw-01", "swift-gw-01.almassira.ma", "10.40.3.41", "swift_gateway", "RHEL 8.9", 4, "production", "swift", "Paiements", "Paiements internationaux", false, false, true, false, headOffice, []string{"demo", "swift", "cscf"}},
	{"hsm-pay-01", "hsm-pay-01.almassira.ma", "10.40.3.45", "hsm", "Thales payShield", 4, "production", "swift", "Paiements", "Paiements internationaux", false, false, true, true, headOffice, []string{"demo", "hsm", "pci"}},
	{"ad-dc-01", "ad-dc-01.almassira.ma", "10.10.0.5", "server", "Windows Server 2022", 4, "production", "internal", "Infrastructure", "Annuaire", false, false, false, false, headOffice, []string{"demo", "active-directory"}},
	{"jump-adm-01", "jump-adm-01.almassira.ma", "10.10.0.50", "server", "Windows Server 2022", 4, "production", "admin", "Infrastructure", "Administration", false, false, false, false, headOffice, []string{"demo", "bastion", "tier0"}},
	{"atm-switch-01", "atm-switch-01.almassira.ma", "10.50.4.10", "monetique", "RHEL 8.9", 4, "production", "monetique", "Monétique", "Réseau GAB", false, false, false, true, headOffice, []string{"demo", "atm", "pci"}},
	{"backup-nas-01", "backup-nas-01.almassira.ma", "10.10.0.90", "storage", "TrueNAS 13", 3, "production", "internal", "Infrastructure", "Sauvegarde", false, false, false, false, headOffice, []string{"demo", "backup"}},
	{"k8s-node-03", "k8s-node-03.almassira.ma", "10.20.1.53", "container", "Ubuntu 22.04", 2, "production", "dmz", "Canaux digitaux", "Banque en ligne", false, false, false, false, headOffice, []string{"demo", "kubernetes"}},
	{"poste-soc-014", "poste-soc-014.almassira.ma", "10.60.5.14", "workstation", "Windows 11 23H2", 2, "production", "internal", "Sécurité", "Poste de travail", false, false, false, false, headOffice, []string{"demo", "workstation"}},
}

func (s *seeder) seedAssets(ctx context.Context) error {
	step("Assets")
	idx, err := s.index(ctx, "asset", "/api/v1/assets")
	if err != nil {
		return err
	}
	s.assets = idx

	// The named fourteen first, then the generated fleet. Order matters only
	// for reading the output: a failure on a named asset stops the run, and
	// seeing it before a hundred branch servers scroll past is the difference
	// between a diagnosis and a hunt.
	all := append(append([]demoAsset{}, demoAssets...), fleetAssets()...)
	for _, a := range all {
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
			"location":           a.Location,
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
	for _, l := range append(append([]struct{ From, To, Type string }{}, assetLinks...), fleetLinks()...) {
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
	total := len(assetLinks) + len(fleetLinks())
	fmt.Printf("   %d dependencies (%d already there)\n", n, total-n)
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

// Les valeurs portées ici, et ce qu'elles valent.
//
// `CVSS` est le score de base publié, `is_exploited` reflète l'appartenance au
// catalogue CISA KEV au moment de l'écriture, et `EPSS` est une valeur datée :
// c'est une probabilité qui change chaque jour, conservée pour que le tri par
// exploitabilité ait un sens à l'écran et non pour être citée comme un chiffre
// courant. La source qui fait foi reste le NVD pour le score et l'API EPSS pour
// la probabilité.
//
// Devant une salle qui connaît ces CVE par cœur — et un RSSI connaît
// Log4Shell —, vérifier deux ou trois lignes avant de présenter coûte cinq
// minutes et évite la seule objection qui décrédibilise tout le reste.
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
	// ── Le reste du catalogue, pour la flotte ────────────────────────────────
	//
	// Dix CVE suffisent aux scénarios et laissent l'écran des vulnérabilités à
	// un chiffre à deux colonnes, ce qui se lit comme une base de test. Celles
	// qui suivent couvrent ce que porte réellement un parc de banque — postes
	// Windows, messagerie, hyperviseurs, réseau, intégration continue — et se
	// rattachent aux actifs par le produit, pas à la main.
	{
		CVE: "CVE-2022-22965", Title: "Spring4Shell — exécution de code via la liaison de données",
		CVSS: 9.8, EPSS: 0.9751, Exploited: true, Exploit: true,
		CWE: "CWE-94", CWEName: "Code Injection", Technique: "T1190",
		Products: []string{"Spring Framework 5.3"}, Patch: true,
		PatchURL:  "https://spring.io/security/cve-2022-22965",
		Published: "2022-04-01", Port: 8080, Service: "http",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2021-34527", Title: "PrintNightmare — exécution de code dans le spouleur d'impression",
		CVSS: 8.8, EPSS: 0.9427, Exploited: true, Exploit: true,
		CWE: "CWE-269", CWEName: "Improper Privilege Management", Technique: "T1068",
		Products: []string{"Windows Server 2019", "Windows Server 2022", "Windows 10"}, Patch: true,
		PatchURL:  "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
		Published: "2021-07-01", Port: 445, Service: "smb",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2021-26855", Title: "ProxyLogon — falsification de requête côté serveur sur Exchange",
		CVSS: 9.8, EPSS: 0.9754, Exploited: true, Exploit: true,
		CWE: "CWE-918", CWEName: "Server-Side Request Forgery", Technique: "T1190",
		Products: []string{"Microsoft Exchange Server 2019", "Microsoft Exchange Server 2016"}, Patch: true,
		PatchURL:  "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
		Published: "2021-03-02", Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-20198", Title: "Cisco IOS XE — création de compte privilégié via l'interface web",
		CVSS: 10.0, EPSS: 0.9442, Exploited: true, Exploit: true,
		CWE: "CWE-420", CWEName: "Unprotected Alternate Channel", Technique: "T1190",
		Products: []string{"Cisco IOS XE 17.6"}, Patch: true,
		PatchURL:  "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
		Published: "2023-10-16", Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2022-1388", Title: "F5 BIG-IP iControl REST — contournement d'authentification",
		CVSS: 9.8, EPSS: 0.9741, Exploited: true, Exploit: true,
		CWE: "CWE-306", CWEName: "Missing Authentication for Critical Function", Technique: "T1190",
		Products: []string{"F5 BIG-IP 16.1"}, Patch: true,
		PatchURL:  "https://my.f5.com/manage/s/article/K23605346",
		Published: "2022-05-05", Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-22515", Title: "Confluence — contrôle d'accès rompu sur la création d'administrateur",
		CVSS: 10.0, EPSS: 0.9741, Exploited: true, Exploit: true,
		CWE: "CWE-284", CWEName: "Improper Access Control", Technique: "T1190",
		Products: []string{"Atlassian Confluence Server"}, Patch: true,
		PatchURL:  "https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html",
		Published: "2023-10-04", Port: 8090, Service: "http",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
	},
	{
		CVE: "CVE-2023-46604", Title: "Apache ActiveMQ — désérialisation menant à l'exécution de code",
		CVSS: 10.0, EPSS: 0.9744, Exploited: true, Exploit: true,
		CWE: "CWE-502", CWEName: "Deserialization of Untrusted Data", Technique: "T1190",
		Products: []string{"Apache ActiveMQ 5.17"}, Patch: true,
		PatchURL:  "https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt",
		Published: "2023-10-27", Port: 61616, Service: "openwire",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2024-27198", Title: "TeamCity — contournement d'authentification de l'interface",
		CVSS: 9.8, EPSS: 0.9735, Exploited: true, Exploit: true,
		CWE: "CWE-288", CWEName: "Authentication Bypass Using an Alternate Path", Technique: "T1190",
		Products: []string{"JetBrains TeamCity < 2023.11.3"}, Patch: true,
		PatchURL:  "https://www.jetbrains.com/privacy-security/issues-fixed/",
		Published: "2024-03-04", Port: 8111, Service: "http",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2021-21972", Title: "vCenter Server — téléversement de fichier non authentifié",
		CVSS: 9.8, EPSS: 0.9754, Exploited: true, Exploit: true,
		CWE: "CWE-22", CWEName: "Path Traversal", Technique: "T1190",
		Products: []string{"VMware vCenter Server 7.0"}, Patch: true,
		PatchURL:  "https://www.vmware.com/security/advisories/VMSA-2021-0002.html",
		Published: "2021-02-24", Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2024-6387", Title: "regreSSHion — exécution de code pré-authentification dans sshd",
		CVSS: 8.1, EPSS: 0.4312, Exploited: false, Exploit: true,
		CWE: "CWE-364", CWEName: "Signal Handler Race Condition", Technique: "T1190",
		Products: []string{"OpenSSH 8.5 — 9.7"}, Patch: true,
		PatchURL:  "https://www.openssh.com/txt/release-9.8",
		Published: "2024-07-01", Port: 22, Service: "ssh",
		Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-44487", Title: "HTTP/2 Rapid Reset — déni de service par annulation de flux",
		CVSS: 7.5, EPSS: 0.9412, Exploited: true, Exploit: true,
		CWE: "CWE-400", CWEName: "Uncontrolled Resource Consumption", Technique: "T1499",
		Products: []string{"F5 BIG-IP 16.1", "Apache Log4j 2.x"}, Patch: true,
		PatchURL:  "https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/",
		Published: "2023-10-10", Port: 443, Service: "https",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
	},
	{
		CVE: "CVE-2023-4863", Title: "libwebp — dépassement de tas sur le décodage WebP",
		CVSS: 8.8, EPSS: 0.5583, Exploited: true, Exploit: true,
		CWE: "CWE-787", CWEName: "Out-of-bounds Write", Technique: "T1203",
		Products: []string{"libwebp < 1.3.2"}, Patch: true,
		PatchURL:  "https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html",
		Published: "2023-09-12", Port: 0, Service: "",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2023-38831", Title: "WinRAR — exécution de code par extension d'archive détournée",
		CVSS: 7.8, EPSS: 0.9361, Exploited: true, Exploit: true,
		CWE: "CWE-345", CWEName: "Insufficient Verification of Data Authenticity", Technique: "T1204",
		Products: []string{"WinRAR < 6.23"}, Patch: true,
		PatchURL:  "https://www.win-rar.com/singlenewsview.html?&tx_ttnews%5Btt_news%5D=232",
		Published: "2023-08-23", Port: 0, Service: "",
		Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2020-0796", Title: "SMBGhost — dépassement dans la compression SMBv3",
		CVSS: 10.0, EPSS: 0.9735, Exploited: true, Exploit: true,
		CWE: "CWE-787", CWEName: "Out-of-bounds Write", Technique: "T1210",
		Products: []string{"Windows 10", "Windows Server 2019"}, Patch: true,
		PatchURL:  "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
		Published: "2020-03-12", Port: 445, Service: "smb",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	{
		CVE: "CVE-2024-21412", Title: "Windows SmartScreen — contournement de l'avertissement de fichier",
		CVSS: 8.1, EPSS: 0.9387, Exploited: true, Exploit: true,
		CWE: "CWE-693", CWEName: "Protection Mechanism Failure", Technique: "T1553",
		Products: []string{"Microsoft Windows SmartScreen"}, Patch: true,
		PatchURL:  "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412",
		Published: "2024-02-13", Port: 0, Service: "",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
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
	fleet := fleetAssets()

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

		// The named assets the scenarios depend on, plus every generated asset
		// whose platform the advisory actually names. Hand-listing the second
		// group would be a hundred lines nobody rereads, and a finding on the
		// wrong platform is what a reviewer notices first.
		targets := append([]string{}, v.OnAssets...)
		for _, a := range fleet {
			if v.affects(a) {
				targets = append(targets, a.Name)
			}
		}
		for _, name := range targets {
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
