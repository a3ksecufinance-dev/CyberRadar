package main

import "fmt"

// The fleet around the fourteen named assets.
//
// Why generate rather than write them out. The fourteen in estate.go carry the
// story: the attack graph walks them, the findings name them, the incidents
// reference them. They have to be written by hand because each one means
// something. But fourteen assets read as a test database, not as a bank, and a
// reviewer looking at a dashboard cannot tell a product that works from one
// that merely starts when every count is in single digits.
//
// So the branch network is generated: twenty-four branches, each with a server,
// a cash machine and two workstations, plus a back office. It is deterministic —
// no randomness — because the seeder is safe to run twice and a fleet that
// shuffled between runs would create duplicates on the second.
//
// Nothing here is load-bearing for the scenarios. Delete the file and the
// demonstration still tells its story, with smaller numbers.

// branches are where a retail bank actually keeps its estate.
var branches = []struct {
	Slug, City string
}{
	{"cas-cfc", "Casablanca Finance City"}, {"cas-maa", "Casablanca Maârif"},
	{"cas-sid", "Casablanca Sidi Maârouf"}, {"cas-ain", "Casablanca Aïn Diab"},
	{"rab-agd", "Rabat Agdal"}, {"rab-hay", "Rabat Hay Riad"},
	{"mar-gue", "Marrakech Guéliz"}, {"mar-men", "Marrakech Ménara"},
	{"fes-atl", "Fès Atlas"}, {"tan-ibe", "Tanger Ibéria"},
	{"tan-med", "Tanger Med"}, {"aga-tal", "Agadir Talborjt"},
	{"mek-ham", "Meknès Hamria"}, {"ouj-and", "Oujda Al Andalous"},
	{"ken-mak", "Kénitra Maâmora"}, {"tet-mar", "Tétouan Marina"},
	{"sal-bet", "Salé Bettana"}, {"moh-par", "Mohammedia Parc"},
	{"jad-pla", "El Jadida Plateau"}, {"ben-bel", "Béni Mellal Belvédère"},
	{"saf-jor", "Safi Jorf"}, {"nad-ari", "Nador Arid"},
	{"set-cen", "Settat Centre"}, {"laa-smr", "Laâyoune Smara"},
}

// backOffice is what sits behind the branches and is neither core banking nor
// payments: the systems a CIO recognises as the bulk of an estate.
var backOffice = []struct {
	Name, Type, OS, Dept, Service string
	Crit                          int
	Env                           string
}{
	{"mail-exch-01", "server", "Exchange Server 2019", "Infrastructure", "Messagerie", 3, "production"},
	{"mail-exch-02", "server", "Exchange Server 2019", "Infrastructure", "Messagerie", 3, "production"},
	{"file-srv-01", "storage", "Windows Server 2019", "Infrastructure", "Partage de fichiers", 2, "production"},
	{"print-srv-01", "server", "Windows Server 2019", "Infrastructure", "Impression", 1, "production"},
	{"vcenter-01", "hypervisor", "VMware vCenter 7.0", "Infrastructure", "Virtualisation", 4, "production"},
	{"esx-prod-01", "hypervisor", "VMware ESXi 7.0", "Infrastructure", "Virtualisation", 4, "production"},
	{"esx-prod-02", "hypervisor", "VMware ESXi 7.0", "Infrastructure", "Virtualisation", 4, "production"},
	{"mq-broker-01", "server", "Apache ActiveMQ 5.17", "Systèmes centraux", "Bus de messages", 3, "production"},
	{"ci-build-01", "server", "TeamCity 2023.11", "Études", "Intégration continue", 2, "production"},
	{"wiki-conf-01", "server", "Atlassian Confluence Server", "Études", "Documentation", 1, "production"},
	{"lb-core-01", "proxy", "F5 BIG-IP 16.1", "Infrastructure", "Répartition de charge", 3, "production"},
	{"rtr-wan-01", "router", "Cisco IOS XE 17.6", "Infrastructure", "Réseau étendu", 4, "production"},
	{"web-ebank-rec", "server", "RHEL 9.3", "Canaux digitaux", "Banque en ligne", 1, "staging"},
	{"app-core-rec", "cbs_server", "RHEL 9.3", "Systèmes centraux", "Core banking", 1, "staging"},
	{"db-core-rec", "database", "Oracle Linux 8", "Systèmes centraux", "Core banking", 1, "staging"},
}

// fleetAssets is the generated estate, appended to the named one.
func fleetAssets() []demoAsset {
	out := make([]demoAsset, 0, len(branches)*4+len(backOffice))

	for i, b := range branches {
		octet := 10 + i // 10.70.10.x … 10.70.33.x, clear of the named assets
		host := func(n int) string { return fmt.Sprintf("10.70.%d.%d", octet, n) }
		fqdn := func(n string) string { return n + ".almassira.ma" }

		srv := fmt.Sprintf("agence-%s-srv", b.Slug)
		gab := fmt.Sprintf("agence-%s-gab", b.Slug)
		out = append(out,
			demoAsset{
				Name: srv, Hostname: fqdn(srv), IP: host(10), Type: "server", OS: "RHEL 9.3",
				Criticality: 2, Environment: "production", Zone: "branch",
				Department: "Réseau d'agences", Service: "Agence " + b.City,
				Location: b.City,
				Tags:     []string{"demo", "agence", b.Slug},
			},
			demoAsset{
				Name: gab, Hostname: fqdn(gab), IP: host(20), Type: "monetique", OS: "Windows 10 IoT LTSC",
				Criticality: 3, Environment: "production", Zone: "monetique",
				Department: "Monétique", Service: "Réseau GAB", PCI: true,
				Location: b.City,
				Tags:     []string{"demo", "atm", "pci", b.Slug},
			},
		)
		// Two workstations per branch: enough to make the inventory read like a
		// bank's, few enough that the estate stays legible on one screen.
		for p := 1; p <= 2; p++ {
			ws := fmt.Sprintf("poste-%s-%02d", b.Slug, p)
			out = append(out, demoAsset{
				Name: ws, Hostname: fqdn(ws), IP: host(100 + p), Type: "workstation",
				OS: "Windows 11 23H2", Criticality: 1, Environment: "production", Zone: "branch",
				Department: "Réseau d'agences", Service: "Poste de travail",
				Location: b.City,
				Tags:     []string{"demo", "workstation", b.Slug},
			})
		}
	}

	for i, b := range backOffice {
		out = append(out, demoAsset{
			Name: b.Name, Hostname: b.Name + ".almassira.ma", IP: fmt.Sprintf("10.65.0.%d", 10+i),
			Type: b.Type, OS: b.OS, Criticality: b.Crit, Environment: b.Env, Zone: "internal",
			Department: b.Dept, Service: b.Service, Location: headOffice,
			Tags: []string{"demo", "back-office"},
		})
	}
	return out
}

// fleetLinks makes the fleet part of the graph rather than a list beside it.
//
// This is what the blast radius on an asset page and the attack path analysis
// both read: without it, taking a branch server changes nothing, and the
// interesting question — what does this reach — has no answer.
func fleetLinks() []struct{ From, To, Type string } {
	var out []struct{ From, To, Type string }
	for _, b := range branches {
		srv := fmt.Sprintf("agence-%s-srv", b.Slug)
		out = append(out,
			struct{ From, To, Type string }{srv, "app-core-01", "DEPENDS_ON"},
			struct{ From, To, Type string }{fmt.Sprintf("agence-%s-gab", b.Slug), "atm-switch-01", "DEPENDS_ON"},
		)
		for p := 1; p <= 2; p++ {
			out = append(out, struct{ From, To, Type string }{
				fmt.Sprintf("poste-%s-%02d", b.Slug, p), srv, "CONNECTS_TO",
			})
		}
	}
	for _, b := range backOffice {
		switch b.Type {
		case "hypervisor":
			out = append(out, struct{ From, To, Type string }{b.Name, "vcenter-01", "MANAGED_BY"})
		case "workstation", "server", "storage", "proxy", "router", "database", "cbs_server":
			out = append(out, struct{ From, To, Type string }{"jump-adm-01", b.Name, "MANAGED_BY"})
		}
	}
	return out
}

// affects decides which generated assets carry a given vulnerability.
//
// By the product it names, rather than by a hand-written list: a finding on a
// Windows 11 workstation for an Exchange flaw is the kind of thing a reviewer
// spots immediately, and one wrong row costs more credibility than fifty right
// ones buy. The named assets keep their explicit OnAssets list — those are the
// ones the scenarios depend on.
func (v demoVuln) affects(a demoAsset) bool {
	for _, product := range v.Products {
		if productMatches(product, a) {
			return true
		}
	}
	return false
}

// productMatches is deliberately narrow: it matches a product against what an
// asset actually runs, and says no when unsure.
//
// The platform is not enough on its own. A cash machine runs Windows 10 IoT,
// and the first version of this matched Outlook, WinRAR and SmartScreen on
// twenty-four of them — three client-side findings on a device nobody reads
// mail from. That is exactly what a CISO notices first, and one wrong row
// costs more credibility than fifty right ones buy. Client software therefore
// needs a workstation, not merely a Windows kernel.
func productMatches(product string, a demoAsset) bool {
	os := a.OS
	switch product {
	case "Apache Log4j 2.x", "Spring Framework 5.3", "OpenSSH < 9.6", "OpenSSH 8.5 — 9.7",
		"Linux kernel 5.14 — 6.6", "libwebp < 1.3.2":
		return os == "RHEL 9.3" || os == "RHEL 8.9" || os == "Oracle Linux 8" || os == "Ubuntu 22.04"
	case "Windows Server 2022", "Windows Server 2019", "Windows Server 2016":
		return os == "Windows Server 2022" || os == "Windows Server 2019"
	case "Microsoft Outlook", "WinRAR < 6.23", "Microsoft Windows SmartScreen":
		return a.Type == "workstation" && os == "Windows 11 23H2"
	case "Windows 10", "Windows 10 IoT LTSC":
		return os == "Windows 10 IoT LTSC"
	case "Microsoft Exchange Server 2019", "Microsoft Exchange Server 2016":
		return os == "Exchange Server 2019"
	case "VMware vCenter Server 7.0":
		return os == "VMware vCenter 7.0"
	case "Apache ActiveMQ 5.17":
		return os == "Apache ActiveMQ 5.17"
	case "JetBrains TeamCity < 2023.11.3":
		return os == "TeamCity 2023.11"
	case "Atlassian Confluence Server":
		return os == "Atlassian Confluence Server"
	case "F5 BIG-IP 16.1":
		return os == "F5 BIG-IP 16.1"
	case "Cisco IOS XE 17.6":
		return os == "Cisco IOS XE 17.6"
	}
	return false
}
