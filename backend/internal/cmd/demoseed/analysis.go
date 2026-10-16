package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ─── Incidents ────────────────────────────────────────────────────────────────

func (s *seeder) seedIncidents(ctx context.Context) error {
	step("Incidents")
	idx, err := s.index(ctx, "soar", "/api/v1/soar/incidents")
	if err != nil {
		return err
	}

	assets := func(names ...string) []uuid.UUID {
		var out []uuid.UUID
		for _, n := range names {
			if id, ok := s.assets[n]; ok {
				out = append(out, id)
			}
		}
		return out
	}
	iocs := func(values ...string) []uuid.UUID {
		var out []uuid.UUID
		for _, v := range values {
			if id, ok := s.iocs[v]; ok {
				out = append(out, id)
			}
		}
		return out
	}

	incidents := []map[string]any{
		{
			"title":       "Session privilégiée ouverte depuis une adresse externe sur le bastion",
			"description": "Une authentification administrateur a réussi sur jump-adm-01 depuis 198.51.100.23, adresse portée au renseignement comme serveur de commande. Session coupée, compte svc-admin suspendu, collecte en cours.",
			"severity":    "CRITICAL", "source_service": "siem",
			"mitre_tactics":    []string{"TA0001", "TA0008"},
			"mitre_techniques": []string{"T1078", "T1021.001"},
			"affected_assets":  assets("jump-adm-01", "swift-gw-01"),
			"ioc_ids":          iocs("198.51.100.23"),
			"tags":             []string{"demo", "accès-privilégié"},
			"properties":       map[string]any{"playbook": "PB-ACCES-PRIV-01", "origin": "demonstration dataset"},
		},
		{
			"title":       "Bourrage d'identifiants sur le portail de banque en ligne",
			"description": "Plus de 400 tentatives en dix minutes depuis 203.0.113.66 et deux adresses voisines. Aucune authentification n'a abouti ; limitation de débit appliquée au niveau du WAF.",
			"severity":    "HIGH", "source_service": "siem",
			"mitre_tactics":    []string{"TA0006"},
			"mitre_techniques": []string{"T1110.004"},
			"affected_assets":  assets("web-ebank-01", "web-ebank-02", "waf-dmz-01"),
			"ioc_ids":          iocs("203.0.113.66"),
			"tags":             []string{"demo", "banque-en-ligne"},
			"properties":       map[string]any{"playbook": "PB-AUTH-02", "origin": "demonstration dataset"},
		},
		{
			"title":       "Transfert sortant anormal depuis le socle de sauvegarde",
			"description": "42 Go transférés de backup-nas-01 vers cdn-metrics.example.net hors fenêtre de sauvegarde. Flux bloqué, empreintes conservées pour analyse.",
			"severity":    "HIGH", "source_service": "ueba",
			"mitre_tactics":    []string{"TA0010"},
			"mitre_techniques": []string{"T1567.002"},
			"affected_assets":  assets("backup-nas-01", "db-core-01"),
			"ioc_ids":          iocs("cdn-metrics.example.net", "198.51.100.77"),
			"tags":             []string{"demo", "exfiltration"},
			"properties":       map[string]any{"playbook": "PB-EXFIL-01", "origin": "demonstration dataset"},
		},
		{
			"title":       "CVE-2024-3400 exploitable sur la passerelle de la DMZ",
			"description": "Le correctif PAN-OS n'est pas appliqué sur waf-dmz-01, exposé sur Internet. EPSS 0,94 et exploitation publique constatée : le délai contractuel de correction est dépassé.",
			"severity":    "CRITICAL", "source_service": "vuln",
			"mitre_tactics":    []string{"TA0001"},
			"mitre_techniques": []string{"T1190"},
			"affected_assets":  assets("waf-dmz-01"),
			"tags":             []string{"demo", "sla-dépassé"},
			"properties":       map[string]any{"cve": "CVE-2024-3400", "origin": "demonstration dataset"},
		},
		{
			"title":       "Courriel d'hameçonnage ciblant la trésorerie",
			"description": "Quatorze destinataires du service trésorerie, pièce jointe menant au chargeur Get2. Deux ouvertures, aucune exécution ; postes isolés le temps de la vérification.",
			"severity":    "MEDIUM", "source_service": "manual",
			"mitre_tactics":    []string{"TA0001"},
			"mitre_techniques": []string{"T1566.001"},
			"affected_assets":  assets("poste-soc-014"),
			"ioc_ids":          iocs("tresorerie@invoice-portal.example.org", "invoice-portal.example.org"),
			"tags":             []string{"demo", "hameçonnage"},
			"properties":       map[string]any{"recipients": 14, "origin": "demonstration dataset"},
		},
	}

	for _, inc := range incidents {
		if _, err := s.ensure(ctx, idx, inc["title"].(string), "soar", "/api/v1/soar/incidents", inc); err != nil {
			return err
		}
	}
	fmt.Printf("   %d incidents\n", len(idx))
	return nil
}

// ─── Attack graph ─────────────────────────────────────────────────────────────

type demoNode struct {
	Label      string
	Asset      string // the asset this node stands for, when there is one
	Type       string
	Risk       float64
	Crit       int
	Internet   bool
	Privileged bool
	Critical   bool
	CritVuln   bool
	Exploit    bool
	Vulns      int
	Zone       string
	IP         string
}

var demoNodes = []demoNode{
	{"waf-dmz-01", "waf-dmz-01", "network", 9.4, 3, true, false, false, true, true, 2, "dmz", "203.0.113.10"},
	{"vpn-gw-01", "vpn-gw-01", "network", 9.2, 3, true, false, false, true, true, 1, "dmz", "203.0.113.11"},
	{"web-ebank-01", "web-ebank-01", "asset", 8.9, 4, true, false, true, true, true, 2, "dmz", "10.20.1.11"},
	{"web-ebank-02", "web-ebank-02", "asset", 8.1, 4, true, false, true, true, true, 1, "dmz", "10.20.1.12"},
	{"k8s-node-03", "k8s-node-03", "asset", 7.6, 2, false, false, false, true, true, 2, "dmz", "10.20.1.53"},
	{"app-core-01", "app-core-01", "asset", 8.4, 4, false, false, true, true, true, 1, "core", "10.30.2.21"},
	{"db-core-01", "db-core-01", "asset", 7.2, 4, false, false, true, false, true, 1, "core", "10.30.2.31"},
	{"jump-adm-01", "jump-adm-01", "asset", 8.8, 4, false, true, true, false, true, 1, "admin", "10.10.0.50"},
	{"ad-dc-01", "ad-dc-01", "asset", 9.1, 4, false, true, true, true, true, 1, "internal", "10.10.0.5"},
	{"swift-gw-01", "swift-gw-01", "asset", 8.6, 4, false, false, true, false, true, 1, "swift", "10.40.3.41"},
	{"hsm-pay-01", "hsm-pay-01", "asset", 6.4, 4, false, false, true, false, false, 0, "swift", "10.40.3.45"},
	{"atm-switch-01", "atm-switch-01", "asset", 7.0, 4, false, false, true, false, false, 0, "monetique", "10.50.4.10"},
	{"backup-nas-01", "backup-nas-01", "asset", 7.8, 3, false, false, false, true, true, 1, "internal", "10.10.0.90"},
	{"poste-soc-014", "poste-soc-014", "asset", 6.1, 2, false, false, false, true, true, 1, "internal", "10.60.5.14"},
	{"svc-admin", "", "identity", 8.5, 4, false, true, true, false, false, 0, "admin", ""},
	{"svc-swift", "", "identity", 7.9, 4, false, true, true, false, false, 0, "swift", ""},
}

type demoEdge struct {
	From, To   string
	Type       string
	Complexity string
	Privileges string
	CVE        string
	Technique  string
}

var demoEdges = []demoEdge{
	{"waf-dmz-01", "web-ebank-01", "network_access", "LOW", "NONE", "CVE-2024-3400", "T1190"},
	{"waf-dmz-01", "web-ebank-02", "network_access", "LOW", "NONE", "CVE-2024-3400", "T1190"},
	{"vpn-gw-01", "jump-adm-01", "network_access", "LOW", "NONE", "CVE-2024-21762", "T1190"},
	{"web-ebank-01", "k8s-node-03", "network_access", "LOW", "LOW", "", "T1021"},
	{"web-ebank-01", "app-core-01", "api_call", "MEDIUM", "LOW", "CVE-2021-44228", "T1190"},
	{"web-ebank-02", "app-core-01", "api_call", "MEDIUM", "LOW", "CVE-2021-44228", "T1190"},
	{"k8s-node-03", "app-core-01", "network_access", "MEDIUM", "LOW", "CVE-2024-1086", "T1068"},
	{"app-core-01", "db-core-01", "credential_reuse", "LOW", "LOW", "", "T1078"},
	{"poste-soc-014", "ad-dc-01", "credential_reuse", "MEDIUM", "LOW", "CVE-2023-23397", "T1187"},
	{"ad-dc-01", "jump-adm-01", "trust_relationship", "LOW", "HIGH", "CVE-2020-1472", "T1068"},
	{"jump-adm-01", "swift-gw-01", "ssh", "LOW", "HIGH", "", "T1021.004"},
	{"jump-adm-01", "db-core-01", "rdp", "LOW", "HIGH", "", "T1021.001"},
	{"jump-adm-01", "atm-switch-01", "ssh", "MEDIUM", "HIGH", "", "T1021.004"},
	{"swift-gw-01", "hsm-pay-01", "api_call", "HIGH", "HIGH", "", "T1552"},
	{"backup-nas-01", "db-core-01", "credential_reuse", "MEDIUM", "LOW", "CVE-2023-34362", "T1078"},
	{"svc-admin", "jump-adm-01", "credential_reuse", "LOW", "LOW", "", "T1078.003"},
	{"svc-swift", "swift-gw-01", "credential_reuse", "LOW", "LOW", "", "T1078.003"},
	{"web-ebank-01", "backup-nas-01", "smb", "MEDIUM", "LOW", "", "T1021.002"},
}

func (s *seeder) seedAttackGraph(ctx context.Context) error {
	step("Attack graph")
	s.nodes = make(map[string]uuid.UUID, len(demoNodes))

	for _, n := range demoNodes {
		// A node points back at whatever it stands for. For an asset that is
		// the asset's own identifier, so the graph and the inventory agree;
		// for anything else a stable name-derived identifier keeps a second
		// run from creating a twin.
		ref, ok := s.assets[n.Asset]
		if !ok {
			ref = uuid.NewSHA1(uuid.NameSpaceOID, []byte("crp-demo-node/"+n.Label))
		}
		body := map[string]any{
			"ref_id": ref, "node_type": n.Type, "label": n.Label,
			"risk_score": n.Risk, "criticality": n.Crit,
			"is_internet_facing": n.Internet, "is_privileged": n.Privileged,
			"is_critical_system": n.Critical, "has_critical_vuln": n.CritVuln,
			"has_known_exploit": n.Exploit, "open_vuln_count": n.Vulns,
			"network_zone": n.Zone, "ip_address": n.IP, "hostname": n.Label,
			"properties": map[string]any{"origin": "demonstration dataset"},
		}
		id, err := s.upsert(ctx, "attackpath", "/api/v1/attack/nodes", body)
		if err != nil {
			return fmt.Errorf("node %s: %w", n.Label, err)
		}
		s.nodes[n.Label] = id
	}

	edges := 0
	for _, e := range demoEdges {
		src, ok := s.nodes[e.From]
		dst, ok2 := s.nodes[e.To]
		if !ok || !ok2 {
			continue
		}
		body := map[string]any{
			"source_id": src, "target_id": dst, "edge_type": e.Type,
			"attack_complexity": e.Complexity, "privileges_required": e.Privileges,
			"cve_id": e.CVE, "mitre_technique": e.Technique,
			"evidence_source": "computed",
			"properties":      map[string]any{"origin": "demonstration dataset"},
		}
		if _, err := s.upsert(ctx, "attackpath", "/api/v1/attack/edges", body); err != nil {
			return fmt.Errorf("edge %s → %s: %w", e.From, e.To, err)
		}
		edges++
	}

	scenarios, err := s.index(ctx, "attackpath", "/api/v1/attack/scenarios")
	if err != nil {
		return err
	}

	node := func(label string) uuid.UUID { return s.nodes[label] }
	wanted := []map[string]any{
		{
			"name":            "De l'Internet à la passerelle SWIFT",
			"description":     "Ce qu'un attaquant qui prend pied sur un service exposé peut atteindre du périmètre de paiement.",
			"entry_node_ids":  []uuid.UUID{node("waf-dmz-01"), node("vpn-gw-01")},
			"target_node_ids": []uuid.UUID{node("swift-gw-01"), node("hsm-pay-01")},
			"max_hops":        6,
		},
		{
			"name":            "Du poste de travail au cœur bancaire",
			"description":     "Chemin partant d'un poste compromis par courriel jusqu'à la base du système central.",
			"entry_node_ids":  []uuid.UUID{node("poste-soc-014")},
			"target_node_ids": []uuid.UUID{node("db-core-01"), node("app-core-01")},
			"max_hops":        6,
		},
		{
			"name":            "De la banque en ligne au réseau des automates",
			"description":     "Chemin partant du portail public jusqu'au commutateur monétique.",
			"entry_node_ids":  []uuid.UUID{node("web-ebank-01"), node("web-ebank-02")},
			"target_node_ids": []uuid.UUID{node("atm-switch-01")},
			"max_hops":        7,
		},
	}

	run := 0
	for _, sc := range wanted {
		id, err := s.ensure(ctx, scenarios, sc["name"].(string), "attackpath", "/api/v1/attack/scenarios", sc)
		if err != nil {
			return err
		}
		// Running the scenario is the point: the paths on screen are the ones
		// this platform enumerated from the graph, not a list written here.
		var out map[string]any
		if err := s.c.post(ctx, "attackpath", fmt.Sprintf("/api/v1/attack/scenarios/%s/run", id), map[string]any{}, &out); err != nil {
			s.softFail("run "+sc["name"].(string), err)
			continue
		}
		run++
	}

	fmt.Printf("   %d nodes, %d edges, %d scenarios (%d analysed)\n",
		len(s.nodes), edges, len(scenarios), run)
	return nil
}

// ─── Compliance ───────────────────────────────────────────────────────────────

type demoControl struct {
	Framework string
	ID        string
	Domain    string
	Title     string
	Priority  string
	Automated bool
	Status    string
	Score     float64
	Note      string
}

// Les cadres que porte réellement une banque marocaine.
//
// DORA est un règlement européen : il n'oblige pas un établissement de droit
// marocain, et le citer devant un DSI de la place le disqualifie plutôt que
// l'inverse. Ce que l'audit regarde ici, c'est la DNSSI de la DGSSI, la
// loi 09-08 et la CNDP pour les données personnelles, puis PCI DSS et le CSP
// SWIFT qui s'appliquent partout où l'on traite une carte ou un virement
// international.
//
// Les intitulés de contrôle ci-dessous sont **la correspondance de la
// plateforme**, pas une citation des textes : ils nomment l'exigence sans
// prétendre reproduire la numérotation officielle d'une directive. Ce que la
// démonstration montre est le mécanisme de rattachement — un contrôle, les
// actifs concernés, un score et sa preuve — et il vaut pour n'importe quel
// référentiel qu'un client apporte.
var demoFrameworks = []map[string]any{
	{"code": "DNSSI", "name": "DNSSI — Directive Nationale de la Sécurité des Systèmes d'Information", "version": "DGSSI",
		"description": "Directive nationale marocaine applicable aux infrastructures d'importance vitale, publiée par la DGSSI."},
	{"code": "LOI0908", "name": "Loi 09-08 — protection des données à caractère personnel", "version": "CNDP",
		"description": "Loi marocaine sur la protection des personnes physiques à l'égard du traitement des données à caractère personnel, contrôlée par la CNDP."},
	{"code": "PCIDSS", "name": "PCI DSS", "version": "4.0",
		"description": "Norme de sécurité des données de l'industrie des cartes de paiement."},
	{"code": "SWIFTCSP", "name": "SWIFT Customer Security Programme", "version": "CSCF v2025",
		"description": "Cadre de contrôles obligatoires pour les utilisateurs du réseau SWIFT."},
	{"code": "ISO27001", "name": "ISO/IEC 27001", "version": "2022",
		"description": "Système de management de la sécurité de l'information."},
}

var demoControls = []demoControl{
	{"DNSSI", "DNSSI-GOUV-01", "Gouvernance SSI", "Cartographie des systèmes d'importance vitale et de leurs dépendances", "CRITICAL", false, "partial", 65, "La cartographie existe mais n'est pas revue à chaque changement d'architecture."},
	{"DNSSI", "DNSSI-VULN-01", "Gestion des vulnérabilités", "Identification continue des vulnérabilités sur le périmètre exposé", "CRITICAL", true, "compliant", 92, "Analyse hebdomadaire de l'ensemble du parc exposé."},
	{"DNSSI", "DNSSI-DETEC-01", "Détection", "Détection des anomalies et des activités inhabituelles", "HIGH", true, "compliant", 88, "Règles de corrélation en production, couverture ATT&CK mesurée."},
	{"DNSSI", "DNSSI-REPON-01", "Réponse et continuité", "Plan de réponse testé au moins une fois par an", "HIGH", false, "partial", 55, "Exercice réalisé, mais sans le prestataire d'infogérance."},
	{"DNSSI", "DNSSI-NOTIF-01", "Déclaration d'incident", "Notification à l'autorité nationale dans les délais prescrits", "CRITICAL", false, "non_compliant", 30, "Le délai de notification initiale a été dépassé lors du dernier incident majeur."},
	{"DNSSI", "DNSSI-TIERS-01", "Risque fournisseur", "Registre des prestataires critiques tenu à jour", "HIGH", false, "partial", 60, "Registre complet pour le cœur bancaire, incomplet pour les canaux digitaux."},
	{"LOI0908", "L0908-DECL-01", "Formalités préalables", "Déclaration des traitements auprès de la CNDP", "HIGH", false, "compliant", 90, "Les traitements du cœur bancaire et des canaux digitaux sont déclarés."},
	{"LOI0908", "L0908-FINA-01", "Finalité et proportionnalité", "Durée de conservation définie et appliquée par traitement", "HIGH", false, "partial", 58, "Les durées sont définies ; la purge automatique ne couvre pas les journaux applicatifs."},
	{"LOI0908", "L0908-SECU-01", "Sécurité des traitements", "Chiffrement des données personnelles au repos et en transit", "CRITICAL", true, "compliant", 86, "Chiffrement en base et TLS imposé ; deux flux internes restent en clair."},
	{"LOI0908", "L0908-DROI-01", "Droits des personnes", "Traçabilité des demandes d'accès, de rectification et d'opposition", "MEDIUM", false, "partial", 48, "Les demandes sont traitées, la preuve du délai de réponse n'est pas conservée."},
	{"LOI0908", "L0908-TRAN-01", "Transfert hors du Maroc", "Autorisation préalable de la CNDP pour tout transfert transfrontalier", "CRITICAL", false, "non_compliant", 25, "Un service d'analyse hébergé hors du Royaume traite des données clients sans autorisation."},
	{"PCIDSS", "PCI-1.2.1", "Réseau", "Restriction des flux entrants et sortants du périmètre carte", "CRITICAL", true, "compliant", 95, "Segmentation validée par le dernier test d'intrusion."},
	{"PCIDSS", "PCI-6.3.3", "Développement sécurisé", "Correctifs de sécurité critiques appliqués sous un mois", "CRITICAL", true, "non_compliant", 40, "CVE-2024-3400 ouverte au-delà du délai sur un actif du périmètre."},
	{"PCIDSS", "PCI-8.3.6", "Authentification", "Authentification multifacteur sur tous les accès administratifs", "CRITICAL", false, "partial", 70, "Couverte sur le bastion, absente sur deux consoles d'administration."},
	{"PCIDSS", "PCI-10.4.1", "Journalisation", "Revue quotidienne des journaux de sécurité", "HIGH", true, "compliant", 90, "Revue automatisée avec escalade au CSIRT."},
	{"PCIDSS", "PCI-11.3.1", "Tests", "Analyse de vulnérabilité interne trimestrielle", "HIGH", true, "compliant", 85, "Dernière campagne close sans écart bloquant."},
	{"SWIFTCSP", "CSCF-1.1", "Sécurisation de l'environnement", "Isolation de la zone SWIFT du reste du réseau", "CRITICAL", false, "partial", 60, "Isolation en place, mais le bastion d'administration est partagé avec d'autres zones."},
	{"SWIFTCSP", "CSCF-2.3", "Réduction de la surface d'attaque", "Durcissement des systèmes de la zone sécurisée", "HIGH", true, "compliant", 87, "Référentiel de durcissement appliqué et contrôlé."},
	{"SWIFTCSP", "CSCF-4.2", "Prévention de la compromission", "Authentification multifacteur pour l'accès aux applications SWIFT", "CRITICAL", false, "compliant", 100, "Jeton matériel obligatoire."},
	{"SWIFTCSP", "CSCF-6.4", "Détection", "Journalisation et détection des activités anormales", "HIGH", true, "partial", 68, "Journaux collectés, corrélation spécifique à SWIFT encore partielle."},
	{"ISO27001", "A.5.7", "Organisation", "Veille sur les menaces", "MEDIUM", true, "compliant", 90, "Flux de renseignement interne et sectoriel."},
	{"ISO27001", "A.8.8", "Technologie", "Gestion des vulnérabilités techniques", "HIGH", true, "partial", 72, "Délais tenus hors périmètre exposé."},
	{"ISO27001", "A.5.30", "Continuité", "Préparation des TIC à la continuité d'activité", "HIGH", false, "partial", 58, "Plan de reprise testé partiellement."},
}

func (s *seeder) seedCompliance(ctx context.Context) error {
	step("Compliance")

	frameworks, err := s.index(ctx, "compliance", "/api/v1/compliance/frameworks")
	if err != nil {
		return err
	}
	fwIDs := map[string]uuid.UUID{}
	for _, f := range demoFrameworks {
		code := f["code"].(string)
		id, err := s.ensure(ctx, frameworks, code, "compliance", "/api/v1/compliance/frameworks", f)
		if err != nil {
			return err
		}
		fwIDs[code] = id
		// A framework nobody activated scores nothing and shows nothing.
		if err := s.c.post(ctx, "compliance", fmt.Sprintf("/api/v1/compliance/frameworks/%s/activate", id), map[string]any{}, nil); err != nil {
			s.softFail("activate "+code, err)
		}
	}

	controls, err := s.index(ctx, "compliance", "/api/v1/compliance/controls")
	if err != nil {
		return err
	}
	s.controls = controls

	type assessment struct {
		FrameworkID uuid.UUID `json:"framework_id"`
		ControlID   uuid.UUID `json:"control_id"`
		Status      string    `json:"status"`
		Score       float64   `json:"score"`
		Notes       string    `json:"notes"`
	}
	var assessments []assessment

	for _, c := range demoControls {
		fwID, ok := fwIDs[c.Framework]
		if !ok {
			continue
		}
		id, err := s.ensure(ctx, s.controls, c.ID, "compliance", "/api/v1/compliance/controls", map[string]any{
			"framework_id": fwID, "control_id": c.ID, "domain": c.Domain,
			"title": c.Title, "description": c.Title,
			"guidance": c.Note,
			"priority": c.Priority, "is_automated": c.Automated,
		})
		if err != nil {
			return err
		}
		assessments = append(assessments, assessment{
			FrameworkID: fwID, ControlID: id,
			Status: c.Status, Score: c.Score, Notes: c.Note,
		})
	}

	if err := s.c.post(ctx, "compliance", "/api/v1/compliance/assessments/bulk",
		map[string]any{"assessments": assessments}, nil); err != nil {
		return fmt.Errorf("bulk assessments: %w", err)
	}

	risks, err := s.index(ctx, "compliance", "/api/v1/compliance/risks")
	if err != nil {
		return err
	}
	due := time.Now().UTC().AddDate(0, 3, 0)
	for _, r := range []map[string]any{
		{"title": "Compromission de la passerelle SWIFT par rebond depuis l'administration",
			"description": "Le bastion d'administration est joignable depuis la zone exposée et administre la passerelle de paiement.",
			"category":    "cybersecurity", "likelihood": 3, "impact": 5,
			"mitigation_plan":     "Dédier un bastion au périmètre SWIFT et restreindre les flux d'administration.",
			"residual_likelihood": 2, "residual_impact": 5, "due_date": due},
		{"title": "Dépassement du délai réglementaire de notification d'incident",
			"description": "Le processus de déclaration dépend d'une validation manuelle indisponible hors heures ouvrées.",
			"category":    "regulatory", "likelihood": 4, "impact": 4,
			"mitigation_plan":     "Astreinte de déclaration et modèle de notification préapprouvé.",
			"residual_likelihood": 2, "residual_impact": 4, "due_date": due},
		{"title": "Exposition prolongée d'une vulnérabilité exploitée publiquement",
			"description": "Un actif du périmètre carte reste vulnérable au-delà du délai contractuel de correction.",
			"category":    "cybersecurity", "likelihood": 4, "impact": 5,
			"mitigation_plan":     "Fenêtre de correction d'urgence et contournement au niveau du pare-feu applicatif.",
			"residual_likelihood": 2, "residual_impact": 5, "due_date": due},
		{"title": "Dépendance à un prestataire d'infogérance non couvert par le registre",
			"description": "Les canaux digitaux reposent sur un prestataire absent du registre des tiers critiques.",
			"category":    "third_party", "likelihood": 3, "impact": 4,
			"mitigation_plan":     "Compléter le registre et inscrire les clauses de résilience au contrat.",
			"residual_likelihood": 2, "residual_impact": 3, "due_date": due},
	} {
		if _, err := s.ensure(ctx, risks, r["title"].(string), "compliance", "/api/v1/compliance/risks", r); err != nil {
			return err
		}
	}

	fmt.Printf("   %d frameworks, %d controls, %d assessments, %d risks\n",
		len(fwIDs), len(s.controls), len(assessments), len(risks))
	return nil
}

// ─── Knowledge graph ──────────────────────────────────────────────────────────

func (s *seeder) seedKnowledgeGraph(ctx context.Context) error {
	step("Knowledge graph")
	idx, err := s.index(ctx, "kg", "/api/v1/kg/entities")
	if err != nil {
		return err
	}
	s.entities = idx

	type entity struct {
		Name string
		Type string
		Risk float64
		Note string
	}
	entities := []entity{
		{"Lazarus Group", "threat_actor", 9.5, "Acteur étatique visant les systèmes de paiement."},
		{"FIN7", "threat_actor", 8.4, "Groupe criminel visant la monétique."},
		{"198.51.100.23", "ip", 9.2, "Serveur de commande."},
		{"198.51.100.77", "ip", 8.0, "Relais d'exfiltration."},
		{"update-swift-secure.example", "domain", 9.4, "Domaine de typosquatting."},
		{"cdn-metrics.example.net", "domain", 8.1, "Destination d'exfiltration."},
		{"CVE-2024-3400", "vulnerability", 9.9, "Injection de commande sur la passerelle exposée."},
		{"CVE-2021-44228", "vulnerability", 9.8, "Exécution de code via journalisation."},
		{"svc-admin", "identity", 8.5, "Compte de service à privilèges sur le bastion."},
		{"svc-swift", "identity", 7.9, "Compte de service du périmètre SWIFT."},
	}

	for _, e := range entities {
		body := map[string]any{
			"entity_type": e.Type, "external_id": "demo/" + e.Name, "name": e.Name,
			"description": e.Note, "risk_score": e.Risk, "confidence": 0.9,
			"tags":       []string{"demo"},
			"properties": map[string]any{"origin": "demonstration dataset"},
		}
		if _, err := s.ensure(ctx, s.entities, e.Name, "kg", "/api/v1/kg/entities", body); err != nil {
			return err
		}
	}

	// The assets are already entities elsewhere; giving them a node here is
	// what lets a neighbour query walk from an indicator to what it touched.
	for _, a := range demoAssets {
		body := map[string]any{
			"entity_type": "asset", "external_id": "asset/" + a.Name, "name": a.Name,
			"description": a.Hostname, "risk_score": float64(a.Criticality) * 2.0,
			"confidence": 1.0, "tags": []string{"demo"},
			"properties": map[string]any{"hostname": a.Hostname, "ip": a.IP, "zone": a.Zone},
		}
		if _, err := s.ensure(ctx, s.entities, a.Name, "kg", "/api/v1/kg/entities", body); err != nil {
			return err
		}
	}

	links := []struct{ From, To, Type string }{
		{"Lazarus Group", "198.51.100.23", "USES"},
		{"Lazarus Group", "update-swift-secure.example", "USES"},
		{"FIN7", "198.51.100.77", "USES"},
		{"FIN7", "cdn-metrics.example.net", "USES"},
		{"update-swift-secure.example", "198.51.100.23", "RESOLVES_TO"},
		{"cdn-metrics.example.net", "198.51.100.77", "RESOLVES_TO"},
		{"198.51.100.23", "jump-adm-01", "COMMUNICATES_WITH"},
		{"198.51.100.77", "backup-nas-01", "COMMUNICATES_WITH"},
		{"waf-dmz-01", "CVE-2024-3400", "HAS_VULNERABILITY"},
		{"web-ebank-01", "CVE-2021-44228", "HAS_VULNERABILITY"},
		{"app-core-01", "CVE-2021-44228", "HAS_VULNERABILITY"},
		{"Lazarus Group", "swift-gw-01", "TARGETS"},
		{"svc-admin", "jump-adm-01", "BELONGS_TO"},
		{"svc-swift", "swift-gw-01", "BELONGS_TO"},
		{"web-ebank-01", "app-core-01", "CONNECTS_TO"},
		{"app-core-01", "db-core-01", "CONNECTS_TO"},
		{"jump-adm-01", "swift-gw-01", "CONNECTS_TO"},
	}

	from := time.Now().UTC().Add(-30 * 24 * time.Hour)
	rels := 0
	for _, l := range links {
		src, ok := s.entities[l.From]
		dst, ok2 := s.entities[l.To]
		if !ok || !ok2 {
			continue
		}
		body := map[string]any{
			"source_id": src, "target_id": dst, "relationship_type": l.Type,
			"weight": 1.0, "confidence": 0.9, "evidence_source": "manual",
			"valid_from": from,
			"properties": map[string]any{"origin": "demonstration dataset"},
		}
		if _, err := s.upsert(ctx, "kg", "/api/v1/kg/relationships", body); err != nil {
			return fmt.Errorf("%s -%s-> %s: %w", l.From, l.Type, l.To, err)
		}
		rels++
	}

	fmt.Printf("   %d entities, %d relationships\n", len(s.entities), rels)
	return nil
}

// jsonEventLine renders one raw event the way a connector would send it: a
// JSON document the collector's own parser has to read.
func jsonEventLine(fields map[string]any) string {
	raw, err := json.Marshal(fields)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
