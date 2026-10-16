package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The suppliers the bank depends on, and the software it ships without
// having written.
//
// Two inventories that answer the same supervisory question from opposite
// ends: who can hurt us from outside, and what is inside what we run. The
// vendors carry a tier — how much of the bank stops when they do — and a
// score that only a completed assessment can move. The components carry the
// vulnerabilities their ecosystems published.
//
// The vendor names are invented, with one deliberate exception: the
// international payment network and the card schemes are named because a
// Moroccan bank's supplier list without them would not be recognisable. No
// statement is made about any of them; the assessment results below are
// demonstration data.

type demoVendor struct {
	Name     string
	Website  string
	Type     string // software | hardware | cloud | managed_service | contractor | open_source | data_provider | other
	Tier     int    // 1 = the bank stops, 4 = an inconvenience
	Contact  string
	Email    string
	Phone    string
	SOC2     bool
	ISO27001 bool
	PCIDSS   bool
	// The last assessment: its grade out of a hundred and how many of its
	// findings were critical. Nil means never assessed.
	Score    int
	Critical int
	Assessed bool
	DaysAgo  int
	Notes    string
}

var demoVendors = []demoVendor{
	{"Atlas Core Banking", "https://atlas-core.example", "software", 1,
		"Direction des comptes", "comptes@atlas-core.example", "+212 522 00 00 01",
		true, true, false, 82, 0, true, 95,
		"Éditeur du socle bancaire. Hébergement sur site, maintenance à distance par tunnel dédié."},
	{"Détroit Monétique", "https://detroit-monetique.example", "managed_service", 1,
		"Cellule exploitation", "exploitation@detroit-monetique.example", "+212 522 00 00 02",
		true, true, true, 88, 0, true, 40,
		"Traitement monétique et personnalisation des cartes. Hébergeur du commutateur de secours."},
	{"SWIFT", "https://www.swift.com", "data_provider", 1,
		"Relation adhérents", "", "",
		false, true, false, 0, 0, false, 0,
		"Réseau de messagerie financière. Attestation annuelle CSP à produire, pas d'évaluation fournisseur au sens du dispositif."},
	{"Chérifienne Hébergement", "https://cherifienne-hebergement.example", "cloud", 1,
		"Service clients grands comptes", "grandscomptes@cherifienne-hebergement.example", "+212 537 00 00 03",
		true, true, false, 71, 1, true, 210,
		"Hébergeur du site de repli de Rabat. Évaluation de 2025 : une non-conformité majeure sur la ségrégation des sauvegardes."},
	{"Maghreb Sécurité Managée", "https://maghreb-secmanagee.example", "managed_service", 2,
		"Direction du SOC", "soc@maghreb-secmanagee.example", "+212 522 00 00 04",
		true, true, false, 76, 0, true, 150,
		"Supervision de sécurité en heures non ouvrées. Accès distant au SIEM en lecture."},
	{"GAB Services Maroc", "https://gab-services.example", "contractor", 2,
		"Planning interventions", "interventions@gab-services.example", "+212 522 00 00 05",
		false, false, false, 48, 2, true, 320,
		"Maintenance du parc de guichets. Évaluation 2025 : terminaux d'intervention personnels, pas de gestion de flotte."},
	{"Rif Télécom Entreprises", "https://rif-telecom.example", "other", 2,
		"Service grands comptes", "entreprises@rif-telecom.example", "+212 539 00 00 06",
		false, true, false, 79, 0, true, 180,
		"Liaisons interagences et secours opérateur."},
	{"Studio Canaux Digitaux", "https://studio-digital.example", "contractor", 2,
		"Direction de projet", "projets@studio-digital.example", "+212 522 00 00 07",
		false, false, false, 61, 1, true, 70,
		"Développement de l'application mobile. Accès au dépôt applicatif et à l'environnement de recette."},
	{"Sahara Archivage", "https://sahara-archivage.example", "other", 3,
		"Service exploitation", "exploitation@sahara-archivage.example", "+212 528 00 00 08",
		false, true, false, 84, 0, true, 260,
		"Archivage physique et destruction certifiée des supports."},
	{"Doukkala Formation", "https://doukkala-formation.example", "other", 4,
		"Secrétariat", "contact@doukkala-formation.example", "+212 523 00 00 09",
		false, false, false, 90, 0, true, 300,
		"Formation réglementaire. Pas d'accès au système d'information."},
}

type demoComponent struct {
	Vendor     string // "" when it is an open-source dependency with no supplier
	Name       string
	Version    string
	Type       string // library | framework | container | os | firmware | application | api | sdk | other
	Ecosystem  string
	License    string
	Repo       string
	UsedIn     []string
	Direct     bool
	Vulns      int
	Critical   int
	EOL        bool
	Deprecated bool
}

// The inventory the builds declare. Every version below is one that really
// carried the advisories the counts refer to; the applications they are used
// in are the invented bank's.
var demoComponents = []demoComponent{
	{"", "org.apache.logging.log4j:log4j-core", "2.14.1", "library", "maven", "Apache-2.0",
		"https://github.com/apache/logging-log4j2", []string{"api-paiement", "batch-compensation"}, false, 4, 2, false, true},
	{"", "org.springframework:spring-web", "5.3.18", "framework", "maven", "Apache-2.0",
		"https://github.com/spring-projects/spring-framework", []string{"api-paiement", "portail-ebank"}, true, 3, 1, false, false},
	{"", "com.fasterxml.jackson.core:jackson-databind", "2.12.6", "library", "maven", "Apache-2.0",
		"https://github.com/FasterXML/jackson-databind", []string{"api-paiement", "api-mobile"}, false, 2, 0, false, false},
	{"", "openssl", "1.1.1n", "library", "deb", "Apache-2.0",
		"https://github.com/openssl/openssl", []string{"socle-conteneurs"}, false, 6, 1, true, false},
	{"", "lodash", "4.17.20", "library", "npm", "MIT",
		"https://github.com/lodash/lodash", []string{"portail-ebank", "console-admin"}, false, 2, 0, false, false},
	{"", "next", "13.4.7", "framework", "npm", "MIT",
		"https://github.com/vercel/next.js", []string{"portail-ebank"}, true, 3, 1, false, false},
	{"", "axios", "0.21.1", "library", "npm", "MIT",
		"https://github.com/axios/axios", []string{"application-mobile", "portail-ebank"}, true, 2, 0, false, false},
	{"", "golang.org/x/crypto", "0.16.0", "library", "go", "BSD-3-Clause",
		"https://github.com/golang/crypto", []string{"passerelle-swift"}, true, 1, 0, false, false},
	{"", "requests", "2.25.1", "library", "pypi", "Apache-2.0",
		"https://github.com/psf/requests", []string{"batch-compensation"}, true, 1, 0, false, false},
	{"", "node", "16.20.2", "os", "docker", "MIT",
		"https://github.com/nodejs/node", []string{"portail-ebank", "api-mobile"}, true, 5, 1, true, false},
	{"Atlas Core Banking", "atlas-core-runtime", "8.4.2", "application", "", "Propriétaire",
		"", []string{"core-banking"}, true, 2, 0, false, false},
	{"Atlas Core Banking", "atlas-core-connector", "3.1.0", "sdk", "maven", "Propriétaire",
		"", []string{"api-paiement", "batch-compensation"}, true, 1, 0, false, false},
	{"Détroit Monétique", "dm-switch-agent", "5.9.1", "application", "", "Propriétaire",
		"", []string{"commutateur-gab"}, true, 1, 1, false, false},
	{"Studio Canaux Digitaux", "almassira-mobile-sdk", "2.3.0", "sdk", "", "Propriétaire",
		"", []string{"application-mobile"}, true, 2, 0, false, false},
	{"", "org.apache.activemq:activemq-broker", "5.17.3", "library", "maven", "Apache-2.0",
		"https://github.com/apache/activemq", []string{"bus-messages"}, true, 2, 1, false, false},
	{"", "jquery", "3.4.1", "library", "npm", "MIT",
		"https://github.com/jquery/jquery", []string{"console-admin"}, false, 1, 0, false, true},
}

var demoSupplyAlerts = []struct {
	Vendor, Component, Type, Severity, Title, Description, Advisory, Remediation, Source string
	CVEs                                                                                 []string
	Systems                                                                              []string
}{
	{"", "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1", "new_vulnerability", "critical",
		"Log4Shell toujours présent dans deux applications de production",
		"log4j-core 2.14.1 reste déclaré dans les SBOM de l'API de paiement et du batch de compensation. La version corrige CVE-2021-44228 à partir de 2.17.1.",
		"https://logging.apache.org/log4j/2.x/security.html",
		"Relever à 2.24.x sur les deux applications, puis republier le SBOM de la chaîne de livraison.",
		"SBOM interne", []string{"CVE-2021-44228", "CVE-2021-45046"}, []string{"api-paiement", "batch-compensation"}},
	{"", "pkg:deb/openssl@1.1.1n", "eol_component", "high",
		"OpenSSL 1.1.1 en fin de support dans l'image socle",
		"La branche 1.1.1 n'est plus maintenue depuis septembre 2023. L'image socle des conteneurs l'embarque encore et porte six avis ouverts.",
		"https://www.openssl.org/policies/releasestrat.html",
		"Reconstruire l'image socle sur une base portant OpenSSL 3.x et rejouer la chaîne de tests.",
		"Analyse de l'image socle", []string{"CVE-2023-0286"}, []string{"socle-conteneurs"}},
	{"GAB Services Maroc", "", "vendor_breach", "high",
		"Prestataire GAB : terminaux d'intervention non gérés",
		"L'évaluation 2025 relève que les techniciens interviennent avec leurs terminaux personnels, hors gestion de flotte. Un de ces terminaux a depuis été détecté rooté par la protection mobile.",
		"", "Imposer des terminaux fournis et gérés, et conditionner la reprise des interventions à leur mise en place.",
		"Évaluation fournisseur", nil, []string{"parc-gab"}},
	{"", "pkg:docker/node@16.20.2", "eol_component", "high",
		"Image Node 16 en fin de vie dans deux applications exposées",
		"Node 16 est sorti du support en septembre 2023. Le portail de banque en ligne et l'API mobile tournent encore dessus.",
		"https://nodejs.org/en/about/previous-releases",
		"Migrer vers une version sous support et relancer la campagne de tests de non-régression.",
		"SBOM interne", nil, []string{"portail-ebank", "api-mobile"}},
	{"Chérifienne Hébergement", "", "policy_violation", "medium",
		"Hébergeur du site de repli : ségrégation des sauvegardes non démontrée",
		"La non-conformité majeure de l'évaluation 2025 n'est pas levée : l'hébergeur n'a pas fourni la preuve que les sauvegardes de la banque sont isolées de celles de ses autres clients.",
		"", "Obtenir la preuve d'isolation ou chiffrer les sauvegardes avec une clé détenue par la banque avant envoi.",
		"Évaluation fournisseur", nil, []string{"site-repli-rabat"}},
	{"", "pkg:npm/jquery@3.4.1", "eol_component", "medium",
		"jQuery 3.4.1 déprécié dans la console d'administration",
		"Dépendance transitive d'un composant graphique abandonné par son auteur. Un avis de type XSS reste ouvert.",
		"https://blog.jquery.com/", "Remplacer le composant graphique ou figer une version maintenue.",
		"SBOM interne", []string{"CVE-2020-11023"}, []string{"console-admin"}},
}

func (s *seeder) seedSupplyChain(ctx context.Context) error {
	step("Chaîne d'approvisionnement")
	now := time.Now().UTC()

	vIdx, err := s.index(ctx, "scs", "/api/v1/scs/vendors")
	if err != nil {
		return err
	}
	// Which suppliers have already been through the exercise. Assessments
	// have no natural key — a supplier is legitimately assessed several
	// times — so the index the other steps use cannot make this one
	// idempotent, and without this a second run files the same campaign
	// again.
	assessed, err := s.assessedVendors(ctx)
	if err != nil {
		return err
	}
	vendors := make(map[string]uuid.UUID, len(demoVendors))
	for _, v := range demoVendors {
		next := now.AddDate(1, 0, 0)
		id, err := s.ensure(ctx, vIdx, v.Name, "scs", "/api/v1/scs/vendors", map[string]any{
			"name": v.Name, "website": v.Website, "vendor_type": v.Type,
			"risk_tier": v.Tier, "contact_name": v.Contact,
			"contact_email": v.Email, "contact_phone": v.Phone,
			"has_soc2": v.SOC2, "has_iso27001": v.ISO27001, "has_pci_dss": v.PCIDSS,
			"next_assessment_at": next, "notes": v.Notes,
			"tags": []string{"demo"},
		})
		if err != nil {
			return err
		}
		vendors[v.Name] = id

		// A supplier's score is not a field one sets: it is what a completed
		// assessment leaves behind. Recording the assessment is therefore the
		// only honest way to make the supplier list rank.
		if !v.Assessed || assessed[id] {
			if v.Assessed {
				s.reused++
			}
			continue
		}
		if err := s.recordAssessment(ctx, id, v, now); err != nil {
			s.note("! évaluation %s: %v", v.Name, err)
		}
	}

	cIdx, err := s.index(ctx, "scs", "/api/v1/scs/components")
	if err != nil {
		return err
	}
	for _, c := range demoComponents {
		purl := c.PURL()
		var vendorID any
		if c.Vendor != "" {
			id, ok := vendors[c.Vendor]
			if !ok {
				return fmt.Errorf("component %q names a supplier that is not in the list: %s", c.Name, c.Vendor)
			}
			vendorID = id
		}
		id, err := s.ensure(ctx, cIdx, purl, "scs", "/api/v1/scs/components", map[string]any{
			"vendor_id": vendorID, "name": c.Name, "version": c.Version,
			"component_type": c.Type, "ecosystem": c.Ecosystem, "purl": purl,
			"license": c.License, "source_repo": c.Repo,
			"used_in": c.UsedIn, "is_direct": c.Direct,
			"tags": []string{"demo"},
		})
		if err != nil {
			return err
		}
		// The advisories, which is what the service turns into a score. A
		// component with nothing open is left alone: a count of zero posted
		// as news would mark it "scanned and clean" on no evidence.
		if c.Vulns == 0 && !c.EOL && !c.Deprecated {
			continue
		}
		if err := s.c.patch(ctx, "scs", "/api/v1/scs/components/"+id.String(), map[string]any{
			"has_known_vulns": c.Vulns > 0, "vuln_count": c.Vulns,
			"critical_vuln_count": c.Critical,
			"is_end_of_life":      c.EOL, "is_deprecated": c.Deprecated,
		}, nil); err != nil {
			return fmt.Errorf("advisories for %q: %w", purl, err)
		}
	}

	aIdx, err := s.index(ctx, "scs", "/api/v1/scs/alerts")
	if err != nil {
		return err
	}
	for _, a := range demoSupplyAlerts {
		body := map[string]any{
			"alert_type": a.Type, "severity": a.Severity,
			"title": a.Title, "description": a.Description,
			"affected_components": nonNil(a.CVEs), "affected_systems": nonNil(a.Systems),
			"cve_ids": nonNil(a.CVEs), "advisory_url": a.Advisory,
			"remediation": a.Remediation, "source": a.Source,
			"tags": []string{"demo"},
		}
		if a.Vendor != "" {
			id, ok := vendors[a.Vendor]
			if !ok {
				return fmt.Errorf("alert %q names a supplier that is not in the list: %s", a.Title, a.Vendor)
			}
			body["vendor_id"] = id
		}
		if a.Component != "" {
			if id, ok := cIdx[a.Component]; ok {
				body["component_id"] = id
			}
		}
		if _, err := s.ensure(ctx, aIdx, a.Title, "scs", "/api/v1/scs/alerts", body); err != nil {
			return err
		}
	}
	return nil
}

// assessedVendors is the set of suppliers that already carry an assessment.
func (s *seeder) assessedVendors(ctx context.Context) (map[uuid.UUID]bool, error) {
	var rows []map[string]any
	if err := s.c.get(ctx, "scs", "/api/v1/scs/assessments", nil, &rows); err != nil {
		return nil, fmt.Errorf("list the assessments: %w", err)
	}
	out := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		if id, err := uuid.Parse(fmt.Sprint(r["vendor_id"])); err == nil {
			out[id] = true
		}
	}
	return out, nil
}

// recordAssessment writes the assessment that produced a supplier's grade, and
// closes it. Closing it is the point: the service writes the supplier's
// assessment date and risk score on completion, and on nothing else.
func (s *seeder) recordAssessment(ctx context.Context, vendorID uuid.UUID, v demoVendor, now time.Time) error {
	done := now.AddDate(0, 0, -v.DaysAgo)
	kind := "security_questionnaire"
	if v.Type == "contractor" || v.Type == "managed_service" {
		kind = "on_site_visit"
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	if err := s.c.post(ctx, "scs", "/api/v1/scs/assessments", map[string]any{
		"vendor_id": vendorID, "assessment_type": kind,
		"assessor":   "Direction des achats — filière risques fournisseurs",
		"planned_at": done.AddDate(0, 0, -21), "due_at": done,
		"notes": "Campagne annuelle d'évaluation des tiers.",
	}, &created); err != nil {
		return err
	}
	s.written++

	findings := make([]any, 0, v.Critical)
	for i := 0; i < v.Critical; i++ {
		findings = append(findings, map[string]any{
			"severity": "critical",
			"summary":  "Non-conformité majeure relevée en séance, plan d'action attendu sous 90 jours.",
		})
	}
	return s.c.patch(ctx, "scs", "/api/v1/scs/assessments/"+created.ID.String(), map[string]any{
		"status": "completed", "score": v.Score,
		"risk_rating": ratingFor(v.Score), "findings": findings,
		"next_due_at":     now.AddDate(1, 0, 0),
		"recommendations": "Reconduction sous réserve de la levée des constats.",
	}, nil)
}

// PURL is the package identifier, and the key that makes a second run a no-op.
// A supplier's own software has no ecosystem to name it in, so it falls back
// to a generic form rather than to an empty key that every such component
// would share.
func (c demoComponent) PURL() string {
	if c.Ecosystem == "" {
		return "pkg:generic/" + c.Name + "@" + c.Version
	}
	return "pkg:" + c.Ecosystem + "/" + c.Name + "@" + c.Version
}

func ratingFor(score int) string {
	switch {
	case score >= 85:
		return "low"
	case score >= 70:
		return "medium"
	case score >= 55:
		return "high"
	default:
		return "critical"
	}
}

// nonNil keeps a nil slice out of the payload: the services store these as
// PostgreSQL arrays, and a JSON null is not one.
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
