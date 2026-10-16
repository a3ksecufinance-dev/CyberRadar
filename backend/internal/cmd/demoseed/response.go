package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The response file and the integration surface.
//
// The incident response module is the formal record: a numbered file, a
// playbook, a forensic timeline and the two figures a supervisor asks for —
// how long it took to see the attack, and how long to recover from it. The
// orchestration module (SOAR, seeded in analysis.go) holds the working
// alerts; this one holds the file that survives them and goes to the
// regulator.
//
// The API gateway is the other half of the same story for an integrator: the
// keys through which another system reads this one, and the webhooks through
// which this one pushes into a ticketing tool.

var demoPlaybooks = []struct {
	Name, Description, Type, Severity string
	Hours                             int
	Tasks                             []map[string]any
}{
	{"PB-RANSOMWARE-01 — Chiffrement d'un périmètre serveur",
		"Confinement, éradication et reprise sur un chiffrement touchant un ou plusieurs serveurs. Conçu pour le périmètre bureautique et les serveurs de fichiers ; le core banking relève du plan de continuité.",
		"ransomware", "critical", 48,
		[]map[string]any{
			{"phase": "containment", "title": "Isoler les machines touchées du réseau", "task_type": "containment", "priority": 1},
			{"phase": "containment", "title": "Suspendre les comptes de service utilisés par la propagation", "task_type": "containment", "priority": 1},
			{"phase": "analysis", "title": "Identifier la souche et le vecteur d'entrée", "task_type": "investigation", "priority": 1},
			{"phase": "containment", "title": "Vérifier l'intégrité et l'isolation des sauvegardes", "task_type": "containment", "priority": 1},
			{"phase": "communication", "title": "Informer la direction générale et activer la cellule de crise", "task_type": "communication", "priority": 1},
			{"phase": "eradication", "title": "Reconstruire les machines à partir d'images saines", "task_type": "eradication", "priority": 2},
			{"phase": "recovery", "title": "Restaurer les données depuis la dernière sauvegarde vérifiée", "task_type": "recovery", "priority": 2},
			{"phase": "communication", "title": "Notifier Bank Al-Maghrib et la CNDP si des données personnelles sont touchées", "task_type": "communication", "priority": 1},
			{"phase": "lessons_learned", "title": "Rédiger le retour d'expérience sous quinze jours", "task_type": "documentation", "priority": 3},
		}},
	{"PB-ACCES-PRIV-01 — Compromission d'un accès privilégié",
		"Réponse à une session administrateur ouverte depuis une origine non attendue, sur un bastion ou un compte à hauts privilèges.",
		"account_compromise", "critical", 12,
		[]map[string]any{
			{"phase": "containment", "title": "Couper la session et suspendre le compte", "task_type": "containment", "priority": 1},
			{"phase": "analysis", "title": "Reconstituer les actions de la session depuis l'enregistrement du bastion", "task_type": "investigation", "priority": 1},
			{"phase": "containment", "title": "Renouveler les secrets auxquels la session donnait accès", "task_type": "containment", "priority": 1},
			{"phase": "analysis", "title": "Rechercher les rebonds vers les zones monétique et SWIFT", "task_type": "investigation", "priority": 1},
			{"phase": "eradication", "title": "Retirer tout accès créé pendant la session", "task_type": "eradication", "priority": 2},
			{"phase": "lessons_learned", "title": "Revoir les conditions d'ouverture de session sur le bastion", "task_type": "documentation", "priority": 3},
		}},
	{"PB-FUITE-DONNEES-01 — Fuite de données personnelles",
		"Traitement d'une exposition de données personnelles, du constat à la notification. Les délais sont ceux de la loi 09-08 et des engagements de la banque.",
		"data_breach", "high", 72,
		[]map[string]any{
			{"phase": "containment", "title": "Arrêter l'exposition et conserver les traces", "task_type": "containment", "priority": 1},
			{"phase": "analysis", "title": "Qualifier la nature et le volume des données exposées", "task_type": "investigation", "priority": 1},
			{"phase": "analysis", "title": "Déterminer si des personnes sont identifiables", "task_type": "investigation", "priority": 1},
			{"phase": "communication", "title": "Saisir le délégué à la protection des données", "task_type": "communication", "priority": 1},
			{"phase": "communication", "title": "Préparer la notification à la CNDP", "task_type": "communication", "priority": 2},
			{"phase": "recovery", "title": "Corriger la cause et vérifier qu'elle ne subsiste pas ailleurs", "task_type": "recovery", "priority": 2},
			{"phase": "documentation", "title": "Verser le dossier au registre des violations", "task_type": "documentation", "priority": 3},
		}},
	{"PB-HAMECONNAGE-01 — Campagne d'hameçonnage ciblée",
		"Traitement d'une campagne visant les collaborateurs ou les clients, du signalement au retrait du domaine.",
		"phishing", "medium", 8,
		[]map[string]any{
			{"phase": "containment", "title": "Bloquer le domaine et retirer les messages des boîtes", "task_type": "containment", "priority": 1},
			{"phase": "analysis", "title": "Identifier les destinataires et ceux qui ont cliqué", "task_type": "investigation", "priority": 2},
			{"phase": "containment", "title": "Réinitialiser les identifiants des comptes exposés", "task_type": "containment", "priority": 1},
			{"phase": "communication", "title": "Demander le retrait du domaine à l'hébergeur", "task_type": "communication", "priority": 2},
			{"phase": "communication", "title": "Avertir la clientèle si la campagne la vise", "task_type": "communication", "priority": 2},
		}},
}

// The response file. Each incident names the playbook it is run under and the
// assets it touches, and carries a timeline — which is what the detection
// delay is derived from.
var demoIRIncidents = []struct {
	Title, Description, Type, Severity, Source, SourceRef, Vector, Playbook string
	Status, Impact, Lead                                                    string
	Priority                                                                int
	DetectedHoursAgo                                                        int
	AttackStartedMinutesBefore                                              int
	Systems, Users, Data, Tactics, Techniques, Team                         []string
	Contained, Exfiltrated, Notifiable                                      bool
	Timeline                                                                []irEvent
}{
	{
		Title:       "Compromission d'un accès privilégié sur le bastion d'administration",
		Description: "Une session administrateur a été ouverte sur jump-adm-01 depuis 198.51.100.23 avec le compte svc-admin. La session a duré onze minutes et a comporté une énumération de l'annuaire puis une tentative de rebond vers la passerelle SWIFT, rejetée par le filtrage de zone.",
		Type:        "account_compromise", Severity: "critical", Priority: 1,
		Source: "SIEM — règle d'authentification privilégiée externe", SourceRef: "ALT-2026-1184",
		Vector: "Identifiants valides", Playbook: "PB-ACCES-PRIV-01",
		Status: "contained", Impact: "Aucun mouvement de fonds. Secrets du compte de service renouvelés.",
		Lead:    "Anas Belkacem",
		Systems: []string{"jump-adm-01", "ad-dc-01", "swift-gw-01"},
		Users:   []string{"svc-admin"}, Data: []string{},
		Tactics: []string{"TA0001", "TA0008"}, Techniques: []string{"T1078", "T1021.001"},
		Team:      []string{"Anas Belkacem", "Karim Alaoui", "Hicham Oulad Brahim"},
		Contained: true, Exfiltrated: false, Notifiable: false,
		DetectedHoursAgo: 6, AttackStartedMinutesBefore: 37,
		Timeline: []irEvent{
			{-37, "attacker_activity", "Première authentification du compte svc-admin depuis 198.51.100.23", "attacker",
				"Authentification réussie sur le bastion. Le compte n'avait jamais été utilisé depuis une adresse hors du réseau d'administration."},
			{-31, "attacker_activity", "Énumération de l'annuaire depuis la session ouverte", "attacker",
				"Requêtes LDAP sur les groupes d'administration du domaine."},
			{-26, "attacker_activity", "Tentative de connexion à la passerelle SWIFT", "attacker",
				"Connexion rejetée par le filtrage entre la zone d'administration et la zone de paiement."},
			{0, "detection", "Règle SIEM déclenchée sur l'authentification privilégiée externe", "système",
				"Corrélation entre l'adresse source et un indicateur du renseignement sur la menace."},
			{4, "action", "Session coupée et compte svc-admin suspendu", "SOC",
				"Coupure depuis la console du bastion, suspension du compte dans l'annuaire."},
			{22, "action", "Renouvellement des secrets accessibles depuis la session", "Infrastructure",
				"Quatorze secrets renouvelés dans le coffre."},
			{95, "recovery", "Enregistrement de session versé au dossier", "SOC",
				"L'enregistrement intégral de la session a été exporté et scellé."},
		},
	},
	{
		Title:       "Chiffrement de deux serveurs de fichiers du périmètre bureautique",
		Description: "Chiffrement constaté sur file-srv-01 et sur un partage secondaire, à partir d'un poste de la direction commerciale. Propagation stoppée par l'isolement du segment. Restauration depuis la sauvegarde de la veille, 4 heures de perte de données sur les partages concernés.",
		Type:        "ransomware", Severity: "critical", Priority: 1,
		Source: "EDR — détection comportementale", SourceRef: "ALT-2026-1102",
		Vector: "Pièce jointe malveillante", Playbook: "PB-RANSOMWARE-01",
		Status: "recovered", Impact: "4 heures de perte de données sur deux partages. Aucune donnée exfiltrée.",
		Lead:    "Karim Alaoui",
		Systems: []string{"file-srv-01", "poste-soc-014"},
		Users:   []string{"mchraibi", "obennani"}, Data: []string{"Partages bureautiques"},
		Tactics: []string{"TA0040", "TA0008"}, Techniques: []string{"T1486", "T1021.002"},
		Team:      []string{"Karim Alaoui", "Anas Belkacem", "Fatima Zahra Idrissi"},
		Contained: true, Exfiltrated: false, Notifiable: false,
		DetectedHoursAgo: 96, AttackStartedMinutesBefore: 142,
		Timeline: []irEvent{
			{-142, "attacker_activity", "Ouverture d'une pièce jointe sur un poste de la direction commerciale", "attacker",
				"Document portant une macro, reçu d'un expéditeur usurpant un correspondant connu."},
			{-118, "attacker_activity", "Déploiement de l'outil de chiffrement sur le partage", "attacker",
				"Écriture massive sur le partage depuis le poste contaminé."},
			{0, "detection", "Détection comportementale sur le rythme d'écriture", "système",
				"L'agent de poste a signalé un rythme de modification de fichiers hors de tout profil connu."},
			{6, "action", "Isolement du segment bureautique concerné", "SOC",
				"Mise en quarantaine réseau des deux machines et du partage."},
			{40, "action", "Vérification de l'isolation des sauvegardes", "Infrastructure",
				"Les sauvegardes hors site n'étaient pas joignables depuis le segment touché."},
			{180, "recovery", "Restauration des partages depuis la sauvegarde de la veille", "Infrastructure",
				"Restauration complète des deux partages."},
			{1440, "note", "Retour d'expérience présenté au comité sécurité", "RSSI",
				"Deux actions retenues : filtrage des macros à la passerelle et séparation des droits sur les partages."},
		},
	},
	{
		Title:       "Exposition de données personnelles dans la base de recette du CRM",
		Description: "La base de recette du CRM est une copie intégrale de la production : 184 000 clients avec numéro de CIN. Volume non chiffré, sans contrôle d'accès, joignable depuis le réseau des études. Aucun accès anormal n'a été retrouvé dans les journaux conservés.",
		Type:        "data_leak", Severity: "high", Priority: 2,
		Source: "DSPM — analyse de classification", SourceRef: "DSPM-2026-0043",
		Vector: "Erreur de configuration", Playbook: "PB-FUITE-DONNEES-01",
		Status: "investigating", Impact: "184 000 enregistrements exposés au réseau interne des études. Pas d'accès externe constaté.",
		Lead:    "Loubna Harrak",
		Systems: []string{"db-crm-rec"},
		Users:   []string{}, Data: []string{"CIN", "Adresse", "Téléphone"},
		Tactics: []string{"TA0009"}, Techniques: []string{"T1530"},
		Team:      []string{"Loubna Harrak", "Karim Alaoui"},
		Contained: false, Exfiltrated: false, Notifiable: true,
		DetectedHoursAgo: 30, AttackStartedMinutesBefore: 0,
		Timeline: []irEvent{
			{0, "detection", "Classification automatique sur la base de recette", "système",
				"L'analyse a identifié une colonne de CIN dans un environnement déclaré non sensible."},
			{35, "action", "Retrait de l'accès réseau depuis les études", "Infrastructure",
				"Filtrage posé sur le port de la base en attendant l'anonymisation."},
			{120, "communication", "Saisine du délégué à la protection des données", "Conformité",
				"Dossier ouvert ; qualification en cours au regard de la loi 09-08."},
			{300, "note", "Recherche d'accès anormaux dans les journaux conservés", "SOC",
				"Quatre-vingt-dix jours de journaux examinés, aucun accès hors de l'équipe projet."},
		},
	},
	{
		Title:       "Campagne d'hameçonnage par SMS visant la clientèle",
		Description: "Campagne reprenant l'identité visuelle de la banque, renvoyant vers almassira-securite.example. Signalée par quatorze clients et détectée sur un terminal du parc. Domaine bloqué à la passerelle, retrait demandé à l'hébergeur.",
		Type:        "phishing", Severity: "medium", Priority: 3,
		Source: "Signalement client", SourceRef: "TKT-2026-8871",
		Vector: "SMS", Playbook: "PB-HAMECONNAGE-01",
		Status: "closed", Impact: "Aucun identifiant client confirmé comme compromis.",
		Lead:    "Hicham Oulad Brahim",
		Systems: []string{"waf-dmz-01"},
		Users:   []string{}, Data: []string{},
		Tactics: []string{"TA0001"}, Techniques: []string{"T1566.002"},
		Team:      []string{"Hicham Oulad Brahim", "Meriem Chraibi"},
		Contained: true, Exfiltrated: false, Notifiable: false,
		DetectedHoursAgo: 150, AttackStartedMinutesBefore: 420,
		Timeline: []irEvent{
			{-420, "attacker_activity", "Enregistrement du domaine almassira-securite.example", "attacker",
				"Domaine déposé le matin même, certificat émis dans la foulée."},
			{0, "detection", "Premier signalement client", "client",
				"Capture d'écran du SMS transmise au centre de relation client."},
			{25, "action", "Blocage du domaine à la passerelle et au WAF", "SOC",
				"Domaine et adresse IP ajoutés aux listes de blocage."},
			{90, "communication", "Demande de retrait adressée à l'hébergeur", "SOC",
				"Demande envoyée avec les éléments de preuve."},
			{1900, "recovery", "Domaine retiré par l'hébergeur", "système",
				"Le domaine ne résout plus. Dossier clos."},
		},
	},
	{
		Title:       "Balayage du réseau technique depuis le réseau bureautique",
		Description: "312 connexions vers les ports Modbus et BACnet en quatre minutes, émises par le poste compromis dans l'incident de chiffrement. Le pare-feu de séparation a tout rejeté ; aucun automate n'a été joint.",
		Type:        "vulnerability_exploit", Severity: "high", Priority: 2,
		Source: "Pare-feu OT", SourceRef: "OT-SCAN-001",
		Vector: "Rebond depuis le poste bureautique", Playbook: "PB-ACCES-PRIV-01",
		Status: "eradicated", Impact: "Aucun automate joint. La séparation de zone a tenu.",
		Lead:    "Rachid Amrani",
		Systems: []string{"fw-ot-dc1", "poste-soc-014"},
		Users:   []string{}, Data: []string{},
		Tactics: []string{"TA0007"}, Techniques: []string{"T1046"},
		Team:      []string{"Rachid Amrani", "Anas Belkacem"},
		Contained: true, Exfiltrated: false, Notifiable: false,
		DetectedHoursAgo: 94, AttackStartedMinutesBefore: 12,
		Timeline: []irEvent{
			{-12, "attacker_activity", "Premier paquet vers le port 502 du réseau technique", "attacker",
				"Émis par le poste déjà identifié dans l'incident de chiffrement."},
			{0, "detection", "Alarme du pare-feu de séparation", "système",
				"Seuil de connexions rejetées dépassé sur la zone technique."},
			{8, "action", "Confirmation que le poste source est celui de l'incident en cours", "SOC",
				"Les deux dossiers sont traités ensemble."},
			{60, "action", "Vérification de l'intégrité des automates de la zone", "Infrastructure",
				"Aucune consigne modifiée, aucun micrologiciel altéré."},
		},
	},
	{
		Title:       "Terminal de prestataire rooté détecté sur le parc de guichets",
		Description: "Le terminal personnel d'un prestataire d'exploitation des guichets a été détecté rooté, sans verrouillage d'écran et avec un correctif de sécurité de 2023. Accès retiré, interventions suspendues jusqu'à la fourniture de terminaux gérés.",
		Type:        "supply_chain", Severity: "high", Priority: 2,
		Source: "Protection mobile", SourceRef: "MOB-2026-0219",
		Vector: "Terminal non géré", Playbook: "PB-ACCES-PRIV-01",
		Status: "open", Impact: "Aucun accès anormal constaté sur le parc de guichets.",
		Lead:    "Rachid Amrani",
		Systems: []string{"gab-switch-ctrl"},
		Users:   []string{"arifi"}, Data: []string{},
		Tactics: []string{"TA0001"}, Techniques: []string{"T1200"},
		Team:      []string{"Rachid Amrani", "Loubna Harrak"},
		Contained: false, Exfiltrated: false, Notifiable: false,
		DetectedHoursAgo: 12, AttackStartedMinutesBefore: 0,
		Timeline: []irEvent{
			{0, "detection", "Signalement de la protection mobile sur le terminal du prestataire", "système",
				"Binaire su et gestionnaire de superutilisateur détectés."},
			{18, "action", "Retrait des accès du prestataire au réseau de guichets", "SOC",
				"Comptes et certificats d'intervention révoqués."},
			{150, "communication", "Convocation du prestataire au titre du dispositif fournisseurs", "Achats",
				"Constat rattaché à l'évaluation 2025 restée sans plan d'action."},
		},
	},
}

// irEvent is one line of the forensic timeline, placed relative to the
// detection: negative before it, positive after.
type irEvent struct {
	Minutes                     int
	Type, Title, Actor, Details string
}

func (s *seeder) seedResponseFile(ctx context.Context) error {
	step("Dossier de réponse à incident")
	now := time.Now().UTC()

	pIdx, err := s.index(ctx, "ir", "/api/v1/ir/playbooks")
	if err != nil {
		return err
	}
	playbooks := make(map[string]uuid.UUID, len(demoPlaybooks))
	for _, p := range demoPlaybooks {
		tasks := make([]any, 0, len(p.Tasks))
		for _, t := range p.Tasks {
			tasks = append(tasks, t)
		}
		id, err := s.ensure(ctx, pIdx, p.Name, "ir", "/api/v1/ir/playbooks", map[string]any{
			"name": p.Name, "description": p.Description,
			"incident_type": p.Type, "severity": p.Severity,
			"tasks": tasks, "estimated_hours": p.Hours,
		})
		if err != nil {
			return err
		}
		playbooks[p.Name] = id
	}

	iIdx, err := s.index(ctx, "ir", "/api/v1/ir/incidents")
	if err != nil {
		return err
	}
	for _, inc := range demoIRIncidents {
		detected := now.Add(-time.Duration(inc.DetectedHoursAgo) * time.Hour)
		body := map[string]any{
			"title": inc.Title, "description": inc.Description,
			"incident_type": inc.Type, "severity": inc.Severity, "priority": inc.Priority,
			"source": inc.Source, "source_ref": inc.SourceRef,
			"affected_systems": nonNil(inc.Systems), "affected_users": nonNil(inc.Users),
			"affected_data": nonNil(inc.Data), "attack_vector": inc.Vector,
			"detected_at": detected, "tags": []string{"demo"},
		}
		if id, ok := playbooks[inc.Playbook]; ok {
			body["playbook_id"] = id
		}
		id, err := s.ensure(ctx, iIdx, inc.Title, "ir", "/api/v1/ir/incidents", body)
		if err != nil {
			return err
		}

		// The timeline first: both figures the screen shows are derived from
		// it — the detection delay from the earliest attacker step, the
		// recovery time from the recovery event — so it has to be written
		// before the file is advanced and closed.
		written, err := s.timelineTitles(ctx, id)
		if err != nil {
			return err
		}
		for _, e := range inc.Timeline {
			if written[e.Title] {
				s.reused++
				continue
			}
			actorType := "analyst"
			switch e.Type {
			case "attacker_activity":
				actorType = "attacker"
			case "detection":
				actorType = "system"
			}
			if err := s.c.post(ctx, "ir",
				fmt.Sprintf("/api/v1/ir/incidents/%s/timeline", id),
				map[string]any{
					"event_time": detected.Add(time.Duration(e.Minutes) * time.Minute),
					"event_type": e.Type, "title": e.Title, "description": e.Details,
					"actor": e.Actor, "actor_type": actorType,
					"source_system": inc.Source, "is_verified": true,
				}, nil); err != nil {
				return fmt.Errorf("timeline for %q: %w", inc.Title, err)
			}
			s.written++
		}

		// Then the state of the file. Status is set last because the service
		// stamps a date — and computes the time to recover — on the
		// transition, not on the value.
		update := map[string]any{
			"status": inc.Status, "is_contained": inc.Contained,
			"data_exfiltrated": inc.Exfiltrated, "estimated_impact": inc.Impact,
			"lead_name":             inc.Lead,
			"team_members":          nonNil(inc.Team),
			"mitre_tactics":         nonNil(inc.Tactics),
			"mitre_techniques":      nonNil(inc.Techniques),
			"requires_notification": inc.Notifiable,
		}
		if err := s.c.patch(ctx, "ir", "/api/v1/ir/incidents/"+id.String(), update, nil); err != nil {
			return fmt.Errorf("state of %q: %w", inc.Title, err)
		}
	}
	return nil
}

// timelineTitles is what this incident's timeline already holds, so a second
// run adds nothing twice.
//
// Counting the events instead would never write anything: the service records
// "Incident detected" on the incident's own creation, so the timeline is
// already one line long before the first forensic event is posted. The
// titles are the key; they are unique within one incident's timeline, which
// is the only scope that matters here.
func (s *seeder) timelineTitles(ctx context.Context, incident uuid.UUID) (map[string]bool, error) {
	var rows []map[string]any
	if err := s.c.get(ctx, "ir",
		fmt.Sprintf("/api/v1/ir/incidents/%s/timeline", incident), nil, &rows); err != nil {
		return nil, fmt.Errorf("read the timeline: %w", err)
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		if title, ok := r["title"].(string); ok {
			out[title] = true
		}
	}
	return out, nil
}

// ─── The integration surface ─────────────────────────────────────────────────

var demoAPIKeys = []struct {
	Name, Description string
	Scopes            []string
	RPM, RPD          int
}{
	{"ServiceNow — création de tickets", "Clé utilisée par l'intégration ServiceNow pour créer et mettre à jour les tickets d'incident.",
		[]string{"read", "write"}, 120, 50000},
	{"Tableau de bord direction", "Lecture seule des indicateurs consolidés pour le tableau de bord de la direction générale.",
		[]string{"read"}, 60, 10000},
	{"SOC infogéré — lecture des alertes", "Accès du prestataire de supervision aux alertes et aux incidents, en lecture.",
		[]string{"read"}, 600, 400000},
	{"Chaîne de livraison — publication des SBOM", "Dépôt des SBOM à chaque livraison par la chaîne d'intégration continue.",
		[]string{"write"}, 30, 2000},
	{"Collecteur d'agence", "Clé portée par les collecteurs déployés en agence pour l'envoi des journaux.",
		[]string{"write"}, 3000, 2000000},
}

var demoWebhooks = []struct {
	Name, URL, Description string
	Events                 []string
}{
	{"ServiceNow — incidents critiques", "https://almassira.service-now.example/api/crp/incident",
		"Ouverture automatique d'un ticket pour tout incident créé au niveau critique.",
		[]string{"incident.created", "alert.created"}},
	{"Cellule de crise — notification", "https://notify.almassira.ma/hooks/cellule-crise",
		"Notification de la cellule de crise sur création d'incident.",
		[]string{"incident.created"}},
	{"Renseignement sur la menace — correspondances", "https://ti.almassira.ma/hooks/ioc-match",
		"Remontée des correspondances d'indicateurs vers la plateforme de renseignement interne.",
		[]string{"ioc.matched"}},
	{"Gestion des vulnérabilités — nouvelles découvertes", "https://vulnops.almassira.ma/hooks/finding",
		"Alimentation du suivi de remédiation à chaque vulnérabilité découverte.",
		[]string{"vuln.found", "anomaly.detected"}},
}

func (s *seeder) seedIntegrationSurface(ctx context.Context) error {
	step("Surface d'intégration")

	kIdx, err := s.index(ctx, "apifw", "/api/v1/apifw/keys")
	if err != nil {
		return err
	}
	for _, k := range demoAPIKeys {
		// A key's secret is shown once and never again. The demonstration
		// does not need it — nothing here calls back in — so it is created
		// and deliberately not recorded anywhere.
		if _, err := s.ensure(ctx, kIdx, k.Name, "apifw", "/api/v1/apifw/keys", map[string]any{
			"name": k.Name, "description": k.Description, "scopes": k.Scopes,
			"rate_limit_rpm": k.RPM, "rate_limit_rpd": k.RPD,
		}); err != nil {
			return err
		}
	}

	wIdx, err := s.index(ctx, "apifw", "/api/v1/apifw/webhooks")
	if err != nil {
		return err
	}
	for _, w := range demoWebhooks {
		id, err := s.ensure(ctx, wIdx, w.Name, "apifw", "/api/v1/apifw/webhooks", map[string]any{
			"name": w.Name, "url": w.URL, "description": w.Description,
			"events": w.Events,
		})
		if err != nil {
			return err
		}
		// Declared, not activated — which is what an integrator configures
		// before go-live, and the only honest state here.
		//
		// These four endpoints are the bank's own systems; none of them
		// exists in a demonstration sandbox. Left active, the dispatcher
		// faithfully attempts every event and fails: one run left eleven
		// thousand failed deliveries behind, and the screen reported a
		// delivery rate of zero per cent — true, and about the platform's
		// own test environment rather than about the platform.
		if err := s.c.post(ctx, "apifw",
			"/api/v1/apifw/webhooks/"+id.String()+"/disable", nil, nil); err != nil {
			return fmt.Errorf("mettre %q en attente d'activation: %w", w.Name, err)
		}
	}
	return nil
}
