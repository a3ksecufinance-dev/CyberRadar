package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The bank's industrial estate.
//
// A bank has no factory, and the first reaction to an OT module on a banking
// demonstration is that it does not apply. It does: the data centre's cooling,
// its power chain, the fire suppression, the badge readers and the camera
// recorders are industrial equipment, they sit on their own networks, they run
// firmware nobody patches, and losing them stops the core banking as surely as
// losing a server. The same is true of the cash-machine estate, which is a
// fleet of embedded systems on a dedicated network.
//
// So the zones below are a Purdue model of a data centre and a cash-machine
// network, not of a production line. That is what makes the screen legible to
// a Moroccan bank's technical management rather than borrowed from industry.

type demoZone struct {
	Name          string
	Description   string
	Type          string // dmz | control | supervisory | enterprise | safety | external | cloud
	Purdue        int
	Site          string
	AirGapped     bool
	Firewall      bool
	IDS           bool
	NetworkRanges []string
}

var demoZones = []demoZone{
	{"Supervision technique DC1", "Gestion technique centralisée du site de Casablanca : climatisation, énergie, détection incendie.",
		"supervisory", 3, "Casablanca DC1", false, true, true, []string{"10.70.1.0/24"}},
	{"Automatismes énergie DC1", "Chaîne d'alimentation : onduleurs, inverseurs de source, groupe électrogène.",
		"control", 2, "Casablanca DC1", false, true, false, []string{"10.70.2.0/24"}},
	{"Sécurité physique DC1", "Contrôle d'accès, vidéosurveillance et détection d'intrusion du site principal.",
		"control", 2, "Casablanca DC1", false, true, false, []string{"10.70.3.0/24"}},
	{"Sûreté incendie DC1", "Détection et extinction automatique. Réseau physiquement séparé, sans passerelle.",
		"safety", 1, "Casablanca DC1", true, false, false, []string{"10.70.4.0/24"}},
	{"Supervision technique DC2", "Gestion technique du site secondaire de Casablanca.",
		"supervisory", 3, "Casablanca DC2", false, true, false, []string{"10.71.1.0/24"}},
	{"Réseau GAB", "Parc de guichets automatiques des vingt-quatre agences, raccordé au commutateur monétique.",
		"control", 2, "Réseau d'agences", false, true, true, []string{"10.72.0.0/16"}},
}

type demoOTAsset struct {
	Name        string
	Description string
	Type        string // plc | hmi | rtu | sensor | historian | scada | dcs | engineering_workstation | ied | firewall | switch | gateway | safety_system | other
	Vendor      string
	Model       string
	Firmware    string
	IP          string
	Protocols   []string
	Site        string
	Zone        string
	Purdue      int
	Criticality string
	Internet    bool
	EOLInMonths int // negative means already past
}

var demoOTAssets = []demoOTAsset{
	{"gtc-dc1-scada", "Poste de supervision de la gestion technique centralisée du site principal.",
		"scada", "Schneider Electric", "EcoStruxure Building Operation", "4.0.3.112", "10.70.1.10",
		[]string{"BACnet/IP", "Modbus TCP"}, "Casablanca DC1", "Supervision technique DC1", 3, "critical", false, 18},
	{"gtc-dc1-hmi-01", "Pupitre d'exploitation en salle de supervision.",
		"hmi", "Schneider Electric", "Magelis GTO", "6.2.1", "10.70.1.21",
		[]string{"BACnet/IP"}, "Casablanca DC1", "Supervision technique DC1", 2, "high", false, 6},
	{"crac-dc1-a", "Groupe froid de la salle A. Arrêt prolongé : extinction thermique de la salle en moins d'une heure.",
		"plc", "Vertiv", "Liebert PCW", "3.4.0", "10.70.1.41",
		[]string{"Modbus TCP"}, "Casablanca DC1", "Supervision technique DC1", 1, "critical", false, -8},
	{"crac-dc1-b", "Groupe froid de la salle B.",
		"plc", "Vertiv", "Liebert PCW", "3.4.0", "10.70.1.42",
		[]string{"Modbus TCP"}, "Casablanca DC1", "Supervision technique DC1", 1, "critical", false, -8},
	{"ups-dc1-01", "Onduleur principal, chaîne A.",
		"ied", "Eaton", "93PM", "2.8.1", "10.70.2.11",
		[]string{"Modbus TCP", "SNMP"}, "Casablanca DC1", "Automatismes énergie DC1", 2, "critical", false, 24},
	{"ups-dc1-02", "Onduleur principal, chaîne B.",
		"ied", "Eaton", "93PM", "2.6.4", "10.70.2.12",
		[]string{"Modbus TCP", "SNMP"}, "Casablanca DC1", "Automatismes énergie DC1", 2, "critical", false, 24},
	{"gen-dc1-ctrl", "Automate de démarrage du groupe électrogène et de l'inverseur de source.",
		"plc", "Deep Sea Electronics", "DSE8610", "1.9.2", "10.70.2.31",
		[]string{"Modbus TCP"}, "Casablanca DC1", "Automatismes énergie DC1", 1, "critical", false, 12},
	{"acs-dc1-ctrl", "Contrôleur d'accès des salles techniques et du local SWIFT.",
		"rtu", "HID Global", "VertX EVO V2000", "3.6.1", "10.70.3.11",
		[]string{"OSDP", "TCP"}, "Casablanca DC1", "Sécurité physique DC1", 2, "high", false, -14},
	{"nvr-dc1-01", "Enregistreur vidéo des salles techniques. Soixante jours de rétention.",
		"other", "Hikvision", "DS-96128NI", "4.30.085", "10.70.3.21",
		[]string{"RTSP", "ONVIF"}, "Casablanca DC1", "Sécurité physique DC1", 2, "medium", true, -20},
	{"fire-dc1-panel", "Centrale de détection et d'extinction. Réseau séparé, aucune passerelle.",
		"safety_system", "Honeywell", "NOTIFIER NFS2-3030", "32.0", "10.70.4.10",
		[]string{"Propriétaire"}, "Casablanca DC1", "Sûreté incendie DC1", 1, "critical", false, 36},
	{"gtc-dc2-scada", "Poste de supervision du site secondaire.",
		"scada", "Siemens", "Desigo CC", "5.1.2", "10.71.1.10",
		[]string{"BACnet/IP"}, "Casablanca DC2", "Supervision technique DC2", 3, "high", false, 20},
	{"crac-dc2-a", "Groupe froid du site secondaire.",
		"plc", "Vertiv", "Liebert PCW", "3.5.2", "10.71.1.41",
		[]string{"Modbus TCP"}, "Casablanca DC2", "Supervision technique DC2", 1, "high", false, 10},
	{"gab-switch-ctrl", "Concentrateur du réseau de guichets, raccordé au commutateur monétique.",
		"gateway", "Diebold Nixdorf", "CS Gateway", "2.4.7", "10.72.0.10",
		[]string{"NDC", "TCP"}, "Réseau d'agences", "Réseau GAB", 2, "critical", false, 14},
	{"gab-cas-cfc-01", "Guichet automatique de l'agence Casablanca Finance City.",
		"other", "Diebold Nixdorf", "CS 5550", "1.8.3", "10.72.1.11",
		[]string{"NDC"}, "Casablanca Finance City", "Réseau GAB", 1, "high", false, -4},
	{"gab-rab-agd-01", "Guichet automatique de l'agence Rabat Agdal.",
		"other", "Diebold Nixdorf", "CS 5550", "1.8.3", "10.72.5.11",
		[]string{"NDC"}, "Rabat Agdal", "Réseau GAB", 1, "high", false, -4},
	{"gab-tan-med-01", "Guichet automatique de l'agence Tanger Med.",
		"other", "NCR", "SelfServ 84", "4.1.0", "10.72.11.11",
		[]string{"NDC"}, "Tanger Med", "Réseau GAB", 1, "high", false, 8},
	{"sw-ot-dc1-01", "Commutateur du réseau d'automatismes, segmenté du réseau bureautique.",
		"switch", "Cisco", "IE-3300", "17.9.4", "10.70.0.2",
		[]string{"TCP"}, "Casablanca DC1", "Automatismes énergie DC1", 2, "high", false, 30},
	{"fw-ot-dc1", "Pare-feu de séparation entre le réseau technique et le réseau d'entreprise.",
		"firewall", "Fortinet", "FortiGate 100F", "7.0.12", "10.70.0.1",
		[]string{"TCP"}, "Casablanca DC1", "Supervision technique DC1", 3, "critical", false, 16},
}

// The advisories recorded against the plant. Every identifier below is a real
// published advisory; what is invented is that this bank's equipment carries
// it. The two things an OT screen has to show that an IT one does not are
// whether availability is at stake and whether safety is.
var demoOTVulns = []struct {
	Asset, CVE, ICS, Title, Description, Severity, Impact, Workaround, PatchNotes string
	CVSS                                                                          float64
	Availability, Safety, PatchAvailable                                          bool
}{
	{"nvr-dc1-01", "CVE-2021-36260", "ICSA-21-250-02",
		"Exécution de commande sans authentification sur l'enregistreur vidéo",
		"Injection de commande dans l'interface web, exploitable sans authentification. L'équipement est joignable depuis le réseau d'entreprise et dispose d'une route sortante.",
		"critical", "Prise de contrôle de l'enregistreur, accès aux flux des salles techniques et point d'appui vers la zone de sécurité physique.",
		"Couper la route sortante et filtrer l'accès à l'interface web au seul poste d'exploitation.",
		"Micrologiciel correctif publié par le constructeur ; la version installée est antérieure.",
		9.8, true, false, true},
	{"acs-dc1-ctrl", "CVE-2023-29168", "",
		"Contrôleur d'accès au-delà de sa fin de support",
		"Le contrôleur des salles techniques et du local SWIFT ne reçoit plus de correctif depuis février 2025. Deux avis restent ouverts, dont un contournement d'authentification sur le port de configuration.",
		"high", "Ouverture non tracée des salles techniques, y compris le local hébergeant la passerelle SWIFT.",
		"Restreindre le port de configuration à la station d'administration et doubler le contrôle par un registre papier aux salles sensibles.",
		"Aucun correctif : remplacement du matériel prévu au plan d'investissement.",
		8.1, false, true, false},
	{"crac-dc1-a", "CVE-2022-30267", "ICSA-22-179-03",
		"Groupe froid : micrologiciel en fin de support, protocole sans authentification",
		"Le Modbus TCP de l'automate n'authentifie pas les commandes. Toute machine de la zone peut imposer une consigne de température.",
		"high", "Arrêt du refroidissement de la salle A : extinction thermique des baies en moins d'une heure.",
		"Liste blanche d'adresses sur le commutateur de zone et alarme de supervision sur tout écart de consigne.",
		"Branche logicielle close ; migration vers la gamme suivante à instruire.",
		7.5, true, true, false},
	{"crac-dc1-b", "CVE-2022-30267", "ICSA-22-179-03",
		"Groupe froid de la salle B : même micrologiciel, même exposition",
		"Identique à la salle A. Les deux groupes sont du même modèle et de la même version, donc une même commande les atteint tous les deux.",
		"high", "Perte simultanée du refroidissement des deux salles : la redondance ne joue pas contre cette cause.",
		"Même mesure que la salle A, et désynchroniser les versions au prochain palier.",
		"Branche logicielle close ; migration vers la gamme suivante à instruire.",
		7.5, true, true, false},
	{"gab-cas-cfc-01", "", "ICSA-24-116-01",
		"Guichet automatique au-delà de la fin de support de son socle",
		"Le socle du guichet n'est plus maintenu depuis avril 2025. Deux agences restent sur cette version en attendant la campagne de remplacement.",
		"high", "Compromission d'un guichet et accès au réseau monétique depuis une agence.",
		"Maintenir le filtrage par le concentrateur et avancer la campagne de remplacement sur les deux agences concernées.",
		"Campagne de remplacement planifiée au deuxième trimestre.",
		7.2, false, false, false},
	{"ups-dc1-02", "CVE-2022-22805", "ICSA-22-067-01",
		"Onduleur chaîne B : micrologiciel antérieur au correctif de la carte réseau",
		"La carte de supervision porte un débordement de tampon dans le traitement des paquets TLS. La chaîne A a été relevée, la chaîne B attend sa fenêtre.",
		"medium", "Redémarrage de la carte de supervision ; la fourniture électrique n'est pas affectée, la télésurveillance l'est.",
		"Restreindre l'accès à la carte au seul réseau d'administration technique.",
		"Correctif disponible ; fenêtre de maintenance à poser.",
		6.5, false, false, true},
	{"gtc-dc1-hmi-01", "", "",
		"Pupitre d'exploitation : session ouverte en permanence",
		"Le pupitre de la salle de supervision reste ouvert sur un compte partagé, sans verrouillage automatique. L'accès physique à la salle est contrôlé mais la traçabilité des actions est perdue.",
		"medium", "Impossibilité d'imputer une action de supervision à une personne.",
		"Activer le verrouillage automatique et nommer les comptes d'exploitation.",
		"Paramétrage, pas de correctif.",
		5.3, false, false, false},
}

var demoOTEvents = []struct {
	Asset, Zone, Type, Severity, Title, Description, SrcIP, DstIP, Protocol, DetectedBy, Rule string
	MinutesAgo                                                                                int
}{
	{"fw-ot-dc1", "Supervision technique DC1", "scan_detected", "high",
		"Balayage du réseau technique depuis le réseau bureautique",
		"312 connexions vers les ports 502 et 47808 en quatre minutes, depuis un poste du réseau bureautique. Le pare-feu de séparation a rejeté l'ensemble ; le poste est celui identifié dans l'incident de compromission en cours.",
		"10.60.5.14", "10.70.1.0/24", "Modbus TCP", "Pare-feu OT", "OT-SCAN-001", 95},
	{"nvr-dc1-01", "Sécurité physique DC1", "unauthorized_access", "critical",
		"Tentative d'authentification réussie sur l'enregistreur vidéo depuis une adresse externe",
		"Connexion à l'interface web de l'enregistreur depuis 198.51.100.23, adresse portée au renseignement comme serveur de commande. La route sortante de l'équipement a été coupée dans la foulée.",
		"198.51.100.23", "10.70.3.21", "HTTPS", "Pare-feu OT", "OT-ACCES-002", 88},
	{"crac-dc1-a", "Supervision technique DC1", "process_anomaly", "high",
		"Consigne de température modifiée hors fenêtre d'exploitation",
		"Consigne portée de 22 °C à 28 °C à 02h14, hors de toute intervention planifiée. Remise à la consigne nominale par l'astreinte au bout de neuf minutes.",
		"10.70.1.10", "10.70.1.41", "Modbus TCP", "Supervision GTC", "OT-CONSIGNE-004", 310},
	{"gab-switch-ctrl", "Réseau GAB", "anomalous_traffic", "medium",
		"Volume sortant inhabituel depuis le concentrateur de guichets",
		"Le concentrateur a émis 1,4 Go vers le commutateur monétique en dehors de la fenêtre de télécollecte. Flux tracé jusqu'à une reprise de journaux après incident réseau, clos sans suite.",
		"10.72.0.10", "10.50.4.10", "TCP", "Sonde réseau OT", "OT-TRAFIC-007", 430},
	{"ups-dc1-01", "Automatismes énergie DC1", "config_change", "low",
		"Modification de configuration sur l'onduleur de la chaîne A",
		"Seuil d'alarme de charge relevé de 80 % à 85 % par la station d'administration technique, pendant la fenêtre de maintenance déclarée.",
		"10.70.0.5", "10.70.2.11", "SNMP", "Supervision GTC", "OT-CONFIG-003", 1500},
	{"acs-dc1-ctrl", "Sécurité physique DC1", "policy_violation", "medium",
		"Badge d'accès au local SWIFT utilisé hors plage autorisée",
		"Ouverture du local de la passerelle SWIFT à 23h47 avec un badge d'exploitation dont la plage s'arrête à 20h00. Intervention confirmée a posteriori par l'astreinte, dérogation non enregistrée.",
		"", "10.70.3.11", "OSDP", "Contrôle d'accès", "OT-ACCES-009", 640},
}

func (s *seeder) seedIndustrial(ctx context.Context) error {
	step("Socle technique et industriel")
	now := time.Now().UTC()

	zIdx, err := s.index(ctx, "ot", "/api/v1/ot/zones")
	if err != nil {
		return err
	}
	zones := make(map[string]uuid.UUID, len(demoZones))
	for _, z := range demoZones {
		id, err := s.ensure(ctx, zIdx, z.Name, "ot", "/api/v1/ot/zones", map[string]any{
			"name": z.Name, "description": z.Description, "zone_type": z.Type,
			"purdue_level": z.Purdue, "site": z.Site,
			"is_air_gapped": z.AirGapped, "firewall_present": z.Firewall,
			"ids_present": z.IDS, "network_ranges": z.NetworkRanges,
		})
		if err != nil {
			return err
		}
		zones[z.Name] = id
	}

	aIdx, err := s.index(ctx, "ot", "/api/v1/ot/assets")
	if err != nil {
		return err
	}
	assets := make(map[string]uuid.UUID, len(demoOTAssets))
	for i, a := range demoOTAssets {
		if _, ok := zones[a.Zone]; !ok {
			return fmt.Errorf("asset %q names a zone that is not declared: %s", a.Name, a.Zone)
		}
		eol := now.AddDate(0, a.EOLInMonths, 0)
		id, err := s.ensure(ctx, aIdx, a.Name, "ot", "/api/v1/ot/assets", map[string]any{
			"name": a.Name, "description": a.Description, "asset_type": a.Type,
			"vendor": a.Vendor, "model": a.Model, "firmware_version": a.Firmware,
			"serial_number": fmt.Sprintf("OT-%04d", 1000+i),
			"ip_address":    a.IP, "protocol": a.Protocols,
			"site": a.Site, "zone": a.Zone, "purdue_level": a.Purdue,
			"criticality": a.Criticality, "is_internet_facing": a.Internet,
			"install_date": now.AddDate(-5, 0, 0), "end_of_life_date": eol,
			"tags": []string{"demo"},
		})
		if err != nil {
			return err
		}
		assets[a.Name] = id
	}

	vIdx, err := s.index(ctx, "ot", "/api/v1/ot/vulnerabilities")
	if err != nil {
		return err
	}
	for _, v := range demoOTVulns {
		asset, ok := assets[v.Asset]
		if !ok {
			return fmt.Errorf("advisory %q names an asset that is not in the estate: %s", v.Title, v.Asset)
		}
		if _, err := s.ensure(ctx, vIdx, v.Title, "ot", "/api/v1/ot/vulnerabilities", map[string]any{
			"asset_id": asset, "cve_id": v.CVE, "ics_cert_id": v.ICS,
			"title": v.Title, "description": v.Description,
			"severity": v.Severity, "cvss_score": v.CVSS,
			"affects_availability": v.Availability, "affects_safety": v.Safety,
			"potential_impact": v.Impact, "patch_available": v.PatchAvailable,
			"patch_notes": v.PatchNotes, "workaround": v.Workaround,
			"tags": []string{"demo"},
		}); err != nil {
			return err
		}
	}

	eIdx, err := s.index(ctx, "ot", "/api/v1/ot/events")
	if err != nil {
		return err
	}
	for _, e := range demoOTEvents {
		body := map[string]any{
			"event_type": e.Type, "severity": e.Severity,
			"title": e.Title, "description": e.Description,
			"source_ip": e.SrcIP, "dest_ip": e.DstIP, "protocol": e.Protocol,
			"detected_by": e.DetectedBy, "detection_rule": e.Rule,
			"event_time": now.Add(-time.Duration(e.MinutesAgo) * time.Minute),
			"tags":       []string{"demo"},
		}
		if id, ok := assets[e.Asset]; ok {
			body["asset_id"] = id
		}
		if id, ok := zones[e.Zone]; ok {
			body["zone_id"] = id
		}
		if _, err := s.ensure(ctx, eIdx, e.Title, "ot", "/api/v1/ot/events", body); err != nil {
			return err
		}
	}
	return nil
}
