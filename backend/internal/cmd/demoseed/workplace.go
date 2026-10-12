package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// The workplace: the phones the bank enrolled and the data stores it holds.
//
// These two screens were the last in the product to have no demonstration
// data, and they are among the first a CIO opens — a bank's mobile fleet and
// the inventory of where its customer data actually sits are the two things
// nobody has a reliable list of. An empty screen here reads as "not
// implemented", which is the wrong answer.
//
// Everything below belongs to the same invented institution as the rest of
// the estate (see estate.go): Banque Al Massira, its people, its departments
// and its branches. The owners' names are invented; the device models,
// operating system versions and store types are the ordinary ones.

type demoDevice struct {
	Name       string
	Type       string // smartphone | tablet | laptop
	Platform   string // ios | android
	OS         string
	Model      string
	Maker      string
	Ownership  string // corporate | byod | cope
	Owner      string
	Login      string
	Department string
	Carrier    string
	Encrypted  bool
	ScreenLock bool
	// What the fleet management agent reported back, which is what makes the
	// device's risk score move.
	Jailbroken bool
	Rooted     bool
	Compliant  bool
	Issues     []string
	LastIP     string
	Location   string
}

// mob is the fleet. Sixteen devices is small for a bank of this size, and
// deliberately so: the screen has to be readable in a room, and the mix —
// corporate iOS for the executive committee, Android in the branches, BYOD at
// the edges — is what carries the point, not the count.
var mob = []demoDevice{
	{"iPhone 15 Pro — Direction générale", "smartphone", "ios", "17.4.1", "iPhone 15 Pro", "Apple", "corporate",
		"Nawal El Fassi", "nelfassi", "Direction générale", "Maroc Telecom", true, true, false, false, true, nil, "10.60.9.21", headOffice},
	{"iPhone 14 — Direction des risques", "smartphone", "ios", "17.4.1", "iPhone 14", "Apple", "corporate",
		"Youssef Berrada", "yberrada", "Risques", "Maroc Telecom", true, true, false, false, true, nil, "10.60.9.22", headOffice},
	{"Galaxy S23 — DSI", "smartphone", "android", "14", "SM-S911B", "Samsung", "corporate",
		"Karim Alaoui", "kalaoui", "DSI", "Orange Maroc", true, true, false, false, true, nil, "10.60.9.23", headOffice},
	{"iPad Pro — Comité de direction", "tablet", "ios", "17.4.1", "iPad Pro 11", "Apple", "corporate",
		"Salma Tazi", "stazi", "Direction générale", "", true, true, false, false, true, nil, "10.60.9.24", headOffice},
	{"Pixel 8 — Audit interne", "smartphone", "android", "14", "Pixel 8", "Google", "corporate",
		"Hicham Oulad Brahim", "houlad", "Audit interne", "inwi", true, true, false, false, true, nil, "10.60.9.25", headOffice},
	{"iPhone 13 — Agence Rabat Agdal", "smartphone", "ios", "16.7.2", "iPhone 13", "Apple", "corporate",
		"Meriem Chraibi", "mchraibi", "Réseau d'agences", "Maroc Telecom", true, true, false, false, false,
		[]string{"Version d'iOS antérieure au minimum exigé par la politique"}, "10.61.4.31", "Rabat Agdal"},
	{"Galaxy A54 — Agence Tanger Med", "smartphone", "android", "13", "SM-A546B", "Samsung", "byod",
		"Omar Bennani", "obennani", "Réseau d'agences", "Orange Maroc", false, true, true, true, false,
		[]string{"Appareil rooté", "Volume de stockage non chiffré", "Application bancaire installée hors magasin"}, "10.61.7.44", "Tanger Med"},
	{"iPhone 12 — Trésorerie", "smartphone", "ios", "17.3.1", "iPhone 12", "Apple", "cope",
		"Imane Kettani", "ikettani", "Trésorerie", "Maroc Telecom", true, true, false, false, true, nil, "10.60.9.26", headOffice},
	{"Galaxy S21 — Monétique", "smartphone", "android", "13", "SM-G991B", "Samsung", "corporate",
		"Rachid Amrani", "ramrani", "Monétique", "inwi", false, true, false, false, false,
		[]string{"Volume de stockage non chiffré"}, "10.60.9.27", headOffice},
	{"iPhone SE — Support SI", "smartphone", "ios", "17.4.1", "iPhone SE 3", "Apple", "corporate",
		"Fatima Zahra Idrissi", "fzidrissi", "DSI", "Orange Maroc", true, true, false, false, true, nil, "10.60.9.28", headOffice},
	{"Galaxy Tab S9 — Force de vente", "tablet", "android", "14", "SM-X710", "Samsung", "corporate",
		"Mehdi Sbai", "msbai", "Commercial", "", true, true, false, false, true, nil, "10.61.1.12", "Casablanca Maârif"},
	{"iPhone 15 — Conformité", "smartphone", "ios", "17.4.1", "iPhone 15", "Apple", "corporate",
		"Loubna Harrak", "lharrak", "Conformité", "Maroc Telecom", true, true, false, false, true, nil, "10.60.9.29", headOffice},
	{"Redmi Note 12 — Prestataire GAB", "smartphone", "android", "12", "23021RAAEG", "Xiaomi", "byod",
		"Abdellah Rifi", "arifi", "Prestataires", "inwi", false, false, false, true, false,
		[]string{"Appareil rooté", "Aucun verrouillage d'écran", "Volume de stockage non chiffré", "Correctif de sécurité vieux de plus de 180 jours"},
		"10.62.8.90", "Casablanca Sidi Maârouf"},
	{"iPhone 11 — Ressources humaines", "smartphone", "ios", "17.2.1", "iPhone 11", "Apple", "byod",
		"Nadia Lamrani", "nlamrani", "Ressources humaines", "Orange Maroc", true, false, false, false, false,
		[]string{"Aucun verrouillage d'écran"}, "10.60.9.30", headOffice},
	{"Galaxy S22 — Sécurité SI", "smartphone", "android", "14", "SM-S901B", "Samsung", "corporate",
		"Anas Belkacem", "abelkacem", "Sécurité SI", "Maroc Telecom", true, true, false, false, true, nil, "10.60.9.31", headOffice},
	{"iPhone 14 Pro — Direction financière", "smartphone", "ios", "17.4.1", "iPhone 14 Pro", "Apple", "corporate",
		"Sanaa Ouazzani", "souazzani", "Finance", "Maroc Telecom", true, true, false, false, true, nil, "10.60.9.32", headOffice},
}

// mobPolicies are the rules the fleet is measured against. They are what makes
// "non-compliant" mean something on the screen rather than a colour.
var mobPolicies = []map[string]any{
	{
		"name": "Chiffrement et verrouillage obligatoires", "policy_type": "device_compliance", "platform": "all",
		"description": "Tout appareil enrôlé chiffre son volume de stockage et verrouille son écran. Exigence DNSSI et PCI DSS 4.0 pour tout terminal accédant à des données de porteur.",
		"rules":       map[string]any{"require_encryption": true, "require_screen_lock": true, "min_passcode_length": 6},
		"action":      "block", "applies_to": "all",
	},
	{
		"name": "Interdiction des appareils déverrouillés", "policy_type": "device_compliance", "platform": "all",
		"description": "Un appareil jailbreaké ou rooté perd l'isolation entre applications : l'accès aux applications métier lui est retiré et le profil est révoqué.",
		"rules":       map[string]any{"block_jailbroken": true, "block_rooted": true},
		"action":      "wipe", "applies_to": "all",
	},
	{
		"name": "Niveau de correctif minimal", "policy_type": "device_compliance", "platform": "all",
		"description": "Le correctif de sécurité du système ne peut dater de plus de 90 jours. Au-delà, l'appareil est signalé ; à 180 jours il est sorti du périmètre.",
		"rules":       map[string]any{"max_patch_age_days": 90, "quarantine_after_days": 180},
		"action":      "alert", "applies_to": "all",
	},
	{
		"name": "Applications bancaires — magasin d'entreprise uniquement", "policy_type": "app_management", "platform": "all",
		"description": "L'application métier et le jeton d'authentification forte ne s'installent que depuis le magasin d'entreprise. Toute installation latérale est un incident.",
		"rules":       map[string]any{"allowed_sources": []string{"enterprise"}, "block_sideload": true},
		"action":      "block", "applies_to": "all",
	},
	{
		"name": "Cloisonnement des appareils personnels", "policy_type": "data_protection", "platform": "all",
		"description": "Sur un appareil personnel, les données de l'entreprise vivent dans un conteneur séparé : pas de copier-coller sortant, pas de sauvegarde vers un service grand public.",
		"rules":       map[string]any{"containerise": true, "block_clipboard_out": true, "block_personal_backup": true},
		"action":      "enforce", "applies_to": "byod",
	},
}

// mobThreats are what the fleet agent reported. Each one names a device above.
var mobThreats = []struct {
	Device, Type, Severity, Title, Description, Indicator, App, DetectedBy string
}{
	{"Galaxy A54 — Agence Tanger Med", "jailbreak_root", "critical",
		"Appareil rooté détecté sur un terminal accédant à l'application d'agence",
		"L'agent de gestion de flotte a trouvé un binaire su et un gestionnaire de superutilisateur. L'isolation entre applications n'est plus garantie : le conteneur d'entreprise est révoqué et l'accès à l'application d'agence suspendu.",
		"/system/xbin/su", "ma.almassira.agence", "Agent MDM"},
	{"Galaxy A54 — Agence Tanger Med", "app_vulnerability", "high",
		"Application bancaire installée hors du magasin d'entreprise",
		"Un paquet signé par un certificat inconnu porte le même identifiant que l'application d'agence. Empreinte relevée et transmise au renseignement sur la menace.",
		"a41f0c7b9e2d58a3c6b1f04e7d9a2b85c3e6f108d4a7b2c9e5f81d3a6b0c4e72", "ma.almassira.agence", "Agent MDM"},
	{"Redmi Note 12 — Prestataire GAB", "jailbreak_root", "critical",
		"Appareil personnel rooté utilisé par un prestataire d'exploitation GAB",
		"Terminal personnel d'un prestataire intervenant sur le parc de guichets. Rooté, sans verrouillage d'écran, correctif de sécurité de 2023. Accès retiré, intervention sur site reprogrammée avec un terminal fourni.",
		"Magisk 26.4", "", "Agent MDM"},
	{"iPhone 11 — Ressources humaines", "phishing", "high",
		"SMS d'hameçonnage reprenant l'identité visuelle de la banque",
		"Message annonçant le blocage de la carte et renvoyant vers almassira-securite.example. Domaine déjà porté au renseignement ; le lien n'a pas été ouvert.",
		"almassira-securite.example", "Messages", "Protection mobile"},
	{"Galaxy S21 — Monétique", "data_leakage", "medium",
		"Sauvegarde du conteneur d'entreprise vers un service grand public",
		"Le service de sauvegarde du constructeur a été activé sur un appareil dont le volume n'est pas chiffré. Sauvegarde désactivée à distance, politique de cloisonnement réappliquée.",
		"", "Samsung Cloud", "Protection mobile"},
	{"iPhone 13 — Agence Rabat Agdal", "rogue_ap", "medium",
		"Point d'accès Wi-Fi usurpant le nom du réseau d'agence",
		"Un point d'accès diffusant le SSID ALMASSIRA-AGENCE depuis une adresse MAC inconnue a été vu à proximité de l'agence. Aucune session n'a été établie ; signalement transmis à la sécurité physique.",
		"8c:1f:64:a3:0d:92", "", "Protection mobile"},
}

func (s *seeder) seedMobileFleet(ctx context.Context) error {
	step("Flotte mobile")

	polIdx, err := s.index(ctx, "mobile", "/api/v1/mobile/policies")
	if err != nil {
		return err
	}
	for _, p := range mobPolicies {
		if _, err := s.ensure(ctx, polIdx, p["name"].(string), "mobile", "/api/v1/mobile/policies", p); err != nil {
			return err
		}
	}

	devIdx, err := s.index(ctx, "mobile", "/api/v1/mobile/devices")
	if err != nil {
		return err
	}
	ids := make(map[string]uuid.UUID, len(mob))
	for i, d := range mob {
		id, err := s.ensure(ctx, devIdx, d.Name, "mobile", "/api/v1/mobile/devices", map[string]any{
			"device_name": d.Name, "device_type": d.Type, "platform": d.Platform,
			"os_version": d.OS, "model": d.Model, "manufacturer": d.Maker,
			"serial_number": fmt.Sprintf("MAS-%s-%03d", shortPlatform(d.Platform), i+1),
			"udid":          deviceUDID(d.Platform, i+1),
			"imei":          fmt.Sprintf("35%013d", 420000000000+i),
			"ownership":     d.Ownership, "owner_name": d.Owner,
			"owner_email": d.Login + "@almassira.ma", "department": d.Department,
			// The enrolment records what the fleet is meant to look like; the
			// update below records what the agent actually found.
			"is_encrypted": true, "is_screen_lock": true,
			"carrier": d.Carrier, "tags": []string{"demo", d.Ownership},
		})
		if err != nil {
			return err
		}
		ids[d.Name] = id

		// What came back from the device. The service recomputes the risk
		// score from these flags, so sending them is what makes the fleet
		// rank rather than read as sixteen zeros.
		issues := d.Issues
		if issues == nil {
			issues = []string{}
		}
		update := map[string]any{
			"is_jailbroken": d.Jailbroken, "is_rooted": d.Rooted,
			"is_encrypted": d.Encrypted, "is_screen_lock": d.ScreenLock,
			"is_compliant": d.Compliant, "compliance_issues": issues,
			"mdm_profile_installed": true,
			"last_location":         d.Location, "last_ip": d.LastIP,
		}
		if err := s.c.patch(ctx, "mobile", "/api/v1/mobile/devices/"+id.String(), update, nil); err != nil {
			return fmt.Errorf("report back for %q: %w", d.Name, err)
		}
	}

	thrIdx, err := s.index(ctx, "mobile", "/api/v1/mobile/threats")
	if err != nil {
		return err
	}
	for _, t := range mobThreats {
		device, ok := ids[t.Device]
		if !ok {
			continue
		}
		if _, err := s.ensure(ctx, thrIdx, t.Title, "mobile", "/api/v1/mobile/threats", map[string]any{
			"device_id": device, "threat_type": t.Type, "severity": t.Severity,
			"title": t.Title, "description": t.Description,
			"threat_indicator": t.Indicator, "affected_app": t.App,
			"detected_by": t.DetectedBy, "tags": []string{"demo"},
		}); err != nil {
			return err
		}
	}
	return nil
}

func shortPlatform(p string) string {
	if p == "ios" {
		return "IOS"
	}
	return "AND"
}

// deviceUDID is the identifier the fleet agent reports, in the shape each
// platform uses: Apple's serial-prefixed form, Android's sixteen hex digits.
// It is derived from the position so a second run produces the same value and
// re-enrols nothing.
func deviceUDID(platform string, n int) string {
	if platform == "ios" {
		return fmt.Sprintf("00008030-%06X%010X", n, 0x1E8A3C04D29+int64(n)*7919)
	}
	return fmt.Sprintf("%016x", 0x7F3C1A0B00000000+int64(n)*104729)
}
