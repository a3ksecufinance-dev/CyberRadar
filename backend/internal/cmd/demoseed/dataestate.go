package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Where the bank's data actually sits, and what was found in it.
//
// The posture of a data store — encrypted, access-controlled, monitored,
// backed up — is declared at creation. The findings are what a scan reported,
// and they are what moves the store's risk: the service recomputes it on every
// finding, so a store with a clear-text card number in a log table ranks above
// one that merely lacks a backup.
//
// Loi 09-08 is why this screen exists for a Moroccan institution: personal
// data has to be declared to the CNDP, and a declaration is worth what the
// inventory behind it is worth.

type demoStore struct {
	Name        string
	Type        string // database | object_storage | file_share | api | data_warehouse | message_queue | code_repository
	Provider    string
	Region      string
	Endpoint    string
	Sensitivity string // public | internal | confidential | restricted | top_secret
	Categories  []string
	Encrypted   bool
	Controlled  bool
	Monitored   bool
	BackedUp    bool
	Owner       string
	Department  string
}

var demoStores = []demoStore{
	{"Core banking — base de production", "database", "on_premise", "Casablanca DC1",
		"db-core-01.almassira.ma:1521", "restricted",
		[]string{"pii", "financial", "pci"}, true, true, true, true, "Systèmes centraux", "Systèmes centraux"},
	{"Coffre des données porteur", "database", "on_premise", "Casablanca DC1",
		"vault-pci-01.almassira.ma:5432", "top_secret",
		[]string{"pci", "credentials"}, true, true, true, true, "Monétique", "Monétique"},
	{"CRM — base clients", "database", "on_premise", "Casablanca DC1",
		"db-crm-01.almassira.ma:5432", "confidential",
		[]string{"pii", "personal_data"}, true, true, false, true, "Commercial", "Commercial"},
	{"Entrepôt décisionnel", "data_warehouse", "on_premise", "Casablanca DC2",
		"dwh-01.almassira.ma:5439", "confidential",
		[]string{"pii", "financial"}, true, true, false, true, "Pilotage", "Pilotage"},
	{"Sauvegardes hors site", "object_storage", "on_premise", "Rabat DC3",
		"s3://almassira-backup-prod", "restricted",
		[]string{"pii", "financial", "pci"}, false, true, false, true, "Infrastructure", "Infrastructure"},
	{"Partage de fichiers — Direction financière", "file_share", "on_premise", "Casablanca DC1",
		"\\\\file-srv-01\\finance", "confidential",
		[]string{"financial", "intellectual_property"}, false, false, false, true, "Finance", "Finance"},
	{"Dossiers du personnel", "file_share", "on_premise", "Casablanca DC1",
		"\\\\file-srv-01\\rh", "restricted",
		[]string{"pii", "personal_data", "legal"}, true, true, false, true, "Ressources humaines", "Ressources humaines"},
	{"File de messages SWIFT", "message_queue", "on_premise", "Casablanca DC1",
		"mq-broker-01.almassira.ma:61616", "top_secret",
		[]string{"financial"}, true, true, true, false, "Paiements", "Paiements"},
	{"API de banque mobile", "api", "on_premise", "Casablanca DC1",
		"https://api.almassira.ma/v2", "confidential",
		[]string{"pii", "financial"}, true, true, true, false, "Canaux digitaux", "Canaux digitaux"},
	{"Dépôt applicatif — canaux digitaux", "code_repository", "on_premise", "Casablanca DC2",
		"https://git.almassira.ma/digital", "internal",
		[]string{"credentials", "intellectual_property"}, true, true, false, true, "Études", "Études"},
	{"Journal applicatif de la banque en ligne", "object_storage", "on_premise", "Casablanca DC2",
		"s3://almassira-logs-ebank", "internal",
		[]string{"pii"}, true, false, true, false, "Canaux digitaux", "Canaux digitaux"},
	{"Recette — copie du CRM", "database", "on_premise", "Casablanca DC2",
		"db-crm-rec.almassira.ma:5432", "confidential",
		[]string{"pii", "personal_data"}, false, false, false, false, "Études", "Études"},
}

// Findings are what a scan reported. Each names its store.
var demoDataFindings = []struct {
	Store, Type, Severity, Path, Field, Title, Description, Remediation string
	Records                                                             int64
	Public                                                              bool
	Encrypted                                                           bool
	Violations                                                          []string
}{
	{"Journal applicatif de la banque en ligne", "pci_data", "critical",
		"ebank/app/2026-09-*/transaction.log", "card_number",
		"Numéros de carte en clair dans le journal applicatif",
		"Le journal de la passerelle de paiement écrit le PAN complet lorsqu'une autorisation échoue. 11 420 lignes concernées sur les 90 jours conservés. Le journal est lisible par toute l'équipe d'exploitation.",
		"Masquer le PAN à l'émission (6 premiers / 4 derniers), purger les journaux existants, et ajouter un contrôle de non-régression dans la chaîne de livraison.",
		11420, false, true, []string{"PCI DSS 4.0 — 3.3", "Loi 09-08 — art. 23"}},
	{"Recette — copie du CRM", "pii", "critical",
		"public.clients", "cin",
		"Copie de production en recette, sans chiffrement ni anonymisation",
		"La base de recette est une copie intégrale du CRM de production : 184 000 clients avec numéro de CIN, adresse et téléphone. Volume non chiffré, pas de contrôle d'accès, accessible depuis le réseau des études.",
		"Anonymiser à la copie ou tirer un jeu de recette synthétique. Chiffrer le volume et restreindre l'accès à l'équipe projet.",
		184000, false, false, []string{"Loi 09-08 — art. 23", "ISO 27001 — A.8.11"}},
	{"Sauvegardes hors site", "financial_data", "high",
		"almassira-backup-prod/core/", "",
		"Sauvegardes du core banking stockées sans chiffrement au repos",
		"Les exports quotidiens du core banking sont écrits sur un stockage objet sans chiffrement au repos. Les sauvegardes partent hors site par liaison opérateur.",
		"Activer le chiffrement côté serveur avec une clé gérée par la banque, et rejouer le chiffrement sur les sauvegardes conservées.",
		0, false, false, []string{"DNSSI — Protection des données", "PCI DSS 4.0 — 3.5"}},
	{"Dépôt applicatif — canaux digitaux", "api_keys", "high",
		"digital/mobile-api/config/application-prod.yml", "swift.gateway.token",
		"Jeton d'accès à la passerelle de paiement dans le dépôt de code",
		"Un jeton de service valable en production figure dans un fichier de configuration versionné, présent dans l'historique depuis 14 mois. Le dépôt est lisible par 38 comptes.",
		"Révoquer le jeton, le déplacer dans le coffre, réécrire l'historique du dépôt et activer l'analyse de secrets à chaque poussée.",
		1, false, true, []string{"ISO 27001 — A.8.24", "SWIFT CSP — 2.5A"}},
	{"Partage de fichiers — Direction financière", "financial_data", "high",
		"finance/reporting/2026/", "",
		"Partage de fichiers sans contrôle d'accès ni chiffrement",
		"Le partage de la direction financière est ouvert à tous les utilisateurs du domaine. Il contient les états de reporting réglementaire et les prévisions de trésorerie.",
		"Restreindre le partage au groupe Finance, activer le chiffrement du volume et journaliser les accès.",
		0, false, false, []string{"ISO 27001 — A.5.15"}},
	{"CRM — base clients", "personal_data", "medium",
		"public.prospects", "telephone",
		"Données de prospection conservées au-delà de la durée déclarée",
		"412 000 fiches de prospection dont la dernière interaction remonte à plus de trois ans, alors que la déclaration CNDP annonce une conservation de 24 mois.",
		"Purger les fiches au-delà de la durée déclarée et automatiser la purge dans le CRM.",
		412000, false, true, []string{"Loi 09-08 — art. 3"}},
	{"Dossiers du personnel", "pii", "medium",
		"rh/dossiers/", "",
		"Dossiers du personnel accessibles au-delà du service RH",
		"Sept comptes hors de la direction des ressources humaines disposent d'un accès en lecture au partage des dossiers du personnel, hérité d'un groupe de migration.",
		"Retirer le groupe hérité et repasser l'habilitation en revue trimestrielle.",
		1860, false, true, []string{"Loi 09-08 — art. 23", "ISO 27001 — A.5.18"}},
	{"API de banque mobile", "pii", "medium",
		"/v2/accounts/{id}/statements", "iban",
		"IBAN complet renvoyé à une application qui ne l'affiche pas",
		"La réponse de l'API expose l'IBAN complet alors que l'application mobile n'en affiche que les quatre derniers caractères. L'écart élargit la surface en cas de compromission du terminal.",
		"Tronquer la réponse côté serveur et n'exposer l'IBAN complet que sur un appel authentifié à forte assurance.",
		0, false, true, []string{"Loi 09-08 — art. 23"}},
	{"Entrepôt décisionnel", "pii", "low",
		"mart.client_360", "email",
		"Adresses électroniques non masquées dans un mart de pilotage",
		"Le mart de pilotage commercial reprend l'adresse électronique en clair alors qu'aucun usage ne la nécessite ; 96 analystes y ont accès.",
		"Masquer la colonne dans la vue de pilotage ou la remplacer par un identifiant pseudonyme.",
		338000, false, true, []string{"Loi 09-08 — art. 23"}},
}

func (s *seeder) seedDataEstate(ctx context.Context) error {
	step("Patrimoine de données")

	idx, err := s.index(ctx, "dspm", "/api/v1/dspm/data-stores")
	if err != nil {
		return err
	}
	ids := make(map[string]uuid.UUID, len(demoStores))
	for _, d := range demoStores {
		id, err := s.ensure(ctx, idx, d.Name, "dspm", "/api/v1/dspm/data-stores", map[string]any{
			"name": d.Name, "store_type": d.Type, "cloud_provider": d.Provider,
			"region": d.Region, "endpoint": d.Endpoint,
			"sensitivity_level": d.Sensitivity, "data_categories": d.Categories,
			"is_encrypted": d.Encrypted, "is_access_controlled": d.Controlled,
			"is_monitored": d.Monitored, "is_backup_enabled": d.BackedUp,
			"owner": d.Owner, "department": d.Department,
			"tags": []string{"demo"},
		})
		if err != nil {
			return err
		}
		ids[d.Name] = id
	}

	fIdx, err := s.index(ctx, "dspm", "/api/v1/dspm/findings")
	if err != nil {
		return err
	}
	for _, f := range demoDataFindings {
		store, ok := ids[f.Store]
		if !ok {
			return fmt.Errorf("finding %q names a store that is not in the estate: %s", f.Title, f.Store)
		}
		if _, err := s.ensure(ctx, fIdx, f.Title, "dspm", "/api/v1/dspm/findings", map[string]any{
			"data_store_id": store, "finding_type": f.Type, "severity": f.Severity,
			"location_path": f.Path, "location_field": f.Field,
			"record_count": f.Records, "is_public_accessible": f.Public,
			"is_encrypted": f.Encrypted,
			"title":        f.Title, "description": f.Description,
			"remediation":           f.Remediation,
			"compliance_violations": f.Violations,
			"tags":                  []string{"demo"},
		}); err != nil {
			return err
		}
	}
	return nil
}
