package handler

import "testing"

// Le code d'un référentiel est une forme, pas une liste.
//
// Il était une énumération de sept valeurs — ISO27001, SOC2, PCIDSS, SWIFTCSP,
// NIS2, DORA, GDPR — posée à la fois dans le validateur et dans une contrainte
// PostgreSQL. Autrement dit, un produit vendu sur la cartographie de conformité
// répondait 422 au référentiel national de son client dès qu'il n'était ni
// européen ni américain. Trouvé en construisant un jeu de démonstration
// marocain : « DNSSI » était refusé.
//
// Ce test existe pour que personne ne referme la liste en croyant durcir
// quelque chose.
func TestAFrameworkCodeIsAShapeAndNotAList(t *testing.T) {
	accepted := []string{
		"ISO27001", "SOC2", "PCIDSS", "SWIFTCSP", "NIS2", "DORA", "GDPR", // celles d'avant
		"DNSSI",    // Maroc, DGSSI
		"LOI0908",  // Maroc, protection des données
		"SAMA-CSF", // Arabie saoudite
		"SOLVA_II", // assurance européenne
		"BAM",      // deux caractères, la borne basse
	}
	for _, code := range accepted {
		if !frameworkCode.MatchString(code) {
			t.Errorf("%q refusé : un client qui apporte son référentiel ne doit pas être renvoyé", code)
		}
	}

	// La forme garde l'hygiène de la donnée : c'est un identifiant, pas un
	// champ libre, et il finit dans une URL et dans un rapport.
	refused := map[string]string{
		"":          "vide",
		"a":         "un seul caractère",
		"iso27001":  "minuscules",
		"ISO 27001": "une espace",
		"ISO/27001": "une barre oblique, qui casse le chemin d'URL",
		"_ISO":      "commence par un souligné",
		"ISO27001'; DROP TABLE comp_frameworks; --":      "une tentative d'injection",
		"CECIESTUNCODEBEAUCOUPTROPLONGPOURUNREFERENTIEL": "plus de 32 caractères",
	}
	for code, why := range refused {
		if frameworkCode.MatchString(code) {
			t.Errorf("%q accepté alors que c'est %s", code, why)
		}
	}
}
