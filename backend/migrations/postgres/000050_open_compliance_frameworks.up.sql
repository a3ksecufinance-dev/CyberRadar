-- Un référentiel de conformité n'est pas une énumération fermée.
--
-- `comp_frameworks.code` n'acceptait que sept valeurs :
-- ISO27001, SOC2, PCIDSS, SWIFTCSP, NIS2, DORA, GDPR. Autrement dit, un
-- produit vendu sur la cartographie de conformité refusait le référentiel
-- national de son client dès que celui-ci n'était ni européen ni américain.
-- Une banque marocaine ne pouvait pas enregistrer la DNSSI de la DGSSI ni la
-- loi 09-08 ; une banque du Golfe ne pouvait pas enregistrer le SAMA CSF ; un
-- assureur ne pouvait pas enregistrer Solvabilité II.
--
-- Trouvé en construisant le jeu de démonstration marocain : l'API répondait
-- 422 sur « DNSSI », et la contrainte était posée deux fois — ici et dans le
-- validateur Go du service.
--
-- Remplacé par une contrainte de forme, qui garde l'hygiène de la donnée sans
-- fermer la liste : majuscules, chiffres, tiret et souligné, de 2 à 32
-- caractères. Les sept valeurs d'origine la satisfont, donc aucune ligne
-- existante n'est touchée.

ALTER TABLE comp_frameworks DROP CONSTRAINT IF EXISTS comp_frameworks_code_check;

ALTER TABLE comp_frameworks
    ADD CONSTRAINT comp_frameworks_code_check
    CHECK (code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$');
