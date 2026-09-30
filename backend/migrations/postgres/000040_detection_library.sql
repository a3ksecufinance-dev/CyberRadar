-- Migration: 000040_detection_library
--
-- A detection engine with an empty rule table is a detection engine that
-- detects nothing. Every customer then writes the same fifteen rules that every
-- other customer writes, badly, from memory, and nobody can say what the
-- platform covers.
--
-- So the platform ships detection content, the tenant adopts what fits, tunes
-- it, and writes its own in the same grammar. Same shape as the risk profiles
-- (000039), for the same reason: what to detect is a judgement, and the vendor's
-- job is to bring a defensible starting point, not to decide.
--
-- The lineage is the point. A tenant rule records which catalogue entry it came
-- from and at which content version, so three questions have answers:
--
--   What do we run that CyberRadar shipped, and what did we change about it?
--   — the difference from the catalogue entry, computed on read so it cannot
--     go stale.
--
--   Has the platform improved a rule we adopted?
--   — the catalogue entry's version is higher than the one we adopted.
--
--   What do we cover, and against which framework?
--   — the catalogue carries the ATT&CK mapping and the control references, so
--     coverage is a query rather than a spreadsheet.
--
-- Two things the catalogue does that a list of rules would not:
--
--   It declares what a rule needs. A detection keyed on a field nothing
--   populates loads, matches nothing, and looks like working coverage — which
--   is worse than no rule. Those entries ship disabled, with the reason.
--
--   It carries the reasoning: why the detection exists, what legitimately trips
--   it, and what to do when it fires. An analyst at three in the morning needs
--   the third one, and a rule without it is a pager that says nothing.

CREATE TABLE IF NOT EXISTS detection_content (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- A stable identifier that survives renaming. It is what a tenant rule
    -- points at, and what an audit report cites.
    code        VARCHAR(40)  NOT NULL,
    version     INT          NOT NULL DEFAULT 1,

    title       VARCHAR(255) NOT NULL,
    description TEXT         NOT NULL,

    category        VARCHAR(50)  NOT NULL,
    severity        VARCHAR(20)  NOT NULL
                        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    mitre_tactic    VARCHAR(10),
    mitre_technique VARCHAR(10),

    -- The rule, in the engine's own grammar. Nothing here is a new dialect:
    -- what the catalogue ships is what a tenant could have written.
    conditions     JSONB NOT NULL,
    actions        JSONB NOT NULL DEFAULT '[]',
    dedup_window_s INT   NOT NULL DEFAULT 300,

    -- Why it exists, what trips it legitimately, what to do. The third is what
    -- an analyst needs at three in the morning.
    rationale       TEXT NOT NULL,
    false_positives TEXT,
    response        TEXT,

    -- Which frameworks this detection helps evidence, and the control it maps
    -- to. A compliance report can then cite the rules that support a control
    -- rather than asserting the control is met.
    frameworks TEXT[] NOT NULL DEFAULT '{}',
    controls   TEXT[] NOT NULL DEFAULT '{}',

    -- What has to be in place for it to fire at all: a connector, an
    -- enrichment, a licensed database. Empty means it works on what the
    -- platform already produces.
    requires TEXT[] NOT NULL DEFAULT '{}',

    -- A rule that cannot fire yet ships off, with requires saying why. Enabling
    -- it by default would present coverage the platform does not have.
    enabled_by_default BOOLEAN NOT NULL DEFAULT true,

    tags       TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ,

    CONSTRAINT detection_content_version_positive CHECK (version >= 1)
);

-- One current version per code. Superseding sets retired_at on the old row, so
-- a tenant that adopted v1 can still be told what v1 said.
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_content_current
    ON detection_content (code) WHERE retired_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_content_code_version
    ON detection_content (code, version);

CREATE INDEX IF NOT EXISTS idx_detection_content_technique
    ON detection_content (mitre_technique) WHERE retired_at IS NULL;

COMMENT ON TABLE detection_content IS
  'The detection rules the platform ships. A tenant adopts from here into detection_rules; the lineage columns there point back.';

-- ─── Lineage on a tenant's rules ─────────────────────────────────────────────

ALTER TABLE detection_rules
    -- The catalogue entry this rule was adopted from, and the version adopted.
    -- NULL for a rule the tenant wrote itself, which is a first-class case:
    -- the library is a starting point, not a cage.
    ADD COLUMN IF NOT EXISTS content_code    VARCHAR(40),
    ADD COLUMN IF NOT EXISTS content_version INT,
    -- When it was adopted, so "we have been running this since March" is an
    -- answer the platform can give.
    ADD COLUMN IF NOT EXISTS adopted_at      TIMESTAMPTZ;

-- A tenant adopts a catalogue entry once. Adopting it twice would double every
-- alert it raises, and the second copy would drift from the first.
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_adopted
    ON detection_rules (tenant_id, content_code) WHERE content_code IS NOT NULL;

COMMENT ON COLUMN detection_rules.content_code IS
  'The catalogue entry this rule came from, or NULL for a rule the tenant wrote. The difference from the entry is computed on read.';

-- ─── The catalogue ───────────────────────────────────────────────────────────
--
-- Every condition below names only fields the engine actually reads
-- (services/siem/internal/service/engine.go, getField). That is not a style
-- preference: a rule naming an unknown field loads, matches nothing, and
-- presents itself as coverage.
--
-- Two fields are deliberately absent. cbs_impact and swift_impact are in the
-- event schema and in the engine's vocabulary, and nothing in the platform ever
-- sets them — they are always zero. A shipped rule keyed on either would be a
-- detection that can never fire, which is the exact failure this catalogue
-- exists to avoid.

INSERT INTO detection_content
  (code, version, title, description, category, severity, mitre_tactic, mitre_technique,
   conditions, actions, dedup_window_s, rationale, false_positives, response,
   frameworks, controls, requires, enabled_by_default, tags)
VALUES

-- ── Credential access ────────────────────────────────────────────────────────
('CRP-IAM-0001', 1,
 'Bourrage d''identifiants depuis une même adresse',
 'Cinq échecs d''authentification ou plus depuis une même adresse source en cinq minutes.',
 'IAM', 'HIGH', 'TA0006', 'T1110.004',
 '{"field_matches":[{"field":"category","op":"eq","value":"IAM"},
                    {"field":"outcome","op":"eq","value":"failure"}],
   "threshold":{"count":5,"window_seconds":300,"group_by":["ip_source"]}}',
 '[{"type":"notify"}]', 300,
 'Un attaquant qui essaie une liste d''identifiants volés produit beaucoup d''échecs depuis peu d''adresses. C''est la première étape de la grande majorité des compromissions de comptes clients.',
 'Un portail dont la session expire mal, un client mobile qui réessaie en boucle, un test de charge. Regarder si les noms d''utilisateur varient : un seul compte qui échoue vingt fois est un utilisateur en difficulté, vingt comptes depuis une adresse ne l''est pas.',
 'Limiter le débit sur l''adresse au niveau du pare-feu applicatif. Vérifier si l''un des comptes visés a fini par réussir — c''est cela qui transforme l''incident.',
 '{DORA,PCIDSS,ISO27001}', '{DORA-10.3,PCI-10.4.1,A.8.16}', '{}', true, '{authentification,standard}'),

('CRP-IAM-0002', 1,
 'Attaque en force sur un compte unique',
 'Dix échecs ou plus sur le même compte en dix minutes, quelle que soit la source.',
 'IAM', 'HIGH', 'TA0006', 'T1110.001',
 '{"field_matches":[{"field":"category","op":"eq","value":"IAM"},
                    {"field":"outcome","op":"eq","value":"failure"}],
   "threshold":{"count":10,"window_seconds":600,"group_by":["user_name"]}}',
 '[{"type":"notify"}]', 600,
 'Distinct du bourrage : ici c''est une cible nommée que l''on martèle, souvent un compte à privilèges dont l''attaquant connaît déjà le nom.',
 'Un compte de service dont le mot de passe a été changé sans mettre à jour l''appelant produit exactement ce motif, sans arrêt.',
 'Identifier si le compte est nominatif ou de service. Un compte de service en échec répété est une rotation mal finie ; un compte nominatif est une attaque.',
 '{DORA,PCIDSS,ISO27001}', '{DORA-10.3,PCI-8.3.6,A.8.16}', '{}', true, '{authentification,standard}'),

('CRP-IAM-0003', 1,
 'Session administrateur ouverte avec succès',
 'Une authentification privilégiée qui aboutit.',
 'IAM', 'CRITICAL', 'TA0001', 'T1078',
 '{"field_matches":[{"field":"action","op":"contains","value":"admin_login"},
                    {"field":"outcome","op":"eq","value":"success"}]}',
 '[{"type":"notify"},{"type":"create_case"}]', 600,
 'Une session à privilèges est le point à partir duquel un attaquant n''a plus besoin d''exploiter quoi que ce soit. Les tracer toutes coûte peu et vaut beaucoup ; c''est aussi ce qu''un évaluateur demande à voir.',
 'Toute administration légitime. Cette règle est faite pour être bruyante et revue, pas pour réveiller quelqu''un — l''affiner sur les plages horaires et les adresses attendues est le premier réglage à faire.',
 'Rapprocher de la demande d''accès privilégié correspondante. Une session sans demande est l''écart à instruire.',
 '{DORA,PCIDSS,SWIFTCSP,ISO27001}', '{DORA-10.3,PCI-8.3.6,CSCF-4.2,A.8.2}', '{}', true, '{accès-privilégié,standard}'),

('CRP-IAM-0004', 1,
 'Élévation de privilèges',
 'Une action d''élévation de privilèges, réussie ou non.',
 'IAM', 'HIGH', 'TA0004', 'T1548',
 '{"field_matches":[{"field":"action","op":"contains","value":"privilege"}]}',
 '[{"type":"notify"}]', 300,
 'L''élévation est l''étape qui sépare un pied dans la porte d''une compromission. Elle est rarement légitime sur un serveur de production en dehors d''une fenêtre de changement.',
 'Les outils d''administration et de déploiement en produisent. Exclure les comptes de service connus plutôt que de baisser la sévérité.',
 'Vérifier la fenêtre de changement. Hors fenêtre, isoler l''hôte avant d''enquêter.',
 '{DORA,ISO27001}', '{DORA-10.3,A.8.2}', '{}', true, '{standard}'),

-- ── Execution ────────────────────────────────────────────────────────────────
('CRP-EXE-0001', 1,
 'Interpréteur lancé sur un actif critique',
 'Le lancement d''un interpréteur de commandes sur un actif dont la sévérité d''événement est critique.',
 'Security', 'CRITICAL', 'TA0002', 'T1059',
 '{"field_matches":[{"field":"action","op":"contains","value":"process_exec"},
                    {"field":"threat_score","op":"gte","value":"8"}]}',
 '[{"type":"notify"},{"type":"create_case"}]', 300,
 'Sur un serveur de paiement ou de cœur bancaire, un interpréteur interactif n''a presque jamais de raison d''être. C''est l''un des signaux les plus spécifiques qui existent.',
 'Les scripts d''exploitation et de sauvegarde. Les inscrire nommément plutôt que d''élargir la condition.',
 'Isoler l''hôte. Récupérer la ligne de commande complète et l''arbre de processus parent avant tout redémarrage.',
 '{DORA,SWIFTCSP,ISO27001}', '{DORA-10.3,CSCF-6.4,A.8.16}', '{}', true, '{exécution,standard}'),

-- ── Command and control ──────────────────────────────────────────────────────
('CRP-C2-0001', 1,
 'Contact avec un indicateur de compromission connu',
 'Une valeur de l''événement figure au renseignement du tenant, quel que soit le champ.',
 'Network', 'CRITICAL', 'TA0011', 'T1071.001',
 '{"field_matches":[{"field":"ioc_matched","op":"exists","value":""}]}',
 '[{"type":"notify"},{"type":"block_ip"}]', 300,
 'La détection la plus directe que la plateforme sache faire : le renseignement du client a nommé cette valeur, et elle vient d''apparaître dans son parc.',
 'Un indicateur périmé ou trop large — une adresse d''hébergeur mutualisé, un domaine de CDN. La qualité du flux est la seule vraie défense ; le champ ioc_matched nomme l''indicateur pour qu''on puisse le retirer.',
 'Confirmer l''indicateur dans le renseignement, puis remonter à l''hôte source et à ce qu''il faisait.',
 '{DORA,SWIFTCSP,ISO27001}', '{DORA-10.3,CSCF-6.4,A.5.7}', '{}', true, '{renseignement,standard}'),

('CRP-C2-0002', 1,
 'Balise vers une adresse de commande et de contrôle',
 'Une adresse IP de l''événement figure au renseignement, sur un flux réseau.',
 'Network', 'CRITICAL', 'TA0011', 'T1071.001',
 '{"field_matches":[{"field":"ioc_matched","op":"contains","value":"ip:"},
                    {"field":"category","op":"eq","value":"Network"}]}',
 '[{"type":"notify"},{"type":"block_ip"}]', 600,
 'Plus étroit que CRP-C2-0001 et bien plus actionnable : une adresse, un flux sortant, un blocage possible immédiatement.',
 'Les mêmes que 0001, plus le cas d''une adresse réattribuée depuis que le flux l''a notée.',
 'Bloquer sortant. Chercher les autres hôtes qui ont parlé à la même adresse sur la même fenêtre — c''est ainsi qu''on trouve l''étendue.',
 '{DORA,SWIFTCSP}', '{DORA-10.3,CSCF-6.4}', '{}', true, '{renseignement,standard}'),

('CRP-C2-0003', 1,
 'Résolution d''un domaine malveillant connu',
 'Un domaine ou une URL de l''événement figure au renseignement.',
 'Network', 'HIGH', 'TA0011', 'T1071.001',
 '{"field_matches":[{"field":"ioc_matched","op":"contains","value":"domain:"}]}',
 '[{"type":"notify"}]', 600,
 'Une résolution précède le flux. Détecter à la résolution donne la fenêtre la plus large pour intervenir avant que quoi que ce soit ne sorte.',
 'Un poste qui résout un domaine cité dans un courriel sans jamais s''y connecter. La résolution est un signal, pas une preuve de connexion.',
 'Vérifier si un flux a suivi. Sinon, traiter comme une exposition à instruire plutôt que comme une compromission.',
 '{DORA,ISO27001}', '{DORA-10.3,A.5.7}', '{}', true, '{renseignement,standard}'),

-- ── Exfiltration ─────────────────────────────────────────────────────────────
('CRP-EXF-0001', 1,
 'Transfert sortant de volume anormal',
 'Un transfert de fichiers sur un événement de sévérité élevée ou critique.',
 'Security', 'HIGH', 'TA0010', 'T1567',
 '{"field_matches":[{"field":"action","op":"contains","value":"file_transfer"},
                    {"field":"threat_score","op":"gte","value":"6"}]}',
 '[{"type":"notify"}]', 900,
 'L''exfiltration est le moment où un incident devient une notification réglementaire. La détecter au transfert, et non à la publication des données, est toute la différence.',
 'Les sauvegardes, les réplications, les exports de fin de mois. Les exclure par compte de service et par fenêtre horaire.',
 'Déterminer la destination et le volume. Si la destination est externe et hors fenêtre, traiter comme une exfiltration jusqu''à preuve du contraire.',
 '{DORA,PCIDSS,ISO27001}', '{DORA-10.3,DORA-17.1,PCI-10.4.1,A.8.12}', '{}', true, '{exfiltration,standard}'),

('CRP-EXF-0002', 1,
 'Transfert vers une destination au renseignement',
 'Un transfert dont la destination figure au renseignement.',
 'Security', 'CRITICAL', 'TA0010', 'T1567',
 '{"field_matches":[{"field":"ioc_matched","op":"contains","value":"@ip_destination"},
                    {"field":"action","op":"contains","value":"transfer"}]}',
 '[{"type":"notify"},{"type":"block_ip"}]', 300,
 'La conjonction des deux — un transfert, et une destination que le renseignement connaît — laisse peu de place au doute.',
 'Très peu. Un faux positif ici est presque toujours un indicateur de mauvaise qualité.',
 'Bloquer, préserver les journaux de flux, et enclencher l''évaluation de notification : c''est le cas où le délai réglementaire commence à courir.',
 '{DORA,PCIDSS}', '{DORA-17.1,PCI-10.4.1}', '{}', true, '{exfiltration,renseignement,standard}'),

-- ── Discovery and lateral movement ───────────────────────────────────────────
('CRP-DIS-0001', 1,
 'Balayage réseau depuis une adresse interne',
 'Vingt actions de découverte ou plus depuis une même adresse en cinq minutes.',
 'Network', 'MEDIUM', 'TA0007', 'T1046',
 '{"field_matches":[{"field":"mitre_technique","op":"eq","value":"T1046"}],
   "threshold":{"count":20,"window_seconds":300,"group_by":["ip_source"]}}',
 '[{"type":"notify"}]', 600,
 'La reconnaissance interne précède le déplacement latéral. C''est l''un des rares moments où l''attaquant est bruyant.',
 'Les scanners de vulnérabilité et les outils d''inventaire, qui font exactement cela pour de bonnes raisons. Les exclure par adresse, pas en montant le seuil.',
 'Vérifier que l''adresse appartient à un outil déclaré. Sinon, identifier l''hôte et ce qu''il a trouvé.',
 '{DORA,ISO27001}', '{DORA-10.3,A.8.16}', '{}', true, '{découverte,standard}'),

('CRP-LAT-0001', 1,
 'Déplacement latéral par service distant',
 'Une action que l''enrichissement classe en déplacement latéral (RDP, SSH, WMI, PsExec).',
 'Network', 'HIGH', 'TA0008', 'T1021',
 '{"field_matches":[{"field":"mitre_technique","op":"eq","value":"T1021"}]}',
 '[{"type":"notify"}]', 600,
 'Le déplacement latéral est ce qui transforme un poste compromis en incident de cœur bancaire. La règle s''appuie sur la classification ATT&CK de l''enrichissement plutôt que sur une liste de verbes, afin de couvrir les quatre protocoles d''un coup.',
 'L''administration quotidienne en produit énormément. À affiner sur les zones : un flux d''administration vers la zone de paiement est une autre affaire qu''un flux au sein d''un même segment bureautique.',
 'Rapprocher des zones source et destination. Un franchissement de zone est l''écart à instruire.',
 '{DORA,SWIFTCSP,ISO27001}', '{DORA-10.3,CSCF-1.1,A.8.22}', '{}', true, '{latéral,standard}'),

-- ── Fraud and impact ─────────────────────────────────────────────────────────
('CRP-FRD-0001', 1,
 'Transaction à risque élevé',
 'Un événement de transaction dont le score de risque atteint 7.',
 'Transaction', 'HIGH', 'TA0040', 'T1657',
 '{"field_matches":[{"field":"category","op":"eq","value":"Transaction"},
                    {"field":"threat_score","op":"gte","value":"7"}]}',
 '[{"type":"notify"},{"type":"create_case"}]', 300,
 'Le vol financier est la finalité de la plupart des attaques contre une banque. Une transaction que l''enrichissement note haut mérite un œil humain avant règlement, pas après.',
 'Les transactions atypiques légitimes — un virement exceptionnel, une opération de trésorerie. C''est le cas d''usage où la revue humaine est la réponse, pas l''affinage.',
 'Suspendre le règlement si le circuit le permet, et rappeler le donneur d''ordre par un canal indépendant.',
 '{DORA,PCIDSS}', '{DORA-10.3,PCI-10.4.1}', '{}', true, '{fraude,standard}'),

-- ── Entries that cannot fire yet, and say so ─────────────────────────────────
('CRP-GEO-0001', 1,
 'Accès depuis un pays sous sanctions',
 'Une authentification depuis un pays que la plateforme classe comme sous sanctions.',
 'IAM', 'CRITICAL', 'TA0001', 'T1078',
 '{"field_matches":[{"field":"geo_anomaly","op":"eq","value":"true"},
                    {"field":"category","op":"eq","value":"IAM"}]}',
 '[{"type":"notify"},{"type":"create_case"}]', 300,
 'Un accès depuis une juridiction sous sanctions est à la fois un signal de compromission et un sujet de conformité en soi.',
 'Un collaborateur en déplacement, un VPN mal choisi. La résolution géographique se trompe aussi.',
 'Confirmer la localisation par un second moyen avant d''agir : bloquer un dirigeant en déplacement coûte cher.',
 '{DORA,ISO27001}', '{DORA-10.3,A.5.7}',
 '{"Base GeoIP MaxMind (GEOIP_DATABASE_PATH) : sans elle l''enrichissement ne résout aucun pays et la règle ne peut pas déclencher."}',
 false, '{géographie,standard}'),

('CRP-IAM-0005', 1,
 'Activité en dehors des heures ouvrées',
 'Une action dont l''enrichissement estime le risque assez élevé pour marquer une activité hors plage.',
 'IAM', 'MEDIUM', 'TA0001', 'T1078',
 '{"field_matches":[{"field":"anomalous_hours","op":"eq","value":"true"},
                    {"field":"category","op":"eq","value":"IAM"}]}',
 '[{"type":"notify"}]', 1800,
 'Une session à trois heures du matin sur un système de paiement n''est pas anormale en soi ; elle l''est pour un compte qui n''en ouvre jamais.',
 'Les astreintes, les clôtures, les équipes en décalage horaire. Cette règle a besoin de la notion de plage attendue par compte pour valoir quelque chose.',
 'Rapprocher du planning d''astreinte avant d''appeler.',
 '{DORA,ISO27001}', '{DORA-10.3,A.8.16}',
 '{"Plages horaires attendues par compte : le champ anomalous_hours dérive aujourd''hui du seul score de risque, ce qui en fait un signal grossier."}',
 false, '{comportement,standard}')

ON CONFLICT DO NOTHING;
