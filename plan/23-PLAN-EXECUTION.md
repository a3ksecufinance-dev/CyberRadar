# Plan d'exécution — vers la plateforme complète

> Date : 2026-10-02 · Périmètre retenu : **le master plan intégral**, 346 user
> stories sur 15 domaines.
> Équipe : non arrêtée → **le plan est exprimé en charge, pas en calendrier**.
> Contrainte de date : aucune → **l'ordre suit les dépendances techniques et la
> dette**, sans arbitrage commercial.
>
> Fusionne et remplace [`21-PRODUCTION-PLAN.md`](21-PRODUCTION-PLAN.md), qui ne
> couvrait que le déploiement, et donne une suite exécutable à
> [`22-ECART-PREVU-MESURE.md`](22-ECART-PREVU-MESURE.md), qui a mesuré l'écart
> fonctionnel.

---

## 0. Le chiffre d'abord

**2 229 jours-homme**, soit **un peu plus de 10 années-homme**.

Il est en tête parce qu'un chiffre de cette taille doit être connu au premier
jour, pas découvert au dix-huitième mois. Il recouvre :

| | Lots | Charge |
|---|---|---:|
| Les 245 user stories restantes (180 absentes + 65 partielles) | L3 → L12 | 1 850 j |
| Le socle, le déploiement et la mesure (ex-`plan/21`) | L0, L1, L2 | 319 j |
| La validation externe (charge interne ; les prestataires s'ajoutent) | L13 | 60 j |
| **Total** | | **2 229 j** |

### Ce que ça donne selon l'équipe

| Équipe | Calendrier | Surcoût de coordination retenu |
|---|---|---|
| 3 ingénieurs | **~3 ans et demi** | négligeable |
| 6 ingénieurs | **~2 ans** | +15 % |
| 10 ingénieurs | **~1 an et 4 mois** | +30 % |

> **Ajouter des gens n'accélère pas tout.** Le lot L13 (test d'intrusion, audit
> de code, revue de conformité) prend trois mois de calendrier quelle que soit
> l'équipe, et plusieurs lots ont une profondeur de dépendance qui borne le
> parallélisme. Au-delà de 10 personnes, le gain marginal devient faible sur ce
> graphe de dépendances.

---

## 1. La méthode d'estimation, et sa précision

**Estimation ascendante par lot**, pas par user story : certaines US coûtent
une journée, d'autres trois semaines, et une moyenne par US serait un chiffre
sans contenu. Chaque lot est chiffré sur ce qu'il faut réellement construire —
un moteur de recherche, un cadre de connecteurs, un générateur de rapports —
puis réparti.

**La précision est de ±50 % à cette granularité.** C'est la précision honnête
d'un chiffrage fait sans découpage en tâches. Les estimations sont les miennes,
pas celles de l'équipe qui les tiendra : la première chose à faire avec ce
document est de les faire ré-estimer par ceux qui exécuteront.

**Ordre de grandeur de contrôle** : 101 US faites correspondent à 77 521 lignes
de Go hors tests, soit ~770 lignes par US. Les 245 restantes au même rythme
donneraient ~190 000 lignes. Le chiffrage de 2 200 jours implique ~86 lignes
par jour-homme, tests et revue compris — ce qui est conforme à ce qu'on observe
sur du logiciel de ce type. **Les deux approches se recoupent**, ce qui ne les
rend pas justes mais écarte l'erreur d'un facteur trois.

---

## 2. Le graphe de dépendances

C'est lui qui fixe l'ordre, puisqu'aucune date ne le fait.

```
 L0 Dette ──┬──▶ L1 Déploiement ──▶ L2 Mesure
 (socle)    │
            └──▶ L3 Découverte ──┬──▶ L4 Inventaire ──▶ L7 Graphe ──┐
                 (le verrou)     │                                   │
                                 ├──▶ L9 Conformité ─────────────────┤
                                 │                                   │
                                 └──▶ L5 Détection avancée ──────────┤
                                                                     │
 L6 Recherche ───────────────────────────────────────────────────────┤
 L8 Gouvernance de la réponse ───────────────────────────────────────┤
 L11 Plateforme d'intégration ───────────────────────────────────────┤
 L12 Socle avancé ───────────────────────────────────────────────────┤
                                                                     ▼
                                                      L10 Interfaces riches
                                                                     │
                                                                     ▼
                                                      L13 Validation externe
```

Trois propriétés de ce graphe méritent d'être dites :

**L3 est le verrou.** La découverte débloque quatre domaines à elle seule :
sans inventaire découvert, on ne classifie rien (D2), on ne corrèle aucune
vulnérabilité à un parc (D7), on ne profile aucune identité venue de
l'annuaire (D3), et on n'évalue aucun contrôle de conformité (D14, aujourd'hui
à 0 %). C'est la conclusion centrale de [`22`](22-ECART-PREVU-MESURE.md) §7.2,
et elle décide de l'ordre.

**L10 vient tard, et c'est volontaire.** On visualise ce qui existe. Construire
une war room ou un visualiseur de graphe avant que le graphe soit alimenté
automatiquement produit une interface sur un jeu de données de démonstration.

**L6, L8, L11 et L12 sont indépendants** et peuvent être menés en parallèle dès
que L0 est fait. Ce sont eux qui absorbent une équipe plus large.

---

## 3. Les quatorze lots

### L0 — Dette et socle d'exécution · ~84 j

**Prérequis à tout le reste.** On ne construit pas 245 user stories sur un
socle où 17 services sur 32 n'ont aucun test : chaque lot suivant y ajouterait
de la dette plus vite qu'il n'ajoute de la valeur.

| Tâche | Charge |
|---|---:|
| Testcontainers (PostgreSQL, ClickHouse, Kafka), une fois pour toutes | 10 j |
| Couverture ≥ 60 % sur `tenant` et `collector` — les deux dont un défaut est silencieux | 20 j |
| Au moins un test sur chacun des 15 autres services sans test | 25 j |
| Parcours de bout en bout scripté et chronométré, en CI | 10 j |
| Migrations à état (`golang-migrate` sur les 47 existantes) | 12 j |
| Sortir `next-auth` de sa version bêta ; `govulncheck` et `npm audit` bloquants | 5 j |
| Les 5 tables mortes : **supprimées** par la migration `000048` — arbitrage tranché, L12 les recréera en les implémentant | 2 j |

**Sortie** : aucun service à 0 test, `make e2e-chain` vert en CI, deux
applications de migrations de suite sans erreur.

---

### L1 — Déploiement et exploitation · ~190 j

Reprend les jalons J1, J3 et J4 de [`21`](21-PRODUCTION-PLAN.md), dont le
détail tâche par tâche reste valable.

| Bloc | Charge |
|---|---:|
| TLS, point d'entrée unique, secrets hors du dépôt, compte de service SOAR | 20 j |
| Limites de ressources, 34 sondes manquantes, images poussées et scannées | 15 j |
| **Consolidation 32 → 8-10 unités** — avant Helm, jamais après | 45 j |
| Helm et Terraform, sondes de vivacité et de disponibilité distinctes, `NetworkPolicy` | 35 j |
| Haute disponibilité : PostgreSQL, Kafka 3 courtiers, ClickHouse, Redis, PDB/HPA | 35 j |
| Reprise : sauvegarde, restauration **exécutée et chronométrée**, RPO/RTO écrits | 20 j |
| Observabilité : alertes Prometheus, Alertmanager, tableaux de bord versionnés, métriques syslog et pipeline manquantes | 15 j |
| Rétention et purge, y compris la purge PostgreSQL qui n'existe pas | 5 j |

**Sortie** : un environnement créé et détruit par commande, deux fois de suite
avec le même résultat ; une panne de chaque composant survivable ; une
reconstruction complète chronométrée.

---

### L2 — Mesure · ~45 j · 1 US

Les 8 KPI du master plan et les 14 exigences non fonctionnelles, dont
**aucun n'a jamais été mesuré**.

| Tâche | Charge |
|---|---:|
| Banc de charge reproductible (injection syslog et API, jeu de données réaliste) | 15 j |
| Les trois chiffres : débit d'ingestion, latence API p95, temps de détection | 10 j |
| Les cinq autres KPI : MTTD, MTTR sous charge, réduction des faux positifs, couverture d'actifs, disponibilité | 10 j |
| Les NFR qui deviennent vérifiables : scaling horizontal exercé, reprise < 15 min, latence pipeline < 3 s, `US-CTI-ENR-002` enrichissement < 500 ms | 10 j |

**Sortie** : les 8 KPI publiés dans un tableau de bord, avec la configuration
matérielle qui les a produits. Et une décision explicite : **tenir le chiffre
de 100 K EPS, ou le changer**.

---

### L3 — La découverte · ~240 j · 27 US

**Le verrou.** Rien n'entre aujourd'hui dans la plateforme tout seul.

| Bloc | US | Charge |
|---|---:|---:|
| Cadre de connecteurs : SDK, cycle de vie, santé, configuration, mise à jour | `US-CDF-CON-001` à `004` | 50 j |
| Découverte passive depuis les logs | `US-CAI-DIS-003` | 20 j |
| Découverte réseau active | `US-CAI-DIS-001`, `002` | 25 j |
| Connecteurs cloud AWS, Azure, GCP | `US-CAI-DIS-004` | 40 j |
| Kubernetes, SaaS et API internes | `US-CAI-DIS-005`, `006` | 25 j |
| Annuaire : AD, LDAP, IAM, PAM | `US-CAI-DIS-007`, `US-IPM-INV-002` | 30 j |
| Scanners de vulnérabilité : Qualys, Tenable, Nessus | `US-VEI-DIS-001`, `003` | 25 j |
| Flux CVE : NVD et MITRE | `US-VEI-DIS-002` | 10 j |
| Feeds CTI : STIX/TAXII, CSV, API, fraîcheur, priorisation | `US-CTI-FED-001` à `004` | 25 j |
| Modes d'ingestion manquants : pull, batch, MQTT/AMQP, NetFlow/IPFIX/sFlow, Parquet/Avro, parser par interface, géolocalisation réelle | `US-CDF-ING-001/002/004/005/006/007`, `PAR-002`, `ENR-003` | 40 j |

**Sortie** : un parc réel découvert sans saisie manuelle, et les quatre
domaines en aval alimentés par lui.

---

### L4 — L'inventaire · ~170 j · 29 US

D2 Asset Intelligence est à 12 % ; c'est le domaine le moins avancé pour une
priorité HAUTE. Il devient constructible une fois L3 fait.

| Bloc | Charge |
|---|---:|
| Classification automatique, score de confiance, catégories custom, workflow de validation | 35 j |
| Empreinte d'actif : déduplication, fusion, réidentification après disparition | 25 j |
| Fiche complète, historique, versions de configuration | 20 j |
| Criticité calculée, impact financier | 20 j |
| Cartographie de dépendances, flux applicatifs et réseau, blast radius | 35 j |
| Shadow IT : détection, score, alerte | 20 j |
| Rogue devices et recommandation de quarantaine | 15 j |
| Cycle de vie, actifs orphelins et dormants | 10 j |
| Exposition et correctifs (D7) : actifs exposés, misconfigurations, credentials exposés, patches disponibles et planifiés, dépassement de SLA | 25 j |

**Sortie** : une fiche d'actif qui se remplit seule, et un blast radius
calculable.

---

### L5 — La détection avancée · ~400 j · 68 US

Le plus gros lot, et celui qui porte la différenciation produit.

| Bloc | US | Charge |
|---|---:|---:|
| XDR : détection cross-couche, story graph, kill chain | `US-DET-XDR-001` à `003` | 60 j |
| Cycle de vie des règles : sandbox, rollback, apprentissage des faux positifs | `US-DET-RUL-001/003/004/005`, `ALT-004` | 50 j |
| Agrégation automatique d'incidents, scoring d'impact métier, navigation ATT&CK | `US-DET-INC-002/004`, `MIT-002/003`, `ALT-005`, `CAS-003` | 35 j |
| UEBA : groupes de pairs, baselines par pairs, combinaison d'anomalies faibles | `US-UBA-BAS-002/004`, `ANO-003`, `PGP-001/002` | 50 j |
| UEBA : insider threat, signaux RH, score insider | `US-UBA-INS-001` à `003` | 35 j |
| UEBA : nouveau device, voyage impossible, post-compromission, analyse de session, hijacking, abus PAM | `US-UBA-COM-001/002/003`, `SES-001/002/003`, `RTL-002/003` | 45 j |
| Fusion cyber-fraude | `US-UBA-FRD-001` à `003` | 30 j |
| ITDR : Pass-the-Hash, Pass-the-Ticket, Kerberoasting, Golden Ticket, latéral par identités, incident ITDR | `US-IPM-TDR-001` à `004` | 45 j |
| Identité : score de risque dynamique et expliqué, corrélation session→action→actif, audit des commandes PAM, chemin d'escalade, service accounts | `US-IPM-RSK-001/002/003`, `PAM-002/003`, `ESC-002/003`, `SVC-002/003`, `INV-003`, `ORB-003` | 50 j |
| CTI : navigation ATT&CK, corrélation acteur, expiration d'IOC, export et partage STIX, prédiction de ciblage | `US-CTI-MIT-001`, `ACT-002/003`, `IOC-004`, `SHR-001/002`, `PRD-001/002` | 35 j |
| Copilot : NL→Cypher/SQL, recommandations prioritaires, explicabilité, journalisation des interactions | `US-AIC-NLQ-002/003`, `REC-001/002/003`, `INV-002`, `EXP-003`, `GRD-002` | 35 j |
| Apprentissage de formats par le parser | `US-CDF-PAR-005` | 15 j |

**Sortie** : une détection qui corrèle entre couches et qui apprend, et une
identité dont le score de risque est calculé — il ne l'est aujourd'hui jamais.

---

### L6 — Recherche et forensic · ~130 j · 9 US

Indépendant : peut démarrer dès L0.

| Bloc | Charge |
|---|---:|
| Moteur de recherche full-text temps réel sur ClickHouse | 45 j |
| Langage de requête SQL-like, analyseur et exécuteur | 40 j |
| Requêtes sauvegardées et partagées, playbooks de chasse | 15 j |
| Rejeu de flux depuis un point donné | 15 j |
| Reconstitution de timeline et export de preuves forensic | 15 j |

**Sortie** : un chasseur de menaces peut poser une question que personne n'a
anticipée.

---

### L7 — Analyse de graphe · ~150 j · 24 US

| Bloc | Charge |
|---|---:|
| Génération automatique du graphe depuis Identity, Asset, Privilege, Vulnerability | 35 j |
| Mise à jour temps réel, propagation < 5 s, archivage des nœuds retirés | 25 j |
| Simulation « si ce compte est compromis », impact d'une non-remédiation | 25 j |
| Blast radius, expression métier, classement | 25 j |
| Centralité, clusters à risque, PageRank cyber | 25 j |
| Alertes sur nouveau chemin critique vers CBS/SWIFT, avec remédiation | 15 j |

**Sortie** : un graphe qui s'alimente seul et un classement de corrections par
nombre de chemins cassés.

---

### L8 — Gouvernance de la réponse · ~150 j · 18 US

Les quinze actions SOAR sont **réelles** : elles bloquent, désactivent,
isolent. Sans palier d'approbation, un client prudent n'en activera aucune.
Ce lot rend utilisable ce qui est déjà construit.

| Bloc | Charge |
|---|---:|
| Approbation humaine : demande, seuils par type d'action, escalade sur délai | 35 j |
| Versionnement, rollback et simulation de playbook | 30 j |
| Déclenchement automatique sur condition (le champ existe, rien ne l'évalue) | 20 j |
| Décision selon criticité + impact + confiance ; réponse adaptative | 25 j |
| Annulation d'une action exécutée | 15 j |
| Intégrations : AD, EDR, ServiceNow/Jira, révocation de session PAM | 25 j |

**Sortie** : une action à haut risque demande une validation, et une action
exécutée s'annule.

---

### L9 — Conformité et rapports · ~130 j · 13 US

D14 est à **0 %** pour une cible bancaire. Les référentiels et les contrôles
sont en base ; rien ne les évalue.

| Bloc | Charge |
|---|---:|
| Moteur d'évaluation de contrôles contre l'état réel du parc | 45 j |
| Référentiels : PCI DSS, SWIFT CSP, DORA, ISO 27001 | 35 j |
| Alerte à l'échec d'un contrôle | 10 j |
| Générateur de rapports : PCI SAQ/ROC, SWIFT, ISO, PDF | 30 j |
| Rapports récurrents programmés | 10 j |

**Sortie** : une posture de conformité qui se calcule, et un rapport qu'un
auditeur accepte.

---

### L10 — Interfaces riches · ~170 j · 15 US

Après les lots qui produisent ce qu'elles affichent.

| Bloc | Charge |
|---|---:|
| Visualisation de graphe interactive : zoom, filtre, expansion, centrage, couleurs par risque | 45 j |
| Heatmap MITRE ATT&CK | 15 j |
| War room collaborative : timeline temps réel, actions, notes, coordination | 50 j |
| Constructeur de tableaux de bord en glisser-déposer, partage | 35 j |
| Tableaux dirigeants : langage métier, service plutôt que serveur, EPS temps réel | 25 j |

**Sortie** : un CISO voit « Service Paiement Monétique — Risque ÉLEVÉ », pas
« PROD-17 vulnérable ».

---

### L11 — Plateforme d'intégration · ~120 j · 14 US

Indépendant après L1 (la passerelle y est posée).

| Bloc | Charge |
|---|---:|
| Limitation de débit par tenant et par endpoint | 15 j |
| OpenAPI complet, généré depuis le code comme l'est déjà la référence | 20 j |
| Portail développeur : documentation, « Try It », génération de clés | 30 j |
| Webhooks sortants : abonnement, reprise, statut de livraison | 20 j |
| SDK Python et SDK TypeScript, avec auth, reprise et pagination | 25 j |
| GraphQL sur les lectures complexes | 10 j |

**Sortie** : un intégrateur tiers travaille sans nous parler.

---

### L12 — Socle avancé · ~190 j · 27 US

Indépendant après L0. Ce sont les 27 US de D0 que les phases précédentes
n'ont pas couvertes.

| Bloc | Charge |
|---|---:|
| Tenants parents/enfants, segmentation par BU et région, analytics cross-tenant en opt-in | 35 j |
| Provisionnement et déprovisionnement automatiques, groupes | 25 j |
| ABAC par BU/région/criticité/sensibilité | 30 j |
| Élévation de privilèges juste-à-temps | 20 j |
| MFA : FIDO2, push, carte à puce ; SAML ; authentification adaptative ; step-up sur contexte | 35 j |
| Secrets : les 29 services restants sur Vault, rotation automatique, audit des accès | 25 j |
| Configuration centralisée, rollback, détection de dérive (les 3 tables mortes) | 25 j |
| Audit immuable, horodatage universel sur tous les services | 15 j |
| Escalade de notification, templates, canal SMS | 15 j |
| Feature flags par tenant, déploiement canary, découverte de services | 20 j |

**Sortie** : un MSSP peut exploiter plusieurs tenants, et un secret se fait
tourner sans redéploiement.

---

### L13 — Validation externe · ~60 j internes + prestataires

| | Calendrier | Charge interne |
|---|---|---:|
| Test d'intrusion externe, boîte grise | 3 sem. | 10 j |
| **Fenêtre de correction** — sans elle, un pentest est un rapport, pas une validation | 2 sem. | 25 j |
| Audit de code tiers | 3 sem. | 10 j |
| Test de charge contradictoire | 1 sem. | 5 j |
| Revue de la matrice RBAC par la sécurité du client | 1 sem. | 5 j |
| Revue de conformité DORA, PCI DSS ou SWIFT CSCF | 2 sem. | 5 j |

**Sortie** : les constats de criticité haute et moyenne corrigés et
revérifiés, rapports signés.

---

## 4. Récapitulatif

| Lot | US | Charge | Dépend de |
|---|---:|---:|---|
| L0 Dette et socle d'exécution | — | 84 j | — |
| L1 Déploiement et exploitation | — | 190 j | L0 |
| L2 Mesure | 1 | 45 j | L1 |
| **L3 Découverte** | 27 | **240 j** | L0 |
| L4 Inventaire | 29 | 170 j | L3 |
| **L5 Détection avancée** | 68 | **400 j** | L3 |
| L6 Recherche et forensic | 9 | 130 j | L0 |
| L7 Analyse de graphe | 24 | 150 j | L4 |
| L8 Gouvernance de la réponse | 18 | 150 j | L0 |
| L9 Conformité et rapports | 13 | 130 j | L3 |
| L10 Interfaces riches | 15 | 170 j | L4, L5, L7 |
| L11 Plateforme d'intégration | 14 | 120 j | L1 |
| L12 Socle avancé | 27 | 190 j | L0 |
| L13 Validation externe | — | 60 j | tous |
| **Total** | **245** | **2 229 j** | |

La répartition des 245 US entre les lots est **exacte** : elle a été vérifiée
contre le décompte par domaine de [`22`](22-ECART-PREVU-MESURE.md), domaine par
domaine, sans reste.

---

## 5. Les portes de qualité

Puisque la qualité passe avant la date, elle doit être une condition de
passage, pas une intention.

**Aucun lot n'est déclaré fini sans les six :**

1. **Couverture ≥ 60 % sur le code que le lot ajoute.** Mesurée, pas estimée.
2. **`make smoke` et le parcours de bout en bout verts**, contre une plateforme
   qui tourne.
3. **Chaque US a un critère d'acceptation vérifiable** — une commande et un
   résultat, pas « la fonctionnalité est disponible ».
4. **La référence d'API régénérée** (`make docs-api`) et le contrôle de dérive
   vert.
5. **Les tests du lot ont été éprouvés par mutation** sur le code critique :
   casser volontairement le garde-fou et vérifier que le test échoue, **et
   qu'il échoue pour la bonne raison**. Un test vert qui ne teste rien est pire
   qu'aucun test — ce dépôt en a déjà rencontré deux.
6. **Aucune dette ajoutée** : pas de nouveau service sans test, pas de nouvelle
   table sans code, pas de nouvelle route hors de la référence générée.

**Une règle d'enchaînement** : on ne commence pas un lot si le précédent a
laissé l'un des six ouverts. C'est ce qui donne un sens opérationnel à
« qualité d'abord » — sinon la qualité est la variable qui cède quand la
charge dérape.

---

## 6. Suivre l'exécution

Huit indicateurs. Ils sont tous calculables par une commande, pour qu'aucun ne
dépende d'une déclaration.

> **Avancement au 2026-10-05.** B7 est fait : les cinq tables sont supprimées
> par la migration `000048`. B1 est fait : `internal/pkg/testinfra` donne à un
> test une base migrée, un ClickHouse migré et un courtier Kafka. **B2 est
> fait** : `tenant` passe de 2,4 % à **72,6 %** et `collector` de 0 % à
> **83,2 %**, tous deux au-dessus de la cible de 60 %. Le travail a trouvé
> trois défauts que ni la compilation ni `vet` ne voyaient — les lettres mortes
> du collecteur publiées sur le sujet des événements, tout syslog RFC 3164
> horodaté en l'an 0000, et les extensions CEF découpées sur les espaces (voir
> [`docs/19`](../docs/19-developpement.md#ce-qui-est-le-plus-couvert)). C'est
> l'argument du lot : la couverture ne protège pas du futur, elle révèle le
> présent. B3 à B6 restent.

| Indicateur | Départ | Cible | Commande |
|---|---|---|---|
| US faites | **101 / 346** | 346 | relevé par lot |
| Services sans test | ~~17~~ → ~~16~~ → **15 / 32** | 0 | `find … -name '*_test.go'` par service |
| Couverture, services critiques | ~~non mesurée~~ → **tenant 73 %, collector 83 %** ✓ | ≥ 60 % | `go test -cover` |
| KPI mesurés | **0 / 8** | 8 | tableau de bord L2 |
| NFR vérifiées | **0 / 14** | 14 | bancs L2 |
| Tables sans code | ~~5 / 142~~ → **0 / 137** ✓ | 0 | script de [`22`](22-ECART-PREVU-MESURE.md) §3 |
| Unités déployables | **32** | 8–10 | `ls bin` |
| Secrets dans le dépôt | **oui** | 0 | `git ls-files \| grep -E '\.pem$\|\.key$'` |

**Le premier est trompeur seul** : les US n'ont pas le même poids, et un lot
peut avancer de 200 jours en fermant 9 US (L6). Suivre les huit ensemble, ou
suivre la charge consommée par lot.

---

## 7. Les risques propres à ce plan

| Risque | Pourquoi il est réel ici | Ce qui le réduit |
|---|---|---|
| **La durée** | À 3 ingénieurs, trois ans et demi. Le marché, la pile technique et l'équipe changeront avant la fin | Livrer par lot, chaque lot ayant une valeur autonome. L3 seul transforme déjà le produit |
| **L'estimation à ±50 %** | 2 235 j peut être 1 100 ou 3 350 | Ré-estimer par lot, par l'équipe, avant de s'engager. Recaler après L0 et L3, qui sont les deux premiers lots mesurables |
| **L5 fait 18 % de la charge** | Un seul lot de 400 j concentre le risque de dérive | Le découper en sous-lots livrables avant de l'attaquer : XDR, UEBA, ITDR et CTI sont quatre chantiers séparables |
| **La qualité cède sous la charge** | C'est le défaut classique d'un plan long sans date | Les six portes de §5, et la règle d'enchaînement. Elles n'ont de valeur que si personne n'a le droit de les lever |
| **Les 8 KPI restent non mesurés** | L2 vient après L1, donc tard. Un prospect peut demander avant | **Sortir les trois chiffres de base de L2 et les faire dès L0** si une sollicitation commerciale arrive. C'est 10 jours |
| **Les connecteurs de L3 vieillissent** | Une API cloud change deux fois par an | Les tests d'intégration des connecteurs tournent contre les API réelles, pas contre des doublures figées |

---

## 8. Ce que je ferais en premier

Sans date qui contraigne, l'ordre technique s'impose — mais à charge égale,
deux choses se placent avant les autres :

1. **L0 en entier.** 90 jours. Rien ne devrait être construit sur un socle où
   `tenant`, qui porte les quatre politiques de tous les clients, n'a aucun
   test.
2. **Les trois chiffres de L2, extraits et faits tout de suite.** 10 jours
   prélevés sur L2. C'est le seul écart du [`22`](22-ECART-PREVU-MESURE.md) qui
   n'a pas de correctif après coup, et il ne dépend d'aucun autre lot.

Ensuite **L3**, et le produit cesse d'être une plateforme qu'il faut remplir à
la main.
