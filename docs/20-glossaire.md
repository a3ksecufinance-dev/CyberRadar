# 20 — Glossaire

Le vocabulaire du produit, et celui du code quand il diffère.

---

## Les objets de la plateforme

**Actif** — Une machine, un service, un compte dans l'inventaire. Porte une
criticité de 1 à 4, un score de risque, et des marqueurs de contexte (DMZ,
CBS, SWIFT, PCI).

**Alerte** — Ce qu'une règle de détection produit quand elle est satisfaite.
Table `crp_siem.alerts`.

**Anomalie** — Ce que l'UEBA produit quand un comportement s'écarte du profil
d'une entité. Huit types, de `OFF_HOURS_ACCESS` à `DATA_EXFILTRATION`.

**Cas** — Le regroupement d'alertes qu'un analyste N1 constitue, dans `siem`.
À ne pas confondre avec un **incident**.

**Chemin d'attaque** — Une route dans le graphe, d'un point d'entrée à une
cible, avec son coût et son score.

**Constat** (*finding*) — Le lien entre un actif et une vulnérabilité, avec son
échéance de remédiation.

**Détection** — Une entrée du catalogue livré, en YAML. Devient une **règle**
quand un tenant l'adopte.

**Entité** — Ce que l'UEBA profile : un utilisateur ou un actif. Son
identifiant est dérivé, pas pris tel quel.

**Incident** — Trois objets portent ce nom, dans trois services :

| | Service | Ce que c'est |
|---|---|---|
| Cas | `siem` | Le regroupement d'alertes d'un analyste |
| Incident SOAR | `soar` | Ce sur quoi un playbook s'est déclenché |
| Incident IR | `ir` | Le dossier formel : preuves, tâches, chronologie |

Rien ne les relie automatiquement.

**Indicateur** (IOC) — Une valeur connue pour être malveillante : adresse,
domaine, empreinte. Indexée par `iocindex` pour être cherchée sur chaque
événement.

**Livraison** / **paquet** (*pack*) — Un fichier `.crpack` signé contenant une
version du catalogue de détection.

**Playbook** — Une suite d'actions automatiques, dans `soar`. Un *playbook de
réponse* dans `ir` est un document pour un humain, pas la même chose.

**Politique** — L'un des quatre jugements paramétrables par tenant.

**Préréglage** (*preset*) — Une politique livrée par la plateforme, qu'un
tenant peut adopter. `tenant_id` vaut `NULL`.

**Profil** — L'état comportemental d'une entité dans l'UEBA : ce qui est normal
pour elle, et six dimensions de score.

**Règle** — Une détection qu'un tenant fait tourner. Peut différer de la
version du catalogue qu'il a adoptée.

**Scénario** — Une question posée au graphe d'attaque : de ce point d'entrée
vers cette cible.

**Tenant** — Une organisation cliente. Le cloisonnement de toutes les données.

---

## Le vocabulaire du contenu

**Adopter** — Un tenant prend une entrée du catalogue et en fait une de ses
règles.

**Canal** — Un répertoire publié portant `index.json`, `index.sig` et les
paquets. Un déploiement le suit.

**Catalogue** — Les quinze détections livrées. *Le standard*, par opposition à
ce qu'un tenant fait tourner.

**Couverture** — Ce que le catalogue couvre par tactique MITRE et par
référentiel, mis en regard de ce que le tenant a adopté.

**Empreinte** (*digest*) — Le SHA-256 d'un fichier, ou du manifeste. C'est elle
qui tient lieu de numéro de version : il n'y a pas de version écrite dans un
fichier de détection.

**Généalogie** — Le lien entre une règle d'un tenant et la version du catalogue
qu'il avait adoptée. Ce qui rend l'écart calculable.

**Index** — `index.json` : la liste des versions publiées, chacune avec
l'empreinte de son manifeste, et laquelle est courante. Signé.

**Magasin de confiance** (*trust store*) — Les clés publiques qu'un déploiement
accepte, plus ses révocations. Configuré par le déploiement, **jamais** porté
par la livraison.

**Manifeste** — `manifest.json` : l'identité du paquet et l'empreinte de chaque
fichier. C'est lui que la signature couvre.

**Remise à niveau** (*upgrade*) — Porter une règle adoptée vers une version
plus récente du catalogue. Une fusion à trois, pas un écrasement.

**Retirer** (*retire*) — Un code que le catalogue ne porte plus est retiré,
jamais supprimé : des tenants l'ont adopté et doivent pouvoir relire ce qu'ils
ont pris.

**Révocation** — Retirer une clé de signature en **ajoutant** un fichier
`*.revoked`, jamais en supprimant un `.pub`.

---

## Le vocabulaire du code

**`apicheck`** — Le relevé de toutes les lectures de tous les services, exercé
contre une plateforme qui tourne.

**`authctx`** — Le porteur d'identité dans le contexte : tenant, utilisateur,
permissions.

**`authmw`** — Le middleware d'authentification et d'autorisation, unique.

**DLQ** (*dead letter queue*) — `crp.events.dlq` : où va un message que le
pipeline n'a pas pu traiter après ses reprises.

**`KnownFields`** — La liste déclarée des champs qu'une règle peut nommer.
Déclarée et non déduite, pour que le catalogue puisse être vérifié contre elle.

**`NormalizedEvent`** — Le contrat entre les étages d'ingestion, aligné sur ECS.

**`OKWithMeta`** — L'écriture d'une liste dans l'enveloppe, avec son `total`.

**`RequirePermission` / `RequirePermissionByMethod`** — Les deux formes
d'autorisation. La seconde se résout en `:read` pour GET, `:write` sinon.

**`svcauth`** — L'identité propre d'un service, pour les appels qui n'ont
personne derrière eux.

---

## Les référentiels cités

**CBS** (*core banking system*) — Le système bancaire central. Un marqueur de
contexte sur un actif, et un plafond de délai dans les politiques de
remédiation.

**CSCF** — *Customer Security Controls Framework*, le référentiel SWIFT.

**DORA** — *Digital Operational Resilience Act*. Le règlement européen de
résilience opérationnelle du secteur financier.

**KEV** — *Known Exploited Vulnerabilities*. Le fait qu'une vulnérabilité soit
réellement exploitée ; vaut +1,5 d'exposition.

**MITRE ATT&CK** — Tactiques (`TA….`) et techniques (`T….`). Chaque détection
en nomme une de chaque.

**PCI DSS** — Le référentiel du périmètre carte.

**SWIFT** — Un marqueur de contexte sur un actif, et un plafond de délai.

---

## Les mesures

**Coût** (d'une arête, d'un chemin) — Ce qu'une transition demande à un
attaquant. Plus il est élevé, plus l'attaque est difficile.

**Criticité** — 1 à 4 sur un actif. Alimente l'impact d'un chemin d'attaque.

**Exposition** — Le score d'une vulnérabilité sur un actif : CVSS, majoré si
exploitée, pondéré par la sévérité. Plafonné à 10.

**Impact** — Ce que coûterait d'atteindre une cible. Dérivé de sa criticité,
de son score de risque, ou — si l'inventaire ne dit rien — d'une **posture**
inscrite dans la politique.

**Score de chemin** — À quel point un chemin est menaçant. Plus de sauts et des
arêtes plus lourdes le **baissent**.

**Score de risque** — 0 à 10, sur un actif ou une entité.

**Sévérité** — `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
