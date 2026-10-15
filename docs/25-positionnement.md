# 25 — Positionnement : à quoi sert ce produit

Ce document existe parce qu'il manquait. Vingt-quatre documents décrivaient
comment la plateforme est construite, ce qu'elle mesure et ce qu'elle promet à
un client — aucun ne disait **à quoi elle sert**. Une équipe qui ne peut pas
répondre à cette question en une phrase construit par accumulation, et c'est ce
qui s'est passé.

---

## 1. La thèse

> **Le SOC d'une institution financière : le seul endroit où un événement du
> système d'information et une transaction du core banking sont corrélés dans
> le même moteur.**

C'est une plateforme de **sécurité**. La conformité est une **sortie**, pas le
produit.

| | Plateforme de sécurité | Plateforme de conformité |
|---|---|---|
| Change l'issue de… | une attaque | un audit |
| Tourne… | en continu | par campagne |
| Utilisateur | analyste SOC | RSSI, auditeur |
| Si on la débranche | on ne voit plus les attaques | on refait les rapports à la main |

Le module de conformité relie une détection au contrôle qu'elle prouve. C'est
précieux, et c'est un sous-produit : la preuve est générée par la détection.
Vendre la cartographie à la place de la détection, c'est vendre le reçu à la
place de la marchandise.

## 2. Pourquoi cette thèse et pas « encore un SIEM »

Le marché est partagé par une frontière que personne ne traverse :

- **Splunk, QRadar, Sentinel, Wazuh** voient une transaction comme une ligne de
  journal sans sémantique. Ils ne savent pas ce qu'est un compte émetteur.
- **SAS, NICE Actimize, Featurespace** voient la transaction, et ne savent rien
  de la compromission du compte qui l'a émise.

La valeur est sur la couture : *le compte administrateur compromis à 14 h 02
est celui qui a validé le virement à 14 h 09.* Pour une banque dont une filiale
établissement de paiement exploite des wallets dans le même core banking, cette
couture **est** le risque.

Un corollaire qui vaut d'être dit : si la thèse est juste, le différenciateur
n'est pas le nombre de modules. C'est le fait que les événements du SI et les
transactions passent par **un seul moteur de corrélation**.

## 3. Ce que le code disait avant qu'on écrive la thèse

Trois constats, trouvés en cherchant la trace de la thèse dans le dépôt.

**32 services, distribution des volumes quasi plate.** Entre 1 700 et 2 800
lignes pour presque tous. Les trois services de la chaîne de valeur —
`collector` (1 324), `pipeline` (855), `audit` (759) — sont **les plus maigres
du dépôt**. C'est la signature d'un CRUD dupliqué, pas d'un produit avec un
centre de gravité.

**`cbs_impact` et `swift_impact` n'étaient jamais assignés.** Les deux colonnes
qui font la spécificité financière du produit : présentes dans le schéma,
écrites dans ClickHouse, interrogeables par le moteur de règles — et à zéro
pour tous les événements, depuis toujours. Une règle conditionnée sur l'une des
deux ne déclenchait jamais, silencieusement, en ressemblant à de la couverture.

**`crp.events.fraud` n'avait aucun consommateur.** Une transaction notée 90
changeait une colonne de statut, publiait sur un topic que rien ne lisait, et
ne levait aucune alerte.

Autrement dit : **la raison d'être du produit tenait dans deux fils non
branchés.** Ce n'était pas un manque de code — il y en a 70 000 lignes. C'était
un manque de thèse : personne n'ayant écrit à quoi sert le produit, personne ne
pouvait voir que ces deux fils étaient les seuls qui comptaient.

Les deux sont branchés depuis (§5).

## 4. Le tri que la thèse impose

| | Services | Sort |
|---|---|---|
| **Cœur** | `collector`, `pipeline`, `siem`, `fraud`, `audit`, + le pack de détection signé | Tout l'investissement va là |
| **Soutien** | `ir`, `soar`, `ueba`, `ti`, `asset`, `identity`, `tenant`, `compliance` *(en sortie)*, `dashboard`, `notification`, `syslog` | Maintenus au service du cœur |
| **Hors thèse** | `cspm`, `dspm`, `dlp`, `ot`, `scs`, `easm`, `apifw`, `iga`, `mobile`, `pam`, `netsec`, `risk` | Drapeau de fonctionnalité, désactivés par défaut |

Les douze derniers sont douze catégories de produits distinctes, chacune une
entreprise à part entière, chacune à environ 2 000 lignes de CRUD. La décision
« livrer, masquer ou couper » était déjà écrite dans
[`plan/21`](../plan/21-PRODUCTION-PLAN.md) comme **requise avant J1**, avec la
recommandation de les masquer. Elle n'a pas été prise, et le plan d'exécution a
été construit par-dessus en traitant les 32 services comme également légitimes.

> Ce n'est pas qu'on avançait à l'aveugle. Le bandeau avait été identifié,
> écrit, et jamais retiré.

**Pourquoi masquer plutôt que couper :** le code ne coûte rien à conserver
derrière un drapeau, et un client qui gratte un domaine superficiel se demande
ensuite ce que valent les six vrais. C'est la démonstration qu'on protège, pas
le code.

## 5. Ce que la thèse a immédiatement changé

Deux fils branchés le jour où elle a été écrite :

1. **`cbs_impact` / `swift_impact` sont renseignés** par le normalisateur, à
   partir du type de source déclaré par le connecteur, au point unique que les
   six parseurs traversent. Une règle peut enfin distinguer un flux bancaire
   d'un journal applicatif.

2. **Une transaction signalée est publiée sur `crp.events.enriched`**, le topic
   du moteur de règles, sous forme d'événement canonique — catégorie
   `Transaction`, `cbs_impact` à 1, score 0-100 ramené sur 0-10, compte émetteur
   porté par `user_id`.

Le second achète trois choses que le module de fraude n'a pas et qu'il aurait
fallu lui construire :

- **le comptage fenêtré** (`threshold: {count, group_by, window_seconds}`), la
  forme dont tout schéma de fraude wallet a besoin — la structuration, c'est
  « N opérations sous le seuil en 24 h » et rien d'autre ;
- **la corrélation** avec les événements SI portant le même acteur ;
- **le chemin alerte → cas → notification → SOAR** qui existe déjà.

Effet de bord utile : la détection livrée `CRP-FRD-0001` (catégorie
`Transaction`, `threat_score ≥ 7`) déclenche désormais sur les transactions
notées 70 et plus. Elle était signée, livrée, activée par défaut — et ne
pouvait rien voir.

## 6. Ce que la thèse ne règle pas

Elle donne un cap, pas des fonctionnalités. Restent ouverts, inchangés par ce
document :

- **Les règles de fraude wallet** restent à écrire et à calibrer sur des
  données réelles. Le moteur sait compter ; personne ne lui a encore dit quoi
  compter.
- **Le moteur de fraude lui-même** reste un squelette : `evaluateRule` ne
  connaît que seuil, liste et égalité exacte. La thèse rend ce manque moins
  grave — le comptage se fait dans le moteur de détection — pas inexistant.
- **Le connecteur core banking** est à écrire. Sans transaction en entrée, rien
  de ce qui précède ne s'exerce.
- **La ségrégation banque/filiale** tient au code applicatif, pas à la base.
- Le détail de ces écarts, chiffré, est dans
  [`24`](24-apport-banque-edp.md) § 6.

## 7. Ce qu'on peut dire à un client, et ce qu'on ne peut pas

**On peut dire :** une chaîne de détection mesurée de bout en bout, un journal
d'audit immuable et vérifiable ligne à ligne, un moteur de corrélation fenêtré,
un pack de détection signé livrable indépendamment du code, et une architecture
où une transaction du core banking passe par le même moteur qu'un événement du
SI.

**On ne peut pas dire :** un moteur de fraude wallet prêt, une conformité DORA,
une cartographie DNSSI ou 09-08 prête à l'emploi, un connecteur core banking,
ni 1 000 événements par seconde — 647 sont mesurés sur deux instances.

La règle qui tient les deux listes : **ce qui n'est pas mesuré ou démontrable
ne se dit pas.** C'est la même règle qui a produit
[`22-mesures.md`](22-mesures.md), et c'est la seule défense contre le document
que ce dépôt vient de passer six mois à écrire sans s'en rendre compte.
