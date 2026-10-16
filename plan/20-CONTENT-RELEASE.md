# Livraison du contenu de détection — procédure

> Périmètre : le catalogue de détection (`backend/content/detections`), son
> empaquetage, sa publication, et les clés qui le signent.
> Outil : `contentctl` (`backend/services/siem/cmd/contentctl`).
> Pour le *pourquoi*, voir `plan/19-AUDIT-AND-ROADMAP.md` §3.23 à §3.25.

Ce document est fait pour être suivi sous pression. Chaque section donne les
commandes, ce qu'on doit voir, et ce qu'il faut faire si on voit autre chose.

---

## 1. Les trois objets

| Objet | Ce que c'est | Qui le détient |
|---|---|---|
| **Clé de signature** | Paire Ed25519. `*.key` privée, `*.pub` publique. | L'équipe contenu. La privée ne quitte jamais la machine de publication. |
| **Paquet** (`*.crpack`) | Une version du catalogue : les détections, un manifeste des empreintes, une signature détachée. | Publié. |
| **Canal** | Un répertoire contenant les paquets, `index.json` (quelles versions existent, laquelle est courante) et `index.sig`. | Publié. Servi par un bucket, un nginx, ou copié sur disque. |

Le canal est **un répertoire de fichiers**. Ce qui le sert est une décision
d'infrastructure : rien dans l'outillage n'en dépend, et un canal copié sur un
disque vers un site isolé fonctionne exactement comme un canal servi en HTTPS.

**Pourquoi le canal est signé en plus des paquets.** Un attaquant qui ne sait
pas forger une signature peut toujours fournir une livraison *authentique mais
ancienne*, publiée avant qu'une détection qui le concerne n'existe. Aucune
signature de paquet ne peut l'exclure : le paquet est exactement aussi vrai
qu'au jour où il a été signé. L'index signé est ce qui dit, de façon vérifiable,
quelle version est courante et à quelle empreinte elle doit correspondre.

---

## 2. Publier une version

```bash
cd backend
# pack.yaml porte le numéro de version. L'incrémenter est le seul geste manuel.
$EDITOR content/detections/pack.yaml

make content-check                 # valide, sans base de données
CRP_CONTENT_SIGN_KEY=/secure/crp-content-2026.key \
CRP_CONTENT_CHANNEL=/srv/crp/content \
  make content-release
```

Ce qu'on doit voir :

```
CyberRadar Detection Pack 2026.11.0 packaged into dist/crp-detections-2026.11.0.crpack
  16 file(s) · manifest 38783900bd9dccec
  signed by 69560669bf010ec4a935de6c4b593989
CyberRadar Detection Pack 2026.11.0 published to /srv/crp/content
  cyberradar-detection-pack-2026.11.0.crpack · manifest 38783900bd9dccec · 7659 bytes
  index.json signed by 69560669bf010ec4a935de6c4b593989
  current: 2026.11.0   (published: 2026.11.0, 2026.10.1)
```

La construction et la publication sont **une seule commande**. Les deux
signatures doivent s'accorder — celle du paquet, et celle de l'index qui épingle
son empreinte. Une chaîne de publication capable de faire l'une sans l'autre
finira par le faire.

### Ce qui est refusé à la publication

| Refus | Ce qu'il veut dire |
|---|---|
| `2026.11.0 is already published with digest X and this pack is Y` | Vous republiez un numéro avec un contenu différent. Un numéro qui change est un numéro que personne ne peut épingler. Publiez sous un nouveau numéro. |
| `… publishes "A"; this pack is "B"` | Deux paquets différents dans un canal. Un déploiement épinglé à une version n'aurait aucun moyen de dire lequel il voulait. |

Republier **le même** paquet est un no-op : la date de publication d'origine est
conservée, rien ne bouge. Rejouer un job de publication est donc sans effet.

### Rétropublier une ancienne version

Publier une version antérieure (combler un trou, re-signer une archive) est
permis et **ne déplace pas `current`**. Faire autrement ferait reculer en
silence tout déploiement qui suit le canal.

---

## 3. Ce qu'un déploiement configure

```bash
CRP_CONTENT_CHANNEL=https://content.example.com/crp
CRP_CONTENT_TRUST=/etc/crp/trust        # répertoire de *.pub et *.revoked
CRP_CONTENT_VERSION=                     # vide = ce que le canal dit courant
```

Installation :

```bash
contentctl -channel "$CRP_CONTENT_CHANNEL" -trust "$CRP_CONTENT_TRUST" -verify-only
contentctl -channel "$CRP_CONTENT_CHANNEL" -trust "$CRP_CONTENT_TRUST" -apply -db "$DATABASE_URL"
```

**Le magasin de confiance est donné par le déploiement, jamais par le paquet.**
Sans `-trust`, le chargement est refusé — il faut dire `-allow-unsigned`
explicitement. Accepter par défaut rendrait la signature décorative : un
déploiement ayant oublié sa confiance ne vérifierait rien en ayant l'air de
vérifier.

### Vérifier ce que le déploiement accepte réellement

```bash
contentctl -trust-list -trust /etc/crp/trust
```

```
/etc/crp/trust
  trusted  a4e8740e666ca76df06338327801a045
  REVOKED  69560669bf010ec4a935de6c4b593989  (revoked, key still on disk) — laptop stolen, INC-4412
```

À faire après chaque modification du magasin. Une révocation est une ligne dans
un fichier, et une ligne dans un fichier se tape de travers.

---

## 4. Rotation planifiée d'une clé

Une rotation normale — la clé n'est pas compromise, elle est simplement
remplacée. Il ne doit exister **aucune fenêtre où plus rien ne vérifie**.

1. **Générer la nouvelle paire.**
   ```bash
   contentctl -keygen /secure/crp-content-2027
   # → signing key a4e8740e… written to …2027.key and …2027.pub
   ```
   La génération refuse d'écraser une clé existante : régénérer orphelinerait
   toutes les livraisons signées avec l'ancienne.

2. **Distribuer la nouvelle clé publique dans tous les magasins de confiance,
   l'ancienne restant en place.** Les deux sont acceptées.
   ```bash
   cp /secure/crp-content-2027.pub /etc/crp/trust/
   contentctl -trust-list -trust /etc/crp/trust     # doit montrer deux clés
   ```

3. **Attendre** que tous les déploiements aient la nouvelle clé. Pas de
   publication sous la nouvelle clé avant cette confirmation.

4. **Publier sous la nouvelle clé.** Les anciennes livraisons restent
   vérifiables, puisque l'ancienne clé est encore acceptée.

5. **Retirer l'ancienne clé publique** des magasins, une fois qu'aucun
   déploiement n'a besoin d'installer une livraison qu'elle a signée.

> Une rotation planifiée **ne produit pas de révocation**. Retirer une clé dit
> « nous ne publions plus sous celle-ci » ; la révoquer dit « tout ce qu'elle a
> signé est suspect ». Les deux ne s'adressent pas au même problème.

---

## 5. Clé compromise — procédure d'urgence

Déclencheur : la clé privée a fuité, ou on ne peut plus affirmer le contraire.

### 5.1 Révoquer (additif, pas une suppression)

Écrire un fichier `*.revoked` dans chaque magasin de confiance :

```bash
cat > /etc/crp/trust/INC-4412.revoked <<'EOF'
# Clé de signature de contenu retirée le 2026-10-02 — INC-4412.
69560669bf010ec4a935de6c4b593989 laptop stolen, INC-4412
EOF
contentctl -trust-list -trust /etc/crp/trust
```

Format : un identifiant de clé par ligne, suivi facultativement de la raison ;
`#` commente. Un identifiant mal formé **fait échouer le chargement** au lieu
d'être ignoré — une révocation dont personne n'a vu qu'elle avait échoué est le
pire cas : l'exploitant croit la clé retirée et elle ne l'est pas.

**Pourquoi un fichier ajouté plutôt qu'un fichier supprimé.** Retirer une clé en
effaçant son `.pub` signifie que l'hôte qui a raté le changement continue de lui
faire confiance et ne dit rien. Un `.revoked` qu'il faut de toute façon
distribuer échoue dans l'autre sens : l'hôte qui l'a reçu refuse, bruyamment, et
celui qui ne l'a pas reçu n'est pas plus mal loti qu'avant.

La révocation tient **sans le fichier de clé** : on peut supprimer le `.pub`, le
refus reste un refus pour révocation, pas pour clé inconnue. Les deux envoient
un exploitant chercher à des endroits différents.

### 5.2 Savoir ce que la clé a signé et que nous avons installé

```bash
contentctl -affected 69560669bf010ec4a935de6c4b593989 -db "$DATABASE_URL"
```

```
2 load(s) signed by 69560669bf010ec4a935de6c4b593989:
  2026-10-02 10:56  2027.1.0    manifest 82430ea25f94ffcf  +1 -0 =14
    from https://content.example.com/crp/cyberradar-detection-pack-2027.1.0.crpack
  …
```

Révoquer arrête la prochaine mauvaise livraison. Cela ne dit **rien** sur celles
déjà installées, et « quelles détections sont entrées sous la clé compromise »
est la question à laquelle il faut répondre dans l'heure.

### 5.3 Reconstituer

1. Générer une nouvelle paire (§4.1).
2. Republier chaque version encore utile **sous un nouveau numéro**, signée par
   la nouvelle clé. Ne pas republier sous l'ancien numéro : le refus
   « already published with digest … » est là pour ça, et le contourner
   casserait toute épingle existante.
3. Distribuer la nouvelle clé publique et la révocation ensemble.
4. Réinstaller sur chaque déploiement, puis vérifier :
   ```bash
   contentctl -affected <ancienne-clé> -db "$DATABASE_URL"
   # doit finir par ne lister que des chargements antérieurs à la réinstallation
   ```

---

## 6. Clé perdue sans compromission

La clé privée est irrécupérable mais personne d'autre ne l'a (disque mort, coffre
effacé). **Ne pas révoquer** : les livraisons passées restent légitimes et les
déploiements doivent pouvoir continuer à les vérifier.

1. Générer une nouvelle paire, la distribuer à côté de l'ancienne clé publique.
2. Publier sous la nouvelle clé.
3. Garder l'ancienne clé publique dans les magasins aussi longtemps qu'une
   livraison qu'elle a signée peut encore devoir être installée.

---

## 7. Les refus, et ce que chacun veut dire

| Message | Cause | Ce qu'on fait |
|---|---|---|
| `CRP-IAM-0001.yaml does not match its digest` | Un fichier du paquet a changé après la signature. | Ne pas installer. Récupérer le paquet depuis le canal officiel. |
| `the signature by key X does not match` | Le manifeste ou l'index a été réécrit après signature. | Ne pas installer. Incident. |
| `carries CRP-ZZZ-9999.yaml, which its manifest does not name` | Un fichier en plus voyage dans l'archive. | Ne pas installer. Incident. |
| `signed by key X, which this deployment does not trust` | Clé inconnue du magasin. | Vérifier `-trust-list`. Soit la rotation n'a pas été distribuée, soit le paquet n'est pas le nôtre. |
| `signed by key X, which this deployment has revoked` | Clé retirée (§5). | Installer une livraison signée par une clé encore acceptée. |
| `index.json says V has digest X; the pack served is Y` | Les deux paquets sont correctement signés, mais ce n'est pas le bon à cette adresse. | Le plus souvent une republication en place côté hébergement. Vérifier le canal avant de conclure à une attaque. |
| `loading a published release needs -trust, or -allow-unsigned` | Aucune confiance configurée. | Configurer `CRP_CONTENT_TRUST`. Ne jamais mettre `-allow-unsigned` sur un déploiement. |
| `this release is V and W is already loaded` | La livraison est antérieure à celle installée. | C'est la protection contre le rejeu. Si le retour arrière est voulu, `-allow-downgrade`. |
| `"…" is not a key identifier (32 hex characters)` | Révocation mal tapée. | Corriger la ligne. Sans cela rien n'est révoqué. |

Un chargement depuis un répertoire (`-dir`, le mode développeur) **avertit** au
lieu de refuser en cas de retour arrière : ce n'est pas une livraison publiée, il
n'y a rien à rejouer, et quelqu'un édite des fichiers qu'il détient.

---

## 8. Ce que cette procédure ne couvre pas

- **Où le canal est hébergé, et avec quelle authentification.** Décision
  d'infrastructure, délibérément hors de l'outillage.
- **La garde de la clé privée.** Un fichier en 0600 sur la machine de
  publication est le minimum, pas une réponse. Un HSM ou un coffre signataire
  est la suite, et `contentctl` ne sait aujourd'hui que lire un fichier PEM.
- **La fraîcheur.** Un déploiement qui n'interroge jamais son canal reste sur
  une version ancienne sans que rien ne l'affirme. L'index ne porte pas de date
  d'expiration.
