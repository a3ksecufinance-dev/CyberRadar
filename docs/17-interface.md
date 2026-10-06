# 17 — Interface

Next.js 14 (App Router), TypeScript, Tailwind, Radix, Recharts, SWR, NextAuth,
next-intl.

```bash
cd frontend
npm install
npm run dev          # :3000
```

---

## La structure

```
src/
  app/[locale]/
    (auth)/login
    (platform)/        dashboard, siem, threats, vulnerabilities, assets,
                       attackpath, compliance, risk, ir, copilot,
                       api-gateway, dspm, mobile, ot, scs, settings
  components/
    layout/            Header, Sidebar, LanguageSwitcher
    settings/          les quatre écrans de politique + PolicyParts
    siem/              RuleLibrary, Coverage, UpgradeDialog
    shared/            EmptyState, ErrorState, LoadingState, badges
    charts/            SeverityBars
    ui/                badge, button, card, input
  hooks/               les lectures SWR
  i18n/                routing, request
  lib/                 api.ts (la table de routes), auth.ts
  types/               alignés sur les modèles Go
  middleware.ts        locale + authentification
messages/
  en.json  fr.json
```

---

## La table de routes

`src/lib/api.ts` est **la source unique** de l'endroit où vit chaque
ressource, transcrite depuis les `RegisterRoutes`/`Routes` des services. Les
hooks et les appels côté serveur y lisent tous les deux, donc un chemin se
corrige à un seul endroit plutôt qu'à deux qui divergent.

Elle porte aussi la table des ports — une entrée fausse est un 404 qu'aucune
page ne peut rattraper.

Cette table est **lue par les tests du back-end** : `internal/pkg/apicheck`
l'analyse pour savoir quoi sonder. Une route que l'interface gagne est couverte
sans que personne ait à y penser, et une route qu'elle renomme ne peut pas
laisser une sonde périmée passer contre un endpoint que plus rien n'appelle.

---

## Authentification

NextAuth contre Keycloak. Le middleware fait deux choses dans l'ordre : la
locale, puis l'authentification.

```ts
// API routes and Next internals must bypass next-intl: it would prefix them
// with a locale, turning /api/auth/* into /en/api/auth/* and breaking every
// NextAuth endpoint.
```

Le jeton de Keycloak est envoyé tel quel aux services, qui le vérifient contre
les clés publiées du royaume. Voir [05 — Sécurité](05-securite.md).

---

## Internationalisation

Deux locales, `en` et `fr`, préfixe toujours présent (`localePrefix: 'always'`).
Les dictionnaires sont dans `messages/`.

### Le contrôle des clés

```bash
npm run check:messages
```

> **Pourquoi il existe.** Cinq en-têtes de colonne avaient été livrés affichant
> `siem.severity`, `dspm.riskScore` et `mobile.lastSeen` : next-intl **rend la
> clé elle-même** quand il ne sait pas la résoudre. La page a donc l'air
> construite plutôt que cassée, et rien n'échoue. Ils ont été trouvés en
> regardant une capture d'écran, ce qui n'est pas un procédé.

Le contrôle vérifie deux choses : que toute clé littérale `t('…')` écrite dans
le code se résout dans **chaque** locale, et que les locales portent des
ensembles de clés identiques. Il tourne en CI.

Il est **délibérément littéral** : il lit les clés épelées dans la source et
n'essaie pas d'évaluer une clé calculée. Une clé construite à l'exécution est à
la charge de son appelant ; une clé écrite en chaîne est à la charge de ce
fichier.

---

## Les états d'une page

Trois composants partagés, utilisés partout, pour que l'absence de données ne
ressemble jamais à une page cassée :

| | Quand |
|---|---|
| `LoadingState` | La lecture est en cours |
| `EmptyState` | La lecture a réussi et n'a rien rendu |
| `ErrorState` | La lecture a échoué, avec de quoi réessayer |

**Zéro résultat et une erreur ne se ressemblent pas**, ce qui est aussi la
raison pour laquelle `total` est toujours émis dans l'enveloppe d'API.

---

## Les écrans de politique

`components/settings/` porte les quatre, et `PolicyParts.tsx` ce qu'ils ont en
commun : `InForce`, `Presets`, `History`, `SaveBar`, `day`. Les quatre ont la
même forme parce qu'ils répondent aux mêmes questions — voir
[16 — Paramétrage](16-parametrage.md).

---

## Les contrôles

```bash
npm run lint
npm run type-check      # tsc --noEmit
npm run check:messages
npm run e2e             # Playwright
npm run build
```

Les types de `src/types` sont **alignés sur les modèles Go réels**, pas sur ce
que l'interface espérait recevoir.

---

## Ce qui n'est pas fait

- **Pas de tests de composants.** Playwright pilote des parcours ; il n'y a pas
  de tests unitaires d'interface.
- **Pas de rendu côté serveur des listes.** Tout passe par SWR côté client,
  donc la première peinture est vide.
- **Pas d'état hors ligne.**
- **Les pages des douze domaines « CRUD + lectures »** affichent ce que leur
  service a ; elles n'ont pas de parcours de travail propre.
