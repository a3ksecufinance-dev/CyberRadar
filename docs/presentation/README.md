# La présentation

`CyberRadar-Presentation.pdf` — 18 pages, 16:9, trois lecteurs : direction
générale (4 à 7), DSI (8 à 12), intégrateur (13 à 16).

```bash
./build.sh          # reconstruire le PDF depuis presentation.html, et le vérifier
```

## Ce qui est tenu dans ce document

**Chaque chiffre est mesuré**, sur le dépôt ou sur une installation réelle.
Là où une mesure n'existe pas — la performance en charge — il est écrit qu'elle
n'existe pas, plutôt qu'estimée. C'est ce qui rend crédible le reste devant une
salle qui vérifiera.

Les chiffres viennent de :

| Chiffre | D'où il sort |
|---|---|
| 32 services, 455 routes, 144 tables, 50 migrations | comptés sur le dépôt |
| 27 635 lignes de test / 81 596 de code | `find … \| xargs wc -l` |
| 9 étapes, 4 s à 45 s | `make e2e-chain`, mesures relevées |
| 125 actifs, 412 constats, 72 alertes, 42 contrôles | `make demo` puis la base |
| 101 / 346, 0 / 8, 0 / 14 | [`plan/23-PLAN-EXECUTION.md`](../../plan/23-PLAN-EXECUTION.md) |

Quand l'un d'eux bouge, il bouge ici aussi. Un document de présentation qui
dérive de la réalité est pire qu'absent.

## `verifier.py`

Il échoue si du texte entre dans la bande du pied de page ou sort de la page.
Il a trouvé deux débordements réels, dont un introduit par la correction du
premier — ce qui est exactement la raison de ne pas se fier à une relecture du
source.

Il ne vérifie pas la justesse du contenu : relire les pages à l'image reste
nécessaire, et c'est ce qui a montré que le tableau de la chaîne annonçait neuf
étapes pour huit lignes.
