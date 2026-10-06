# La présentation du projet

`CyberRadar-Presentation.pdf` — 20 pages, 16:9.

```bash
./build.sh          # reconstruire le PDF depuis presentation.html, et le vérifier
```

## Ce que ce document est, et ce qu'il n'est pas

C'est une **présentation de projet** : ce que la plateforme est, ce qu'elle
couvre, ce qu'elle apporte à chaque interlocuteur. Ce n'est pas un relevé
d'avancement — celui-ci vit dans
[`plan/23-PLAN-EXECUTION.md`](../../plan/23-PLAN-EXECUTION.md) et n'a pas sa
place devant un client.

La distinction compte dans la construction : une présentation de projet parle
au futur et au présent du produit, un relevé d'avancement parle du travail de
l'équipe. Mettre le second devant une direction générale donne l'impression
d'un chantier plutôt que d'une offre.

| Pages | Pour qui | Question à laquelle elles répondent |
|---|---|---|
| 1 à 10 | Tous | Le constat, la proposition, le périmètre, le fonctionnement, l'architecture, la souveraineté, la sécurité, la conformité |
| 11 | Direction générale | Sommes-nous exposés, combien de temps pour réagir, sommes-nous en règle |
| 12 | DSI | Est-ce exploitable par mon équipe, avec mes outils |
| 13 | RSSI | Du signal à la preuve : détection, réponse, traçabilité, et ce qui reste paramétrable |
| 14 | Intégrateur | Que déployer, que brancher, que puis-je vendre par-dessus |
| 15 à 17 | Tous | Ce qui distingue : contenu livrable, paramétrage, interface |
| 18 à 20 | Tous | Trajectoire, modalités d'un pilote, synthèse |

## Les affirmations à ne pas relâcher

Trois phrases du document engagent, et ont été vérifiées sur le code :

- **« Aucun flux sortant nécessaire au fonctionnement »** — seul le service
  Copilot émet des appels sortants, et il est optionnel. Le canal de contenu
  est une livraison volontaire, installable depuis un fichier.
- **« Les habilitations sont appliquées à l'exécution »** — chaque route exige
  une permission nommée, et des tests le tiennent.
- **« Un contrôle de conformité porte les actifs concernés et sa preuve »** —
  le modèle le permet ; les intitulés du jeu de démonstration sont la
  correspondance de la plateforme, pas une citation des textes officiels.

Si l'une devient fausse, elle sort du document le jour même. Une plateforme de
sécurité se juge d'abord sur ce qu'elle affirme d'elle-même.

## `verifier.py`

Il échoue si du texte entre dans la bande du pied de page ou sort de la page.
Il a trouvé deux débordements réels, dont un introduit par la correction du
premier. Sa première version reconnaissait le pied de page par « / 18 » écrit
en dur : le jour où le document est passé à vingt pages, elle a rendu sept faux
positifs. Il reconnaît désormais la forme « n / total ».

Il ne vérifie pas le contenu : relire les pages à l'image reste nécessaire, et
c'est ce qui avait montré qu'un tableau annonçait neuf étapes pour huit lignes.
