# Les fiches par module

`CyberRadar-Modules.pdf` — le recueil, 48 pages A4, seize modules à trois
pages chacun. `fiches/CyberRadar-<module>.pdf` — la même fiche, isolée, à
envoyer seule quand l'interlocuteur n'a qu'un sujet.

```bash
./build.py                # reconstruire les seize fiches, le recueil, et vérifier
./build.py --only siem    # une seule, pour itérer vite
python3 verifier.py       # vérifier sans reconstruire
```

## La forme, et pourquoi elle est fixe

Chaque module tient en trois pages, toujours les mêmes :

| Page | Contenu | Pourquoi |
|---|---|---|
| 1 | Le problème, puis ce que fait le module | Un lecteur qui ne reconnaît pas son problème ne lit pas la suite |
| 2 | La capture de l'écran, puis ce qu'elle montre | L'écran est la preuve ; la légende dit où regarder |
| 3 | Le mécanisme, numéroté, puis les avantages | Le mécanisme précède l'avantage : un avantage sans mécanisme est une promesse |

La mise en page vit dans `build.py`, le contenu dans `modules.py`. Une
correction de forme profite aux seize fiches — c'est la seule façon de ne pas
les voir diverger au fil des relectures.

## Les captures

`captures/<module>.png` : des captures **réelles**, prises sur la plateforme
en fonctionnement, après authentification par le fournisseur d'identité, en
français, sur le jeu de démonstration (Banque Al Massira — 125 actifs, 24
agences). Aucune retouche, aucune maquette, aucun écran reconstitué.

Elles se reprennent en relançant la plateforme puis le script de capture :

```bash
cd ../../backend && ./scripts/dev-local.sh up && ./bin/demo-seed
node /chemin/vers/capture.js        # écrit captures/<module>.png
```

Une capture d'écran vide dirait « pas encore implémenté » quelle que soit la
légende : six modules — flotte mobile, posture des données, chaîne
d'approvisionnement, systèmes industriels, réponse à incident, passerelle
d'API — n'avaient aucune donnée de démonstration et ont été peuplés pour
cela, par les mêmes API que le reste de l'estate.

## Les affirmations, relues sur le code

La page 3 de chaque fiche décrit un mécanisme, et un mécanisme qui n'existe
pas est la seule faute qu'un intégrateur relèvera à coup sûr. Les soixante-dix
lignes de « Comment ça marche » ont donc été relues contre le code, pas contre
le souvenir qu'on en avait. Dix ont été réécrites :

| Fiche | Ce qui était écrit | Ce que fait le code |
|---|---|---|
| Passerelle d'API | « Les portées sont vérifiées à chaque appel », « la limite de débit s'applique » | Les deux sont **enregistrées** sur la clé ; rien ne les applique encore. L'authentification entrante passe par le fournisseur d'identité. Dit tel quel sur la fiche |
| Vulnérabilités | « Rattachées aux actifs par le produit qu'elles nomment » | Le constat porte l'actif et la vulnérabilité ; c'est l'import qui fait le lien |
| Posture des données | « Rattachés à un actif de l'inventaire », « rattachés à un contrôle de conformité » | Aucune clé étrangère ni vers l'actif ni vers le contrôle ; le constat nomme les textes en défaut, en texte |
| Chaîne logicielle | « Les composants sont rattachés aux actifs » | Ils déclarent les **applications** qui les embarquent |
| Systèmes industriels | « Observés passivement » | Déclarés par l'API ou importés ; la plateforme n'émet rien, ce qui est le point |
| Flotte mobile | « Les terminaux s'enrôlent et remontent leur état » | C'est l'outil de gestion de flotte qui dépose l'état, par l'API |
| Paramétrage | « L'historique est tracé comme toute autre action » | Les politiques sont versionnées et portent leur auteur |

Aucune de ces corrections n'enlève une capacité : elles disent qui fait le
geste. Une fiche qui promet une liaison automatique là où il y a une API à
appeler fait perdre une journée à l'intégration, et la confiance avec.

Quand un de ces mécanismes sera implémenté, la ligne change ici le jour même.

## `verifier.py`

Il échoue si du texte entre dans la bande du pied de page ou sort de la page.
`build.py` l'appelle sur ce qu'il vient de produire : vérifier la version
précédente ne sert à rien, et une page coupée ne se voit pas dans le source —
elle se voit en salle, sur le vidéoprojecteur d'un client.

Il ne vérifie pas le contenu. Relire les pages à l'image reste nécessaire.
