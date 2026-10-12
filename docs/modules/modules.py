# -*- coding: utf-8 -*-
"""Le contenu des fiches, séparé de leur mise en page.

Quinze fiches écrites à la main seraient quinze occasions de diverger : une
corrigée, quatorze qui gardent l'erreur. Le contenu vit ici, la mise en page
dans build.py, et une correction de forme profite à toutes.

Chaque fiche tient en trois pages — ce que c'est, l'écran réel, comment ça
marche et ce que ça rapporte — parce qu'une fiche produit qu'on ne lit pas en
entier ne sert à rien.
"""

MODULES = [
  dict(
    slug="dashboard", famille="Pilotage", titre="Tableau de bord",
    accroche="La posture de sécurité de l'organisation, sur un écran",
    probleme=(
      "Un comité de direction demande « où en sommes-nous ». La réponse habituelle "
      "demande trois jours, cinq exports et un tableur, et elle est périmée le jour où "
      "elle arrive."),
    quoi=(
      "Une vue unique qui agrège ce que les vingt-cinq domaines savent : les alertes "
      "ouvertes, les incidents en cours, les vulnérabilités critiques, les "
      "correspondances d'indicateurs du jour, et la posture par référentiel de "
      "conformité. Les chiffres ne sont pas recopiés : ils viennent des mêmes données "
      "que les écrans d'analyse."),
    lecture=[
      ("Score de sécurité", "Une note unique, recalculée en continu à partir des alertes ouvertes, des vulnérabilités non traitées et de l'écart de conformité."),
      ("Les quatre compteurs", "Menaces actives, incidents ouverts, vulnérabilités critiques, correspondances d'indicateurs — chacun avec son dépassement de délai."),
      ("Posture de conformité", "Un anneau par référentiel. Le détail par contrôle est à un clic."),
      ("Alertes récentes", "Les dernières levées, avec leur sévérité et leur état. Elles mènent directement au cas."),
    ],
    mecanisme=[
      "Chaque domaine publie ses indicateurs sur le bus d'événements, à son rythme.",
      "Le service de tableau de bord les agrège par organisation et les tient à jour.",
      "L'écran lit cet agrégat : il n'interroge pas les vingt-cinq domaines à chaque affichage.",
      "Un domaine arrêté laisse son dernier chiffre visible, daté — et non une case vide.",
    ],
    avantages=[
      ("Une réponse immédiate au comité", "La question « où en sommes-nous » a une réponse à l'écran, datée, sans travail de préparation."),
      ("Un seul chiffre discutable", "Le score agrège ce qui compte. On discute de sa composition, pas de quelle source a raison."),
      ("Aucune recopie", "Les chiffres du comité et ceux de l'analyste sortent de la même base. Ils ne peuvent pas diverger."),
    ],
  ),
  dict(
    slug="siem", famille="Détection", titre="SIEM / XDR",
    accroche="Le moteur de détection, et la bibliothèque qui l'alimente",
    probleme=(
      "Un SIEM se juge sur deux choses : ce qu'il détecte, et ce qu'il ne détecte pas. "
      "La seconde est rarement documentée, et c'est pourtant la question d'un auditeur."),
    quoi=(
      "Un moteur de corrélation qui consomme les événements normalisés et lève des "
      "alertes sur des règles à seuil et à fenêtre. Trois onglets : les alertes, la "
      "bibliothèque de détections livrée avec la plateforme, et la couverture ATT&CK "
      "qui en découle."),
    lecture=[
      ("Les quatre compteurs", "Alertes totales, ouvertes, critiques, et levées sur 24 heures."),
      ("La colonne Règle", "Le nom de la détection qui a déclenché. Ici des règles du catalogue, adoptées et ajustées par le client."),
      ("La colonne Entité", "L'adresse ou le compte à l'origine. C'est la clé de regroupement du seuil."),
      ("Onglet Bibliothèque", "Le catalogue livré, ce qui est adopté, ce qui ne l'est pas, et l'écart de chaque règle adoptée par rapport au standard."),
    ],
    mecanisme=[
      "Le moteur consomme le flux d'événements enrichis, en continu.",
      "Pour chaque événement, il évalue les règles actives de l'organisation concernée.",
      "Une règle à seuil compte les occurrences par entité dans une fenêtre glissante, partagée entre les répliques : deux instances comptent ensemble.",
      "Au franchissement, l'alerte est levée, dédupliquée par règle et par entité, puis publiée pour la suite de la chaîne.",
    ],
    avantages=[
      ("La couverture est un objet, pas une promesse", "Le catalogue est versionné et signé. On sait dire ce qui est couvert, et ce qui ne l'est pas."),
      ("L'écart est défendable", "Un seuil ajusté garde la trace de son origine. « Pourquoi trois et non cinq » a une réponse écrite."),
      ("Les détections se livrent sans montée de version", "Une nouvelle famille d'attaque est couverte en heures, sans fenêtre de maintenance."),
    ],
  ),
  dict(
    slug="assets", famille="Visibilité", titre="Inventaire d'actifs",
    accroche="Ce que vous possédez, ce que ça vaut, et ce qui en dépend",
    probleme=(
      "La plupart des inventaires sont des tableurs : justes le jour de leur création. "
      "Une alerte sur un serveur dont personne ne sait s'il porte le cœur bancaire est "
      "une alerte qu'on ne sait pas prioriser."),
    quoi=(
      "Un inventaire où chaque actif porte sa criticité métier, son exposition, son "
      "environnement, son service métier, et ses dépendances vers les autres actifs. "
      "C'est le référentiel que tous les autres domaines consultent."),
    lecture=[
      ("Criticité", "De 1 à 4, fixée par le métier et non déduite du type de machine."),
      ("Portée réglementaire", "Les marqueurs cœur bancaire, SWIFT et périmètre carte, qui décident de quels contrôles s'appliquent."),
      ("Exposition", "Ce qui est joignable depuis l'extérieur, calculé et non déclaré."),
      ("Dépendances", "Ce que l'actif atteint et ce qui l'atteint — la matière du calcul de chemins d'attaque."),
    ],
    mecanisme=[
      "Les actifs entrent par l'API ou par la découverte, et portent leur propre identifiant d'origine.",
      "La criticité et les marqueurs réglementaires sont des décisions métier, saisies une fois.",
      "Les dépendances forment un graphe, qui alimente le rayon d'impact et l'analyse de chemins.",
      "Le score de risque d'un actif se recalcule à chaque changement de ses vulnérabilités.",
    ],
    avantages=[
      ("Une alerte priorisée dès la détection", "L'alerte porte la criticité de l'actif. Le tri ne demande pas d'ouvrir un autre outil."),
      ("Le rayon d'impact est immédiat", "« Si celui-ci tombe, quoi d'autre tombe » se lit, au lieu de se reconstituer."),
      ("Un seul inventaire pour tous les domaines", "Conformité, vulnérabilités, chemins d'attaque et détection parlent des mêmes objets."),
    ],
  ),
  dict(
    slug="vulnerabilities", famille="Exposition", titre="Gestion des vulnérabilités",
    accroche="Non pas la liste des failles, mais l'ordre dans lequel les traiter",
    probleme=(
      "Un scanner rend dix mille lignes. La question n'est pas de les voir, c'est de "
      "savoir par laquelle commencer, et de prouver qu'on a respecté ses propres délais."),
    quoi=(
      "Les vulnérabilités du catalogue public, les constats par actif, et un classement "
      "qui croise la gravité publiée, la probabilité d'exploitation, l'exploitation "
      "constatée dans la nature, et la criticité de l'actif touché."),
    lecture=[
      ("Score et probabilité", "Le score de base publié, et la probabilité d'exploitation — une valeur datée, pas une vérité permanente."),
      ("Exploitée dans la nature", "Le marqueur qui change l'ordre de traitement plus que le score lui-même."),
      ("Constats par actif", "La même vulnérabilité sur quarante machines, c'est quarante constats et une seule fiche."),
      ("Délai de remédiation", "Le délai que vous avez fixé par criticité, et le dépassement calculé."),
    ],
    mecanisme=[
      "Un constat lie une vulnérabilité à un actif ; les imports de scanner les déposent en lot, par l'API.",
      "L'exposition est calculée : une faille distante sur un actif joignable depuis l'extérieur ne pèse pas comme la même sur un poste interne.",
      "Les délais de remédiation sont paramétrables par criticité, par organisation.",
      "Le dépassement de délai est un état calculé, pas un champ à tenir à jour.",
    ],
    avantages=[
      ("Un ordre de traitement défendable", "La priorité se justifie par quatre facteurs explicites, pas par le score du scanner."),
      ("Vos délais, pas les nôtres", "Les délais par criticité sont votre politique. Les changer ne demande pas de livraison."),
      ("La preuve du respect des délais", "L'échéance et son dépassement sont calculés depuis votre politique et la date de découverte : c'est ce qu'un auditeur demande."),
    ],
  ),
  dict(
    slug="threats", famille="Détection", titre="Renseignement sur la menace",
    accroche="Des indicateurs qui influencent la détection, et non un flux à côté",
    probleme=(
      "Beaucoup de plateformes consomment des indicateurs puis les affichent dans un "
      "écran séparé. Un indicateur reconnu après la décision de détection n'a rien changé."),
    quoi=(
      "Un référentiel d'indicateurs — adresses, domaines, empreintes — et d'acteurs de "
      "menace, avec l'index de correspondance que le pipeline interroge pendant "
      "l'enrichissement, avant que le moteur de règles ne décide."),
    lecture=[
      ("Indicateurs actifs", "Ce que la plateforme reconnaîtra dans le flux, maintenant."),
      ("Acteurs", "Les groupes suivis, leurs techniques, et les indicateurs qui leur sont rattachés."),
      ("Correspondances", "Les événements réels qui ont rencontré un indicateur, avec l'actif concerné."),
    ],
    mecanisme=[
      "Les indicateurs entrent par l'API ou par import, avec leur source et leur date de péremption.",
      "Un index en mémoire est tenu à jour et rafraîchi périodiquement par le pipeline d'ingestion.",
      "Chaque événement normalisé est confronté à cet index pendant l'enrichissement.",
      "Une correspondance élève le score de risque de l'événement avant que les règles ne s'appliquent.",
    ],
    avantages=[
      ("Le renseignement change la détection", "Une correspondance pèse sur la décision, elle ne la commente pas après coup."),
      ("Vos propres indicateurs", "Ceux d'un CERT sectoriel, d'un correspondant bancaire ou d'une analyse interne s'ajoutent comme les autres."),
      ("Pas de flux imposé", "Aucun abonnement n'est obligatoire pour que la plateforme fonctionne."),
    ],
  ),
  dict(
    slug="attackpath", famille="Détection", titre="Chemins d'attaque",
    accroche="Non pas « cet actif est vulnérable », mais « voici comment on atteint le cœur »",
    probleme=(
      "Une vulnérabilité moyenne sur une machine sans importance peut être la première "
      "marche vers le système central. Une liste de vulnérabilités ne le montre jamais."),
    quoi=(
      "Un graphe des actifs et de leurs dépendances, parcouru pour trouver les chemins "
      "qu'un attaquant peut emprunter depuis un point d'entrée jusqu'à une cible de "
      "valeur, avec le coût de chaque étape."),
    lecture=[
      ("Scénarios", "Un point d'entrée, une cible, et les chemins trouvés entre les deux."),
      ("Coût d'un chemin", "Ce qu'il en coûte à l'attaquant — plus il est faible, plus le chemin est préoccupant."),
      ("Étapes", "Chaque saut, la vulnérabilité ou la relation qui le permet, et l'actif traversé."),
    ],
    mecanisme=[
      "Le graphe est construit depuis l'inventaire : actifs, dépendances, comptes, expositions.",
      "Chaque arête porte un coût, issu des vulnérabilités présentes et du type de relation.",
      "Le parcours cherche les chemins de moindre coût vers les actifs marqués critiques.",
      "Les pondérations sont paramétrables : c'est votre jugement du risque, pas le nôtre.",
    ],
    avantages=[
      ("Corriger ce qui coupe le chemin", "Une correction bien placée ferme plusieurs chemins. L'effort se concentre là où il paie."),
      ("Un argument lisible par la direction", "« Trois sauts entre internet et le cœur bancaire » se comprend sans être technicien."),
      ("Les pondérations sont les vôtres", "Ce qui compte comme un saut facile dans votre contexte se règle sans livraison."),
    ],
  ),
  dict(
    slug="ir", famille="Réponse", titre="Réponse à incident",
    accroche="Du cas ouvert à la clôture, avec la chronologie que l'auditeur demandera",
    probleme=(
      "La réponse à incident se gère souvent dans l'outil de ticketing général. Six mois "
      "plus tard, reconstituer qui a décidé quoi et quand relève de l'archéologie."),
    quoi=(
      "Des incidents avec leur gravité, leurs actifs concernés, leurs tâches, leurs "
      "preuves et leur chronologie. Chaque action, humaine ou automatique, s'y inscrit "
      "au moment où elle a lieu."),
    lecture=[
      ("Gravité et délai", "La gravité fixe le délai attendu ; le dépassement est calculé."),
      ("Chronologie", "L'ordre réel des événements et des décisions, horodaté."),
      ("Preuves", "Ce qui a été collecté, par qui, et quand."),
      ("Tâches", "Ce qui reste à faire, et par qui."),
    ],
    mecanisme=[
      "Un incident naît d'une alerte promue, d'un signalement ou d'un playbook.",
      "Les actifs concernés viennent de l'inventaire : leur criticité qualifie l'incident.",
      "Chaque action écrit dans la chronologie, y compris celles exécutées par un automate.",
      "Le délai de détection se déduit de la chronologie — du premier acte attribué à l'attaquant jusqu'à la détection — et le délai de rétablissement de l'événement de reprise, pas de l'heure à laquelle le dossier a été renseigné.",
      "La clôture demande une cause et une leçon, qui alimentent le registre des risques.",
    ],
    avantages=[
      ("La chronologie existe sans effort", "Elle s'écrit pendant l'incident, pas après. C'est la différence entre une trace et un souvenir."),
      ("Les délais réglementaires sont suivis", "Le délai de notification à l'autorité est un compteur visible, pas une date notée ailleurs."),
      ("Les leçons alimentent le risque", "Un incident clos nourrit le registre des risques. La boucle se ferme."),
    ],
  ),
  dict(
    slug="compliance", famille="Gouvernance", titre="Conformité réglementaire",
    accroche="Les référentiels du Royaume, reliés à des actifs réels",
    probleme=(
      "La conformité se démontre souvent par des captures d'écran et des tableurs, "
      "reconstitués à chaque audit. Entre deux visites, personne ne sait où l'on en est."),
    quoi=(
      "Les référentiels qui obligent un établissement marocain — DNSSI de la DGSSI, "
      "loi 09-08 et CNDP, PCI DSS, SWIFT CSP, ISO 27001 — avec, par contrôle, son état, "
      "son score, les actifs concernés et la preuve qui l'étaye."),
    lecture=[
      ("Score par référentiel", "La part des contrôles conformes, pondérée. Le détail est en dessous."),
      ("Répartition", "Conforme, partiel, non conforme, non évalué. « Non évalué » est une information, pas un vide."),
      ("Contrôles", "Chacun porte son domaine, sa priorité, et la note qui explique son état."),
    ],
    mecanisme=[
      "Un référentiel s'enregistre avec ses contrôles ; la liste n'est pas fermée à quelques cadres occidentaux.",
      "Un contrôle se rattache aux actifs qu'il concerne, par marqueur réglementaire ou par sélection.",
      "L'évaluation produit un état, un score et une preuve, datés.",
      "Les scores par référentiel remontent au tableau de bord sans ressaisie.",
    ],
    avantages=[
      ("L'audit se prépare en continu", "L'état est à jour en permanence. La visite ne déclenche plus trois semaines de travail."),
      ("Les référentiels marocains, pas seulement européens", "DNSSI et loi 09-08 sont traités comme PCI DSS ou ISO. Et le vôtre s'ajoute."),
      ("Un écart relié à des actifs", "« Ce contrôle est partiel » devient « sur ces douze actifs », donc actionnable."),
    ],
  ),
  dict(
    slug="risk", famille="Gouvernance", titre="Registre des risques",
    accroche="Le risque comme objet suivi, pas comme tableur annuel",
    probleme=(
      "Le registre des risques est souvent un fichier mis à jour une fois par an, "
      "déconnecté de ce que la plateforme de sécurité observe tous les jours."),
    quoi=(
      "Un registre avec probabilité, impact, score, propriétaire et plan de traitement, "
      "alimenté par ce que les autres domaines constatent : incidents clos, écarts de "
      "conformité, vulnérabilités persistantes."),
    lecture=[
      ("Matrice", "Probabilité et impact de 1 à 5, et le score qui en découle."),
      ("Catégorie", "Opérationnel, cyber, réglementaire, tiers, fuite de données."),
      ("Propriétaire et état", "Qui porte le risque, et où en est son traitement."),
    ],
    mecanisme=[
      "Un risque s'ouvre manuellement ou naît de la clôture d'un incident.",
      "Le score croise probabilité et impact, selon l'échelle de l'organisation.",
      "Le profil de risque de l'organisation agrège les risques ouverts et leur évolution.",
      "Les écarts de conformité et les vulnérabilités persistantes nourrissent la réévaluation.",
    ],
    avantages=[
      ("Un registre vivant", "Il bouge quand la réalité bouge, pas à date fixe."),
      ("Relié à l'opérationnel", "Le risque cité au comité est celui que le SOC observe, pas une abstraction parallèle."),
      ("L'échelle est la vôtre", "Les seuils et les pondérations suivent votre méthode d'appréciation."),
    ],
  ),
  dict(
    slug="dspm", famille="Exposition", titre="Posture des données",
    accroche="Où sont les données sensibles, et qui peut les atteindre",
    probleme=(
      "La loi 09-08 impose de savoir quelles données personnelles vous traitez, où elles "
      "sont, et qui y accède. Peu d'organisations peuvent répondre sans enquête."),
    quoi=(
      "Un inventaire des dépôts de données, leur classification, le type de données "
      "qu'ils portent, leur exposition et leurs accès — avec les constats qui en découlent."),
    lecture=[
      ("Dépôts", "Bases, partages, compartiments objet, avec leur classification."),
      ("Types de données", "Données personnelles, données de carte, secrets — ce qui déclenche une obligation."),
      ("Constats", "Un dépôt exposé, un accès trop large, un chiffrement absent."),
    ],
    mecanisme=[
      "Les dépôts sont déclarés par l'API, avec leur type, leur hébergement, leur classification et leur posture.",
      "La classification peut être déclarée ou déduite d'un échantillonnage.",
      "Chaque constat nomme les textes qu'il met en défaut — loi 09-08, PCI DSS — et devient reprenable dans le dossier de conformité.",
      "Le score d'un dépôt croise sa sensibilité, son chiffrement, son contrôle d'accès et ses constats ouverts : il bouge dès qu'un constat est ouvert ou refermé.",
    ],
    avantages=[
      ("Une réponse à la CNDP", "« Quelles données, où, et qui y accède » se lit à l'écran."),
      ("Les transferts hors du Royaume se voient", "L'hébergement et la région de chaque dépôt sont des colonnes de l'inventaire, pas une découverte faite en audit."),
      ("Repris dans le dossier de conformité", "Un constat nomme les textes qu'il met en défaut, et se verse tel quel dans l'évaluation du contrôle correspondant."),
    ],
  ),
  dict(
    slug="scs", famille="Exposition", titre="Chaîne logicielle",
    accroche="Ce que vos fournisseurs et vos dépendances vous font porter",
    probleme=(
      "Une part croissante des incidents entre par un fournisseur ou par une "
      "bibliothèque. Les deux sont rarement inventoriés avec la même rigueur que les serveurs."),
    quoi=(
      "Les fournisseurs, leur évaluation, leurs incidents ; et les composants logiciels "
      "des applications, leur version, leurs vulnérabilités et leur fin de support."),
    lecture=[
      ("Fournisseurs", "Leur criticité, la date de leur dernière évaluation, et son résultat."),
      ("Composants", "Les bibliothèques, leur version, et ce qu'on y connaît de vulnérable."),
      ("Alertes", "Un composant en fin de support, un fournisseur dont l'évaluation est périmée."),
    ],
    mecanisme=[
      "Une nomenclature logicielle importée crée ou met à jour les composants d'une application.",
      "Le score de risque d'un composant croise ses vulnérabilités critiques, sa fin de support et son abandon.",
      "Une évaluation close avec sa note fixe la date et le score de risque du fournisseur : la liste se classe sur ce que l'évaluation a constaté, pas sur une saisie.",
      "Chaque composant déclare les applications qui l'embarquent : le périmètre d'un avis publié se lit sans enquête.",
    ],
    avantages=[
      ("Le risque fournisseur devient suivi", "Le registre des prestataires critiques exigé par la DNSSI existe, à jour."),
      ("Une faille de bibliothèque trouve ses applications", "« Qui embarque cette version » a une réponse immédiate, tirée de la nomenclature et non d'un courriel."),
      ("La fin de support est anticipée", "Elle se voit avant d'être un constat d'audit."),
    ],
  ),
  dict(
    slug="ot", famille="Exposition", titre="Systèmes industriels",
    accroche="Les équipements qu'on ne redémarre pas, et les zones qui les protègent",
    probleme=(
      "Un automate ne se patche pas comme un serveur, et un scanner classique peut "
      "l'arrêter. Les outils informatiques traditionnels y sont inadaptés, voire dangereux."),
    quoi=(
      "Un inventaire des équipements industriels par zone, leurs protocoles, leurs "
      "vulnérabilités, et les politiques d'isolement entre zones."),
    lecture=[
      ("Zones", "Le découpage en niveaux, et ce qui a le droit de traverser."),
      ("Équipements", "Automates, supervision, passerelles, avec leur criticité de procédé."),
      ("Politiques", "L'isolement attendu entre zones, et les écarts constatés."),
    ],
    mecanisme=[
      "Les équipements sont déclarés par l'API ou repris de l'outil de supervision : la plateforme n'émet rien sur le réseau industriel.",
      "Les avis — CVE et ICS-CERT — sont rattachés aux équipements sans aucun balayage : un automate ne se sonde pas.",
      "Les politiques de zone décrivent ce qui est autorisé ; l'écart est ce qui se voit en premier.",
      "Le score de risque d'un équipement tient compte de la criticité du procédé, pas seulement de la faille.",
    ],
    avantages=[
      ("Aucune sonde intrusive", "L'inventaire se constitue sans risquer d'arrêter une chaîne."),
      ("La segmentation s'écrit avant de se discuter", "Les zones, leurs niveaux et les flux attendus sont déclarés : l'écart relevé devient un constat daté plutôt qu'un souvenir d'atelier."),
      ("Un vocabulaire industriel", "Zones, procédés et criticité de production, pas seulement adresses et ports."),
    ],
  ),
  dict(
    slug="mobile", famille="Exposition", titre="Flotte mobile",
    accroche="Les terminaux qui portent vos applications bancaires",
    probleme=(
      "Un terminal compromis ou débridé qui porte l'application bancaire du client est "
      "une exposition directe, et elle est rarement dans le même écran que le reste."),
    quoi=(
      "Les terminaux enrôlés, leur système, leur conformité à la politique, les "
      "applications installées, et les actions à distance disponibles."),
    lecture=[
      ("Terminaux", "Système, version, état d'enrôlement, dernière communication."),
      ("Conformité", "Débridage, version non supportée, chiffrement absent."),
      ("Actions", "Verrouillage et effacement à distance, tracés comme toute autre action."),
    ],
    mecanisme=[
      "L'outil de gestion de flotte dépose l'état de chaque terminal par l'API : chiffrement, verrouillage, déverrouillage du système, écarts constatés.",
      "La politique définit ce qui rend un terminal non conforme.",
      "Une action à distance passe par la même autorisation et la même trace que le reste de la plateforme.",
      "Un terminal non conforme devient un constat, relié à son propriétaire.",
    ],
    avantages=[
      ("Les terminaux dans la même vue", "Ils cessent d'être un angle mort géré par un autre outil et une autre équipe."),
      ("Les actions à distance sont tracées", "Un effacement est nominatif et horodaté — ce qui est aussi une protection pour l'exploitant."),
      ("Le cloisonnement vaut aussi ici", "Un client ne peut pas agir sur le terminal d'un autre, et c'est vérifié à chaque écriture."),
    ],
  ),
  dict(
    slug="api-gateway", famille="Réponse", titre="Passerelle d'API",
    accroche="Par où les autres systèmes entrent, et par où la plateforme sort",
    probleme=(
      "Une plateforme de sécurité qui ne se branche pas devient une vingt-et-unième console. "
      "Et un accès machine ouvert « le temps du projet », sans portée ni limite ni date, "
      "est un accès qui restera ouvert."),
    quoi=(
      "Les clés d'API par lesquelles un système tiers lit la plateforme — chacune avec ses portées, "
      "sa limite de débit et son dernier usage — et les webhooks par lesquels la plateforme pousse "
      "ses événements vers l'outillage de l'organisation."),
    lecture=[
      ("Clés", "À qui, pour quoi faire, à quel débit, et quand elles ont servi pour la dernière fois."),
      ("Portées", "Lecture, écriture, administration : ce que la clé a le droit de faire, et rien de plus."),
      ("Webhooks", "Les événements poussés, vers quelle adresse, et l'état des dernières remises."),
      ("Remises", "Ce qui est parti, ce qui a échoué, et depuis combien de temps."),
    ],
    mecanisme=[
      "Une clé est affichée une seule fois, à sa création : la plateforme n'en conserve qu'une empreinte SHA-256.",
      "Chaque clé porte ses portées, ses limites de débit et sa date d'expiration — le contrat déclaré de l'accès machine, "
      "et ce que le registre permet de revoir.",
      "Renouveler une clé la remplace sans supprimer l'intégration ; la révoquer l'invalide immédiatement.",
      "Un webhook signe son envoi avec un secret partagé (en-tête X-CRP-Signature), pour que le récepteur sache d'où il vient.",
      "Une remise en échec est réessayée trois fois, puis consignée avec son code de retour : l'intégration dit elle-même quand elle est rompue.",
      "Les appels entrants de la plateforme sont aujourd'hui authentifiés par le fournisseur d'identité de l'organisation. "
      "L'authentification par clé, avec application des portées et du débit, est la prochaine étape de ce module.",
    ],
    avantages=[
      ("Les événements vont vers vos outils, pas l'inverse",
       "Un incident critique ouvre un ticket chez vous, signé et réessayé. La plateforme s'insère dans l'exploitation "
       "existante au lieu d'en demander une nouvelle."),
      ("Une intégration rompue se voit",
       "Les remises en échec sont comptées et datées par destinataire. Un connecteur mort cesse d'être une découverte "
       "faite le jour où l'on en a besoin."),
      ("L'accès machine est déclaré avant d'être ouvert",
       "Qui aura accès, pour quoi faire, à quel débit, jusqu'à quand : le registre existe et se revoit, "
       "au lieu d'un compte technique créé « le temps du projet »."),
    ],
  ),
  dict(
    slug="copilot", famille="Pilotage", titre="Assistant d'investigation",
    accroche="Une question en français, une réponse tirée de vos propres données",
    probleme=(
      "Les données existent, mais il faut connaître six écrans et un langage de requête "
      "pour les croiser. L'analyste expérimenté sait ; les autres attendent."),
    quoi=(
      "Un assistant qui interroge la plateforme à votre place : il appelle ses propres "
      "API, croise les domaines, et répond en citant ce qu'il a lu."),
    lecture=[
      ("La question", "En langage naturel — « quels actifs exposés portent une vulnérabilité exploitée »."),
      ("Le raisonnement", "Les appels qu'il a faits pour répondre, visibles."),
      ("La réponse", "Avec les objets concernés, cliquables."),
    ],
    mecanisme=[
      "L'assistant dispose d'outils : interroger les actifs, les alertes, les vulnérabilités, la conformité.",
      "Il agit avec le jeton de la personne connectée, donc avec ses permissions — et pas davantage.",
      "Les documents internes sont indexés pour que les réponses citent vos procédures.",
      "Il est optionnel : il s'appuie sur un modèle externe, et la plateforme fonctionne sans lui.",
    ],
    avantages=[
      ("Le niveau 1 gagne en autonomie", "Une question qui demandait un expert se pose directement."),
      ("Les permissions sont respectées", "L'assistant ne voit que ce que la personne a le droit de voir."),
      ("Désactivable", "C'est le seul composant qui appelle l'extérieur. Il se coupe sans perdre le reste."),
    ],
  ),
  dict(
    slug="settings", famille="Socle", titre="Paramétrage",
    accroche="Ce qui relève de votre politique ne doit pas être dans notre code",
    probleme=(
      "Changer un seuil de détection demande souvent un ticket chez l'éditeur et une "
      "montée de version. Une politique de sécurité qui dépend d'une livraison n'est pas "
      "une politique."),
    quoi=(
      "Quatre familles de décisions, paramétrables par organisation : les seuils "
      "comportementaux, les délais de remédiation par criticité, les pondérations des "
      "chemins d'attaque, et l'adoption des détections."),
    lecture=[
      ("Seuils comportementaux", "À partir de combien d'écarts un comportement devient suspect."),
      ("Délais de remédiation", "Le nombre de jours accordé par criticité de vulnérabilité."),
      ("Pondérations", "Ce qui compte comme un saut facile dans le calcul de chemins."),
    ],
    mecanisme=[
      "Chaque politique est une donnée de l'organisation, pas une constante du code.",
      "Une modification prend effet sans redémarrage ni livraison.",
      "Les valeurs par défaut sont celles d'une banque de détail ; elles se discutent.",
      "Chaque politique est versionnée et porte qui l'a posée : une valeur en vigueur se rattache à une décision datée.",
    ],
    avantages=[
      ("Votre politique vous appartient", "Les quatre décisions se prennent par votre équipe, sans nous."),
      ("Aucune fenêtre de maintenance", "Un seuil change en séance, pendant un comité de sécurité."),
      ("Chaque organisation la sienne", "Deux filiales du même groupe peuvent avoir des politiques différentes."),
    ],
  ),
]
