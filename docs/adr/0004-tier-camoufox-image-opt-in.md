# ADR 0004 -- Tier `camoufox` (Firefox anti-detection) en variante d'image opt-in

- **Statut** : principe ACCEPTED (decision operateur du 2026-09-11, citee plus bas) ;
  decisions 1 a 7 PROPOSEES par l'architecte, a ratifier avant la tranche 1.
- **Date** : 2026-09-11
- **Portee** : ajout d'un cinquieme tier de fetch, `camoufox`, et d'une troisieme
  cible d'image, opt-in. Amende la Decision 5 de
  [ADR 0002](./0002-productionisation.md) ("pas de 3e tier d'image") ; ne change ni
  l'image `autonomous` par defaut, ni les tiers existants.
- **Sources de verite** : cartes de la roadmap 5438dd0b (ce tier) et 5e84a704 (spike
  anti-Akamai), gates d8b7b8fd et 6521bbce (lecons de liveness), code de `main`.

## Contexte

Magalu est l'un des six sites surveilles, et le seul protege par Akamai Bot Manager.
Faits mesures pendant le spike 5e84a704 et la mesure de RAM qui l'a suivi :

- Le tier `uc` (SeleniumBase UC, Chromium) est bloque par Akamai **dans le conteneur
  Linux**, avec ou sans pin de resolution : page 403 d'environ 1,2 Ko. La cause est
  l'empreinte du Chrome Linux, pas le pin ni l'IP (les memes outils passent depuis
  l'hote, meme IP publique). Aucun correctif du pin ne debloquera `uc`.
- **Camoufox 0.5.6** (fork de Firefox) franchit Akamai en headless dans un conteneur
  `python:3.12-slim`, sans xvfb, des le premier essai (vraie page, `__NEXT_DATA__`
  present, prix lu).
- Le bypass tient **derriere un proxy CONNECT avec pin par hote** : sur une cible
  neutre pinnee vers 192.0.2.1, la navigation echoue (le controle mord) ; Magalu
  pinne sur son IP resolue rend la vraie page. Mesure faite avec `geoip=False`.
- Binaire d'environ 1,3 Go, recupere par `camoufox fetch` au build ; aucun appel
  reseau de telechargement au runtime ensuite ; sha256 epinglable. Licence MPL-2.0.
- RAM au pic : 1220 a 1258 Mo par fetch Camoufox (arbre de process complet), contre
  642 a 652 Mo pour Chromium sur la meme page. Retour a la base apres fermeture : la
  memoire n'est consommee que pendant le fetch.
- Sans init dans le conteneur, chaque fetch Camoufox laisse 4 process zombies
  (Chromium : 2), meme cause que la carte d8b7b8fd.

**Decision operateur, citee telle quelle** : « B ; mais à condition de rendre facile
l'activation de cette image. En tout cas on câble tout ce qu'il faut pour pouvoir
l'utiliser si l'utilisateur la veut. (Typiquement, moi j'en aurais besoin) ». Le cout
disque avait ete accepte sans reserve au prealable.

Consequence : une **variante d'image opt-in**, l'image `autonomous` par defaut reste
inchangee, l'activation tient en une commande documentee, et tout est cable de bout
en bout.

## Structure actuelle (cartographie, pas l'ideal)

- **Pas d'escalade automatique entre tiers.** Le tier est declare **par site** dans le
  catalogue (`sites.fetcher`) et resolu par un routeur statique. L'escalade inter-tiers
  de l'invariant 6 est explicitement renvoyee a un futur routeur dynamique, qui
  n'existe pas. L'invariant 6 est donc tenu au niveau du catalogue : chaque site
  declare le tier le moins couteux qui passe.
- **Disponibilite d'un tier** : un registre tier -> module optionnel, verifie par
  `importlib.util.find_spec` (presence du paquet, sans import). Un tier absent ou
  inconnu est fail-closed par source : log au demarrage, ajout de source refuse,
  source ignoree au scrape sans ScrapeRecord (carte 3aeb8a19).
- **Porte Chromium unique** (`autolycos.browser_gate.BrowserGate`), partagee par les
  tiers `browser` et `uc`, bornee par `KERDOOS_BROWSER_MAX_CONCURRENT`, inter-process
  par verrous fichier sous Linux (ADR 0002 Decision 2).
- **SSRF** : `PinningProxy` (egress-proxy CONNECT loopback) resout une fois, rejette
  toute IP non globale, epingle l'IP et restreint les ports a 80/443. Il ne filtre
  **pas** les noms de domaine : l'allowlist de domaines du tier `browser` est portee
  par un garde `page.route` dans le navigateur.
- **Image** : un Dockerfile multi-stage, stages `base`, `slim`, `autonomous` ; compose
  a deux profils exclusifs, `slim` et `autonomous`. Pas encore d'init en PID 1 dans
  l'image (carte d8b7b8fd en cours).
- **WebUI** : l'indicateur d'echelle des tiers attend `uc_selenium` alors que le tier
  rapporte `uc` ; il affiche aujourd'hui une profondeur 0 pour `uc` (defaut
  preexistant, releve a cette occasion).

## Choix du support : un ADR 0004 plutot qu'un amendement de l'ADR 0002

Un nouveau tier, une nouvelle cible d'image, une nouvelle licence tierce et une
nouvelle classe de binaire epingle forment une decision a part entiere, qui merite sa
propre trace. L'amender dans l'ADR 0002 (productionisation generale) le noierait. Le
seul point de l'ADR 0002 contredit, "pas de 3e tier d'image" (Decision 5), recoit un
renvoi explicite vers le present ADR.

---

## Decision 1 -- Place du tier : cinquieme barreau, declare par site

### Options
- **A -- Escalade automatique apres `uc`** (au runtime, un echec `uc` bascule sur
  `camoufox`). *Cout* eleve : c'est le routeur dynamique que le code n'a jamais eu.
  *Risque* : chaque fetch Magalu paierait d'abord un `uc` voue a l'echec (mesure),
  puis un Camoufox. Rejetee.
- **B -- Tier declare par site**, cinquieme barreau de l'echelle de cout
  (`http` < `tls` < `browser` < `uc` < `camoufox`). *Cout* faible : meme mecanisme que
  les quatre tiers existants.

### Decision : **B**
Force decisive : le tier est deja une propriete du site, et l'invariant 6 est tenu au
catalogue (le tier le moins couteux qui passe). Pour Magalu en conteneur, `uc` ne passe
pas (mesure), donc le moins couteux qui passe est `camoufox`.

- Le catalogue livre declare `fetcher: camoufox` pour Magalu. Nom du tier et valeur de
  `FetchResult.method` : `camoufox`.
- **Sur l'image par defaut**, le tier est indisponible et suit le patron 3aeb8a19 :
  log au demarrage, ajout de source refuse, source ignoree au scrape sans ScrapeRecord.
  Aujourd'hui, les sources Magalu y restent INDETERMINATE a chaque tick ; elles seront
  ignorees avec un diagnostic explicite, ce qui est plus honnete.
- **Disponibilite = paquet ET binaire.** `find_spec` seul ne suffit pas pour ce tier :
  un paquet installe sans binaire recupere declencherait un telechargement au runtime,
  interdit (ADR 0002 Decision 5). La disponibilite exige les deux ; le tier ne
  telecharge jamais rien au runtime.
- **Indicateur WebUI** : ajouter le barreau `camoufox` (profondeur 5) et corriger la
  cle `uc` dans la meme tranche.

## Decision 2 -- Activation : une cible de build et un profil compose

### Options
- **A -- Cible `autonomous-camoufox` + profil compose `camoufox`**, construits en local
  comme les deux images actuelles.
- **B -- Tag d'image publie sur un registre.** Aucune chaine de publication d'image
  n'existe dans le depot aujourd'hui ; hors perimetre.
- **C -- Binaire toujours present dans `autonomous`, active par une variable.**
  Contredit la decision operateur (image par defaut inchangee, 1,3 Go en plus pour
  tous). Rejetee.

### Decision : **A**
- Cible `autonomous-camoufox`, construite **a partir de** `autonomous` : elle garde
  `browser` et `uc`, ajoute l'extra `camoufox`, les bibliotheques systeme de Firefox et
  le binaire recupere au build. Tag local `kerdoos:autonomous-camoufox`.
- Service compose `kerdoos-camoufox`, profil `camoufox`, exclusif des deux autres
  (meme volume `/data`, memes regles de port que `kerdoos-autonomous`).
- **Commande documentee unique** : `docker compose --profile camoufox up -d --build`.
- **Epinglage** (patron du chromedriver `uc`, ADR 0002 Decision 5) : version du paquet
  figee dans `uv.lock`, sha256 du binaire en `ARG` du Dockerfile et verifie au build ;
  echec du build si le sha256 ne correspond pas. Taille de l'image **mesuree** sur
  l'image reelle en tranche 2 (le delta de +1,5 a 2,5 Go reste une estimation).
- **Variables d'environnement** :
  - partagees avec les autres navigateurs : `KERDOOS_BROWSER_MAX_CONCURRENT`,
    `KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS` (Decision 3) ;
  - propres au tier : `KERDOOS_CAMOUFOX_LAUNCH_TIMEOUT_SECONDS`,
    `KERDOOS_CAMOUFOX_NAV_TIMEOUT_SECONDS`, `KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS`.
    Leurs defauts sont fixes par mesure en tranche 1 (le spike n'a pas mesure les
    durees de lancement ni de navigation de Camoufox), avec la contrainte
    lancement + navigation < fetch < attente de la porte, et un WARNING au demarrage
    (jamais un refus) si l'ordre n'est pas respecte, comme pour le tier `browser`.
    Le timeout de navigation est configurable des le depart (regle operateur : rien en
    dur).
- Aucune variable d'activation en plus du profil : la disponibilite du tier est
  detectee (Decision 1).

## Decision 3 -- Concurrence et memoire : la meme porte que Chromium

### Options
- **A -- Meme porte** : une place = un navigateur vivant, quel qu'il soit.
- **B -- Porte distincte** pour Camoufox : autorise Chromium et Firefox en meme temps
  (0,65 + 1,26 Go), ce qui casse la propriete "une seule porte" qui a justifie la
  topologie S-B (ADR 0002 Decision 1).
- **C -- Porte ponderee** (Camoufox prend deux places) : exige d'acquerir plusieurs
  places atomiquement, dans le semaphore et dans les verrous fichier, avec un risque
  d'interblocage. Cout sans rapport avec le besoin tant que le defaut est 1.

### Decision : **A**
Force decisive : une seule porte memoire (ADR 0002 Decision 1). Avec le defaut
`KERDOOS_BROWSER_MAX_CONCURRENT=1`, le pic est borne par l'instance la plus lourde, soit
environ 1,26 Go mesure.

- **Note pour l'operateur** (a porter dans `env.example`) : sur l'image camoufox,
  compter environ 1,3 Go par place (pic mesure 1220 a 1258 Mo), en plus de la base de
  l'application ; choisir `KERDOOS_BROWSER_MAX_CONCURRENT` selon la RAM libre de la
  machine. Aucune valeur en dur au-dela du defaut de 1.
- Reversible : si des operateurs montent le plafond et que le melange Chromium/Firefox
  devient un probleme mesure, l'option C se rouvre.

## Decision 4 -- SSRF : proxy existant obligatoire ET garde de domaine

- **Obligatoire** : Camoufox est lance avec le `PinningProxy` existant comme proxy
  unique (resolution unique, rejet des IP non globales, pin, ports 80/443, loopback).
  Aucun proxy propre au tier. Le reglage de resolution de Firefox mesure pendant le
  spike (`network.dns.forceResolve`) n'est **pas** le controle retenu.
- **Deny-by-default = deux couches**, comme pour le tier `browser` : le proxy porte le
  controle d'IP, un garde `page.route` porte l'allowlist de domaines (domaines du
  catalogue + sous-ressources declarees du site). Le proxy seul ne filtre pas les noms.
- **Aucun chemin reseau hors proxy** : `geoip=False` (pas d'appel de pre-vol vers un
  service d'echo d'IP ; le bypass a ete mesure dans cette configuration) ; DNS sur HTTPS
  et WebRTC desactives par les preferences Firefox, et l'appelant ne peut pas passer de
  preference qui modifie le proxy ou la resolution (equivalent Firefox de
  `strip_dangerous_browser_args`).
- **Preuves d'execution exigees** (tranche 4, dans l'image, avec
  `KERDOOS_REQUIRE_IMAGE_TESTS=1`), chacune **jugee au contenu** (titre ou code
  d'erreur Firefox), jamais a la taille ou a l'absence d'exception, puisqu'une page
  d'erreur navigateur peut peser des centaines de Ko :
  1. cible neutre (`example.com`) dont le proxy resout vers 192.0.2.1 : la navigation
     echoue ;
  2. hote hors allowlist : la requete est avortee par le garde de domaine ;
  3. cible resolue vers une IP non globale : le proxy refuse la connexion.

## Decision 5 -- Liveness : lecons obligatoires des tiers Chromium

Toutes MESUREES sur les tiers `browser` et `uc` (cartes d8b7b8fd et 6521bbce), toutes
exigees ici des la premiere tranche :

- **Echeance totale du fetch** dans **un thread proprietaire** (lancement, page,
  navigation, lecture, fermeture), borne par `KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS`.
  L'API sync de Playwright est liee a son thread (mesure pour patchright) ; Camoufox
  reposant sur la meme API, la contrainte est presumee identique, a confirmer en
  tranche 1.
- **Kill cible** : identification des process du lancement par un marqueur porte par
  sa ligne de commande (argument dedie si Firefox l'accepte, sinon le chemin du profil
  propre au lancement), ou par l'ensemble de process **fige a l'echeance**. Jamais de
  re-balayage apres la liberation de la porte, jamais de rattachement par
  `create_time` (resolution d'une seconde, mesuree inerte ou nuisible).
- **Porte liberee apres la mort effective** des process tues (`wait_procs`), jamais
  avant.
- **Threads abandonnes comptes et plafonnes**, avec un plafond configurable, un log
  ERROR quand il est atteint, et une decrementation sur tous les chemins.
- **psutil declare dans l'extra du tier**, et son import protege.
- **Init en PID 1 dans l'image** (tini), herite de `autonomous` une fois d8b7b8fd
  merge : sans init, 4 zombies par fetch Camoufox (mesure).
- **Acceptation** (tranche 4, dans l'image) : un Firefox fige (SIGSTOP) apres le
  lancement rend un FetchError dans l'echeance, la porte est liberee apres la mort des
  process, aucun process du lancement ne survit a 5 s, et 5 fetches consecutifs
  laissent 0 zombie.

## Decision 6 -- Import paresseux et extra `camoufox`

- Extra d'autolycos nomme **`camoufox`** : le paquet Camoufox (version mesuree 0.5.6,
  borne exacte figee en tranche 1) et psutil. Pas l'extra `geoip` du paquet
  (`geoip=False`, Decision 4).
- Le paquet n'est importe que **dans une fonction** de l'adaptateur, y compris pour
  classer une exception (lecon de 0e2cc73 : sans l'extra, rien ne casse, et un paquet
  casse ne masque pas l'exception d'origine).
- Le registre du routeur recoit le tier `camoufox` (module et fabrique) ; la
  disponibilite verifie paquet et binaire (Decision 1).
- Le paquet Camoufox depend de Playwright, et l'image contient deja patchright :
  cohabitation presumee sans conflit (noms de module distincts), a verifier par la
  resolution de `uv.lock` en tranche 1 et par les tests en image en tranche 4.

## Decision 7 -- Decoupage en tranches

| Tranche | Contenu | Depend de |
|---|---|---|
| T0 | Prerequis : d8b7b8fd merge (tini dans le Dockerfile, cycle de fetch borne avec C1 a C3 fermes) ; decision de 6521bbce sur l'ensemble fige | -- |
| T1 | Adaptateur autolycos : extra, import paresseux, proxy + garde de domaine, liveness de la Decision 5, registre du routeur, disponibilite paquet + binaire, tests unitaires avec un faux Camoufox ; mesure des durees de lancement et de navigation (image de sonde du spike) pour fixer les defauts | T0 |
| T2 | Dockerfile : cible `autonomous-camoufox`, bibliotheques systeme, `camoufox fetch` epingle par sha256 ; compose : profil `camoufox` ; `env.example` (variables, note de RAM) ; taille d'image mesuree | T0 (le Dockerfile est modifie par d8b7b8fd), T1 (l'extra existe dans `uv.lock`) |
| T3 | Cablage kerdoos : variables dans `get_settings`, WARNING d'ordre, injection par la racine de composition (WebUI et CLI), tests de cablage par racine, indicateur WebUI (barreau `camoufox`, cle `uc` corrigee), catalogue Magalu -> `camoufox`, documentation d'exploitation | T1 ; en parallele de T2 |
| T4 | Tests en image : preuves SSRF de la Decision 4, liveness de la Decision 5, RAM re-mesuree sur l'image reelle, `MagaluParser` sur une vraie page Camoufox (fixture issue du spike) | T2, T3 |

Chaque tranche passe le gate a trois lentilles (architecte, reviewer, securite).

---

## Consequences

- **Positives** : Magalu redevient accessible pour l'operateur qui en a besoin, sans
  alourdir l'image par defaut ; le nouveau tier herite des protections deja mesurees
  (proxy, porte unique, liveness), sans nouvelle porte ni nouveau proxy.
- **Negatives / dettes** : une troisieme cible d'image a maintenir et a reconstruire a
  chaque montee de version de Camoufox (binaire et sha256) ; un pic memoire presque
  double par place sur cette image ; une dependance tierce MPL-2.0 de plus.
- **Ce qui ne change pas** : l'image `autonomous` et ses deux tiers navigateur, la
  semantique de `KERDOOS_BROWSER_MAX_CONCURRENT`, le PinningProxy, l'etat a trois
  valeurs (un echec Camoufox donne INDETERMINATE, un tier absent ignore la source).

## Questions ouvertes pour l'operateur

1. **Avenir du tier `uc`** : une fois Magalu declare en `camoufox`, plus aucun site du
   catalogue n'utilise `uc`, dont le pin SSRF a en outre ete mesure comme non tenu dans
   le conteneur. Le garder, le deprecier ou le retirer ?
2. **Distribution de l'image** : si l'image camoufox est un jour publiee ou transmise a
   un tiers, la licence MPL-2.0 impose d'y joindre sa notice et l'acces aux sources de
   Camoufox. Est-ce envisage ?
3. **Bascule d'un `config.db` existant** : le catalogue livre declare `camoufox` pour
   Magalu, mais une base deja peuplee garde `uc` tant que l'operateur ne repasse pas
   par la porte admin du catalogue. Faut-il automatiser cette bascule, ou la documenter
   comme une etape manuelle ?

## Changelog

- **2026-09-11 -- PROPOSED**. Redige par l'architecte a partir de la decision operateur
  (option B, variante d'image opt-in a activation simple) et des mesures du spike
  5e84a704 et de la carte 5438dd0b.
