# ADR 0004 -- Tier `camoufox` (Firefox anti-detection) en variante d'image opt-in

- **Statut** : ACCEPTED (2026-09-11). Principe : decision operateur, citee plus bas.
  Decisions 1 a 8 : ratifiees par le team-lead au titre de son mandat d'autonomie,
  apres validation de la revue security-auditor (ratifiable apres les retouches R1 a
  R3). Les conditions de securite C1 a C6 y sont integrees (table de tracabilite en fin
  de document). Les trois questions operateur restent ouvertes.
- **Date** : 2026-09-11
- **Portee** : ajout d'un cinquieme tier de fetch, `camoufox`, et d'une troisieme
  cible d'image, opt-in. Amende la Decision 5 de
  [ADR 0002](./0002-productionisation.md) ("pas de 3e tier d'image"). Durcit au passage
  l'egress-proxy commun (Decision 4, condition C1), ce qui touche aussi le tier
  `browser` existant.
- **Sources de verite** : cartes de la roadmap 5438dd0b (ce tier) et 5e84a704 (spike
  anti-Akamai), gates d8b7b8fd et 6521bbce (lecons de liveness), revue security-auditor
  de la premiere version de cet ADR, code de `main`.

## Contexte

Magalu est l'un des six sites surveilles, et le seul protege par Akamai Bot Manager.
Faits mesures pendant le spike 5e84a704 et la mesure de RAM qui l'a suivi :

- Le tier `uc` (SeleniumBase UC, Chromium) est bloque par Akamai **dans le conteneur
  Linux**, avec ou sans pin de resolution : page 403 d'environ 1,2 Ko. La cause est
  l'empreinte du Chrome Linux, pas le pin ni l'IP (les memes outils passent depuis
  l'hote, meme IP publique).
- **Camoufox 0.5.6** (fork de Firefox) franchit Akamai en headless dans un conteneur
  `python:3.12-slim`, sans xvfb, des le premier essai (vraie page, `__NEXT_DATA__`
  present, prix lu).
- Le bypass tient **derriere un proxy CONNECT avec pin par hote** : sur une cible
  neutre pinnee vers 192.0.2.1, la navigation echoue (le controle mord) ; Magalu
  pinne sur son IP resolue rend la vraie page. Mesure faite avec `geoip=False`.
- Binaire d'environ 1,3 Go. Licence MPL-2.0.
- RAM au pic : 1220 a 1258 Mo par fetch Camoufox (arbre de process complet), contre
  642 a 652 Mo pour Chromium sur la meme page. Retour a la base apres fermeture : la
  memoire n'est consommee que pendant le fetch.
- Sans init dans le conteneur, chaque fetch Camoufox laisse 4 process zombies
  (Chromium : 2), meme cause que la carte d8b7b8fd.
- **MercadoLivre, deuxieme site candidat** (mesure sur **un seul echantillon**, une
  requete sur la meme fiche produit, a confirmer en T4) : le tier `browser` actuel
  (patchright, Chromium complet, user-agent sans "Headless") recoit un 200 mais sur un
  mur de verification de compte (40802 octets, aucune donnee produit) ; Camoufox (image
  du spike) recoit la vraie fiche (1055964 octets, etat pre-charge de la page, JSON-LD
  Product avec un prix de 9434 BRL et la disponibilite InStock).

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
- **SSRF** : `PinningProxy` (egress-proxy CONNECT loopback) lit l'autorite du CONNECT,
  refuse les ports autres que 80/443, puis resout une fois, rejette toute IP non
  globale et epingle l'IP. Il ne filtre **pas** les noms de domaine. L'allowlist de
  domaines du tier `browser` est portee par un garde `page.route`, pose sur la page
  seulement : il ne voit ni les service workers, ni les WebSockets, ni les popups, ni le
  trafic interne du navigateur (constat de la revue security-auditor).
- **Image** : un Dockerfile multi-stage, stages `base`, `slim`, `autonomous` ; compose
  a deux profils exclusifs, `slim` et `autonomous`. Pas encore d'init en PID 1 dans
  l'image (carte d8b7b8fd en cours). L'image `autonomous` s'execute en root.
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
- MercadoLivre, declare aujourd'hui `fetcher: browser`, est candidat au meme tier sur
  la foi d'une mesure unique (Contexte). Son routage vers `camoufox` dans le catalogue
  se fait en T3, et sa confirmation sur plusieurs echantillons en T4 ; si T4 ne
  confirme pas, MercadoLivre revient a `browser`.
- **Sur l'image par defaut**, le tier est indisponible et suit le patron 3aeb8a19 :
  log au demarrage, ajout de source refuse, source ignoree au scrape sans ScrapeRecord.
- **Disponibilite = paquet + binaire + version** (renforcee par la condition C5) : le
  paquet est importable, le binaire est present a l'emplacement fixe par l'image, sa
  version installee est **egale a la version epinglee** et **compatible avec le
  plancher de version** exige par le paquet. Sinon, indisponible (fail-closed). Le tier
  ne telecharge jamais rien a l'execution (Decision 6).
- **Indicateur WebUI** : ajouter le barreau `camoufox` (profondeur 5) et corriger la
  cle `uc` dans la meme tranche.

## Decision 2 -- Activation et build : une cible, un profil, un build deterministe

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
  le binaire. Tag local `kerdoos:autonomous-camoufox`.
- Service compose `kerdoos-camoufox`, profil `camoufox`, exclusif des deux autres
  (meme volume `/data`, memes regles de port que `kerdoos-autonomous`, durcissement de
  la Decision 8).
- **Commande documentee unique** : `docker compose --profile camoufox up -d --build`.

### Build deterministe (condition C4)
La commande `camoufox fetch` du paquet **n'est jamais utilisee**. Selon la revue
security-auditor (code `pkgman.py` de Camoufox), elle prend le premier asset compatible
via l'API GitHub et saute la verification quand le digest manque : c'est une
resolution dynamique, pas un epinglage.

- Le Dockerfile telecharge l'**URL d'asset exacte** du tag retenu. Son sha256 est un
  `ARG` du Dockerfile, verifie au build (echec du build sinon), et recoupe **au moment de
  la capture** avec le digest publie par GitHub pour cet asset.
- Provenance notee a cote de l'`ARG` : tag, URL d'asset, digest GitHub, date de
  capture.
- Les addons embarques et les donnees `browserforge` sont epingles de la meme facon
  (URL exacte + sha256), jamais resolus au build.
- Si un `GITHUB_TOKEN` sert au build (limite de debit de l'API) : secret BuildKit
  uniquement, jamais en `ARG` ni en `ENV`, jamais present a l'execution.
- Taille de l'image **mesuree** sur l'image reelle en tranche T2 (le delta de +1,5 a
  2,5 Go reste une estimation).

### Variables d'environnement
- Partagees avec les autres navigateurs : `KERDOOS_BROWSER_MAX_CONCURRENT`,
  `KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS` (Decision 3).
- Propres au tier : `KERDOOS_CAMOUFOX_LAUNCH_TIMEOUT_SECONDS`,
  `KERDOOS_CAMOUFOX_NAV_TIMEOUT_SECONDS`, `KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS`.
  Leurs defauts sont fixes par mesure en tranche T1 (le spike n'a pas mesure les
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

## Decision 4 -- SSRF : le proxy devient le point de controle suffisant

### C1 -- Allowlist de domaines dans le PinningProxy (commune a tous les tiers navigateur)
- Le `PinningProxy` applique l'allowlist de **domaines** (DomainPolicy + domaines de
  sous-ressources declares du site) a l'**autorite du CONNECT**, **avant** toute
  resolution. Hors allowlist : refus, sans resolution ni connexion.
- Raison : le proxy est le seul point par lequel passe **tout** le trafic du navigateur
  (pages, service workers, WebSockets, popups, trafic interne). Un garde pose dans le
  navigateur ne voit qu'une partie de ce trafic ; il reste en **defense en profondeur**,
  jamais comme controle principal.
- **Etendu au tier `browser` existant** dans la meme tranche (T0.5) : le trou y est
  preexistant.

### C2 -- Preferences Firefox imposees
Une liste **explicite et figee** de preferences, fusionnee **par-dessus** toute
preference de l'appelant (l'appelant ne peut ni les retirer ni les modifier), equivalent
Firefox de `strip_dangerous_browser_args` :

- Proxy sans echappatoire : `network.proxy.allow_hijacking_localhost=true` (sinon
  Firefox envoie 127.0.0.1 en direct, hors proxy) ; `network.proxy.no_proxies_on=""` ;
  `network.proxy.failover_direct=false`.
- Resolution et connexions anticipees coupees : `network.trr.mode=5` ;
  `network.dns.disablePrefetch=true` ; `network.prefetch-next=false` ;
  `network.predictor.enabled=false` ; `network.http.speculative-parallel-limit=0`.
- Transports hors proxy coupes : `media.peerconnection.enabled=false` ;
  `network.http.http3.enable=false`.
- Workers de fond coupes : `dom.serviceWorkers.enabled=false` ;
  `dom.push.enabled=false`.
- Trafic interne coupe : portail captif, verification de connectivite, safebrowsing,
  mises a jour (`app.update`, `extensions.update`), telemetrie et `datareporting`,
  geolocalisation, remote settings. En T1, ces categories sont **enumerees par nom
  exact de preference** dans le code, et un test verifie le dictionnaire final apres
  fusion avec les preferences de l'appelant.
- **OCSP : desactive** (`security.OCSP.enabled=0`). Raison : avec l'allowlist C1, les
  requetes OCSP vers les repondeurs des autorites de certification seraient refusees
  par le proxy de toute facon ; la verification de revocation en ligne est donc
  abandonnee explicitement plutot qu'implicitement. Parite avec le tier Chromium, qui ne
  fait pas de verification de revocation en ligne par defaut. Risque accepte : les
  cibles sont un catalogue admin fixe de sites marchands sous TLS. L'agrafage OCSP reste
  actif (`security.ssl.enable_ocsp_stapling=true`, aucune requete sortante) ; couper
  remote settings laisse CRLite perime ou absent, ce qui est coherent avec ce risque
  accepte.
- `geoip=False` : pas d'appel de pre-vol vers un service d'echo d'IP (le bypass a ete
  mesure dans cette configuration).
- Le reglage de resolution mesure pendant le spike (`network.dns.forceResolve`) n'est
  **pas** un controle retenu.

### C3 -- Garde au niveau du contexte
- Validation de la cible (`validate_target`) **avant** tout lancement.
- Un **contexte par fetch** et une page par contexte ; contexte cree avec
  `service_workers="block"`.
- Garde pose sur le **contexte** (`context.route("**/*")`), donc applique aussi aux
  popups ; garde WebSocket au niveau du contexte si l'API le permet (sinon, le controle
  C1 du proxy suffit).

### Preuves d'execution exigees (tranche T4, dans l'image, `KERDOOS_REQUIRE_IMAGE_TESTS=1`)
Chaque preuve est **jugee au contenu** (titre, code d'erreur, journal), jamais a la
taille ou a la seule absence d'exception : une page d'erreur de navigateur peut peser
des centaines de Ko.

- **Cible neutre pinnee** : `example.com` resolue par le proxy vers 192.0.2.1 -> la
  navigation echoue.
- **Hote hors allowlist** : refuse par le proxy (C1), sans resolution.
- **Hote allowliste qui resout vers une IP non globale** (resolveur de test, ou
  domaine de test vers 10.x, 127.x, 169.254.169.254 ou ::ffff:127.0.0.1) : refuse par
  le proxy au controle d'IP (`ip_is_safe`), juge au journal du proxy. C'est la preuve
  anti-rebinding, la seule qui exerce la deuxieme couche du proxy : depuis C1, le
  loopback de T4-1 est refuse avant toute resolution et ne la teste pas.
- **T4-1** : 127.0.0.1, `localhost` et `[::1]` passent par le proxy et sont refuses.
- **T4-2** : audit d'egress par `strace -f -e trace=connect,sendto,sendmsg,sendmmsg`
  (QUIC et WebRTC emettent par `sendmsg` et `sendmmsg`) sur tout l'arbre de process
  Firefox pendant un fetch puis 30 s d'inactivite, rapproche du journal des autorites
  CONNECT du proxy : aucune connexion hors proxy, aucune autorite hors allowlist.
  `CAP_SYS_PTRACE` n'est accorde qu'au conteneur de TEST, jamais au compose de
  production (qui garde le `cap_drop: [ALL]` de la Decision 8).
- **T4-3** : un WebSocket vers un hote hors allowlist est refuse.
- **T4-4** : un service worker, un Worker dedie et un `window.open` ne sortent pas de
  l'allowlist.
- **T4-5** : `RTCPeerConnection` est indefini dans la page.
- **T4-6** : proxy tue pendant un fetch -> aucune bascule en connexion directe.

## Decision 5 -- Liveness : lecons obligatoires des tiers Chromium

Toutes MESUREES sur les tiers `browser` et `uc` (cartes d8b7b8fd et 6521bbce), toutes
exigees ici des la tranche T1 :

- **Echeance totale du fetch** dans **un thread proprietaire** (lancement, page,
  navigation, lecture, fermeture), bornee par `KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS`.
  L'API sync de Playwright est liee a son thread (mesure pour patchright) ; Camoufox
  reposant sur la meme API, la contrainte est presumee identique, a confirmer en T1.
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
- **Acceptation** (T4, dans l'image) : un Firefox fige (SIGSTOP) apres le lancement
  rend un FetchError dans l'echeance, la porte est liberee apres la mort des process,
  aucun process du lancement ne survit a 5 s, et 5 fetches consecutifs laissent
  0 zombie.

## Decision 6 -- Extra `camoufox`, import paresseux, zero telechargement a l'execution

- Extra d'autolycos nomme **`camoufox`** : le paquet Camoufox (version mesuree 0.5.6,
  borne exacte figee en T1) et psutil. Pas l'extra `geoip` du paquet (`geoip=False`).
- Le paquet n'est importe que **dans une fonction** de l'adaptateur, y compris pour
  classer une exception (lecon de 0e2cc73 : sans l'extra, rien ne casse, et un paquet
  casse ne masque pas l'exception d'origine). **L'import ne declenche aucune recherche
  ni aucun telechargement de binaire.**
- **Zero telechargement a l'execution, par construction (condition C5).** Selon la
  revue security-auditor (code `pkgman.py` de Camoufox), la recherche du binaire
  telecharge par defaut quand il manque, et retelecharge si le plancher de version,
  calcule a partir de la version de Playwright installee, n'est pas satisfait. Un simple
  changement de version de Playwright dans `uv.lock` declencherait alors un
  telechargement direct au lancement, hors proxy (CWE-494), avec suppression possible
  du binaire existant. Exigences :
  - l'adaptateur passe un chemin de binaire explicite, ou desactive le telechargement
    automatique ; aucun chemin de code ne peut atteindre le telechargement ;
  - disponibilite fail-closed selon la Decision 1 (paquet + binaire + version egale et
    compatible avec le plancher) ;
  - **assertion au build** : le build echoue si la version du binaire ne satisfait pas
    le plancher calcule ; tout changement de version de Playwright ou de patchright
    dans `uv.lock` force donc la reverification du binaire au build.
- Le registre du routeur recoit le tier `camoufox` (module et fabrique).
- Le paquet Camoufox depend de Playwright, et l'image contient deja patchright :
  cohabitation presumee sans conflit (noms de module distincts), a verifier par la
  resolution de `uv.lock` en T1 et par les tests en image en T4.
- **Preuve T4-7** : zero telechargement sous `--network none`, avec des espions qui
  levent sur les fonctions d'installation et de telechargement du paquet et sur
  `requests.get`, y compris dans un scenario ou le plancher de version Playwright est
  releve artificiellement.

## Decision 7 -- Decoupage en tranches

| Tranche | Contenu | Depend de |
|---|---|---|
| T0 | Prerequis : d8b7b8fd merge (tini dans le Dockerfile, cycle de fetch borne avec C1 a C3 de son gate fermes) ; decision de 6521bbce sur l'ensemble fige | -- |
| T0.5 | Condition C1 : allowlist de domaines a l'autorite du CONNECT dans `egress_proxy.py`, appliquee au tier `browser` existant ; tests du proxy (hote hors allowlist refuse sans resolution, loopback) | T0 (`browser.py` est modifie par d8b7b8fd) |
| T1 | Adaptateur autolycos : extra, import paresseux, zero telechargement (C5 cote code), preferences imposees (C2), garde de contexte (C3), liveness de la Decision 5, registre du routeur, disponibilite paquet + binaire + version, tests unitaires avec un faux Camoufox ; mesure des durees de lancement et de navigation pour fixer les defauts | T0, T0.5 (API du proxy) |
| T2 | Dockerfile : cible `autonomous-camoufox`, bibliotheques systeme, telechargement deterministe epingle (C4), assertion de version au build (C5), durcissement (Decision 8) ; compose : profil `camoufox` durci ; `env.example` (variables, note de RAM) ; taille d'image mesuree | T0, T1 (l'extra existe dans `uv.lock`) |
| T3 | Cablage kerdoos : variables dans `get_settings`, WARNING d'ordre, injection par la racine de composition (WebUI et CLI), tests de cablage par racine, indicateur WebUI (barreau `camoufox`, cle `uc` corrigee), catalogue Magalu et MercadoLivre -> `camoufox`, documentation d'exploitation (dont `CLAUDE.md` invariant 6 et `AGENTS.md`) | T1 ; en parallele de T2 |
| T4 | Tests en image : preuves SSRF de la Decision 4 (dont T4-1 a T4-6), zero telechargement T4-7, durcissement T4-8, reproductibilite T4-9, liveness de la Decision 5, RAM re-mesuree sur l'image reelle, `MagaluParser` sur une vraie page Camoufox (fixture issue du spike), MercadoLivre confirme sur plusieurs echantillons avec son parser (sinon retour a `browser`) | T2, T3 |

Chaque tranche passe le gate a trois lentilles (architecte, reviewer, securite).

## Decision 8 -- Durcissement de l'image camoufox (condition C6)

- **Utilisateur non-root** dans la cible `autonomous-camoufox`, avec un `HOME`
  inscriptible (profil Firefox, cache). La propriete du volume `/data` pour cet
  utilisateur est a traiter en T2 (le volume est aujourd'hui ecrit par root).
- **Sandbox de contenu Firefox active** : aucune variable `MOZ_DISABLE_*SANDBOX` dans
  l'image ni dans le compose. `security.sandbox.content.level` n'est jamais abaisse (ni
  a 0, ni a une valeur reduite), ni par la liste figee de C2, ni par l'appelant.
- **Compose** : `cap_drop: [ALL]`, `security_opt: no-new-privileges`, profil seccomp par
  defaut (jamais `unconfined`) ; `read_only` avec des `tmpfs` pour les repertoires
  inscriptibles si le fonctionnement le permet, a mesurer en T2. Aucun `cap_add`
  (notamment `SYS_ADMIN`) ni seccomp `unconfined` pour reparer la sandbox si elle ne
  demarre pas : le probleme se regle dans l'image, pas en elargissant les privileges.
- **Base Firefox documentee** : version de Firefox sur laquelle repose le binaire
  Camoufox epingle, notee a cote de l'epinglage ; **politique de re-epinglage** a chaque
  release de securite amont de Firefox reprise par Camoufox.
- **Preuve T4-8** : dans l'image, les process Firefox tournent avec un uid different de
  0, et la sandbox de contenu est active.
- **Preuve T4-9** : le sha256 verifie au build est egal au digest GitHub de l'asset, et
  un second build produit le meme binaire.

---

## Tracabilite des conditions de securite

| Condition | Objet | Ou dans cet ADR |
|---|---|---|
| C1 | Allowlist de domaines dans le proxy, point de controle suffisant | Decision 4 (C1), tranche T0.5 |
| C2 | Preferences Firefox imposees, OCSP tranche | Decision 4 (C2) |
| C3 | Garde au niveau du contexte | Decision 4 (C3) |
| C4 | Build deterministe, provenance, secrets de build | Decision 2 (build deterministe) |
| C5 | Zero telechargement a l'execution, par construction | Decision 1 (disponibilite), Decision 6 |
| C6 | Durcissement de l'image | Decision 8 |
| C7 | Correction factuelle sur le pin du tier `uc` | Questions ouvertes (1) |

## Consequences

- **Positives** : Magalu redevient accessible pour l'operateur qui en a besoin, sans
  alourdir l'image par defaut ; le nouveau tier herite des protections deja mesurees
  (porte unique, liveness) ; l'allowlist de domaines dans le proxy ferme aussi un trou
  preexistant du tier `browser`.
- **Negatives / dettes** : une troisieme cible d'image a maintenir et a re-epingler a
  chaque release de securite amont ; un pic memoire presque double par place sur cette
  image ; une dependance tierce MPL-2.0 de plus ; OCSP desactive sur ce tier.
- **Ce qui ne change pas** : l'image `autonomous` (hors durcissement du proxy commun),
  la semantique de `KERDOOS_BROWSER_MAX_CONCURRENT`, l'etat a trois valeurs (un echec
  Camoufox donne INDETERMINATE, un tier absent ignore la source).

## Questions ouvertes pour l'operateur

1. **Avenir du tier `uc`** : une fois Magalu declare en `camoufox`, plus aucun site du
   catalogue n'utilise `uc`. Son pin SSRF **tient** (le constat inverse etait un faux
   positif, corrige, et le defaut reel de troncature des arguments est corrige par la
   carte dde2d243) ; restent non testes les IP litterales et les redirections 30x. Le
   garder, le deprecier ou le retirer ?
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
- **2026-09-11 -- conditions de securite integrees**. Revue security-auditor : le proxy
  devient le point de controle suffisant (C1, tranche T0.5 qui couvre aussi le tier
  `browser`), preferences Firefox imposees et OCSP desactive (C2), garde de contexte
  (C3), build deterministe sans `camoufox fetch` (C4), zero telechargement a l'execution
  par construction (C5), durcissement de l'image (C6, Decision 8), neuf preuves T4.
  Correction de la question ouverte 1 (C7).
- **2026-09-11 -- ACCEPTED**. Retouches de ratification securite (R1 a R3, N1, N2) ;
  decisions 1 a 8 ratifiees par le team-lead au titre de son mandat d'autonomie, apres
  validation de la revue security-auditor. Ajout de MercadoLivre comme deuxieme site
  candidat, mesure sur un seul echantillon, a confirmer en T4. Les trois questions
  operateur restent ouvertes.
