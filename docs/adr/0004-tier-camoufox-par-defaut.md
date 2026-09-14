# ADR 0004 -- Tier `camoufox` (Firefox anti-detection) dans l'image `autonomous` par defaut

- **Statut** : ACCEPTED (2026-09-11), **revise le 2026-09-12** par decision operateur :
  Camoufox n'est plus une variante d'image opt-in, il est livre et actif d'office dans
  `kerdoos:autonomous`. Decisions 1 a 8 : ratifiees par le team-lead au titre de son
  mandat d'autonomie, apres validation de la revue security-auditor (ratifiable apres
  les retouches R1 a R3) ; la Decision 2 est reecrite par la revision, et la
  **Decision 9** (tier `uc` deprecie) est une decision operateur directe. Les
  conditions de securite C1 a C7 sont integrees (table de tracabilite en fin de
  document) et **n'ont pas bouge a la revision** : elles ne dependaient pas de
  l'opt-in.
- **Date** : 2026-09-11, revise le 2026-09-12
- **Portee** : ajout d'un cinquieme tier de fetch, `camoufox`, embarque dans la cible
  `autonomous` existante. Amende la Decision 5 de
  [ADR 0002](./0002-productionisation.md) sur deux points : le **contenu**
  d'`autonomous` change (taille, pic memoire), et cette image ne s'execute plus en root
  (Decision 8, condition C6) alors que l'ADR 0002 la decrit en root. Durcit au passage
  l'egress-proxy commun (Decision 4, condition C1), ce qui touche aussi le tier
  `browser` existant. Tranche l'avenir du tier `uc` (Decision 9).
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
  (Chromium : 2), meme cause que la carte d8b7b8fd. Cette cause est levee depuis :
  tini est en PID 1 dans l'image (carte d8b7b8fd, merge 761bf17).
- **MercadoLivre, deuxieme site candidat** (mesure sur **un seul echantillon**, une
  requete sur la meme fiche produit, infirme en T4 : amendement du 2026-09-14 sous la
  Decision 1) : le tier `browser` actuel
  (patchright, Chromium complet, user-agent sans "Headless") recoit un 200 mais sur un
  mur de verification de compte (40802 octets, aucune donnee produit) ; Camoufox (image
  du spike) recoit la vraie fiche (1055964 octets, etat pre-charge de la page, JSON-LD
  Product avec un prix de 9434 BRL et la disponibilite InStock).

**Premiere decision operateur, citee telle quelle** : « B ; mais à condition de rendre
facile l'activation de cette image. En tout cas on câble tout ce qu'il faut pour pouvoir
l'utiliser si l'utilisateur la veut. (Typiquement, moi j'en aurais besoin) ». Le cout
disque avait ete accepte sans reserve au prealable.

**Decision operateur de revision, citee telle quelle** : « 1. Déprécie uc ; on ne sait
jamais "demain", il se pourrait qu'une mise à jour le rende "meilleure" que Camoufox.
2. On bascule Camoufox en obligatoire alors ; pas d'opt-in pour l'activer. Il est actif
de base. 3. Kerdoos est fait pour être publique. 4. Il n'y a pas encore d'utilisateur de
Kerdoos ; outil encore en conception ; donc pas besoin d'étapes manuelle documentée. Vu
que ça sera livré par défaut. »

Consequences retenues : Camoufox est **dans l'image `autonomous` par defaut**, sans
variante ni profil d'activation ; le tier `uc` est **deprecie** (Decision 9) ; le depot
est destine a etre **public**, donc la licence de Camoufox est traitee ici (Decision 2) ;
il n'existe **aucun utilisateur**, donc aucune bascule ni migration a prevoir.

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
  a deux profils exclusifs, `slim` et `autonomous`. tini est en PID 1 dans toutes
  les cibles (`ENTRYPOINT ["/usr/bin/tini", "-s", "--"]` du stage `base`, carte
  d8b7b8fd) ; le compose n'a pas d'`init: true`. L'image `slim` s'execute en
  non-root (`USER 10001`), l'image `autonomous` en root.
- **WebUI** : l'indicateur d'echelle des tiers connait quatre barreaux
  (`http`, `tls`, `browser`, `uc`), figes a trois endroits independants l'un de
  l'autre : le tuple `_TIER_LADDER`, le nombre de pastilles de la macro `tier()`, et
  le tuple d'options du `select` d'ajout de site. La cle `uc`, qui etait restee
  `uc_selenium` et faisait afficher une profondeur 0, est corrigee sur `main`
  (commit ffc2fb8) ; le barreau `camoufox` n'existe nulle part.

## Choix du support : un ADR 0004 plutot qu'un amendement de l'ADR 0002

Un nouveau tier, une nouvelle licence tierce, une nouvelle classe de binaire epingle et
un changement de gabarit de l'image par defaut forment une decision a part entiere, qui
merite sa propre trace. L'amender dans l'ADR 0002 (productionisation generale) le
noierait. La Decision 5 de l'ADR 0002 recoit un renvoi explicite vers le present ADR :
son affirmation "pas de 3e tier d'image" reste vraie, mais le contenu, la taille et le
durcissement de la cible `autonomous` changent.

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

- Le catalogue livre declare `fetcher: camoufox` pour **Magalu** (MercadoLivre y
  figurait jusqu'a l'amendement du 2026-09-14 ci-dessous). Nom du
  tier et valeur de `FetchResult.method` : `camoufox`. Aucun utilisateur n'existe
  (decision operateur), donc il n'y a ni bascule ni migration d'un `config.db` deja
  peuple a prevoir.
- Le routage de MercadoLivre repose sur une mesure unique (Contexte) : il est pose dans
  le catalogue en T3 et confirme sur plusieurs echantillons en T4 ; si T4 ne confirme
  pas, MercadoLivre revient a `browser`.

  > **Amendement du 2026-09-14 (T4, carte 5438dd0b)** : T4 n'a pas confirme Camoufox ;
  > MercadoLivre revient a `browser` dans le catalogue livre, Magalu reste sur
  > `camoufox`. Mesures sur l'image `kerdoos-t4:6835df6`, fiches MLB35045987 et
  > MLB35158445 :
  >
  > - `camoufox` : **0 fiche sur 7 essais** entre 07:35 et 08:25 UTC. Cinq murs
  >   `captcha-wall-index` de 39 Ko servis en 200 et non signales par
  >   `looks_challenged`, un mur `account-verification` de 72 Ko signale, un HTTP 503.
  > - `browser` : **6 essais sur 6 en HTTP 403** entre 08:13 et 08:25 UTC, page
  >   `ui-empty-state` de 2582 octets, signalee (retry puis INDETERMINATE). Ce n'est plus
  >   le mur de 40802 octets du Contexte.
  > - Le seul echantillon positif de Camoufox reste celui du 2026-09-11.
  >
  > A resultat egal (INDETERMINATE), `browser` echoue de facon signalee au lieu d'un mur
  > muet et consomme environ 1,9 fois moins de RAM au pic (Contexte). **Reserve, supposee
  > et non mesuree** : la reputation de l'IP de sortie, apres 13 requetes MercadoLivre en
  > 50 minutes, peut peser sur les deux tiers ; ils recevaient pourtant des pages
  > differentes a la meme minute. Le mur non signale releve de la carte dc122802 et ne
  > change pas cet ADR.
- **Sur l'image `slim`**, le tier est indisponible et suit le patron 3aeb8a19 :
  log au demarrage, ajout de source refuse, source ignoree au scrape sans ScrapeRecord.
  C'est le seul deploiement sans Camoufox.
- **Disponibilite = paquet + binaire + version** (renforcee par la condition C5) : le
  paquet est importable, le binaire est present a l'emplacement fixe par l'image, sa
  version installee est **egale a la version epinglee** et **compatible avec le
  plancher de version** exige par le paquet. Sinon, indisponible (fail-closed). Le tier
  ne telecharge jamais rien a l'execution (Decision 6).
- **Indicateur WebUI** : ajouter le barreau `camoufox` (profondeur 5) en T3. La cle
  `uc`, qui etait restee `uc_selenium` dans `_TIER_LADDER`, est **deja corrigee sur
  `main`** (commit ffc2fb8) ; il reste donc le seul barreau `camoufox` a ajouter, a
  trois endroits distincts : le tuple `_TIER_LADDER`, le nombre de pastilles de la
  macro `tier()` (fige a quatre), et le tuple d'options du `select` d'ajout de site
  (independant de `_TIER_LADDER`).

### Echelle d'escalade telle qu'elle devient (invariant 6)

`http` < `tls` < `browser` < `uc` (deprecie, Decision 9) < `camoufox`

Cinq barreaux, ordonnes par cout croissant. Deux precisions qui ne se lisent pas dans
l'ordre seul :

- **L'ordre est un cout, pas un parcours.** Il n'existe aucune escalade automatique
  d'un barreau au suivant : le tier est declare par site dans le catalogue et resolu
  par un routeur statique. L'invariant 6 se tient au catalogue, en declarant pour
  chaque site le barreau le moins couteux qui passe.
- **`uc` garde sa place de quatrieme barreau bien qu'il soit deprecie.** Sa position
  mesure son cout, pas son usage : aucun site du catalogue ne le declare
  (Decision 9), mais le barreau reste dans l'echelle, dans l'indicateur WebUI et
  dans le `select` d'ajout de site, pour que la reevaluation prevue par la
  Decision 9 ne demande aucune remise en place.

Consequence documentaire (tranche T3) : l'invariant 6 de `CLAUDE.md` et la phrase
d'architecture du `README.md` enumerent aujourd'hui quatre barreaux et s'arretent a
`uc` ; les deux enonces doivent citer les cinq barreaux et la place de `camoufox`.

## Decision 2 -- Livraison : camoufox dans `autonomous`, build deterministe, licence

### Options
- **A -- Cible `autonomous-camoufox` + profil compose `camoufox`** (variante d'image
  opt-in), construits en local comme les deux images actuelles. *Cout* : une
  troisieme cible et un troisieme profil a maintenir et a re-epingler. *Risque* : la
  seule image qui franchit Akamai n'est pas celle que l'operateur lance par defaut ;
  toute configuration de site en `camoufox` est fail-closed sur l'image standard.
  **Retenue dans la premiere version de cet ADR, annulee par la revision operateur.**
- **B -- Binaire toujours present dans `autonomous`, actif d'office.** *Cout* :
  **+2,20 Go mesures en T2** (image `autonomous` a 4,62 Go contre 2,42 Go avant
  Camoufox, dont 1,29 Go pour la seule couche du binaire ; l'estimation initiale de
  +1,5 a 2,5 Go tombait juste) sur l'image par defaut, pour tous les deploiements
  `autonomous`, y compris ceux qui ne surveillent aucun site Akamai.
  *Risque* : la surface de securite de Firefox s'ajoute a celle de Chromium dans
  l'image par defaut, ce qui rend le durcissement de la Decision 8 obligatoire et non
  plus local a une variante. *Reversibilite* : bonne, la cible reste une cible du
  meme Dockerfile.
- **C -- Binaire present dans `autonomous`, active par une variable.** Cumule le cout
  disque de B et la complexite d'activation de A, sans le benefice de l'un ni de
  l'autre : le binaire est de toute facon telecharge et stocke. Rejetee.
- **D -- Tag d'image publie sur un registre.** Aucune chaine de publication d'image
  n'existe dans le depot aujourd'hui ; hors perimetre.

### Decision : **B**
Force decisive : la decision operateur de revision (« On bascule Camoufox en
obligatoire alors ; pas d'opt-in pour l'activer. Il est actif de base. »), motivee par
le fait que l'image `autonomous` n'a de raison d'etre que de franchir les protections.
Une image `autonomous` qui echoue sur le seul site Akamai du catalogue n'est pas
autonome.

- **Aucune nouvelle cible, aucun nouveau profil.** Le Dockerfile garde les stages
  `base`, `slim`, `autonomous` ; le compose garde ses deux profils exclusifs `slim` et
  `autonomous`. Le stage `autonomous` ajoute l'extra `camoufox`, les bibliotheques
  systeme de Firefox et le binaire epingle, a cote de `browser` et `uc`.
- **Commande documentee, inchangee** : `docker compose --profile autonomous up -d
  --build`.
- **`kerdoos:slim` reste la seule image sans navigateur.** C'est le seul deploiement
  ou le tier `camoufox` est indisponible, fail-closed selon le patron 3aeb8a19
  (Decision 1).
- **Aucune variable d'activation.** La disponibilite du tier est detectee
  (Decision 1), jamais declaree.

### Build deterministe (condition C4)
La commande `camoufox fetch` du paquet **n'est jamais utilisee**. Selon la revue
security-auditor (code `pkgman.py` de Camoufox), elle prend le premier asset compatible
via l'API GitHub et saute la verification quand le digest manque : c'est une
resolution dynamique, pas un epinglage.

- Le Dockerfile telecharge l'**URL d'asset exacte** du tag retenu. Son sha256 est un
  `ARG` du Dockerfile, verifie au build (echec du build sinon), et recoupe **au moment de
  la capture** avec le digest publie par GitHub pour cet asset.
- **Provenance** notee a cote de l'`ARG`, dans le Dockerfile : tag amont, URL d'asset
  exacte, digest publie par GitHub, version de Firefox de base. **Contexte de
  capture** (date, outil, qui a recoupe le digest) dans le **message du commit** qui
  introduit ou change le digest, jamais dans le code : la convention du depot refuse
  les dates dans les commentaires (garde de commentaires), et le pin `UC_DRIVER_SHA256`
  de l'ADR 0002 a deja tranche ainsi. La version precedente de cette exigence demandait
  la date de capture a cote de l'`ARG` ; elle ne pouvait etre satisfaite qu'en
  contournant le garde, ce qui en faisait une exigence mal ecrite. (Revise le
  2026-09-13.)
- Les addons embarques et les donnees `browserforge` sont epingles de la meme facon
  (URL exacte + sha256), jamais resolus au build.
- Si un `GITHUB_TOKEN` sert au build (limite de debit de l'API) : secret BuildKit
  uniquement, jamais en `ARG` ni en `ENV`, jamais present a l'execution.
- Taille de l'image **mesuree en T2** : 4,62 Go contre 2,42 Go avant Camoufox, soit
  +2,20 Go dont 1,29 Go pour la couche du binaire.

### Licence MPL-2.0 du binaire embarque

Camoufox est un fork de Firefox distribue sous MPL-2.0. Lecture d'ingenieur, pas un
avis juridique :

- **Copyleft par fichier**, pas par projet : l'obligation porte sur les fichiers de
  Camoufox, pas sur ceux de Kerdoos. La licence du depot n'est pas affectee, et le
  depot peut rester public sans contrainte supplementaire. **Kerdoos n'apporte aucune
  modification a Camoufox** ; s'il en apportait un jour, les fichiers modifies
  resteraient sous MPL-2.0, ce qui est un cout a payer au moment ou la modification
  serait decidee, pas maintenant.
- **Publier le depot ne redistribue pas Camoufox** : le depot contient un Dockerfile
  qui telecharge le binaire au build, pas le binaire. Aucune obligation
  supplementaire.
- **Publier une IMAGE construite le redistribue** : joindre alors le texte de la
  licence MPL-2.0 et les notices de copyright, et pointer les destinataires vers les
  sources amont **au tag epingle** (le meme que celui du sha256 verifie au build).
- **Etat de la trace** : la section du `README.md` qui porte cette lecture est
  **deja sur `main`** (commit 9607172). Il reste du en T2 un fichier `NOTICE`
  embarque dans l'image (texte de licence, copyright, URL des sources au tag
  epingle), pour que l'obligation soit tenue par l'artefact lui-meme et pas seulement
  par le depot.
- Aucune chaine de publication d'image n'existe aujourd'hui (Decision 2, option D) :
  l'obligation est donc dormante, et le `NOTICE` la rend tenue d'avance.

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
- Aucune variable d'activation : la disponibilite du tier est detectee (Decision 1).

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

- **Note pour l'operateur** (a porter dans `env.example`, a cote de
  `KERDOOS_BROWSER_MAX_CONCURRENT=1`) : sur l'image `autonomous`, une place peut
  desormais couter environ 1,3 Go (pic mesure 1220 a 1258 Mo pour Camoufox, contre
  642 a 652 Mo pour Chromium), en plus de la base de l'application ; le pic a retenir
  pour dimensionner est celui du navigateur le plus lourd, puisque la porte est
  commune. Choisir `KERDOOS_BROWSER_MAX_CONCURRENT` selon la RAM libre de la machine.
  Aucune valeur en dur au-dela du defaut de 1.
- Consequence de la livraison par defaut (Decision 2) : ce plafond de RAM par place
  concerne maintenant **tout** deploiement `autonomous`, plus seulement ceux qui
  auraient choisi une variante. C'est la contrepartie assumee de la revision
  operateur.
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

### C3 -- Structure du contexte et proxy inevitable (revise le 2026-09-13)

**Fait mesure qui motive la revision** (lentille securite, vrai Firefox dans un
conteneur, source `autolycos@3758a8b` montee en lecture seule, playwright 1.62.0 dans
l'image de spike contre 1.61.0 dans le lock) : `context.route("**/*")` n'invoque
**jamais** son handler avec le couple Camoufox/Playwright. Sur un fetch reel vers le
loopback, la liste des appels au predicat est vide ; sur les autres scenarios, le
predicat n'est appele que depuis le thread du proxy, jamais depuis celui du fetch, et
la premiere instruction du handler n'apparait dans aucun journal. `route_web_socket`
est presume inerte de la meme facon (non mesure separement). Le test unitaire de T1
tourne sur un faux Camoufox : il prouve que le code POSE la garde, pas qu'elle MORD.
Dans la meme campagne, garde de contexte RETIREE, dix-sept canaux declenches par la
page vers le loopback (img, preconnect, dns-prefetch, prefetch, preload, iframe, ping,
form, fetch, sendBeacon, WebSocket, EventSource, Worker, `window.open`, plus deux
hotes de rebinding) ont donne zero connexion hors proxy : le `PinningProxy` arrete
tout, et l'anti-rebinding est ferme deux fois (domaine avant resolution, `ip_is_safe`
apres). Exploitabilite mesuree : nulle.

**Ce que C3 exige desormais** (la version precedente comptait la garde de contexte
comme un second rempart ; elle ne l'est pas sur ce tier) :

- Validation de la cible (`validate_target`) **avant** tout lancement.
- Un **contexte par fetch** et une page par contexte ; contexte cree avec
  `service_workers="block"`. Cette structure est tenue par le code (un navigateur et un
  contexte par fetch, fermes en `finally`) ; l'effet de `service_workers="block"` sur
  ce couple est a **mesurer** en T4 (preuve T4-4), pas presume.
- **Le second rempart du tier est le proxy inevitable, pas la garde de contexte.** Il
  est constitue par les preferences imposees de C2 qui retirent a Firefox tout chemin
  direct (`network.proxy.allow_hijacking_localhost=true`,
  `network.proxy.no_proxies_on=""`, `network.proxy.failover_direct=false`,
  `network.trr.mode=5`, WebRTC et HTTP/3 coupes) et par le fait que le proxy est
  configure par le dictionnaire `proxy=` du lancement, jamais par un argument
  scrubbable. Deux couches independantes subsistent donc : (1) aucune sortie sans
  CONNECT (C2 + proxy inevitable, preuves T4-1, T4-2, T4-6 et T4-10) ; (2) chaque
  CONNECT est juge deux fois par le proxy, domaine avant resolution puis IP apres
  (C1, preuves "hote hors allowlist" et anti-rebinding). Ce sont ces deux couches que
  la tracabilite compte, et que T4 doit prouver separement.
- **La garde de contexte est RETIREE de l'adaptateur `camoufox`** (T4-11 executee le
  2026-09-13, resultat ci-dessous). La version precedente de ce point la conservait
  "au rang de meilleur effort, non comptee" en attendant la mesure ; la regle de
  decision qu'elle fixait (un handler jamais appele sur le thread du fetch = garde
  retiree) a fait son office. **Ne pas la reintroduire**, meme de bonne foi et meme
  sur une autre version du couple, sans une nouvelle preuve T4-11 positive : deux
  motifs de retrait, pas un.
  1. **Inerte** : sur l'image reelle avec le playwright du lock (1.61.0, et non le
     1.62.0 de l'image de spike du premier constat), le handler de `context.route` est
     invoque ZERO fois sur trois essais.
  2. **Nuisible la ou elle etait censee proteger** : en A/B a une seule variable,
     reproduit deux fois sur deux, AVEC la garde un fetch sur une page qui ouvre
     beaucoup de canaux part en timeout total de 90 s (duree du fetch mesuree en
     temps mural par la sonde, fetch plus une pause d'une seconde et le teardown :
     99,4 s puis 108,6 s ; que la porte soit tenue pendant l'essentiel de cet
     intervalle est DEDUIT du cycle de l'adaptateur, pas mesure) ; SANS elle, le
     meme fetch rend 200 en 16,2 s puis 19,0 s (meme temps mural). Un fetch
     normal rend un resultat en 7,5 s avec la garde : elle ne casse pas tous les
     fetches, elle degrade precisement les pages hostiles, celles qui multiplient les
     canaux. Une garde qui n'arrete rien ET qui transforme les pages qu'elle vise en
     timeouts de porte n'est pas neutre a conserver : c'est un cout de liveness paye
     sur la porte partagee (Decision 3) sans aucun benefice de securite. L'argument
     "elle ne coute rien" de la version precedente etait faux, et non anticipe.
  Le retrait couvre `context.route` et `route_web_socket` ; `service_workers="block"`
  reste (structure du contexte), son effet etant mesure par T4-4.
- **Voie ecartee pour l'instant** : un rempart intra-navigateur par WebExtension
  (`webRequest.onBeforeRequest` bloquant, allowlist par fetch, chargee par
  `addons=`). Il serait reel et independant de l'interception Playwright, mais il
  ajoute un artefact a epingler (C4), une surface de detection non mesuree (les
  interceptions de requetes sont un signal de detection connu du projet amont,
  issues daijro/camoufox #271 et #428, lues le 2026-09-13) et un cout de
  construction que rien ne justifie tant que la preuve T4-10 tient. A rouvrir
  seulement si T4-10 ou T4-2 revele une sortie hors proxy.
- **Le tier `browser` (patchright/Chromium) porte la meme construction** (`context.route`
  + `route_web_socket` + `service_workers="block"`), qualifiee depuis T3 de "meilleur
  effort, non comptee" dans sa docstring, jamais mesuree. La meme mesure lui est due,
  sous le nom **T4-11-browser**, avec la meme regle de decision ET le meme A/B de
  liveness (page multi-canaux avec et sans garde, duree du fetch et tenue de la
  porte) : le resultat Camoufox ne se transpose pas (autre navigateur, autre
  mecanisme d'interception), mais le risque qu'il a revele, une garde qui coute sur
  la porte partagee sans mordre, vaut pour tout rempart intra-navigateur. Tant que
  T4-11-browser n'est pas executee, la garde du tier `browser` reste non comptee et
  son cout de liveness est inconnu.

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
- **T4-10 (C3 revise) -- proxy suffisant, garde retiree** : avec la garde de contexte
  neutralisee (handler remplace par un no-op qui journalise), une page servie sur un
  hote allowliste declenche les dix-sept canaux de la campagne du 2026-09-13 vers le
  loopback, une IP privee, l'adresse metadata et deux hotes de rebinding ; attendu :
  zero connexion sur les ecouteurs de test, zero `connect`/`sendto`/`sendmsg` hors
  proxy dans `strace` (T4-2), et une ligne de refus du proxy par canal. C'est la preuve
  que la couche "aucune sortie sans CONNECT" tient seule.
- **T4-11 (C3 revise) -- la garde mord-elle ? EXECUTEE le 2026-09-13 en T2, par le
  release-engineer, sur l'image `autonomous` reelle avec le playwright du lock
  (1.61.0).** Methode : handler de `context.route` journalisant en premiere
  instruction le thread courant et l'URL, page multi-canaux servie sur un hote
  allowliste avec des sous-ressources hors allowlist ; puis A/B a une seule variable
  (garde posee / garde absente) sur la meme page, deux repetitions. Resultat :
  handler invoque **zero fois sur trois essais** ; avec la garde, le fetch multi-
  canaux atteint le timeout total de 90 s (duree du fetch en temps mural de la sonde,
  fetch plus une pause d'une seconde et teardown : 99,4 s puis 108,6 s ; la tenue de
  la porte sur l'essentiel de cet intervalle est deduite, non mesuree) ; sans la
  garde, 200 en 16,2 s puis 19,0 s (meme temps mural) ; un fetch normal rend en 7,5 s avec la
  garde. Verdict par la regle de decision : **garde retiree** de l'adaptateur
  `camoufox` (`context.route` et `route_web_socket`). La forme initiale de cette
  preuve (attendu pour re-promouvoir : au moins un appel sur le thread `camoufox-fetch`
  pour `bloque.example` sans CONNECT correspondant au proxy) reste la forme a
  rejouer si quelqu'un veut reintroduire une garde intra-navigateur sur ce tier.
- **T4-11-browser -- meme preuve sur le tier `browser` (patchright/Chromium), NON
  EXECUTEE.** Handler journalisant thread + URL, `<img src="https://bloque.example/
  x.png">` et un `WebSocket` hors allowlist, formes `context.route`, `page.route` et
  `route_web_socket`, PLUS l'A/B de liveness (page multi-canaux avec et sans garde,
  duree du fetch et tenue de la porte, deux repetitions). Regle de decision
  identique : jamais appele, ou appele mais degradant les fetches, = retrait ;
  appele sur le thread du fetch sans degradation = re-promotion au rang de rempart
  avec sa docstring. Due en T4.

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
- **Threads abandonnes comptes et plafonnes**, avec un plafond configurable sur le
  modele de `KERDOOS_BROWSER_MAX_ABANDONED_FETCHES` (tier `browser`), un log ERROR
  quand il est atteint, et une decrementation sur tous les chemins.
- **psutil declare dans l'extra du tier**, et son import protege.
- **Init en PID 1 dans l'image** (tini) : fait, herite du stage `base` par
  `autonomous` (carte d8b7b8fd, merge 761bf17). Sans init, 4 zombies par fetch
  Camoufox (mesure) ; la preuve en image reste due en T4.
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
    **Mesure en T2** : cette assertion a mordu des le premier build, parce que le
    fichier `version.json` que la readiness lit a cote du binaire **n'est pas dans
    l'archive amont** ; c'est la methode `set_version()` du module `pkgman` du
    paquet qui l'ecrit apres extraction, sur le chemin d'installation dont
    `camoufox fetch` (interdit par C4) n'est qu'un declencheur parmi d'autres. C'est
    pourquoi un telechargement deterministe qui remplace ce chemin doit produire le
    fichier lui-meme. Sans l'assertion, l'image aurait ete
    livree avec un tier qui se declare indisponible a chaque scrape (fail-closed
    silencieux, patron 3aeb8a19). Exigence explicite depuis : le Dockerfile ecrit
    lui-meme `version.json` (version et build du tag epingle) a cote du binaire,
    et l'assertion de readiness au build reste la preuve que l'image livre une
    installation que l'adaptateur accepte.
- **Bruit de journal, mesure en T1/T2** : chaque lancement emet un `LeakWarning`
  `proxy_without_geoip` que `i_know_what_im_doing=True` ne masque pas. Il est
  supprime par un filtre de warnings pose **une seule fois, au niveau du module**
  de l'adaptateur, jamais par lancement : les filtres de `warnings` sont globaux au
  process, et deux fetches concurrents qui poseraient et retireraient chacun le
  leur se marcheraient dessus.
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
| T0 | **FAIT.** Prerequis : d8b7b8fd (tini dans le Dockerfile, cycle de fetch borne avec C1 a C3 de son gate fermes), merge 761bf17 ; 6521bbce (ensemble fige, pas de `create_time`), merge 733715a | -- |
| T0.5 | **En cours** (carte 5806b7d7). Condition C1 : allowlist de domaines a l'autorite du CONNECT dans `egress_proxy.py`, appliquee au tier `browser` existant ; tests du proxy (hote hors allowlist refuse sans resolution, loopback) | T0 (levee : fait) |
| T1 | Adaptateur autolycos : extra, import paresseux, zero telechargement (C5 cote code), preferences imposees (C2), garde de contexte (C3), liveness de la Decision 5, registre du routeur, disponibilite paquet + binaire + version, tests unitaires avec un faux Camoufox ; mesure des durees de lancement et de navigation pour fixer les defauts | T0, T0.5 (API du proxy) |
| T2 | Dockerfile, **stage `autonomous` existant, aucune nouvelle cible** : bibliotheques systeme de Firefox, telechargement deterministe epingle (C4), assertion de version au build (C5), durcissement de la Decision 8 (non-root, `HOME` inscriptible, propriete de `/data`), `NOTICE` MPL-2.0 embarque ; compose : durcissement du service `kerdoos-autonomous` deja present, aucun nouveau profil ; `env.example` (variables du tier, note de RAM) ; taille d'image mesuree | T0, T1 (l'extra existe dans `uv.lock`) |
| T3 | Cablage kerdoos : variables dans `get_settings`, WARNING d'ordre, injection par la racine de composition (WebUI et CLI), tests de cablage par racine, indicateur WebUI (barreau `camoufox` dans `_TIER_LADDER`, nombre de pastilles de la macro `tier()`, tuple d'options du `select` d'ajout de site), catalogue Magalu et MercadoLivre -> `camoufox`, documentation d'exploitation (invariant 6 de `CLAUDE.md`, echelle du `README.md`, `AGENTS.md`) | T1 ; en parallele de T2 |
| T4 | Tests en image : preuves SSRF de la Decision 4 (dont T4-1 a T4-6, la preuve anti-rebinding comprise), zero telechargement T4-7, durcissement T4-8, reproductibilite T4-9, liveness de la Decision 5, RAM re-mesuree sur l'image reelle, `MagaluParser` sur une vraie page Camoufox (fixture Camoufox reelle, image T4), MercadoLivre confirme sur plusieurs echantillons avec son parser (sinon retour a `browser`) | T2, T3 |

Chaque tranche passe le gate a trois lentilles (architecte, reviewer, securite).

## Decision 8 -- Durcissement de l'image `autonomous` (condition C6)

La revision operateur deplace la portee de cette decision : elle visait une variante
d'image, elle vise desormais **l'image `autonomous` elle-meme**, qui s'execute en root
aujourd'hui (ADR 0002, Decision 5, section « Init en PID 1 »). C'est le changement au
rayon d'action le plus large de cet ADR : il touche aussi les tiers `browser` et `uc`
deja livres, et la propriete du volume `/data` ecrit par root. Il est indissociable de
la Decision 2 : embarquer Firefox dans l'image par defaut sans la durcir reviendrait a
elargir la surface de tous les deploiements.

- **Utilisateur non-root** dans la cible `autonomous`, avec un `HOME` inscriptible
  (profil Firefox, caches des navigateurs). La **propriete du volume `/data`** pour cet
  utilisateur est a traiter en T2 : le volume est aujourd'hui ecrit par root, et un
  deploiement existant porte des fichiers appartenant a root. Si le basculement ne peut
  pas etre rendu sur, T2 le remonte comme un point de decision plutot que de le forcer.
  Aucun utilisateur de Kerdoos n'existe (decision operateur), donc aucune procedure de
  reprise de volume n'a a etre documentee, mais le cas doit etre teste dans l'image.
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

## Decision 9 -- Tier `uc` : deprecie, conserve

Une fois Magalu declare en `camoufox`, plus aucun site du catalogue n'utilise `uc`, et
le tier est **mesure bloque par Akamai dans le conteneur Linux** (Contexte). La
question posee a l'operateur etait : le garder, le deprecier ou le retirer ?

### Options
- **A -- Retirer le tier** (adaptateur, extra, pre-fetch du chromedriver, entree de
  registre, barreau WebUI). *Gain* : une dependance et une surface de moins dans
  l'image. *Cout* : suppression d'un adaptateur fonctionnel et de ses tests, et perte
  de l'option si une version amont le rend a nouveau meilleur. *Reversibilite* :
  faible, il faudrait le reecrire.
- **B -- Le deprecier sans le retirer** : code, tests, extra et barreau conserves,
  aucun site du catalogue, aucune nouvelle fonctionnalite. *Cout* : une surface
  maintenue sans usage. *Reversibilite* : totale.
- **C -- Le maintenir a parite** avec les autres tiers (corrections, couverture,
  evolutions). Cout de maintenance sans benefice mesure aujourd'hui. Rejetee.

### Decision : **B**, par decision operateur
Citee telle quelle : « Deprecie uc ; on ne sait jamais "demain", il se pourrait qu'une
mise a jour le rende "meilleure" que Camoufox. »

- **Conserve** : l'adaptateur, ses tests, son extra, son pre-fetch de chromedriver au
  build (ADR 0002, correction Q-e), sa place de quatrieme barreau de l'echelle, son
  option dans le `select` d'ajout de site. Retirer l'option du `select` couterait la
  reversibilite que la depreciation cherche justement a garder.
- **Deprecie** : aucun site du catalogue livre ne declare `uc` ; aucune nouvelle
  fonctionnalite, aucune extension de couverture ni de preuve en image ne lui est due
  par cet ADR. Les corrections de securite ou de liveness qui portent sur la porte
  commune ou le proxy continuent de s'y appliquer, puisqu'elles ne lui sont pas
  propres.
- **Condition de reevaluation** : une version amont de SeleniumBase UC ou de Chromium
  qui franchit Akamai en conteneur, mesuree comme Camoufox l'a ete. La reevaluation se
  fait alors sur mesure, pas sur annonce.
- **Etat de securite (condition C7)** : le pin SSRF du tier `uc` **tient**. Le constat
  inverse de la premiere revue etait un faux positif, et le defaut reel de troncature
  des arguments est corrige (carte dde2d243). Restent non testes les IP litterales et
  les redirections 30x : la depreciation les laisse non testes, ce qui est acceptable
  tant qu'aucun site ne declare ce tier, et redevient du le jour ou un site le
  declare.

---

## Tracabilite des conditions de securite

| Condition | Objet | Ou dans cet ADR |
|---|---|---|
| C1 | Allowlist de domaines dans le proxy, point de controle suffisant | Decision 4 (C1), tranche T0.5 |
| C2 | Preferences Firefox imposees, OCSP tranche | Decision 4 (C2) |
| C3 | Structure du contexte + proxy inevitable comme second rempart ; garde de contexte RETIREE du tier `camoufox` (T4-11 executee : inerte et degradant les pages hostiles) ; T4-11-browser due | Decision 4 (C3 referme), preuves T4-10, T4-11, T4-11-browser |
| C4 | Build deterministe, provenance, secrets de build | Decision 2 (build deterministe) |
| C5 | Zero telechargement a l'execution, par construction | Decision 1 (disponibilite), Decision 6 |
| C6 | Durcissement de l'image | Decision 8 |
| C7 | Correction factuelle sur le pin du tier `uc` | Decision 9 (etat de securite) |

## Consequences

- **Positives** : Magalu redevient accessible sur l'image `autonomous` standard, sans
  qu'aucun operateur n'ait a choisir une variante ni a connaitre l'existence du tier ;
  le nouveau tier
  herite des protections deja mesurees (porte unique, liveness) ; l'allowlist de
  domaines dans le proxy ferme un trou preexistant du tier `browser` ; l'image
  `autonomous` passe non-root, ce qu'elle aurait du etre de toute facon.
- **Negatives / dettes** : +2,20 Go mesures (4,62 Go contre 2,42 Go) sur l'image par
  defaut, pour tous les deploiements `autonomous`, y compris ceux qui ne surveillent
  aucun site protege ; un pic memoire par place qui passe d'environ 0,65 a environ 1,26 Go ;
  un binaire de plus a re-epingler a chaque release de securite amont de Firefox ; une
  dependance tierce MPL-2.0 dans l'image (obligation dormante tant qu'aucune image
  n'est publiee) ; OCSP desactive sur ce tier ; un tier `uc` conserve sans usage
  (Decision 9).
- **Ce qui ne change pas** : le nombre de cibles d'image et de profils compose (deux et
  deux) ; la commande de demarrage ; l'image `kerdoos:slim` ; la semantique de
  `KERDOOS_BROWSER_MAX_CONCURRENT` ; l'etat a trois valeurs (un echec Camoufox donne
  INDETERMINATE, un tier absent ignore la source sans ScrapeRecord) ; l'absence
  d'escalade automatique entre tiers ; le tier de MercadoLivre, candidat non confirme
  en T4, qui reste `browser`.
- **Ce qui n'est pas fait et ne le sera pas** : aucune migration ni bascule d'un
  `config.db` existant. Il n'y a aucun utilisateur de Kerdoos (decision operateur) : le
  catalogue livre suffit, et ecrire un plan de migration pour une base qui n'existe
  pas serait du code mort.

## Questions ouvertes

Les trois questions posees a l'operateur dans la version precedente sont **tranchees**
(Decision 9 pour `uc`, Decision 2 pour la licence, Decisions 1 et 8 pour l'absence de
migration). Restent des inconnues techniques, toutes bornees a une tranche et sans
decision operateur requise :

1. **Basculement de `autonomous` en non-root avec le volume `/data`** (T2) : si le
   durcissement ne peut pas etre rendu sur sans casser l'ecriture du volume, T2 le
   remonte comme point de decision au lieu de le forcer.
2. **Cohabitation de Playwright (dependance de Camoufox) et de patchright** dans la
   meme image : presumee sans conflit (noms de module distincts), a verifier par la
   resolution de `uv.lock` en T1 et par les tests en image en T4.
3. **Routage de MercadoLivre** : **fermee le 2026-09-14**, T4 n'a pas confirme
   Camoufox, MercadoLivre revient a `browser` (amendement sous la Decision 1).
4. **Taille reelle de l'image** : **fermee en T2**, mesuree a 4,62 Go contre 2,42 Go
   (+2,20 Go, dont 1,29 Go pour la couche du binaire).
5. **T4-11-browser** : la garde de contexte du tier `browser` n'a jamais ete mesuree ;
   sa preuve (Decision 4, C3) est due en T4, avec l'A/B de liveness.

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
- **2026-09-11 -- T0 fait**. Cartes d8b7b8fd (merge 761bf17) et 6521bbce (merge
  733715a) mergees : tini en PID 1 dans l'image, cycle de fetch `browser` borne. La
  dependance de T0.5 est levee ; T0.5 est en cours (carte 5806b7d7).
- **2026-09-12 -- REVISION operateur : camoufox par defaut**. Le fichier est renomme
  `0004-tier-camoufox-par-defaut.md`. Camoufox est livre et actif d'office dans
  `kerdoos:autonomous` : plus de cible `autonomous-camoufox`, plus de profil compose
  `camoufox`, plus de commande d'activation (Decision 2, option B). La licence
  MPL-2.0 est traitee dans la Decision 2 (obligation dormante, `NOTICE` du en T2 ; la
  section du `README.md` est deja sur `main`, commit 9607172). Le tier `uc` est
  deprecie et conserve (**Decision 9**, nouvelle), ce qui ferme la condition C7. Le
  durcissement de la Decision 8 porte desormais sur l'image `autonomous` elle-meme,
  qui tourne en root. Aucune migration de `config.db` : il n'existe aucun
  utilisateur. Les trois questions operateur sont fermees ; les questions ouvertes
  restantes sont des inconnues techniques bornees aux tranches. L'echelle
  d'escalade de l'invariant 6 est enoncee explicitement sous la Decision 1
  (`http` < `tls` < `browser` < `uc` deprecie < `camoufox`), et sa reprise dans
  `CLAUDE.md` et `README.md` est portee par la tranche T3. La correction de la cle
  `uc` de l'indicateur WebUI, encore due dans la version precedente, est faite sur
  `main` (commit ffc2fb8).
- **2026-09-13 -- C3 revise (garde de contexte inerte sur Camoufox)**. La lentille
  securite a mesure, sur le vrai Firefox en conteneur (`autolycos@3758a8b`), que
  `context.route` n'invoque jamais son handler avec ce couple, et que le proxy seul
  arrete les dix-sept canaux testes. C3 ne compte plus la garde de contexte comme
  rempart : le second rempart du tier est le proxy inevitable (preferences C2 +
  `proxy=` de lancement), prouve par T4-10 ; la garde reste dans le code au rang de
  "meilleur effort, non comptee", et T4-11 decide de sa re-promotion ou de son
  retrait sur mesure. La voie WebExtension est ecartee tant que T4-10 tient. Le
  tier `browser` passe par la meme mesure. Arbitrage architecte a la demande du
  team-lead ; ratification au titre du mandat d'autonomie.
- **2026-09-13 -- T4-11 executee, C3 referme, mesures de T2 versees**. T4-11 (image
  reelle, playwright du lock 1.61.0) : handler de `context.route` invoque zero fois
  sur trois essais, et A/B reproduit deux fois : avec la garde un fetch multi-canaux
  atteint le timeout de 90 s (temps mural de la sonde 99,4 s puis 108,6 s, tenue de
  la porte deduite), sans elle 200 en 16,2 s puis 19,0 s ; un fetch normal rend en
  7,5 s avec la garde. La garde est RETIREE du tier
  `camoufox` pour deux motifs, inerte et degradant precisement les pages hostiles ;
  le tier `browser` recoit la preuve T4-11-browser (non executee). L'exigence de
  provenance de C4 est reecrite : provenance dans l'`ARG`, contexte de capture dans
  le message de commit, jamais de date dans le code (convention du depot, precedent
  `UC_DRIVER_SHA256`). Mesures de T2 versees : image `autonomous` a 4,62 Go contre
  2,42 Go (+2,20 Go, 1,29 Go de couche binaire) ; l'assertion de readiness au build a
  mordu au premier build parce que `version.json` n'est pas dans l'archive amont
  (ecrit par `pkgman.set_version()` sur le chemin d'installation du paquet), le
  Dockerfile l'ecrit desormais ; le
  `LeakWarning proxy_without_geoip` est filtre une fois au niveau module (filtres
  globaux au process). Question ouverte 4 fermee, question 5 (T4-11-browser)
  ouverte.
- **2026-09-14 -- T4 MercadoLivre non confirme, retour a `browser`**. Camoufox 0 fiche
  sur 7 essais, `browser` 6 sur 6 en 403 signale ; decision du team-lead en application
  de la clause de la Decision 1. Catalogue livre et test de cablage alignes, question
  ouverte 3 fermee. Detail et reserve sur l'IP de sortie : amendement sous la Decision 1.
- **2026-09-14 -- T4-D : contrat de lecture du document et controle du document
  final**. Deux defauts confirmes par les preuves en image de T4-B (vrai Firefox,
  image `kerdoos-t4:6835df6`) sont corriges dans l'adaptateur. (1) La lecture du
  DOM passait par `page.evaluate`, qui n'a pas de timeout et attend le thread
  principal de la page : une page occupee tenait la lecture au-dela du budget de
  navigation (6,0 s mesures pour 5 s). La lecture passe par `page.wait_for_function`
  avec un timeout egal au budget de navigation restant (1 ms au minimum, 0 valant
  "illimite" pour Playwright), sur une expression qui mesure toujours le plafond
  dans la page et rend `documentURI` et DOM en une seule primitive. Contrat : une
  premiere lecture hors budget rend `FetchError` (retry du coeur, invariant 5) ; une
  lecture de sondage d'interstitiel hors budget rend l'interstitiel deja lu,
  `challenged=True` (indetermine, invariant 3). La lecture partage le budget de
  navigation, elle n'en recoit pas un propre. (2) Apres une navigation JS post-load
  vers une adresse refusee, Firefox garde `page.url` sur l'URL tentee alors que
  `document.documentURI` vaut `about:neterror`, sans evenement `response` ni
  `requestfailed` (mesure) : la page d'erreur sortait en 200. Le controle du document
  final porte desormais sur `page.url` ET sur le `documentURI` lu avec le DOM : schema
  `http(s)`, egalite d'hote (condition du gate securite T1, sans elargissement a la
  politique de domaine), port final egal au port demande ou au port par defaut du
  schema final (`http` peut monter vers `https`), et refus du retour de `https` vers
  `http` (le proxy n'ouvre que 80 et 443, le refus protege le contenu, pas l'egress).
  Le status rendu est celui de la derniere reponse de navigation du cadre principal,
  associee au document par son URL et non par l'ordre d'arrivee, le status du `goto`
  ne decrivant que le premier document. `page.on("response")` est une observation
  au service du status, jamais un rempart au sens de C3. Le budget total reste tenu :
  lancement 20 s + navigation et lectures 45 s + fermeture, sous les 90 s de la
  Decision 5. Divergence constatee : le tier `browser` lit encore `page.content()`
  sans timeout, ne controle pas le document final et garde le status du `goto` ; la
  parite est portee par la carte 30333254, a coupler avec T4-11-browser.
