# ADR 0002 -- Productionisation : digest per-owner, ordonnancement, packaging Docker

- **Statut** : ACCEPTED (2026-07-10) -- questions Q-a a Q-e tranchees par l'operateur
  apres discussion du cadrage design (architect). Prochaine etape : implementation
  Phase 6 (digest + scheduler), puis Phase 7 (packaging Docker), puis Phase 5 (MCP).
- **Date** : 2026-07-10
- **Portee** : mise en production de Kerdoos. Couvre la Phase 6 (digest agrege
  par owner + ordonnancement) et la Phase 7 (packaging / deploiement Docker). Ne
  casse aucun invariant ni aucune decision de [ADR 0001](./0001-plateforme-post-mvp-webui-mcp-multitenant.md).
- **Sources de verite** : `CLAUDE.md`, `DESIGN.md`, [ADR 0001](./0001-plateforme-post-mvp-webui-mcp-multitenant.md)
  (S5.1 discipline SQLite/FD3, S8 topologie Docker, S9 browser/egress), `task_plan.md`
  (Phases 6/7), Dockerfile + docker-compose.yml reels, memoires Kleos #11254/#11255/#11257.

## Contexte

Kerdoos a atteint la fin de la Phase 4 (WebUI complete et durcie, `main` @ a6fd60f,
320 tests). Le coeur produit -- le **digest quotidien agrege par mail** -- n'est
pas encore implemente ; sans lui, packager livrerait une WebUI qui ne fait pas son
travail. L'operateur a donc **reordonne** le plan :

> **Phase 6** (digest per-owner + scheduler) -> **Phase 7** (packaging Docker) ->
> **Phase 5** (serveur MCP, en dernier).

Justification de l'ordre : MCP est monte *same-app ASGI* (ADR 0001 Q2) ; l'ajouter
apres coup = des routes en plus sur le meme process uvicorn, **zero changement de
topologie**. Le scheduler, lui, est a cheval entre une feature (Phase 6) et un
detail de deploiement (Phase 7) : les deux sont traitees ensemble ici.

ADR 0001 avait deja verrouille l'ossature : digest par owner en SQL, cron daily +
file intra-process pour `run_now`, deux tags d'image `slim`/`autonomous`,
egress-proxy CONNECT loopback, `9222` jamais mappe, `max_concurrent=1`, SMTP depuis
la config. Le present ADR **tranche les seams laisses flous** par ADR 0001 et
**formalise l'outillage** (dont la decision etait reportee post-spike dans
`CLAUDE.md`).

### Principe directeur -- altitude de la decision

Kerdoos est un logiciel autonome ; sa cible de deploiement est une *consequence*,
pas une contrainte de conception (`CLAUDE.md`, hors-scope infra de l'operateur).
On garde donc les decisions a la bonne altitude : Kerdoos expose des **contrats**
(`kerdoos digest` idempotent, app auto-schedulable, WAL per-op) ; le **comment** du
declenchement et de l'hebergement reste un detail de deploiement.

## Forces en presence

- **OOM** : le mini-PC / LXC cible a un historique OOM. Chromium (tier browser /
  uc) est le principal consommateur RAM. `browser.max_concurrent=1` borne la
  concurrence *intra-process*, mais **pas** l'inter-process.
- **SQLite** : deux fichiers (`config.db`, `state.db`) derriere WAL + connexion
  per-op (FD3, ADR 0001 S5.1). SQLite ne gagne rien en debit d'ecriture avec
  plusieurs process writers.
- **Fetchers sync-bloquants** : `patchright.sync_api`, `curl_cffi`, `requests` sont
  des API **bloquantes** ; executees telles quelles dans un handler ASGI elles
  gelent l'event loop.
- **Echelle** : une poignee d'owners sur un LAN, un seul petit LXC. Pas de besoin
  d'echelle horizontale day one (le seam futur = migration Postgres, deja anticipe
  `DESIGN.md`).
- **Multi-tenant** : owner_id filtre en SQL (dernier rempart), jamais serialise.
  Le digest ne doit jamais melanger deux owners.

---

## Decision 1 (Q-a) -- Topologie du scheduler : timer intra-process (S-B)

### Probleme
ADR 0001 Q6 a verrouille le *modele* (cron daily + file intra-process pour
`run_now`) mais pas *ou* vit l'ordonnanceur. Un cron **externe** lancant un
`kerdoos digest` **separe** pendant qu'un `run_now` scrape dans le process web
produit **deux Chromium concurrents** (le cron et le web ignorent chacun le
`max_concurrent` de l'autre) -> risque OOM. C'est la force decisive.

### Options considerees
- **S-A -- cron externe -> `kerdoos digest` court-lived** (saveur ADR 0001 S8).
  *Benefice* : robuste, survit au restart du web, process qui exit (ne tient pas
  l'event loop). *Cout* : deux ordonnanceurs de nature differente ; contention
  Chromium inter-process a l'heure du digest ; le schedule vit hors artefact
  (crontab du LXC = infra).
- **S-B -- timer asyncio intra-process** qui, une fois par jour a l'heure
  configuree, **enfile le digest dans la MEME file que `run_now`**. *Benefice* : un
  seul process, une seule file, **une seule porte browser** (inter + intra process),
  aucun cron/infra externe (app auto-schedulable = self-contained). Elimine le seam
  "deux ordonnanceurs". *Cout* : couple le digest a l'uptime du container ; exige
  `workers=1`. *Realisation* : pas de file commune au digest et a `run_now` ; la
  "porte browser unique" est une porte Chromium partagee (Decisions 1 et 2).
- **S-C -- APScheduler in-process**. Plus lourd, meme couplage, aucun benefice sur
  S-B pour un unique job quotidien. **Rejetee.**

### Decision : **S-B**, avec garde-fou `workers>1`
Force decisive : la **coherence OOM** -- une seule porte browser inter et intra
process. L'operateur a ratifie la deviation vis a vis d'ADR 0001 Q6 : le
self-contained prime pour l'ergonomie de deploiement. La realisation a finalement
ajoute une borne inter-process par verrous fichier (Decision 2) : elle couvre aussi
un `kerdoos digest` lance par cron a cote de la WebUI.

- Le timer intra-process est le **defaut a `workers=1`**.
- **Garde-fou** : si `workers>1` (override env), l'app **NE demarre PAS** le
  scheduler intra-process et **LOGGUE un avertissement** invitant a declencher le
  digest par un **cron externe appelant `kerdoos digest`**. (Rendre `workers>1`
  "propre" dans l'app -- election de leader, file DB-backed partagee -- est un lot
  de dev futur, hors-scope ici.)
- **Deux points d'entree distincts** (nommage acte par l'operateur 2026-07-10) :
  - **`kerdoos digest`** -- **batch quotidien** : scrape-all + agregation + envoi
    du digest par owner. C'est le point d'entree du timer S-B (et de tout cron
    externe en mode `workers>1`).
  - **`run_now`** -- action **per-owner a la demande** (bouton WebUI "verifier
    maintenant" / MCP), qui passe par sa propre file (voir ci-dessous). Distincte
    du batch quotidien.
- Le couplage a l'uptime est mitige par `restart: unless-stopped`, **sans
  rattrapage au redemarrage** : l'evaluateur reprend a la fenetre courante de
  chaque job (modele par job, ADR 0003). La fenetre en cours au redemarrage est
  emise au premier tick si elle ne l'a pas deja ete ; les fenetres anterieures,
  manquees pendant l'arret, ne sont jamais emises. Raison produit : un digest de
  prix vieux de plusieurs jours n'a pas de valeur pour le destinataire.
  L'exactly-once reste garanti par la cle primaire `(job_id, window_start)`.
- **Deux files distinctes, une seule porte Chromium** (realisation, carte ca30b736) :
  - `run_now` passe par une `RunQueue` **intra-process** (aligne ADR 0001 Q6) :
    une `asyncio.Queue` et un **consumer unique** lance dans le lifespan de la
    WebUI. Le bouton "verifier maintenant" enfile l'owner et rend la main
    immediatement ; une demande pour un owner deja en file ou en cours est
    fusionnee avec la precedente. Le statut (en file, en cours, termine, erreur) est
    garde en memoire, affiche sur le tableau de bord, et perdu au redemarrage (les
    releves deja ecrits restent dans `state.db`).
  - **Cooldown par owner** : apres un run termine, une nouvelle demande du meme
    owner est refusee pendant `KERDOOS_RUN_NOW_COOLDOWN_SECONDS` (defaut 300 ; 0
    le desactive). Le temps restant est affiche sur le tableau de bord.
  - **Relance supervisee du consumer** : un crash du consumer lui-meme (et non
    l'echec d'un owner, deja isole) le relance, apres une pause fixe de 0,5 s,
    jusqu'a `KERDOOS_RUN_QUEUE_MAX_RESTARTS` fois (defaut 5 ; 0 = aucune relance).
    Le compteur revient a zero a chaque run termine. Au-dela, la file est declaree
    morte : les nouvelles demandes sont refusees (statut erreur) jusqu'au
    redemarrage du process.
  - Le digest ne passe **pas** par cette file : il est porte par la boucle de
    l'evaluateur (ADR 0003 Decision 4).
  - La garantie memoire n'est donc **pas** portee par une file commune, mais par
    **une porte Chromium unique**, `autolycos.browser_gate.BrowserGate`, que les
    tiers `browser` et `uc` prennent autour de chaque cycle lancement-fermeture de
    Chromium, quel que soit l'appelant (consumer `run_now`, Plan A de
    l'evaluateur, CLI). Bornes et portee : Decision 2.

### Consequence transverse -- offload hors de l'event loop
Les fetchers etant sync-bloquants, le consumer `run_now` et le Plan A de
l'evaluateur executent le scrape via `asyncio.to_thread` pour ne pas bloquer
l'event loop ASGI. Ce n'est **pas** un threadpool a un slot : la borne sur les
Chromium vivants est portee par la porte (Decision 2), pas par le pool de threads.

---

## Decision 2 (Q-c) -- Concurrence : `workers=1` et `max_concurrent=1` par defaut

### Decision
`workers=1` (uvicorn, `KERDOOS_WORKERS`) et une seule instance Chromium vivante
(`KERDOOS_BROWSER_MAX_CONCURRENT=1`) sont des **defauts surchargeables par variable
d'environnement** (l'enveloppe OOM depend de la machine cible). `workers=1` est la
**topologie par defaut documentee**.

### Porte Chromium : variables et portee (realisation, carte ca30b736)
- `KERDOOS_BROWSER_MAX_CONCURRENT` (defaut 1) : nombre maximal de Chromium vivants.
  **Une seule borne pour les tiers `browser` (patchright) et `uc` (seleniumbase)**,
  qui consomment la meme memoire. Une valeur invalide ou <= 0 retombe sur le
  defaut, avec un warning.
- `KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS` (defaut 120) : attente maximale d'une
  place. A l'echeance, le fetch leve une `FetchError`, qui n'est pas reessayee et
  donne un releve `INDETERMINATE` (blocage transitoire, invariant 3), jamais une
  rupture de stock.
- Les deux valeurs sont lues par la racine de composition (WebUI, CLI) et injectees
  dans `BrowserGate` : autolycos ne lit jamais l'environnement (invariant 2).
- **Portee** :
  - sous Linux (image Docker), la borne est **inter-process** : N fichiers
    `browser-slot-<i>.lock`, verrouilles par `fcntl.flock`, dans le repertoire de
    la base d'etat (`/data` dans l'image), partages par tous les process qui
    utilisent cette base. Le noyau libere un verrou a la mort de son process : pas
    de verrou orphelin a nettoyer ;
  - sous Windows (developpement), `fcntl` n'existe pas : la borne est **par process
    seulement**, et un warning le signale a la construction de la porte ;
  - la CLI (`kerdoos digest`, `kerdoos run`) place ses verrous a cote de la base
    passee en `--db`, dont le defaut est `KERDOOS_STATE_DB` (`kerdoos.db` si la
    variable est absente) : dans l'image, elle partage donc les slots de la WebUI
    sans option supplementaire. Un `--db` explicite hors de `/data` la fait sortir
    de la borne commune.
- **Timeouts de lancement** : chaque tier borne son propre lancement de Chromium, en
  plus de l'attente de la porte.
  - `KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS` (defaut 30) pour le tier `uc` ;
  - `KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS` (defaut 20) pour le tier `browser`.
    Sans lui, patchright borne le lancement a 180 s, au-dela de l'attente de la
    porte ;
  - a l'echeance : `FetchError`, puis releve `INDETERMINATE`, et la porte est
    liberee. Une valeur invalide ou <= 0 retombe sur le defaut, avec un warning ;
  - aucune validation croisee : l'ordre attendu (lancement < navigation, 30 s
    codees en dur pour le tier `browser`, < attente de la porte) n'est pas verifie.
- **Limite connue** (carte d8b7b8fd) : apres le lancement, les etapes du tier
  `browser` hors navigation (`new_page`, stealth, `page.content()`,
  `browser.close()`) n'ont pas de timeout explicite. Un Chromium fige a ce moment
  garde la porte.

### Justification
1. SQLite ne gagne rien en debit d'ecriture avec N process writers.
2. La file `run_now` est **per-process** (asyncio) : avec N workers, un job enfile
   dans le worker A est invisible du worker B -> `workers=1` est un **prerequis** de
   la topologie S-B.
3. La porte Chromium (`KERDOOS_BROWSER_MAX_CONCURRENT=1`) serialise deja le chemin
   browser lourd.
4. LXC petit + OOM : N workers lancant chacun un Chromium = risque RAM.

Un seul worker uvicorn (concurrence async + offload threadpool) tient la charge LAN
(poignee d'owners). L'echelle horizontale reelle = le seam **migration Postgres**
(deja anticipe `DESIGN.md`), co-datee avec une file de jobs DB-backed si elle
devient necessaire.

---

## Decision 3 (Q-d) -- Outillage fige : uv + hatchling + uvicorn + ruff

### Decision
L'outillage Python est **acte** (cela clot la mention "outillage reporte
post-spike" de `CLAUDE.md`) :

| Role | Outil | Etat |
|---|---|---|
| Gestion des deps / lockfile | **uv** (`uv.lock` frozen) | de facto en place, formalise |
| Build backend | **hatchling** (`packages = ["src/kerdoos"]`) | en place ; wheel embarque `templates/` + `static/` (valide empiriquement par reviewer) |
| Serveur ASGI | **uvicorn** (`[standard]`, extra `web`) | en place |
| Lint + format | **ruff** (outil unique) | **nouveau -- acte ici** |
| Tests | pytest + httpx (`[dependency-groups] dev`) | en place |

### Consequence
Introduire la config ruff (`[tool.ruff]`) et l'integrer au gate per-commit
(implementation Phase 6/7). Aucun autre outil de lint/format (pas de black/isort/
flake8 separes -- ruff couvre les trois).

---

## Decision 4 (Q-b) -- Exposition reseau : LAN-only day one, rate-limit differe

### Decision
Le deploiement cible est **LAN-only day one** (firewall du reseau local + auth interne).
Consequences :

- **Rate-limit `/login` : DIFFERE.** L'auth interne (sessions Phase 3/4, anti-enum,
  cookie HMAC) reste **primaire**. En LAN-only, le rate-limit est une defense en
  profondeur non prioritaire.
- Une **auth externe** (Authelia / forward-auth) est un seam **optionnel et leger**,
  a n'ajouter que si peu couteux ; elle ne remplace pas l'auth interne.
- **WAN** (Tailscale / Wireguard) = **hors-scope** pour l'instant.

### Declencheur de re-evaluation
Si le reverse-proxy expose un jour `/login` **au-dela du LAN** (route publique),
le rate-limit (ou un front Authelia sur `/login`) devient un **prerequis
pre-deploiement**. A trancher a ce moment-la, pas maintenant.

---

## Decision 5 -- Strategie d'image Docker (Option A) + pre-fetch chromedriver (Q-e)

### Decision : Option A (un Dockerfile multi-stage, deux targets)
On garde la structure reelle actuelle : **un** Dockerfile multi-stage, stage `base`
partage (deps), deux targets finaux -> deux tags :

- **`kerdoos:slim`** : tiers `http` + `tls` + extra `web` (uvicorn). Image legere,
  cold start rapide. Un site configure avec `fetcher: browser` ou `fetcher: uc`
  sur cette image est fail-closed PAR SOURCE : signale une fois au demarrage
  (log), refuse tout ajout d'une nouvelle source vers ce site, et chaque source
  deja configuree est ignoree au scrape (aucun ScrapeRecord ecrit) au lieu
  d'etre rejouee indefiniment en INDETERMINATE (card 3aeb8a19). La detection
  ne verifie que la PRESENCE du paquet Python (`importlib.util.find_spec`) :
  un `seleniumbase` installe sans navigateur Chrome disponible est quand
  meme compte comme "disponible" -- perimetre assume, pas couvert ici. Un
  nom de tier INCONNU (faute de frappe, ou une ligne arrivee dans config.db
  par une porte sans validation propre comme `kerdoos config import`) est
  traite comme indisponible, meme regle fail-closed qu'un tier absent.
- **`kerdoos:autonomous`** : + tiers `browser` (patchright) + `uc` (seleniumbase).
  Embarque le Chromium **de patchright** (pas celui de playwright vanilla).

Pas de sur-decoupage (pas de 3e tier base->slim->autonomous) : le plus petit
changement, deja valide au gate Phase 0, conforme ADR 0001 S8. **Amende par
[ADR 0004](./0004-tier-camoufox-image-opt-in.md)** : une troisieme cible opt-in,
`autonomous-camoufox`, construite a partir de `autonomous` ; l'image
`autonomous` par defaut reste inchangee.

### Correction Q-e -- pre-fetch de l'undetected-chromedriver au build
Le tier `uc` (seleniumbase) telecharge son `undetected-chromedriver` **au runtime**
par defaut. Derriere l'egress-proxy CONNECT (loopback, allowlist stricte), ce
telechargement au premier run **echoue**. **Decision : pre-fetch le
chromedriver AU BUILD** de l'image, dans le stage `autonomous` (a cote de
`patchright install --with-deps chromium`). Aucun telechargement reseau au premier
run `uc`.

### Correction Q-f -- navigateur du tier uc : reutilisation du Chromium patchright
Seleniumbase ne trouve jamais le Chromium prive installe par patchright
(cache prive `~/.cache/ms-playwright`, invisible pour la detection de
navigateur de seleniumbase). Pas de second navigateur installe : le tier `uc`
**reutilise le Chromium de patchright**, dont l'adaptateur (`UcFetcher`) passe
le chemin explicitement a `seleniumbase.Driver(binary_location=...)`. Cette
majeure de version doit rester alignee avec celle de `UC_DRIVER_VERSION`
(le chromedriver pre-fetch ci-dessus) -- une derive silencieuse rouvrirait
exactement le telechargement runtime non pin/non verifie que Q-e a ferme. Le
build echoue si les deux majeures divergent, en comparant leurs versions
via le meme chemin de resolution que celui utilise a l'execution.

### Correction Q-g -- le tier uc embarque DEUX drivers, aucun telechargement runtime tolere
Seleniumbase a son propre mecanisme de contournement du signal `HeadlessChrome`
dans `navigator.userAgent` (`uc_agent_cache`, actif des que `headless=True` et
Chromium >= 117) : il lance une session jetable via un `chromedriver` **PLAIN**,
distinct du `uc_driver` patche ci-dessus, pour capturer un User-Agent Chrome
authentique avant de l'injecter dans la session undetected. Sans ce fichier
present, ce mecanisme retelecharge silencieusement (verifie par execution,
`with suppress(Exception)` cote seleniumbase) -- meme classe CWE-494 que Q-e,
sur un fichier different. **Decision : aucune deuxieme requete reseau ni
deuxieme pin.** Le `chromedriver` plain est une COPIE du `uc_driver` deja
telecharge et verifie par sha256 (meme artefact, deux noms de fichier) --
un seul hash a maintenir, aucun risque de derive entre les deux. L'assertion
de fin de stage (Q-f) verifie aussi la majeure de ce `chromedriver` copie.

---

## Decision 6 -- Persistance SQLite et secrets (confirmations ADR 0001)

### Volumes
- `config.db` + `state.db` sur un **volume nomme `/data`** (deux fichiers = separation
  **logique**, invariant #7 ; pas besoin de deux devices physiques).
- Paths lus depuis `KERDOOS_CONFIG_DB` / `KERDOOS_STATE_DB`.
- WAL + connexion per-op (FD3) deja en place -> cohabitation sure entre le process
  web et une eventuelle invocation `kerdoos digest` sur le meme volume.

### Secrets (jamais dans l'image)
- `KERDOOS_SESSION_SECRET` : requis, **>=32 caracteres, fail-fast** (deja implemente,
  Phase 4a). Sert aussi de cle CSRF (domain-separee par prefixe `csrf:`).
- `KERDOOS_CONFIG_DB` / `KERDOOS_STATE_DB` : paths de deploiement.
- **Creds SMTP** (host/port/from/auth) : depuis la config, **jamais codes en dur**
  (`CLAUDE.md`). Injectes via `env_file` (`.env` gitignore) ou docker secrets.
- **Politique reseau du relais SMTP** (roadmap 4a8afdf2) : le relais configure
  ne doit PAS pouvoir livrer vers les plages privees/reservees (RFC 1918,
  `127/8`, `169.254/16`, et les equivalents IPv6 `fc00::/7`/`::1`/`fe80::/10`).
  La validation d'adresse email (`_EMAIL_RE`, `_VALID_DOMAIN_RE`) rejette un
  litteral IP mais ne peut pas detecter un domaine public qui RESOUT vers une
  IP interne (ex. `10.0.0.1.nip.io`) -- c'est une politique reseau du relais
  lui-meme, hors du perimetre applicatif de Kerdoos.
- `KERDOOS_COOKIE_SECURE` : `true` par defaut ; `false` uniquement pour un
  deploiement plain-http LAN.

### Reseau (confirme ADR 0001 S8/S9)
Port WebUI -> reverse-proxy LAN ; **`9222` (CDP) JAMAIS mappe** ; egress-proxy
**loopback-only** ; `KERDOOS_BROWSER_MAX_CONCURRENT=1` par defaut (Decision 2).

---

## Decision 7 -- Digest : agregation, 3-etats, gestion des echecs

> **SUPERSEDED (2026-07-10) par [ADR 0003](./0003-digest-jobs-notification-rules.md)** :
> le modele "un digest unique quotidien agrege par owner" est remplace par des **jobs
> de notification multi-jobs par owner** (chaque owner cree N jobs, chacun sa selection
> de sources, sa frequence, son template). Les principes conserves ci-dessous (etat
> 3-valeurs jamais collapse, isolation par unite, digest partiel, SMTP depuis config,
> skip si email NULL) restent valides mais s'appliquent desormais **par job** au lieu de
> **par owner**. Voir ADR 0003 pour le modele de donnees, le decouplage scrape/notif et
> le scheduler multi-jobs.

### Agregation owner-scopee (confirme ADR 0001)
Un `DigestService` (couche `core/app` ou module `digest/`) **itere les owners** ;
pour chaque owner : `latest_all(owner)` -> rend **un** digest -> l'envoie a
`owners.email`. **`email IS NULL` => SKIP** (consultation WebUI seule, jamais agrege
dans le mail d'un autre owner). Filtre `owner_id = ?` en SQL ; `owner_id` **jamais
serialise** dans le mail. Invariant #8 respecte (un digest agrege par owner, jamais
de notification par produit).

### Interaction avec l'etat 3-valeurs
Deux phases distinctes par run : (1) **SCRAPE** par source avec retry + backoff,
aboutissant a un etat 3-valeurs *settled* ; (2) **DIGEST** qui lit `latest_all`
**apres** le scrape. Regle dure : le digest **rend fidelement les 3 etats** et ne
**collapse JAMAIS** `indetermine` (blocage anti-bot transitoire) en `indisponible`
(rupture de stock). Le "to_watch" du dashboard (`indetermine` + `indisponible`)
devient le resume actionnable du mail.

### Gestion des echecs (isolation par owner)
- **Un owner qui echoue ne bloque JAMAIS les autres** : boucle supervisee avec
  `try/except` **par owner** + `continue` + log WARNING (sinon un owner defaillant
  tue le cycle entier).
- **Retry + backoff borne** sur echec SMTP transitoire : implemente, par job, dans
  le meme appel d'envoi, jamais d'un tick a l'autre. Seuls sont retentes une
  reponse SMTP 4xx explicite (greylisting) et un echec de connexion survenu avant
  l'envoi du message, au plus `KERDOOS_SMTP_RETRY_ATTEMPTS` fois (defaut 2, soit
  trois essais) avec une pause de `KERDOOS_SMTP_RETRY_BACKOFF_SECONDS` (defaut 2),
  sous une echeance absolue inferieure au delai du reaper. Tout autre echec
  (connexion perdue apres l'envoi, 5xx, refus d'authentification) n'est pas
  retente : la ligne `job_runs` passe en `error` et la fenetre est consommee.
- **Digest partiel** : une source en blocage transitoire n'immobilise pas le digest
  entier ; elle apparait marquee `indetermine`.
- L'echec d'envoi est **enregistre dans l'etat** pour visibilite operateur.

---

## Decision 8 -- Trajectoire de consommation d'autolycos (build-couple)

`autolycos` est en cours d'extraction vers le repo separe `VOCSAP/autolycos`
(extraction actee 2026-07-10, cf. `CLAUDE.md`). Le nom PyPI est reserve
**maintenant** via une pre-version `0.1.0a1` (Trusted Publishing OIDC). Trajectoire
de consommation, integree au packaging :

| Phase | Mode de consommation d'autolycos |
|---|---|
| Dev local (jusqu'a Phase 7) | **hybride** : path / editable (`[tool.uv.sources] autolycos = { workspace = true }`) -- source de verite = `packages/autolycos/` du monorepo |
| Build (jusqu'a publication) | **git-pin** (revision epinglee) |
| Build Docker **post-publication** | `uv sync` tire **autolycos depuis PyPI** (version finale publiee post-Phase 7) -> Dockerfile simplifie, **pas de git dans le stage build** |

La **version finale publiee** et le **rewire de kerdoos** (consommer autolycos en
dependance externe plutot qu'en workspace) sont differes a **l'apres-Phase 7**, une
fois l'API (les 8 symboles du contrat : `ports.{Fetcher,FetchResult,Router}`,
`safety.{DomainPolicy,check_scheme_and_domain}`, `errors.{SSRFError,FetchError}`,
`router.StaticRouter`) stabilisee. Jusque-la, l'invariant "`autolycos/` n'importe
jamais `core/`" reste **inchange** et garanti par la separation de packages.

---

## Decision 9 -- Point de branchement MCP (Phase 5, confirme topologie-neutre)

Le serveur MCP (FastMCP) se monte **same-app ASGI** : `create_app` inclut le
sub-app / router MCP ; `bearer -> Principal` est **deja construit** (`verify_bearer`
existe depuis Phase 4a). Meme container, meme process, meme uvicorn, **+ routes**.
Reordonner MCP en dernier est donc **topologie-neutre** : aucun rework de la
topologie Docker ni du composition root. Confirme le raisonnement de l'ordonnancement.

---

## Tensions avec ADR 0001 (resolues)

- **T1 (majeure) -- scheduler.** S-B (timer intra-process) **devie** d'ADR 0001
  Q6/S8 ("cron systeme du LXC"). **Deviation RATIFIEE** par l'operateur (self-contained
  prime). La note de deviation d'ADR 0001 S8 est mise a jour en consequence (le
  present ADR devient la reference pour l'ordonnancement). `kerdoos digest` (CLI)
  reste disponible pour le mode cron externe (garde-fou `workers>1`).
- **T2 (mineure) -- `workers=1`.** Non explicite dans ADR 0001 mais decoule de
  FD3 + SQLite + file intra-process. **Rendu explicite et contraignant** ici
  (defaut surchargeable, avec garde-fou).
- **T3 (mineure) -- "infra hors-scope".** `CLAUDE.md` coupe des deux cotes sur le
  cron. **Resolu vers le self-contained** (app auto-schedulable) : le schedule vit
  dans l'artefact, pas dans la crontab du LXC.

Aucune violation des invariants 1, 2, 3, 6, 7, 8, 9. Le contrat `kerdoos digest`
idempotent + WAL per-op garantit la cohabitation web + digest sans casser
l'invariant #7.

## Consequences

- **Positives** : deploiement self-contained (l'app se schedule seule, aucun cron
  a configurer cote infra) ; une seule porte browser (coherence OOM) ; outillage
  fige (fin de l'ambiguite post-spike) ; image et reseau deja valides ; Dockerfile
  simplifie apres publication d'autolycos (pas de git au build).
- **Negatives / dettes assumees** : le digest est couple a l'uptime du container
  (mitige par la restart policy, sans rattrapage des fenetres manquees, cf.
  Decision 1) ; `workers>1` n'est pas "propre" day one
  (garde-fou + lot de dev futur) ; l'echelle horizontale exigera le seam Postgres.

## Questions residuelles

- **Format de rendu du digest** (HTML mail vs texte ; template Jinja partage avec
  l'apercu WebUI ?) -- a cadrer au debut de l'implementation Phase 6, non bloquant
  pour l'ADR.
- **Heure du digest et fuseau** (UTC vs America/Sao_Paulo) -- parametrable ; valeur
  par defaut a confirmer avec l'operateur en Phase 6.
- **Frequence par site** (mentionnee comme point ouvert DESIGN.md #9) -- day one =
  un run quotidien global ; une frequence differenciee par site est un raffinement
  futur.

## Changelog

- **2026-07-10 -- PROPOSE -> ACCEPTED**. Arbitrage operateur des questions Q-a a Q-e
  (scheduler S-B avec garde-fou `workers>1` ; LAN-only + rate-limit differe ;
  `workers=1`/`max_concurrent=1` defauts surchargeables ; outillage fige
  uv+hatchling+uvicorn+ruff ; pre-fetch chromedriver au build). Points annexes actes :
  image Option A, volume `/data`, secrets via env/secrets, trajectoire de
  consommation autolycos build-couple, MCP same-app topologie-neutre. Deviation
  scheduler vis a vis d'ADR 0001 Q6/S8 ratifiee.
- **2026-07-10 -- sign-off operateur + nommage CLI acte**. Point d'entree du batch
  quotidien = commande dediee **`kerdoos digest`** (scrape-all + agregation + envoi),
  DISTINCTE de `run_now` (per-owner a la demande via UI/MCP). Le garde-fou `workers>1`
  invite a un cron externe appelant `kerdoos digest`.
