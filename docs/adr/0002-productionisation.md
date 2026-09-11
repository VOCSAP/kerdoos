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
  `workers=1`.
- **S-C -- APScheduler in-process**. Plus lourd, meme couplage, aucun benefice sur
  S-B pour un unique job quotidien. **Rejetee.**

### Decision : **S-B**, avec garde-fou `workers>1`
Force decisive : la **coherence OOM** -- une seule porte browser inter et intra
process, sans lock inter-process a inventer. L'operateur a ratifie la deviation vis
a vis d'ADR 0001 Q6 : le self-contained prime pour l'ergonomie de deploiement.

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
    maintenant" / MCP), enfilee dans la file intra-process. Distincte du batch
    quotidien.
- Le couplage a l'uptime est mitige par `restart: unless-stopped` **et** un check
  **catch-up** au boot : si `last_digest_run > 24h`, l'app enfile un digest de
  rattrapage. Le digest est idempotent (il lit l'etat settled, il n'ecrit pas de
  prix).
- `run_now` reste une **file INTRA-process** (aligne ADR 0001 Q6) : le bouton WebUI
  "verifier maintenant" enfile un job (owner_id) et rend la main immediatement ;
  un consumer unique traite la file en serie.

### Consequence transverse -- offload threadpool obligatoire
Les fetchers etant sync-bloquants, le **consumer de la file DOIT offloader le
travail de fetch en threadpool 1-slot** (`run_in_executor` + semaphore/executor a
un seul worker) pour ne pas bloquer l'event loop ASGI. Le slot unique materialise
aussi `max_concurrent=1` cote application. Vrai pour `run_now` ET pour le digest.

---

## Decision 2 (Q-c) -- Concurrence : `workers=1` et `max_concurrent=1` par defaut

### Decision
`workers=1` (uvicorn) et `browser.max_concurrent=1` sont des **defauts
surchargeables par variable d'environnement** (l'enveloppe OOM depend de la machine
cible). `workers=1` est la **topologie par defaut documentee**.

### Justification
1. SQLite ne gagne rien en debit d'ecriture avec N process writers.
2. La file `run_now` est **per-process** (asyncio) : avec N workers, un job enfile
   dans le worker A est invisible du worker B -> `workers=1` est un **prerequis** de
   la topologie S-B.
3. `max_concurrent=1` serialise deja le chemin browser lourd.
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
  meme compte comme "disponible" -- perimetre assume, pas couvert ici.
- **`kerdoos:autonomous`** : + tiers `browser` (patchright) + `uc` (seleniumbase).
  Embarque le Chromium **de patchright** (pas celui de playwright vanilla).

Pas de sur-decoupage (pas de 3e tier base->slim->autonomous) : le plus petit
changement, deja valide au gate Phase 0, conforme ADR 0001 S8.

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
- `KERDOOS_COOKIE_SECURE` : `true` par defaut ; `false` uniquement pour un
  deploiement plain-http LAN.

### Reseau (confirme ADR 0001 S8/S9)
Port WebUI -> reverse-proxy LAN ; **`9222` (CDP) JAMAIS mappe** ; egress-proxy
**loopback-only** ; `browser.max_concurrent=1` par defaut.

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
- **Retry + backoff borne** sur echec SMTP transitoire (connexion refusee,
  greylisting 4xx), puis abandon pour cet owner ce cycle (le digest est quotidien :
  un miss est recuperable au prochain run).
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
  (mitige par restart policy + catch-up) ; `workers>1` n'est pas "propre" day one
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
