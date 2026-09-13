# CLAUDE.md -- Kerdoos

## Objectif de ce projet

Kerdoos surveille quotidiennement le **prix** et la **disponibilite** de
produits tech sur des e-commercants bresiliens et envoie des **digests
configurables par le tenant** (jamais de notification brute par produit --
invariant 8). Architecture **ports & adapters** : le coeur ne connait aucun
outil, seulement des ports stables ; **Kerdoos** est le coeur/orchestrateur,
**Autolycos** le sous-systeme anti-bot (etymologie des deux noms :
`README.md`).

**Repo** `VOCSAP/kerdoos` (monorepo, uv workspace). `autolycos` est deja
extrait en **package du workspace** (`packages/autolycos/`, depuis la Phase 0
-- garantit l'invariant 2) ; l'extraction vers le **repo separe**
`VOCSAP/autolycos` + publication PyPI reste ouverte
(`docs/adr/0002-productionisation.md` Decision 8, roadmap partagee).
**Sources de verite** : `docs/adr/` (architecture) et `DESIGN.md` (guide de
design de l'interface) ; ce CLAUDE.md est le resume operationnel, pas
l'inventaire.

## Outillage

Tranche (`docs/adr/0002-productionisation.md`, Decision 3) : **uv** (deps +
workspace) + **hatchling** (build) + **uvicorn** (ASGI) + **pytest** (tests)
+ **ruff** (lint/format, outil unique -- detail des dependances :
`pyproject.toml` de chaque package + `uv.lock`). **Ecart connu** : `ruff` est
acte mais pas encore cable (aucune config `[tool.ruff]`, absent de
`uv.lock`, `uv run ruff --version` echoue) -- ne pas supposer qu'il tourne
deja en gate per-commit.

## Principe directeur -- ports & adapters

Le **coeur ne connait que des ports** (`Fetcher`, `Parser`, `ConfigStore`,
`StateStore` -- signatures dans leurs `ports.py` respectifs, pas ici : elles
changent plus vite que ce fichier). Ecart non deductible d'une lecture rapide
du code : `ConfigStore` est scinde par ISP en lecture (`ConfigStore`,
utilisable par le coeur) et ecriture (`MutableConfigStore`, reserve aux
interfaces CLI/WebUI/MCP), pour que le coeur ne recoive jamais d'autorite
d'ecriture par accident. Distinction a preserver : le **routeur** (dans
`autolycos/`) est la *politique de selection* du Fetcher ; les
**adaptateurs** encapsulent chaque *outil* -- deux couches separees.

## Layout du repo (uv workspace)

Deux packages du workspace : `packages/kerdoos/src/kerdoos/` (coeur --
domain, scheduler, use-cases, registry/ConfigStore, parsers, digest,
persistence, interfaces cli/web minces) et
`packages/autolycos/src/autolycos/` (sous-systeme anti-bot -- Fetcher,
routeur, safety/SSRF, egress-proxy, adapters http/tls/browser/uc/camoufox). Le reste
se lit sur disque.

## Invariants -- a ne jamais violer

1. **Aucun outil ne fuit dans `core/`.** `core/` importe des ports, jamais
   `playwright`, `curl_cffi`, `patchright`, `seleniumbase`, `camoufox` -- ces outils
   vivent uniquement dans `autolycos/adapters/` (et les parsers concrets dans
   `kerdoos/parsers/`).
2. **`autolycos/` n'importe jamais `core/`/`kerdoos`.** Sous-systeme
   extractible sans refactor -- garanti par la separation physique de package.
3. **Etat a 3 valeurs : `{ok, indetermine, indisponible}`.** Ne jamais
   confondre un blocage transitoire (anti-bot, 503 isole) avec une rupture de
   stock. Le non-determinisme est reel (Amazon `blocked <-> render`, ML `503`).
   L'absence d'un produit sur un site (pas d'entree `sources`) n'est pas non
   plus une rupture de stock et ne doit jamais etre modelisee comme un scrape
   indisponible -- confondre les deux fabrique un faux delta "de retour en
   stock" au premier scrape reel.
4. **La collecte lit le prix courant**, elle ne verifie pas une valeur figee.
5. **Retry + backoff** systematiques sur non-determinisme.
6. **Echelle des tiers par cout croissant** cote Fetcher : `http` < `tls` <
   `browser` < `uc` (deprecie) < `camoufox`. L'ordre est un cout, pas un
   parcours : aucune escalade automatique, chaque site declare le tier le
   moins couteux qui passe (`docs/adr/0004-tier-camoufox-par-defaut.md`).
7. **Config et etat separes** : `ConfigStore` (`config.db`) vs `StateStore`
   (`state.db`), fichiers physiquement distincts, chacun derriere son
   abstraction -> migration (Postgres) sans toucher le coeur.
8. **Digests agreges configurables par tenant, jamais de notification brute
   par produit.** Un owner cree N digest jobs (selection de sources,
   frequence, template) ; une source n'est scrapee qu'une fois par fenetre,
   a la cadence la plus frequente parmi les jobs qui la referencent
   (decouplage scrape/notification) ; templating en liste blanche (defense
   SSTI). Modele complet : `docs/adr/0003-digest-jobs-notification-rules.md`
   (supersede l'ancien "un digest unique par owner").
9. **Coeur = bibliotheque.** CLI, WebUI et MCP (Phase 5) sont des interfaces
   **minces**, sans logique metier.
10. **Multi-tenant -- `owner_id` en SQL comme dernier rempart.** Toujours
    derive du `Principal` authentifie (jamais du corps de requete client),
    filtre **inline** dans chaque requete SQL. `owner_id` n'est **jamais
    serialise** vers le client.

## Deux modes d'usage

- **Mode A -- surveillance de fiche (en place)** : URL produit connue ->
  lecture prix + dispo, routeur = lookup statique.
- **Mode B -- veille / recherche vague (non planifie)** : site
  potentiellement inconnu -> detection dynamique du protecteur. Non conçu en
  detail dans un document actuel, aucune phase ne l'implemente.

## Convention de code

- **Code, commentaires inline, logs, identifiants : anglais.**
- **Documentation (`.md`), raisonnement, messages de commit : francais**
  (`README.md` public et metadonnees de package restent en anglais).
- **Jamais de tiret cadratin** (em dash) -- utiliser `--` ou reformuler.

## Point d'integration externe -- SMTP

Le digest est emis vers un **relais SMTP externe configurable** (host, port,
`from`, auth), lu depuis la config/l'environnement. **Aucune adresse ni
detail d'infra d'hebergement ne doit etre code en dur.**
