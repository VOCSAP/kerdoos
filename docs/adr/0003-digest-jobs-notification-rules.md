# ADR 0003 -- Digest jobs / notification rules (multi-jobs per owner)

- **Statut** : ACCEPTED (2026-07-10) -- sign-off operateur ; 7 questions Q-a a Q-g
  tranchees (voir "Resolutions"). Findings de la consultation securite (peer -5)
  **integres** (voir Decision 10 + D1/D3/D4/D5). Prochaine etape : implementation
  Phase 6, gate archi (double scoping IDOR, decouplage scrape/notif, scheduler
  exactly-once).
- **Date** : 2026-07-10
- **Portee** : modele de notification de Kerdoos. **SUPERSEDE la section Phase 6
  d'[ADR 0002](./0002-productionisation.md)** (Decision 7 "un digest unique quotidien
  agrege par owner"). Conserve le coeur scheduler S-B d'ADR 0002 (Decisions 1-2).
- **Sources de verite** : `CLAUDE.md`, `DESIGN.md`, [ADR 0001](./0001-plateforme-post-mvp-webui-mcp-multitenant.md),
  [ADR 0002](./0002-productionisation.md), schema config.db reel (owners/sites/
  products/sources) + state.db (scrapes), memoires Kleos #11162 (piege CREATE UNIQUE
  INDEX), #11265 (templating guide).

## Contexte

ADR 0002 supposait **un** digest quotidien agrege par owner. L'operateur elargit le
modele : chaque owner cree **autant de jobs de notification qu'il veut**, chacun avec
sa selection de produits/sources, sa frequence, son template. Exemple operateur :

- `job1` -- horaire, selection `{magalu/A}` ;
- `job2` -- quotidien, selection `{magalu/A, magalu/B, pichau/A}`.

La source `magalu/A` est referencee par les deux jobs, a deux cadences. **Decision
cle validee par l'operateur** : une SOURCE n'est scrapee qu'**une fois par fenetre**,
a la cadence la plus **frequente** parmi les jobs qui la referencent. Les jobs sont
des **vues** qui agregent et envoient l'etat deja scrape. **Jamais N scrapes pour N
jobs partageant une source.** Le modele de **cadence de scrape** (union des besoins,
dedup par source) est concu **separement** des jobs de notification.

### Ce qui est verrouille par l'operateur (grave dans l'ADR)

1. Entite per-tenant "digest job / notification rule" : `{ id, owner_id, nom,
   selection de sources, frequence (horaire/quotidien/cron), heure + fuseau, template
   + options, enabled }`. **Owner-scope STRICT** (owner_id en SQL, dernier rempart ;
   un job ne reference QUE les sources de son owner).
2. Decouplage scrape / notification (voir ci-dessus).
3. Scheduler = evaluateur **multi-jobs** (N crons par owner, fuseaux), gardant le
   coeur S-B (asyncio intra-process, defaut `workers=1` + garde-fou `workers>1`).
4. **Templating GUIDE** : l'utilisateur choisit un template fourni + coche des options
   (colonnes, ordre, pix/carte, seuil de variation, agrege vs mono). Variables et
   filtres en **liste blanche**. Pas d'edition de template arbitraire au MVP (SSTI).
5. **Aucun garde-fou de frequence par site** (trop couteux a maintenir) : la WebUI
   affiche un AVERTISSEMENT "requetes plus rapprochees = exposition anti-bot accrue".
   Risque **assume cote utilisateur**.
6. Etat 3-valeurs respecte (jamais collapse `indetermine` -> `indisponible`), isolation
   `try/except` par job/owner, digest partiel, SMTP depuis config.

## Structure actuelle (cartographie, pas l'ideal)

- **config.db** (`SqliteConfigStore`, `_SCHEMA_VERSION=3`, WAL + per-op) : `owners`,
  `sites` (catalogue admin global), `products(owner_id, product_key)`,
  `sources(source_id PK, owner_id, product_key, site, url)`. `source_id` derive
  deterministe (`make_source_id`). `PRAGMA foreign_keys=ON`.
- **state.db** (`SqliteStateStore`) : `scrapes(owner_id, source_id, ts, status,
  price_*, availability, ...)` -- historique complet, `ts` par scrape.
- **Invariant #7** : config et etat **separes**, chacun derriere son abstraction.
- **Scheduler** : n'existe pas encore (Phase 6 non commencee).

---

## Decision 1 -- Modele de donnees et placement config/etat

### Probleme
Ou vivent les jobs, la liaison job<->sources, et le bookkeeping d'execution, sans
casser l'invariant #7 (config vs etat) ?

### Cle de partage retenue
- Un **job** = une **regle declarative** (quoi surveiller, a quelle cadence, comment
  rendre) => **CONFIG** => `config.db`.
- La **liaison job<->sources** = configuration => `config.db`.
- Le **bookkeeping d'execution** (quand un job a ete envoye, statut) = **ETAT mutable
  runtime** => `state.db`.
- La **cadence de scrape** et le **dernier scrape** d'une source : la cadence est
  **derivee** de la config (union des frequences des jobs) ; le "dernier scrape" est
  **deja** `MAX(scrapes.ts WHERE source_id=?)` dans `state.db` -- **aucune table de
  cadence a creer**.

### Tables proposees

**config.db** (bump `_SCHEMA_VERSION` 3 -> 4, migration additive `CREATE TABLE IF NOT
EXISTS`) :
```sql
CREATE TABLE digest_jobs (
    id             TEXT PRIMARY KEY,            -- opaque (uuid)
    owner_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    frequency_kind TEXT NOT NULL,               -- 'hourly' | 'daily' | 'cron'
    schedule_cron  TEXT NOT NULL,               -- expression cron NORMALISEE (cf. D2)
    timezone       TEXT NOT NULL DEFAULT 'UTC', -- IANA (ex: America/Sao_Paulo)
    template_id    TEXT NOT NULL,               -- clef du registre serveur (cf. D5)
    options        TEXT NOT NULL DEFAULT '{}',  -- JSON options en LISTE BLANCHE (cf. D5)
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT,
    UNIQUE (owner_id, name)                     -- INLINE, sur table neuve (cf. note #11162)
);

CREATE TABLE digest_job_sources (
    owner_id   TEXT NOT NULL,                   -- porte le scope (discipline "owner en SQL")
    job_id     TEXT NOT NULL,
    source_id  TEXT NOT NULL,
    PRIMARY KEY (job_id, source_id),
    FOREIGN KEY (job_id)    REFERENCES digest_jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (source_id) REFERENCES sources(source_id) ON DELETE CASCADE
);
```

**state.db** :
```sql
CREATE TABLE job_runs (
    job_id    TEXT NOT NULL,
    owner_id  TEXT NOT NULL,
    window_start TEXT NOT NULL,   -- borne de la fenetre planifiee (clef d'idempotence, cf. D4)
    fired_at  TEXT NOT NULL,
    sent_at   TEXT,               -- NULL si echoue/skippe
    status    TEXT NOT NULL,      -- 'queued'|'running' (transitoires), puis 'sent'|'error'|'skipped_no_email'|'skipped_no_sources'
    error     TEXT,
    PRIMARY KEY (job_id, window_start)
);
```

Cycle reel d'une ligne `job_runs` : inseree en `queued`, passee en `running` avant
l'envoi, puis terminale en `sent`, `error` (echec ou timeout d'envoi, ou ligne restee
`queued`/`running` au-dela du delai maximal d'envoi et passee en `error` par le
reaper) ou `skipped_no_email`. Un job sans source ecrit directement
`skipped_no_sources`. Un refus d'envoi pour capacite (plafond de threads d'envoi
orphelins atteint) n'ecrit **aucune** ligne : la fenetre reste rejouable au tick
suivant. Toute ligne ecrite consomme sa fenetre (cle primaire). La colonne est un
`TEXT` sans contrainte `CHECK`.

### Notes structurelles
- **Piege #11162 EVITE** : les contraintes `UNIQUE` sont **inline dans le `CREATE
  TABLE`** de tables NEUVES (aucune ligne pre-existante). Le piege "CREATE UNIQUE
  INDEX sur table peuplee -> IntegrityError hors `__init__`" ne s'applique QUE quand
  on ajoute un index unique a une table deja peuplee. Migration additive =
  `CREATE TABLE IF NOT EXISTS` idempotent, pas d'ALTER destructif.
- **owner-scope dernier rempart -- DOUBLE SCOPING IDOR** (securite -5 #2, CWE-639/284) :
  `digest_job_sources.owner_id` porte le scope pour la discipline "filtre owner_id EN
  SQL". Le scoping doit etre applique aux **DEUX** points, pas un seul (defense en
  profondeur, pas de single point of bypass) :
  1. **Au PERSIST** (`add_job_source`) : `INSERT ... SELECT ... WHERE owner_id = ?`
     (ou pre-check owner-scope miroir de `remove_product`) -- refuse d'attacher une
     source qui n'appartient pas a l'owner du job.
  2. **Au RUN** (evaluateur) : **recharger les sources du job via
     `WHERE owner_id = job.owner_id`**, JAMAIS faire confiance aux `source_id` stockes
     tels quels. `owner_id` vient du Principal / du job resolu, jamais du body.
  Test qui mord : owner B forge le `source_id` de A -> la source de A est **absente** du
  job de B ET **0 scrape** declenche pour B sur l'URL de A.
- **Cascade** : `ON DELETE CASCADE` sur les deux FK. Supprimer un job -> ses liaisons
  partent. Supprimer une source -> elle disparait de tous les jobs qui la referencaient.
  Un job qui se retrouve a **zero source** est **skippe** par l'evaluateur : aucun
  mail vide, une ligne `job_runs` au statut `skipped_no_sources`, fenetre consommee.
  Il n'est **pas encore signale dans la WebUI** : l'affichage du dernier statut d'un
  job n'existe pas (carte 3c557a9c).
- **Pas de FK cross-DB** : `job_runs` (state.db) ne peut pas FK vers `digest_jobs`
  (config.db). Le lien est logique ; le `DigestService` lit les deux stores et joint
  en memoire (coherent avec `AppService` qui lit deja config + etat).

### Options ecartees
- **Tout en state.db** : mettrait la config (regles) dans l'etat -> viole #7.
- **Tout en config.db (y compris job_runs)** : melange le bookkeeping mutable
  d'execution dans la config declarative -> brouille #7 et pollue l'export YAML de
  config (ADR 0001 Q4) avec du runtime.

**Recommandation : le split ci-dessus** (regle=config, execution=etat, cadence
derivee). Force decisive : preserver l'invariant #7 et garder l'export de config
propre (les jobs sont exportables/versionnables ; les runs non).

---

## Decision 2 -- Representation de la frequence

### Options
- **A -- colonnes structurees** (`kind` + `hour` + `minute` + `weekday` + `cron_expr`
  + `tz`) : explicite, mais l'evaluateur doit brancher sur `kind` (3 chemins) et on
  multiplie les colonnes semi-remplies.
- **B -- cron normalise + label** : `schedule_cron` (TEXT, toujours une expression cron
  normalisee) + `timezone` (IANA) + `frequency_kind` (label pour le round-trip UI :
  "Horaire"/"Quotidien"/"Cron"). L'evaluateur a **un seul chemin** (evaluation cron
  dans le fuseau). "Horaire a la minute M" et "quotidien a HH:MM" se normalisent
  trivialement en cron.

### Recommandation : **Option B** (cron normalise + label + tz IANA)
Un evaluateur cron est **de toute facon necessaire** (la frequence "cron" est une
option de premier rang). Normaliser hourly/daily en cron unifie l'evaluation. Le
`frequency_kind` sert uniquement a la WebUI (afficher un formulaire simple plutot
qu'une expression brute).

### Outillage (Q-b, acte 2026-07-10) : `croniter` + `tzdata`
Decision operateur : **accepter `croniter`** (pur-Python, mature) pour l'evaluation
cron, et **`tzdata`** pour la base de fuseaux IANA (le `python:3.x-slim` n'embarque
pas la base tz systeme ; `zoneinfo` est stdlib 3.9+ mais a besoin des donnees). Ceci
**etend formellement l'outillage fige d'ADR 0002 D3** (uv/hatchling/uvicorn/ruff +
pytest/httpx) avec ces deux dependances runtime. A ajouter aux `dependencies` du
package et au lockfile.

---

## Decision 3 -- Decouplage scrape-cadence / notification (algorithme coeur)

C'est l'exigence centrale de l'operateur. Deux plans distincts par tick d'evaluation :

### Plan A -- cadence de scrape (union, dedup par source)
1. Rassembler l'ensemble des sources referencees par au moins **un job `enabled`**
   (tous owners confondus au niveau scheduler ; le scope owner reste porte par les
   lignes).
2. Pour chaque source : **periode requise = min des periodes** des jobs `enabled` qui
   la referencent (la cadence la **plus frequente** gagne). Une source referencee par
   un job horaire ET un job quotidien est scrapee **horaire**.
3. Si `now - last_scraped(source) >= periode_requise` (avec `last_scraped =
   MAX(scrapes.ts)`), **enfiler UN scrape** pour cette source. **Un seul scrape par
   source par fenetre**, quel que soit le nombre de jobs qui la referencent.

### Plan B -- notification (vues sur l'etat deja scrape)
1. Pour chaque job `enabled` **du a maintenant** (cf. D4) : rendre le digest depuis
   l'etat **le plus recent disponible** (`latest` par source de sa selection) et
   envoyer.
2. Le job **ne bloque pas** en attendant un scrape frais : il envoie le
   **best-available-latest** au moment de l'envoi. La fraicheur d'une source est
   **bornee** par le job le plus frequent qui la reference (garantie par le Plan A) --
   donc un job qui fire lit un etat suffisamment frais par construction.

### Consequence
Zero scrape redondant. La cadence de scrape est **derivee** (jamais stockee comme une
propriete de source), donc ajouter/retirer/desactiver un job recalcule
automatiquement la cadence effective au tick suivant. Aucune migration de donnees
quand la selection change.

---

## Decision 4 -- Scheduler multi-jobs (evaluateur, garde le coeur S-B)

### Design
Un **unique** task asyncio (le timer S-B d'ADR 0002 D1, `workers=1`) qui **tick**
periodiquement (resolution proposee : **60 s**). A chaque tick, l'**evaluateur** :

1. **Plan A** (scrape) : calcule l'union des scrapes dus (D3), enfile dans la file
   intra-process (consumer offload threadpool 1-slot, `max_concurrent=1` -- ADR 0002).
2. **Plan B** (notify) : pour chaque job `enabled`, calcule sa **window_start** = la
   plus recente occurrence planifiee <= now (cron + tz). **Idempotence** : si
   `job_runs` contient deja une ligne `(job_id, window_start)`, **skip** (deja
   traite). Sinon, rendre + envoyer + INSERT `job_runs`.

### Idempotence et redemarrage
La clef `(job_id, window_start)` rend chaque fenetre planifiee **exactement-une-fois**.
Au redemarrage, **aucun rattrapage** (ADR 0002 Decision 1) : `window_start` est la
derniere occurrence planifiee <= now, donc la fenetre courante, si elle est absente de
`job_runs`, part au premier tick (une seule fois) ; les fenetres anterieures, manquees
pendant l'arret, ne sont jamais emises. Un tick n'est **pas** en lecture seule : le
Plan A scrape et ecrit des prix dans `state.db` dans le meme tick que le Plan B.
L'idempotence porte sur l'**envoi** (une ligne `job_runs` par fenetre), pas sur l'etat
des prix.

### Garde-fou workers>1 (herite ADR 0002 D1)
`workers=1` par defaut : le scheduler tourne intra-process. Si `workers>1`, l'app **ne
demarre PAS** l'evaluateur intra-process et loggue d'utiliser un **cron externe
appelant `kerdoos digest`** (D8).

### Isolation des echecs
Boucle supervisee : `try/except` **par job** dans le Plan B, `try/except` **par
source** dans le Plan A + `continue` + log WARNING. Un job (ou une source) defaillant
ne bloque ni le tick ni les autres jobs/owners.

### Singleton par job -- coalescing (securite -5 #4, minimum vital)
Si le run precedent d'un job est **encore queued/running** (file `max_concurrent=1`),
**SKIP le tick** pour ce job au lieu d'empiler un doublon (**coalescing**). Idem
scrape : une source deja en file n'est pas re-enfilee. C'est DISTINCT du garde-fou de
frequence par site refuse par l'operateur (D7) : le singleton ne limite pas la
cadence, il empeche seulement un job/scrape de **s'empiler sur lui-meme** (protege la
file `max_concurrent=1` d'un backlog auto-inflige). Complements recommandes par -5 :
plafond global de jobs concurrents+queued par owner/instance, et **detection de
backlog** (metrique profondeur de file + warning WebUI). Le singleton-par-job est
**remonte a l'operateur pour confirmation** (Q-g).

### Options ecartees
- **APScheduler / N tasks (un par job)** : N tasks asyncio = complexite de cycle de vie
  (creation/annulation a chaque CRUD de job), risque de fuite de tasks. **Rejete** : un
  evaluateur unique qui balaie la table a chaque tick est plus simple, resilient au
  restart, et sans etat de scheduler a synchroniser avec la DB.

**Recommandation : evaluateur unique a tick 60 s + idempotence par `window_start`.**

---

## Decision 5 -- Templating guide (liste blanche, anti-SSTI)

> **CONSULTATION SECURITE EN COURS (peer -5)** sur templating + frequence. Cette
> section pose l'ossature ; les findings -5 seront integres avant ACCEPTED.

### Design
- **Registre de templates cote serveur** : un ensemble FIXE de templates Jinja fournis
  (autoescape ON, deja en place dans `templates.py`), indexes par `template_id`. Le job
  stocke un `template_id`, **jamais** du texte de template. Un `template_id` inconnu est
  rejete a l'ecriture.
- **Options en liste blanche** : `digest_jobs.options` = JSON **valide contre un schema**
  a l'ecriture (clefs autorisees, types, bornes) : colonnes affichees, ordre, inclure
  pix/carte, seuil de variation, etc. Jamais passe brut au renderer.
- **Un template flexible 1..N items** (Q-f, acte 2026-07-10) : PAS de matrice de
  compatibilite template<->selection. Un seul template flexible rend **1 a N items**
  (une ligne/carte par source de la selection) ; le cas "mono-produit" est simplement
  une **selection de 1**. Donc pas de distinction "agrege vs mono" a stocker, pas de
  filtre de compatibilite dans la WebUI -- toute selection est rendue par le meme
  template.
- **Contexte de rendu restreint = VIEW-MODEL PLAT** (contrainte securite -5 #3) : le
  renderer recoit un **view-model plat** (dataclass/dict de `str` **deja formates**),
  **JAMAIS** les objets domaine / lignes ORM bruts. Passer un objet domaine a Jinja
  ouvre l'acces attribut arbitraire (`__class__`, `__globals__`) meme sans template
  utilisateur. Variables exposees en liste blanche (product_name, site,
  price_pix/card formates, status, availability, variation, url...) + filtres existants
  (`brl`, `status_label`, `availability_label`, `tier_level`...). Aucune expression
  Jinja utilisateur => **surface SSTI nulle**.
- **HTML mail = contenu scrape UNTRUSTED** (securite -5 #3, CWE-79/80) : autoescape ON
  sur le rendu HTML ; **jamais de `|safe`** sur une donnee user/scrapee. Le `href` d'un
  lien source est **filtre par une allowlist de scheme http/https** en reutilisant le
  choke-point `autolycos.safety.check_scheme_and_domain` (pas de `javascript:`/`data:`).
  Raison non-negociable : phishing/lien-spoof meme si le client mail strippe le JS, ET
  si le digest est un jour re-rendu dans la WebUI ("voir dans le navigateur") -> XSS
  browser complet.

### Pourquoi (pas de Jinja libre)
Un template edite par l'utilisateur = injection de template cote serveur (SSTI) : acces
a `__class__`, `__globals__`, exfiltration/RCE. La liste blanche
(template_id enumere + options schema-validees + contexte restreint) elimine la classe
entiere. Kleos #11265.

### Validation des options (Q-d, actee 2026-07-10) : dataclass maison
Le `options` JSON est valide par un schema **code en dur** (dataclass + validation
manuelle : clefs autorisees, types, bornes), **pas** de nouvelle dependance (pydantic
ecarte au MVP) vu le petit nombre d'options. Toute clef inconnue ou valeur hors bornes
est rejetee a l'ecriture.

---

## Decision 6 -- Owner sans email (job non-envoyable)

Un job qui envoie un mail exige `owners.email`. Que se passe-t-il si un job `enabled`
appartient a un owner sans email ?

### Options
- **A -- skip + statut `skipped_no_email`** : l'evaluateur saute le job, enregistre le
  statut, la WebUI affiche "ajoutez un email pour recevoir ce job". Le job reste
  `enabled` et **reprend automatiquement** des qu'un email est ajoute.
- **B -- bloquer la creation/activation** si l'owner n'a pas d'email (validation a
  l'ecriture).
- **C -- auto-desactiver** le job.

### Decision (Q-a, actee 2026-07-10) : **Option A**
Coherent avec la semantique ADR 0001 "owner sans email = WebUI-only" : l'email peut
etre ajoute plus tard (le profil Phase 4 le permet), et le job doit reprendre sans
reconfiguration. B couple la creation du job a l'etat du profil (friction) ; C perd
l'intention utilisateur. Le job reste **creable et visible** dans la WebUI (statut
`skipped_no_email`), simplement **non-envoye** tant qu'aucun email n'existe.

---

## Decision 7 -- Frequence : aucun garde-fou, avertissement WebUI

Decision operateur : **aucun garde-fou de frequence par site** (trop couteux a
maintenir). L'utilisateur decide de la cadence. La WebUI affiche un **avertissement**
sur le formulaire de job : "des requetes plus rapprochees augmentent l'exposition
anti-bot (blocages, challenges) et la charge". Le **risque est documente comme assume
cote utilisateur**. L'ADR l'acte tel quel.

### Pas de plancher, mais un plafond de concurrence (Q-e, actee 2026-07-10)
Decision operateur : **AUCUN plancher de frequence "dur"** (pas de refus < 5 min). A la
place, la protection anti-abus est **structurelle**, pas temporelle :
- **singleton par job (coalescing)** -- D4 / S4 : un job ne s'empile jamais sur lui-meme ;
- **plafond global simple de jobs concurrents** (+ queued) par instance/owner -- D4 : borne
  le backlog quelle que soit la cadence demandee.
Ces deux gardes limitent la **charge concurrente**, jamais la **cadence** (que
l'utilisateur choisit librement). Corollaire assume : une cadence agressive sur un site
protege (Akamai/Magalu) peut degrader le tier `uc` partage (le decouplage D3 borne le
nombre de scrapes, pas leur frequence). Risque documente comme **assume cote
utilisateur** ; la WebUI l'avertit.

---

## Decision 8 -- Reconciliation CLI `kerdoos digest`

Dans le monde multi-jobs, **`kerdoos digest` = "executer UN tick d'evaluation"** :
Plan A (scrapes dus) + Plan B (jobs dus), puis exit. C'est exactement ce qu'un **cron
externe** appelle quand `workers>1` (garde-fou D4). Le timer S-B intra-process et la
CLI partagent **la meme fonction d'evaluation** ; deux declencheurs (timer asyncio OU
CLI), une seule logique.

- Un cron externe doit appeler `kerdoos digest` a une cadence >= resolution du tick
  (ex: chaque minute) pour honorer les schedules fins. A documenter dans l'ADR/README
  de deploiement.
- `run_now` (per-owner, a la demande UI/MCP) reste **distinct** : il ne passe pas par
  l'evaluateur de schedules, il enfile un scrape immediat pour les sources d'un owner
  (ADR 0002 nommage).

---

## Decision 9 -- WebUI : section "Notifications"

Interface MINCE (invariant #9) : vues sur `AppService`/un nouveau `DigestJobService`.
Ecrans :
- **Lister** les jobs de l'owner (nom, frequence, nb de sources, template, enabled,
  dernier statut d'envoi).
- **Creer / editer** un job : nom, **selection de sources cochees** (uniquement les
  sources de l'owner -- rendu depuis `list_config(owner)`), frequence (formulaire
  horaire/quotidien/cron + fuseau), choix de template + options cochees (le template
  flexible rend 1..N items, donc aucun filtre de compatibilite selection<->template,
  Q-f), avertissement frequence (D7).
- **Activer/desactiver**, **supprimer** (owner-scope, KeyError -> 404 generique, pas
  d'oracle cross-tenant, comme `remove_product`).
- **Apercu** du rendu (le meme renderer whitelist que l'envoi).
Toute la logique de scoping/validite reste dans le service ; les routes orchestrent +
rendent. CSRF au niveau router (Phase 4b), `owner_id` jamais serialise.

---

## Decision 10 -- Securite (findings consultation -5, priorises)

Fait terrain (-5) : `digest/render.py` est plein-texte aujourd'hui et strippe deja les
CRLF des erreurs (`_sanitize_error`) ; le **rendu HTML mail est un sink NEUF**. Les
findings ci-dessous sont des **contraintes de conception dures** de l'ADR 0003, pas
des recommandations optionnelles. Confiance -5 : 88% design-level, a reconfirmer au
gate code Phase 6.

- **S1 [HIGH] Injection d'en-tete mail (CWE-93)** : toute chaine user/scrapee entrant
  dans le `Subject` ou un header SMTP (nom de job, nom de produit) doit **STRIP CR/LF +
  cap de longueur**. `_sanitize_error` le fait deja pour le body -> **etendre aux
  headers ET a la partie `text/plain`** du multipart. Le plus grave et le plus discret.
- **S2 [HIGH] IDOR selection de job (CWE-639/284)** : **double scoping** persist + run
  (detaille en D1). Pas de single point of bypass. Test qui mord en D1.
- **S3 [MEDIUM] XSS/HTML mail (CWE-79/80)** : **view-model PLAT** + autoescape ON +
  aucun `|safe` sur data user/scrapee + `href` filtre scheme-allowlist http/https via
  `autolycos.safety.check_scheme_and_domain` (detaille en D5). Vaut pour le mail ET un
  eventuel re-rendu WebUI "voir dans le navigateur".
- **S4 [MEDIUM] DoS interne de la file `max_concurrent=1`** : **singleton par job
  (coalescing)** minimum vital + plafond global concurrents+queued par owner/instance +
  detection de backlog (detaille en D4). Distinct du garde-fou frequence (D7).
- **S5 [LOW/CONFIRME] SSTI ferme** par l'approche liste-blanche (D5) : templates
  dev-authored versionnes + options = enum ferme, jamais du texte libre injecte dans la
  source du template. Self-ban anti-bot = assume (D7).

Ces exigences sont reportees dans les criteres du **gate securite Phase 6** : la suite
de tests devra inclure le test IDOR qui mord (S2), un test d'injection CRLF header/subject
(S1), un test XSS mail (payload `<script>`/`javascript:` href -> echappe/rejete, S3), et
un test de coalescing (S4).

## Reconciliation avec ADR 0002

| ADR 0002 | Statut sous ADR 0003 |
|---|---|
| D7 "digest unique quotidien agrege par owner" | **SUPERSEDE** : cas particulier = un seul job quotidien. |
| D1 scheduler S-B (asyncio intra-process, workers=1 + garde-fou) | **CONSERVE** : le timer unique devient un **evaluateur multi-jobs** ; meme coeur. |
| D1 `kerdoos digest` = batch quotidien | **GENERALISE** : `kerdoos digest` = un tick d'evaluation (D8). |
| 3-etats, try/except isolation, digest partiel, SMTP config | **CONSERVE**, applique **par job** au lieu de par owner. |
| D2 workers=1/max_concurrent=1, D6 volume /data, secrets | **INCHANGE**. |

Mettre a jour l'en-tete de la section Phase 6 d'ADR 0002 avec une note
"SUPERSEDED by ADR 0003" (a faire a l'ACCEPTED de 0003).

## Tensions / incoherences signalees

- **T1 (outillage)** : l'evaluation cron+tz peut exiger `croniter` (+ `tzdata` sur image
  slim), au-dela de l'outillage fige ADR 0002 D3. A ratifier (Q-b).
- **T2 (config/etat)** : les jobs (config.db) sont joints en memoire aux scrapes
  (state.db) ; aucun FK cross-DB. Coherent avec l'existant, pas une violation, mais a
  acter explicitement pour que l'implementation ne tente pas un FK cross-fichier.
- **T3 (export config)** : ADR 0001 Q4 prevoit un export YAML de la config. Les
  `digest_jobs`/`digest_job_sources` (config.db) devraient etre inclus dans l'export
  (versionnables) ; `job_runs` (etat) exclu. A confirmer que l'importeur/exporteur YAML
  est etendu en Phase 6.
- **T4 (frequence agressive)** : corollaire assume de D7 -- degradation possible du tier
  `uc` partage ; -5 pourra recommander un plancher anti-abus.
- Aucune violation des invariants 1/2/3/6/7/8/9. Le decouplage D3 renforce meme
  l'invariant "une source scrapee proprement" en dedupliquant les scrapes.

## Resolutions (sign-off operateur 2026-07-10)

Les 7 questions sont tranchees (recos architecte validees en bloc) :

- **Q-a** : owner sans email = **skip + reprise auto** (job creable, non-envoye, visible
  WebUI avec statut `skipped_no_email`). Voir D6.
- **Q-b** : **`croniter` + `tzdata`** acceptes (etend l'outillage fige ADR 0002 D3).
  Voir D2.
- **Q-c** : resolution du tick = **60 s**. Voir D4.
- **Q-d** : validation des `options` = **dataclass maison** (MVP, pas de pydantic).
  Voir D5.
- **Q-e** : **PAS de plancher de frequence**. A la place : singleton-par-job + **plafond
  global simple de jobs concurrents**. Voir D4/D7.
- **Q-f** : **un template flexible qui rend 1..N items** ; le mono = selection de 1.
  Pas de matrice de compatibilite. Voir D5/D9.
- **Q-g** : **singleton-par-job (coalescing) confirme**. Voir D4/S4.

## Consequences

- **Positives** : modele expressif (N jobs/owner), zero scrape redondant (decouplage),
  scheduler unique resilient (idempotence par fenetre), templating sans surface SSTI,
  config exportable/versionnable.
- **Negatives / dettes** : une table de plus a migrer (additive, sans risque #11162) ;
  potentielle dep `croniter`/`tzdata` ; la cadence agressive reste un risque anti-bot
  assume par l'utilisateur ; la jointure config/etat en memoire (pas de FK cross-DB)
  demande une discipline de service.

## Changelog

- **2026-07-10 -- PROPOSED**. Design lead architect apres elargissement operateur du
  modele digest (multi-jobs). Supersede la section Phase 6 d'ADR 0002.
- **2026-07-10 -- findings securite -5 integres**. Section Decision 10 (S1-S5
  priorises) + durcissements : view-model plat anti-XSS + href scheme-allowlist (D5),
  double scoping IDOR persist+run (D1), singleton-par-job coalescing (D4), strip CRLF
  headers/subject/text-plain (S1). Nouvelle question Q-g (confirmation coalescing).
- **2026-07-10 -- PROPOSED -> ACCEPTED**. Sign-off operateur, 7 questions tranchees
  (recos validees en bloc, section "Resolutions") : Q-a skip+reprise ; Q-b croniter+tzdata ;
  Q-c tick 60s ; Q-d dataclass ; Q-e pas de plancher frequence (singleton + plafond
  global concurrent a la place) ; Q-f un template flexible 1..N items (mono = selection
  de 1, pas de matrice de compat) ; Q-g coalescing confirme. Prochaine etape :
  implementation Phase 6 + gate archi.
