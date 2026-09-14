# ADR 0005 -- Serveur MCP same-app : bibliotheque, montage, authentification, tranches

- **Statut** : ACCEPTED (2026-09-13). Passe de conception de la carte 362d5dab
  (Phase 5). Les decisions D1 a D6 sont ratifiees par le team-lead au titre de
  son mandat d'autonomie, telles que recommandees ci-dessous ; les tranches T0 a
  T4 sont le plan d'execution, T0 en premier.
- **Date** : 2026-09-13
- **Changelog** :
  - 2026-09-13, PROPOSED -> ACCEPTED. Arbitrages team-lead : D1 = A (SDK
    officiel `mcp` v2 ; si `uv lock` ne resout pas contre `starlette 1.3.1`
    sans retrograder `fastapi`/`starlette`, remonter AVANT tout contournement,
    le socle web n'est pas retrograde pour une interface) ; D2 = A
    (`TokenVerifier` adosse a `AuthService.verify_bearer` ; une `ContextVar`
    dont on suppose qu'elle survit au dispatch est la classe de defaut latent
    que cette phase existe pour reveler, pas pour introduire) ; D3 = B (surface
    minimale par paliers ; `add_site`, tools de tokens et digest jobs restent
    dehors) ; D4 = A (dependance dure) ; D5 = trois variables, apres lecture de
    la carte 2c200b7c (section 2, D5) ; D6 accepte. La serialisation de
    `owner_id` par `/me` sort du perimetre (carte separee du team-lead).
- **Contrainte (pas un choix de perimetre)** : **un token ne fabrique pas
  d'autres tokens.** Aucun tool MCP ne mint, ne liste, ne revoque un credential
  ni ne modifie l'identite (`create_token`, `list_tokens`, `revoke_token`,
  `revoke_all`, `set_email`). Un token fuite reste borne a sa duree de vie et
  a son perimetre tenant ; il ne peut ni se prolonger ni se multiplier. Cette
  contrainte survit a toute extension future de la surface (T4 et au-dela) et
  se verifie par un test sur `tools/list`.
- **Disambiguation "FastMCP"** : les ADR 0001 (section 10) et 0002 (section
  "MCP") nomment "FastMCP". Depuis la v2 du SDK officiel `mcp` (2.2.0 au
  2026-09-13), la classe `FastMCP` de `mcp.server.fastmcp` est renommee
  `MCPServer` (`from mcp.server import MCPServer`) et l'ancien chemin est
  supprime ; le paquet tiers `fastmcp` (gofastmcp.com) est un autre projet.
  Dans les ADR 0001 et 0002, lire "FastMCP" comme "`MCPServer` du SDK officiel
  `mcp`" (D1). Une note de renvoi est ajoutee dans chacun de ces deux ADR.
- **Portee** : expose les use-cases de `AppService` a un client MCP (Claude Code,
  Claude Desktop, tout hote MCP) par un serveur monte dans la MEME application ASGI
  que la WebUI (decision Q2 de [ADR 0001](./0001-plateforme-post-mvp-webui-mcp-multitenant.md),
  section 10, non remise en cause). Precise ce que l'ADR 0001 laissait ouvert :
  quelle bibliotheque, comment le bearer devient un `Principal`, comment le cycle
  de vie se compose avec le lifespan existant, quelle surface de tools au premier
  jalon, et quels risques de securite chaque tranche active.
- **Sources de verite** : code de `main` (fa23df8), ADR 0001 sections 6 et 10,
  ADR 0002 section "MCP", carte 362d5dab, documentation du SDK MCP Python v2.2.0
  (py.sdk.modelcontextprotocol.io, pages `run/asgi`, `run/authorization`,
  `whats-new`) et de FastMCP (gofastmcp.com, pages `integrations/fastapi`,
  `servers/auth/token-verification`) consultees le 2026-09-13.

## 1. Contexte : ce qui existe reellement sur `main`

Tout ce qui suit est mesure sur `main` = fa23df8.

| Brique | Etat | Ou |
|---|---|---|
| `AuthService.verify_bearer(token) -> Principal \| None` | Construit, teste au niveau service (mint, role serveur, owner disabled coupe, revocation, concurrence 8x20 threads) | `core/app/auth.py:189-194` ; `tests/test_auth.py:415-461, 656-690` |
| `SqliteAuthStore.resolve_token` | JOIN `owners` avec `state='active'` inline, connexion per-op WAL | `registry/auth_store.py:341` ; contrat `auth/ports.py:141` |
| Dependance FastAPI `deps.verify_bearer` | Construite (scheme `bearer` compare en minuscules, 401 uniforme `"invalid or expired token"`), **referencee par aucun routeur ni aucun test** | `interfaces/web/deps.py:60-75` ; `grep -rl verify_bearer packages tests` ne rend que `auth.py`, `deps.py`, `test_auth.py` ; aucun test n'envoie d'en-tete `Authorization` |
| Topologie ASGI | `create_app()` : un `FastAPI(lifespan=_lifespan)` ; lifespan = tache `RunQueue.run_supervised` + evaluateur de digest opt-in ; routeurs `health`, `public`, `protected`, `admin`, `web` ; un seul `mount` (`/static`) | `interfaces/web/app.py:77-187` |
| Singletons | `auth_service`, `app_service`, `run_queue`, `domain_policy`, `session_cookie`, `csrf_secret` sur `app.state` | `app.py:161-177` |
| `run_now` | Non bloquant : `POST /run` fait `await queue.enqueue(owner_id)` ; la boucle consommatrice appelle `AppService.run_now` avec le `StaticRouter` unique | `routers/web.py:125-135` ; `core/run_queue.py` |
| Stores config/etat | Per-op (FD3 de l'ADR 0001 section 5.1 est realise) | `app.py:4-5` |
| Rempart role admin | `AppService.add_site` re-verifie `principal.role == "admin"` | `services.py:187-195` |
| Validation d'URL en ecriture | `add_source` : site du catalogue, tier disponible, `validate_source_url(domain_policy)`, `make_source_id(owner, ...)` | `services.py:212-239` |
| Dependance MCP | **Absente** : ni `mcp` ni `fastmcp` dans `uv.lock` ni dans le venv ; pas d'extra `[mcp]` | `packages/kerdoos/pyproject.toml:25-26` ; `uv.lock` |
| Contrat d'imports | `TOOLS` du test statique ne contient pas `mcp` | `tests/test_import_contract.py:27-29` |

Ce que la carte suppose acquis et qui ne l'est pas :

1. **Le socle bearer n'a jamais ete traverse par une requete HTTP.** Les trois
   proprietes du gate (401 uniforme, scheme insensible a la casse, hash jamais en
   clair) sont ecrites dans `deps.py` mais aucun test ne les exerce sur le fil.
   La Phase 5 les active ET les met sous test pour la premiere fois.
2. **"FastMCP" n'est plus un nom univoque.** Le SDK officiel `mcp` est passe en v2
   (2.2.0) et y a renomme `FastMCP` en `MCPServer` (`from mcp.server import
   MCPServer` ; l'ancien chemin `mcp.server.fastmcp` est supprime, pas deprecie).
   Le paquet tiers `fastmcp` (gofastmcp.com) continue d'exister avec sa propre API
   (`mcp.http_app()`, `TokenVerifier`, `Depends`). Le choix est a trancher (D1).
3. **Monter un serveur MCP n'est pas un `include_router`.** Dans les deux
   bibliotheques, le sous-app monte porte un lifespan (gestionnaire de sessions)
   que Starlette **n'execute pas** pour un `Mount` ; l'app hote doit l'entrer dans
   son propre lifespan, sinon la premiere requete `/mcp` echoue
   (`RuntimeError: Task group is not initialized`). Le `_lifespan` de `app.py`
   doit donc etre etendu : ce n'est pas "zero rework de topologie", c'est un
   petit rework borne au lifespan.
4. **Protection anti-rebinding DNS du SDK officiel.** `streamable_http_app()`
   n'accepte par defaut que les requetes adressees a `localhost` et repond
   `421 Misdirected Request` a tout le reste tant que `transport_security=`
   n'a pas recu une allowlist d'hotes. Derriere un reverse-proxy LAN, il faut une
   variable d'environnement dediee (D5).
5. **En v2 du SDK, un tool `def` (synchrone) s'execute sur un thread worker**, pas
   sur la boucle. `AppService` (SQLite per-op) le supporte ; `RunQueue.enqueue`
   est une coroutine et doit etre appelee depuis un tool `async def`.

## 2. Decisions a trancher

### D1 -- Bibliotheque : SDK officiel `mcp` v2 ou paquet tiers `fastmcp`

- **Option A -- `mcp>=2.2,<3` (SDK officiel, `MCPServer`)**. Reference du
  protocole (2026-07-28 et anterieurs servis ensemble), `streamable_http_app()`
  retourne une app Starlette a monter, `TokenVerifier` + `get_access_token()`
  fournis, OpenTelemetry en middleware par defaut (sans exporteur : inerte).
  *Cout* : nouvelle dependance transitive `httpx2` (le SDK a remplace httpx) a
  cote de `httpx` (groupe dev) ; contrainte a verifier a la resolution `uv lock`
  contre `starlette 1.3.1` / `fastapi 0.139` installes. *Risque* : v2 est une
  reecriture recente (comportements "sans erreur d'import" listes dans
  `whats-new`). *Reversibilite* : haute, la surface utilisee est de trois
  symboles (`MCPServer`, `TokenVerifier`, `AccessToken`) plus le montage.
- **Option B -- `fastmcp` (tiers)**. API plus riche (`Depends`, providers d'auth,
  `from_fastapi`), `mcp_app = mcp.http_app(path="/")` + `FastAPI(lifespan=
  mcp_app.lifespan)`. *Cout* : une couche d'opinions au-dessus du SDK, qui
  depend elle-meme de `mcp` (version a aligner) ; deux cadences de release a
  suivre. *Risque* : surface plus large que le besoin (nous n'exposons que des
  tools). *Reversibilite* : moyenne (les `Depends` et providers sont propres au
  paquet).

**Recommandation : Option A.** Force decisive : l'interface doit rester mince
(invariant 9) et l'auth doit rester la notre (`AuthService`). Le SDK officiel
fournit exactement le point d'extension necessaire (`TokenVerifier`, une methode)
sans imposer de modele d'auth supplementaire, et n'ajoute pas de couche a
versionner. L'ADR 0001 dit "FastMCP" : ce nom designait l'API decorateur, que
`MCPServer` conserve (`@mcp.tool()`). L'ADR 0001 section 10 est a amender par
une note "FastMCP = `MCPServer` du SDK officiel".

### D2 -- Point d'application de l'authentification

- **Option A -- `TokenVerifier` du SDK, adosse a `AuthService.verify_bearer`.**
  Une classe `KerdoosTokenVerifier(auth_service)` dont `verify_token(token)`
  appelle `auth.verify_bearer(token)` et retourne `AccessToken(token=token,
  client_id=principal.owner_id, subject=principal.owner_id, scopes=[principal.role])`
  ou `None`. Le middleware d'auth du SDK refuse en 401 AVANT tout parsing JSON-RPC
  (uniforme par construction : `None` -> meme reponse, quel que soit le motif) et
  expose `get_access_token()` dans tout handler, propagation garantie par le SDK a
  travers son propre modele de taches. *Cout* : `token_verifier=` exige
  `auth=AuthSettings(issuer_url, resource_server_url, ...)` ; le SDK publie alors
  `/.well-known/oauth-protected-resource/mcp` (metadonnees RFC 9728, non
  authentifiees, sans secret) et un `WWW-Authenticate` qui pointe dessus.
  Kerdoos est bien l'emetteur de ses tokens (`create_token`), donc
  `issuer_url` = URL publique de Kerdoos est vrai au sens "qui a emis", mais
  Kerdoos n'implemente pas de serveur d'autorisation OAuth : un client qui
  suivrait la decouverte s'arreterait en 404. Les hotes MCP configures avec un
  bearer statique ne font pas de decouverte. *Risque* : faible. *Reversibilite* :
  haute.
- **Option B -- garde ASGI maison autour du `Mount`.** Un wrapper ASGI qui lit
  `Authorization`, appelle `auth.verify_bearer`, repond 401 (meme corps que
  `deps.verify_bearer`) sinon, et stocke le `Principal` pour les tools. *Cout* :
  code de transport a ecrire et a tester ; surtout, la propagation du principal
  vers le handler n'est PAS garantie : le SDK dispatche les messages d'une session
  vers ses propres taches, une `ContextVar` posee dans l'ASGI n'y survit pas
  forcement, et l'acces a la requete depuis le `Context` du tool est a verifier
  version par version. *Risque* : moyen (un principal `None` silencieux dans un
  tool est exactement le defaut latent que le gate doit exclure). *Reversibilite*
  : haute.

**Recommandation : Option A**, avec deux garde-fous qui ramenent le "point
d'application unique" de l'ADR 0001 section 6 : (1) aucun tool ne lit
`get_access_token()` directement ; tous passent par un helper
`current_principal() -> Principal` (`interfaces/mcp/deps.py`) qui leve si le
token est absent (fail-closed, jamais `None` tolere) et reconstruit `Principal`
depuis `subject` + `scopes` ; (2) tous les tools sont enregistres par UNE
fonction `register_tools(mcp, app_service, run_queue)` et un test structurel
verifie que chaque tool enregistre passe par le helper (en inspectant la
fermeture ou par un decorateur commun `@tenant_tool` qui injecte le principal en
premier argument). Le `deps.verify_bearer` FastAPI reste en place pour une
eventuelle API JSON bearer future ; sa logique de parsing n'est plus le chemin
MCP.

### D3 -- Surface de tools du premier jalon

- **Option A -- miroir complet de `AppService`** (config CRUD, sites, digest
  jobs, run, tokens). *Cout* eleve, gate securite large.
- **Option B -- surface minimale tenant-only, par paliers** (voir tranches) :
  lecture (`list_state`, `get_history`, `list_config`, `run_status`), ecriture
  produits/sources, `run_now`. **Exclus explicitement du MCP** :
  `add_site` (point de controle de l'allowlist SSRF, reste WebUI/CLI admin),
  `create_token` / `revoke_*` / `set_email` (un token ne doit pas pouvoir
  fabriquer d'autres tokens ni changer l'identite : un token fuite resterait
  borne a sa duree de vie et a son perimetre), digest jobs (ADR 0003, a ajouter
  en T4 si demande).

**Recommandation : Option B.** Force decisive : chaque tool est une porte
nouvelle ; on ouvre celles dont la valeur pour un agent est evidente (voir l'etat,
declencher un run, ajouter un produit) et aucune qui elargit l'allowlist ou
propage des credentials.

### D4 -- Dependance dure ou extra `[mcp]`

- **Option A -- dependance dure** dans `packages/kerdoos/pyproject.toml`, import
  au niveau module dans `interfaces/mcp/`, montage pilote par
  `KERDOOS_MCP_ENABLED`. *Cout* : quelques Mo dans l'image slim. *Benefice* : un
  seul mode de defaillance (le flag), pas de branche "flag actif mais paquet
  absent".
- **Option B -- extra `[mcp]`** (esquisse de l'ADR 0001 section 7) + import
  paresseux + `RuntimeError` au boot si le flag est actif sans le paquet ; les
  deux cibles Docker ajoutent `--extra mcp`. *Cout* : une branche de plus a
  tester ; *benefice* : install CLI-only plus legere.

**Recommandation : Option A** (plus petit changement ; `fastapi` est deja une
dependance dure pour un usage CLI-only, l'argument de legerete est deja perdu).

### D5 -- Configuration d'exploitation

Alignement avec la carte 2c200b7c (branche `fix/2c200b7c-forwarded-allow-ips`,
lue dans l'arbre de travail le 2026-09-13, non encore commitee) : elle introduit
**une seule** variable, `KERDOOS_FORWARDED_ALLOW_IPS` = liste des **adresses IP
de reverse-proxy** dont uvicorn accepte `X-Forwarded-For`/`X-Forwarded-Proto`
(Dockerfile CMD `--proxy-headers --forwarded-allow-ips`, sinon
`--no-proxy-headers` ; `env.example:14-24`, `README.md:87-91`,
`tests/test_forwarded_allow_ips.py`). Elle repond a "qui est le proxy de
confiance", pas a "quelle URL le client voit" : aucune notion d'URL publique ni
d'allowlist `Host` n'existe dans le depot (recherche `PUBLIC_URL|BASE_URL|
ALLOWED_HOSTS|TrustedHost|root_path` sur l'arbre : aucune occurrence en code).
Les deux reglages sont donc distincts et complementaires ; pour ne pas poser
deux fois la question "quel hote", l'allowlist `Host` du SDK est **derivee** de
l'URL publique.

Variables lues dans `config.py` (jamais par `interfaces/mcp` directement, meme
discipline que `KERDOOS_BROWSER_*`) :

- `KERDOOS_MCP_ENABLED` : defaut **false** dans le code (un lifespan worker de plus
  doit etre opt-in pour que les tests `TestClient(create_app())` existants ne
  changent pas, regle pytest) ; `true` dans l'ENV du Dockerfile, comme
  `KERDOOS_DIGEST_EVALUATOR_ENABLED`.
- `KERDOOS_PUBLIC_URL` : URL vue du client (`https://kerdoos.lan` ou
  `http://192.168.x.y:8000`). Sert `resource_server_url` (= `<PUBLIC_URL>/mcp`)
  et `issuer_url` de `AuthSettings`, ET fournit l'allowlist `Host` par defaut
  (`host` et `host:port` de l'URL). Sans valeur et MCP actif : refus de demarrer
  (`RuntimeError`, meme pattern que `KERDOOS_SESSION_SECRET`).
- `KERDOOS_MCP_ALLOWED_HOSTS` : optionnelle, CSV **ajoutee** a l'allowlist
  derivee (cas : acces par IP LAN et par nom en meme temps). Jamais `*`
  (fail-closed ; une valeur `*` est refusee au boot).

Note : la confiance des en-tetes `X-Forwarded-*` (2c200b7c) ne reecrit pas
`Host` ; l'allowlist du SDK compare l'en-tete `Host` tel que le reverse-proxy le
transmet, en general inchange. `env.example` et `README.md` documentent les
trois variables a cote de `KERDOOS_FORWARDED_ALLOW_IPS` (T0).

### D6 -- Chemin et composition du lifespan

- Montage `app.mount("/mcp", mcp.streamable_http_app(streamable_http_path="/",
  transport_security=...))` : endpoint public `/mcp`. Le `Mount` est ajoute APRES
  les `include_router` (Starlette teste dans l'ordre ; le mount ne capture que le
  prefixe `/mcp`, aucun routeur existant n'est masque).
- `_lifespan` de `app.py` entre `mcp.session_manager.run()` dans un
  `AsyncExitStack` a cote des taches `RunQueue`/evaluateur, uniquement si le
  flag est actif ; `session_manager` n'existe qu'apres l'appel a
  `streamable_http_app()`, donc l'app MCP est construite dans `create_app`
  (composition root) avant le `FastAPI(...)`.
- `_auth_error_handler` (app.py:61-74) ne voit pas les 401 du SDK (emis par son
  middleware dans le sous-app) : pas de rendu HTML a craindre pour `/mcp`.

## 3. Structure cible

```
packages/kerdoos/src/kerdoos/interfaces/mcp/
  __init__.py
  server.py     build_mcp_server(settings, auth_service, app_service, run_queue) -> MCPServer
  auth.py       KerdoosTokenVerifier(auth_service) ; current_principal()
  tools.py      register_tools(mcp, app_service, run_queue) ; view-models plats
```

Flux d'une requete tool : `POST /mcp` -> middleware auth SDK -> `KerdoosTokenVerifier`
-> `AuthService.verify_bearer` -> `SqliteAuthStore.resolve_token` (state='active'
inline) -> handler -> `current_principal()` -> `AppService.<use-case>(owner_id, ...)`
-> SQL `WHERE owner_id = ?`. Le fetch (tool `run_now`) ne passe que par
`RunQueue.enqueue` : meme consommateur, meme `StaticRouter`, meme
`CatalogueDomainPolicy`, meme `BrowserGate` que `POST /run`. `interfaces/mcp`
n'importe rien d'`autolycos` (test structurel).

## 4. Plan de tranches

Chaque tranche est livrable et gatable seule (triple-lentille, security-auditor en
lead). Les tests cites sont des tests qui mordent, pas des tests de presence.

### T0 -- Socle : dependance, montage, gate bearer (aucun tool metier)

- Depend de : rien. Tranche D1, D2, D4, D5, D6.
- Contenu : `mcp>=2.2,<3` dans pyproject + `uv lock` ; `interfaces/mcp/` avec
  `build_mcp_server` et un seul tool de sonde `whoami` (retourne `role`, jamais
  `owner_id` : le `/me` WebUI serialise `owner_id`, le MCP ne reproduit pas cet
  ecart) ; montage + lifespan + settings ; `TOOLS += "mcp"` dans
  `test_import_contract.py` ; Dockerfile ENV.
- Acceptation :
  - `uv lock` resout sans retrograder `fastapi`/`starlette` (mesure a rapporter).
  - Flag OFF : suite existante inchangee (790 passed / 27 skipped attendu, a
    confirmer par le batch gate).
  - Flag ON, `TestClient(create_app())` : (a) sans en-tete, token inconnu, token
    expire, token revoque, owner disabled -> **cinq reponses octet-identiques**
    (status + corps + en-tetes hors date) ; (b) `authorization: BEARER <tok>` et
    `bearer <tok>` acceptes ; (c) token valide -> `whoami` repond ; (d) un
    `Host` hors allowlist -> 421 ; (e) le hash sha256 n'apparait dans aucune
    reponse ni aucun log capture (test sur `caplog` + corps).
  - Test structurel : `kerdoos.interfaces.mcp` n'importe aucun module
    `autolycos.*` ; `core/` n'importe pas `mcp` (contrat etendu).
- Risque a lever en T0 : la casse du scheme est parsee par le middleware du SDK,
  pas par notre verifier. Si le test (b) echoue, le correctif est un middleware de
  normalisation avant le sous-app, a decider au gate T0, pas a improviser.

### T1 -- Tools de lecture

- Depend de : T0.
- Tools : `list_state`, `get_history(source_id, limit<=200)`, `list_config`,
  `run_status`. Sorties = view-models plats (dataclasses -> dict) sans `owner_id`
  (les DTO `DigestJob` portent `owner_id`, `registry/ports.py:214` ; les
  `ScrapeRecord`/`Product`/`ProductSource` n'en portent pas ; un test serialise
  chaque sortie et asserte l'absence de la cle et de la valeur de l'owner).
- Acceptation : deux owners A et B avec chacun une source ; token A -> `get_history
  (source_B)` rend vide, meme forme que "source inconnue" (pas d'oracle
  d'existence cross-tenant) ; `list_state` A ne contient aucune valeur de B ;
  `limit` borne cote tool (clamp, pas d'erreur 500 sur `limit=10**9`).

### T2 -- Tools d'ecriture tenant (produits, sources)

- Depend de : T1.
- Tools : `add_product`, `add_source(product_key, site, url)`, `remove_source`,
  `remove_product`. Le schema d'entree ne contient AUCUN parametre `owner`
  (test structurel sur `tools/list` : aucun schema ne contient `owner`).
- Acceptation SSRF (le chemin est `AppService.add_source`, deja garde ; on
  prouve que le MCP ne le contourne pas) : URL hors catalogue -> refus ;
  `http://127.0.0.1/`, `http://169.254.169.254/`, `http://[::ffff:10.0.0.1]/` ->
  refus par la meme exception que le WebUI ; `product_key` contenant `:` ->
  refus ; site dont le tier est indisponible sur l'image -> refus
  `FetcherTierUnavailableError` traduit en `ToolError` sans fuite de
  traceback ; un `remove_source` avec le `source_id` d'un autre owner -> no-op
  silencieux (meme comportement que `remove_source` WebUI, a confirmer au gate).
- Erreurs : seules les `ValueError`/`KeyError`/`ConfigError`/`PermissionError`
  attendues deviennent des messages `ToolError` ; toute autre exception reste le
  generique du SDK (`Error executing tool <name>`), la traceback en log serveur.

### T3 -- `run_now` (declenchement de fetch)

- Depend de : T1 (pour `run_status`).
- Tool `async def run_now()` -> `await run_queue.enqueue(owner_id)` ; retourne
  `{"enqueued": bool, "cooldown_remaining_seconds": ...}`. Jamais d'attente du
  resultat (le browser peut prendre des minutes ; les tools v2 ont un timeout
  client).
- Acceptation : le `RunQueue` utilise est `app.state.run_queue` (identite
  d'objet testee) ; deux `run_now` consecutifs -> le second coalesce ; le
  cooldown `KERDOOS_RUN_NOW_COOLDOWN_SECONDS` s'applique au MCP comme au WebUI
  (un agent qui boucle ne martele pas la porte browser ni la reputation IP) ;
  aucun import d'`autolycos` dans `interfaces/mcp` (deja en T0, re-affirme).

### T4 -- Extensions (optionnelles, hors jalon)

- Digest jobs (`list_jobs`, `create_job`, ...) : demande produit a confirmer ;
  reutilise le view-model plat de l'ADR 0003.
- `add_site` par MCP : NON recommande ; si l'operateur le veut, double rempart
  (`scopes` contient `admin` + `AppService.add_site` re-verifie) et test 403 aux
  deux niveaux (T6 de l'ADR 0001).
- Ressources/prompts MCP : hors scope.

## 5. Surface de risque securite par tranche

| Tranche | Risque active | Garde | Test qui mord |
|---|---|---|---|
| T0 | Enumeration de tokens via 401 differencies | `verify_token` rend `None` pour tout motif ; le SDK repond avant parsing | 5 cas octet-identiques |
| T0 | Scheme `Bearer` sensible a la casse | parsing SDK (a verifier) | `BEARER`/`bearer` acceptes |
| T0 | Hash en clair | `AccessToken.token` porte le token brut en memoire de requete seulement ; jamais logue | assertion sur logs + corps |
| T0 | Rebinding DNS / Host arbitraire | `TransportSecuritySettings.allowed_hosts` | 421 hors allowlist |
| T0 | Route `/.well-known/oauth-protected-resource/mcp` non authentifiee | ne contient que `resource`, `authorization_servers`, `scopes_supported` ; aucun secret | test : corps ne contient ni owner ni hash |
| T0 | Lifespan MCP casse la WebUI (cycle de vie couple, ADR 0001 s.10) | flag OFF par defaut ; `AsyncExitStack` avec teardown ordonne | suite existante inchangee flag OFF ; flag ON, `/health` repond |
| T1 | Fuite cross-tenant par `source_id` devine | `owner_id` inline en SQL (`history(owner, source_id)`) | A ne lit pas B ; reponse uniforme |
| T1 | Serialisation de `owner_id` | view-models plats | scan des sorties |
| T1 | Owner disabled avec token valide | `resolve_token` JOIN `state='active'` | 401 apres `state='disabled'` |
| T2 | SSRF par `add_source` (nouvelle porte vers la config du fetcher) | `validate_source_url(domain_policy)` + catalogue admin + `ip_is_safe` au fetch | 4 URL hostiles refusees |
| T2 | Collision de `source_id` cross-tenant | `make_source_id(owner du Principal, ...)` + rejet de `:` | `product_key="a:b"` refuse |
| T2 | Extension de l'allowlist par un tenant | `add_site` absent du MCP | `tools/list` ne contient pas `add_site` |
| T3 | Contournement du pin http / `ip_is_safe` / `DomainPolicy` | le tool n'a pas de parametre URL ; il enqueue, le consommateur unique fetch | identite `run_queue` ; zero import autolycos |
| T3 | Deni de service sur la porte browser / reputation IP | coalescing + cooldown de `RunQueue` | second `run_now` coalesce |
| Toutes | Propagation de credentials par un token | tools `create_token`/`revoke_*` absents | `tools/list` |
| Toutes | Concurrence SQLite | stores per-op (FD3) ; tools sync sur threads workers | test concurrent existant + un appel MCP parallele |

## 6. Consequences

- Positives : trois interfaces sur un `AppService` unique (invariant 9 tenu) ;
  auth resolue par le meme `AuthService` (un seul `Principal`) ; aucun nouveau
  chemin vers `autolycos`.
- Couts : dependance `mcp` (+ `httpx2`, `mcp-types`, `opentelemetry-api`
  transitifs) ; trois variables d'environnement ; le lifespan de `app.py` gagne
  une branche ; une route de metadonnees OAuth non authentifiee.
- A ne pas casser : les 790 tests existants avec le flag OFF ; la topologie
  `workers` (le gestionnaire de sessions MCP est par process, sans etat partage
  : avec `KERDOOS_WORKERS>1` un client 2025 a sessions doit etre colle a un
  worker, ce que la stack ne fait pas ; documenter "MCP = workers=1" comme
  l'evaluateur).

## 7. Questions tranchees et items restants

Les questions D1 a D6 sont tranchees (changelog). Restent, a traiter dans les
tranches :

1. T0 : resolution `uv lock` de `mcp>=2.2,<3` contre `starlette 1.3.1` /
   `fastapi 0.139` (a remonter au team-lead si elle exige une retrogradation).
2. T0 : casse du scheme `Bearer` parsee par le middleware du SDK (test T0(b) ;
   correctif eventuel decide au gate T0).
3. T4 : les digest jobs par MCP restent une demande produit a confirmer.
4. `/me` et `owner_id` : hors perimetre, carte separee du team-lead.
