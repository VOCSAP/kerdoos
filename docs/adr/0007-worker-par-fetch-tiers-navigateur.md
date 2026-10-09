# ADR 0007 -- Sortir le cycle launch->close des tiers navigateur du processus long

- **Statut** : PROPOSED (2026-10-09), carte roadmap `0778a9bc`. A faire attaquer par
  un challenger avant presentation a l'operateur.
- **Amende** : ADR 0002 Decision 1 (porte navigateur, workers=1) sur le *lieu* du
  cycle navigateur, pas sur sa borne ; ADR 0004 Decision 5 (plafond de threads
  abandonnes du tier camoufox) dont la semantique est remplacee.
- **Absorbe** : carte `6f235a20` (motif de liveness duplique browser/camoufox).
- **Depend de** : carte `963a777e` mergee (`main` `0e84a1e`), qui corrige la seule
  branche crash du tier browser et laisse ouverts les cas « navigateur gele ».
- **Sources de verite** : Kleos #21229, #21230 (diagnostic du debugger), #21235
  (decision operateur), #17006 et #17031 (lecons de liveness d8b7b8fd), #17562
  (attribution strace), code de `main` `0e84a1e`.

## Contexte

Kerdoos tourne en processus long (scheduler intra-process, ADR 0002 Decision 1).
Les tiers `browser` (patchright, Chromium) et `camoufox` (Firefox) executent chaque
fetch dans un thread proprietaire du cycle complet lancement -> navigation ->
fermeture, borne par un `join(timeout=fetch_timeout_seconds)` externe
(`browser.py:617-657`, `camoufox.py:722-741`). Cette forme est imposee par l'API
sync de Playwright, qui n'est pas utilisable depuis un autre thread que celui qui a
ouvert `sync_playwright()` (MESURE, d8b7b8fd).

Fait mesure par le debugger (Kleos #21229, image `a06a916`) : quand le thread
principal tue le driver Node de Playwright pendant que le thread de fetch est encore
dans un appel sync, ce thread ne sort jamais. Il boucle dans
`_sync_base.py:91-92` (`while not task.done(): self._dispatcher_fiber.switch()`),
brule environ un coeur, tient le GIL et son egress-proxy. Avec deux de ces threads,
un fetch browser normal passe de 1,3-2,4 s a 7-8 s. Cote camoufox, chaque fetch gele
tue a l'echeance laisse un tel thread, et le plafond `MAX_ABANDONED_FETCH_THREADS=5`
se rapproche a chaque incident. Classe amont : playwright-python#3222.

Le correctif local 963a777e (mergee en `0e84a1e`) epargne le driver sur la branche
crash du tier browser et joint le thread sous une grace bornee. Il ne couvre pas :

- un navigateur ou un driver **gele** (SIGSTOP, OOM partiel, deadlock interne) :
  epargner le driver ne libere pas le thread, qui reste dans l'appel ;
- la branche « read exceeded its budget » de `browser.py`, qui est un crash apres
  `goto` (Kleos #19080) et tue encore le driver ;
- la deadline camoufox, ou epargner le driver laisse des processus et des threads
  bloques (MESURE, Kleos #21229 : « pas transposable »).

Le motif de liveness existe en trois copies (uc, browser, camoufox) et a deja
diverge en semantique (carte 6f235a20) : la prochaine correction se ferait trois
fois. L'operateur a decide (Kleos #21235) de traiter la cause : un thread Python ne
peut pas etre tue, un processus si.

## Forces

- **F1 -- Liveness** : apres N incidents de n'importe quelle classe (crash, gel,
  timeout), le processus long doit garder la meme latence de fetch et ne porter
  aucun thread ni processus orphelin. C'est la force decisive.
- **F2 -- Invariant 3** : aucun chemin d'echec du mecanisme (worker tue, worker
  mort, sortie tronquee) ne doit produire `indisponible`. Seul un `FetchResult`
  complet produit un statut ; tout le reste est une `FetchError`, que
  `core/orchestrator.py:51` degrade en `INDETERMINATE`.
- **F3 -- SSRF** : l'egress-proxy CONNECT loopback (ADR 0004 D4/C1) reste le controle
  primaire ; `validate_target` reste le premier appel du fetch ; aucun flag de
  lancement ne contourne `strip_dangerous_browser_args`.
- **F4 -- Porte navigateur** : au plus `max_concurrent` navigateurs vivants, porte
  relachee seulement apres mort confirmee (C1 de d8b7b8fd, ADR 0002 D1).
- **F5 -- Gel PyPI** : `ports`, `safety`, `errors`, `router`, `browser_gate` et
  `tiers` ne changent pas de contrat (Kleos #17632 : dernier commit de contrat =
  `23b3432`).
- **F6 -- Preuves image** : T4-2 et T4-10 de l'ADR 0004 attribuent l'egress par
  arbre de processus sous `strace -f` (fermeture transitive depuis les `execve` du
  binaire navigateur, Kleos #17562) ; elles doivent rester valides sans reecriture.
- **F7 -- Cout** : Kerdoos est un batch quotidien de quelques dizaines de sources ;
  une seconde de plus par fetch est acceptable, une seconde de plus par fetch
  *suivant* un incident ne l'est pas (c'est le defaut actuel).

## Options

### Option A -- Un sous-processus worker par fetch (`subprocess`)

Le parent (processus long) garde `validate_target`, la porte, le budget et le
plafond. Il lance `python -m autolycos.adapters._fetch_worker` dans une **nouvelle
session** (`start_new_session=True`, donc nouveau groupe de processus), lui passe la
requete sur stdin, lit la reponse sur stdout avec `communicate(timeout=...)`. Le
worker ouvre l'egress-proxy, lance le navigateur, navigue, lit le document, ferme,
ecrit la reponse et sort. A l'echeance ou sur toute sortie anormale, le parent tue
**le groupe entier** (`os.killpg(pgid, SIGKILL)`), attend la mort confirmee, et ne
relache la porte qu'ensuite.

- Cout : un demarrage d'interpreteur + import de patchright ou camoufox par fetch
  (a MESURER, M1 ci-dessous ; SUPPOSE entre 0,3 et 1,5 s sur l'image Linux).
- Risque : faible. Le code du cycle navigateur est deplace, pas reecrit ; la
  mecanique parent est plus simple que les trois copies actuelles.
- Reversibilite : haute. L'ancien thread proprietaire reste un mode de secours
  possible pendant une tranche, derriere la meme facade `Fetcher`.
- Rayon : `browser.py`, `camoufox.py`, un module worker nouveau, `tiers.py`
  (termes de budget uniquement, voir F5 et la question Q2).

### Option B -- Worker persistant recycle

Un worker par tier, lance paresseusement, qui sert les fetchs en sequence sur un
canal (requete/reponse), recycle apres N fetchs ou apres tout incident. Meme
transport, meme kill en bloc.

- Cout : amortit le demarrage ; ajoute un etat (worker vivant ou non, generation),
  un protocole multi-messages, une detection de worker muet, un recyclage.
- Risque : moyen. Un worker partage reintroduit, a l'interieur du worker, le
  probleme de depart (un thread sync bloque dans un worker vivant) ; le remede est
  « tuer le worker a tout incident », ce qui ramene a A pour le cas qui compte.
- Reversibilite : haute vers A (meme worker, cycle de vie different).
- Rayon : identique a A plus la gestion de cycle de vie.

### Option C -- `multiprocessing` (start method `spawn`)

Meme decoupage que A, via `multiprocessing.Process` + `Pipe`.

- Cout : pickling des arguments et du resultat (gratuit : `FetchResult` est un
  dataclass de primitives, `DomainPolicy` un `frozenset`), mais aussi le
  resource tracker, le semaphore tracker et les pieges du start method : `fork` est
  exclu (le parent porte le scheduler, uvicorn et les threads de proxy), `spawn`
  reimporte le module appelant, et le groupe de processus n'est pas cree par
  defaut (pas de `start_new_session`). Le kill en bloc devient une seconde
  mecanique a ecrire par-dessus.
- Risque : moyen (surface d'outil plus large pour le meme resultat).
- Reversibilite : haute.
- Verdict : rien que A n'offre pas, deux pieges de plus.

### Option D -- Statu quo (correctifs locaux par branche)

Continuer 963a777e branche par branche : epargner le driver partout, joindre avec
grace, compter les spinners.

- Cout : chaque nouvelle classe d'incident se corrige trois fois ; la carte
  74310de2 et 963a777e sont les 5e et 6e passes de liveness du projet.
- Risque : eleve sur F1 : aucun remede local n'existe pour un navigateur gele
  (MESURE, Kleos #21229), le plafond finit par refuser le tier jusqu'au redemarrage.
- Reversibilite : sans objet.

## Decision

**Option A**, avec B comme optimisation conditionnelle a la mesure M1 (tranche T4,
non engagee). Force decisive : F1. Un processus se tue, un thread non ; tout
remede qui laisse le cycle navigateur dans l'interpreteur long laisse un chemin
par lequel un thread reste bloque. A est aussi le plus petit changement qui ferme
*toutes* les classes d'incident d'un coup, et il supprime deux des trois copies du
motif de liveness (6f235a20) au lieu d'en ajouter une variante.

### D1 -- Decoupage parent / worker

| Responsabilite | Parent (processus long) | Worker (par fetch) |
|---|---|---|
| `validate_target` (SSRF, premier appel) | oui, avant tout spawn | non (deja fait) |
| Porte navigateur (`BrowserGate`) | acquiert et relache | jamais |
| Budget `fetch_timeout_seconds` | `communicate(timeout=)` | timeouts internes (launch, nav) |
| Egress-proxy `PinningProxy` | non | oui, possede et arrete |
| Lancement, navigation, lecture, fermeture | non | oui, un seul thread, le principal |
| Kill en bloc + mort confirmee | oui | non |
| Plafond d'abandon | oui | non |
| Journalisation | relaie stderr du worker en WARNING | ecrit sur stderr |

Le worker est un module de `autolycos` (`autolycos/adapters/_fetch_worker.py`,
nom indicatif) qui n'importe que `autolycos` (invariant 2). Le parent le lance
avec `sys.executable -m`, jamais par un chemin de script.

### D2 -- Qui possede le proxy : le worker

Le proxy est un serveur de sockets loopback avec un thread d'acceptation
(`egress_proxy.py:134-161`). Trois raisons de le mettre dans le worker :

1. Le kill en bloc doit ne rien laisser dans l'interpreteur : un proxy du parent
   dont le `stop()` attend un `accept()` est lui-meme un point de blocage
   (`egress_proxy.py:147-161` documente deja que `close()` seul ne reveille pas
   `accept()` sous Linux).
2. Un proxy par fetch est deja la forme actuelle (`browser.py:438`,
   `camoufox.py:614`) : le `domain_allowed` du proxy est construit a partir de
   `DomainPolicy` + `subresource_domains`, deux valeurs serialisables en JSON.
3. Le pin SSRF n'est pas « propage » : il est **recalcule** par le proxy du worker
   au CONNECT (`resolve_and_pin`, `safety.py:157`), comme aujourd'hui. Il n'y a
   aucune IP a transmettre du parent au worker, donc aucun canal par lequel un pin
   perime pourrait survivre.

Consequence sur la preuve strace (F6) : le `connect()` du proxy vers l'IP pinnee
part du worker, comme il partait de la sonde Python aujourd'hui ; l'arbre attribue
au navigateur (fermeture depuis les `execve` de `camoufox-bin` ou
`chrome-headless-shell`) ne contient ni le worker ni la sonde, exactement comme
aujourd'hui. Le passage de « proxy dans la sonde » a « proxy dans un enfant de la
sonde » ne change pas la partition « navigateur / hors navigateur » que la preuve
mesure. A verifier en image (M5), pas a supposer.

### D3 -- Transport de la requete, du resultat et des erreurs

Requete (stdin, un document JSON) : `tier`, `url`, `allowed_domains` (liste),
`subresource_domains` (liste), `launch_timeout_seconds`, `nav_timeout_ms` ou
`nav_timeout_seconds`, `launch_marker`, et pour camoufox `executable_path`,
`expected_version`. Rien d'autre : pas d'args de lancement libres (le worker
construit les siens et applique `strip_dangerous_browser_args`), pas de
credentials.

Reponse (stdout, un document JSON, puis EOF) :

```
{"kind": "result", "html": ..., "status": 200, "method": "browser", "challenged": false}
{"kind": "error", "type": "FetchError" | "SSRFError", "message": "..."}
```

Codes de sortie : `0` document emis ; toute autre valeur, ou un stdout vide,
tronque ou non parsable, ou un timeout de `communicate`, donne `FetchError` cote
parent avec le code et la fin de stderr. JSON plutot que pickle : quatre champs de
primitives, et aucune desserialisation de code depuis un enfant, meme si c'est le
notre.

Invariant 3 (F2) : le parent ne construit un `FetchResult` **que** depuis un
document `result` complet. Un worker tue, gele ou mort en silence est une
`FetchError`, comme l'est aujourd'hui une echeance ; `core` ne voit aucune
difference. `SSRFError` est relayee comme `SSRFError` (le proxy du worker peut
refuser un CONNECT ; aujourd'hui ce refus se traduit en echec de navigation dans le
navigateur, pas en exception Python : le worker ne fait que journaliser).

Les exceptions inattendues du worker (bug, import casse) deviennent une
`FetchError` dont le message cite le type et la premiere ligne du traceback ;
le traceback complet va dans le journal du parent, pas dans le message.

### D4 -- Porte, budget, kill en bloc

- La porte est tenue par le parent sur tout le cycle : spawn -> `communicate` ->
  mort confirmee. Le `lock_dir` cross-process de `BrowserGate` reste inutile ici
  (le worker n'acquiert rien), il garde son role entre workers uvicorn.
- Le budget est **un** nombre : `communicate(timeout=fetch_timeout_seconds)`.
  A l'echeance : `killpg(SIGKILL)` sur le groupe, `psutil.wait_procs` borne par
  `_KILL_WAIT_SECONDS`, puis une seconde passe **par marqueur de lancement**
  (le `_launch_process_tree` existant, deplace dans un module commun) pour tout
  processus qui aurait quitte le groupe (un navigateur qui ferait `setsid` : a
  MESURER, M2). La porte est relachee apres.
- Pire cas de tenue de porte : `fetch_timeout + _KILL_WAIT_SECONDS`, inchange par
  rapport a la branche deadline actuelle (`browser.py:638-653`).
- Un worker qui a emis son document mais ne sort pas (fermeture lente) est joint
  jusqu'au budget restant puis tue : le resultat est **gagne**, pas perdu. Ce cas
  n'existe pas dans la forme thread (le resultat et la sortie du thread sont lies).
- Sous Windows (dev seulement) : pas de `killpg` ; `psutil` tue l'arbre depuis le
  PID du worker. La porte y est deja « in-process only » (`browser_gate.py:54-60`).

### D5 -- Plafond d'abandon : une seule semantique

Le plafond compte desormais des **groupes de processus dont la mort n'est pas
confirmee** (survivants apres SIGKILL + attente, ou `psutil` indisponible), par
tier, decremente quand une passe ulterieure (au fetch suivant) les trouve morts.
Il n'y a plus de thread a compter : la divergence browser/camoufox (74310de2,
6f235a20) disparait avec son objet. Le refus au plafond reste une `FetchError`
journalisee en ERROR.

### D6 -- Perimetre : browser et camoufox ; uc intact

`uc` est deprecie (ADR 0004 Decision 9) et aucun site ne le declare. Il garde son
thread proprietaire et sa copie du motif, jusqu'a sa suppression. L'ADR ne cree
pas un worker pour un tier mort.

### D7 -- Gel PyPI (F5)

| Module gele | Effet de l'ADR |
|---|---|
| `ports.py` | aucun : `FetchResult`, `Fetcher`, `Router` inchanges |
| `safety.py` | aucun : `DomainPolicy`, `validate_target`, `resolve_and_pin` inchanges ; le worker les importe |
| `errors.py` | aucun : `FetchError`, `SSRFError` inchanges |
| `router.py` | aucun en surface : les fabriques `_make_browser`/`_make_camoufox` construisent les memes classes avec les memes kwargs |
| `browser_gate.py` | aucun |
| `tiers.py` | **signatures inchangees** ; les *termes* de `BrowserBudget.check` et `CamoufoxBudget.check` decrivent un nettoyage qui change (`kill_wait_seconds` x 1, plus de `late_sweep_seconds`). `TermName` contient deja `kill_wait_seconds`. Question Q2. |

Les constructeurs `BrowserFetcher(...)` et `CamoufoxFetcher(...)` gardent leurs
parametres ; `max_abandoned_fetches` change de sens (D5) sans changer de type.

### D8 -- Attribution et preuves image (F6)

Les tests `tests/image/test_camoufox_image.py` lancent une sonde Python sous
`strace -f` et attribuent par fermeture transitive depuis les `execve` du binaire
navigateur. Un worker intermediaire ajoute un niveau a l'arbre sans changer la
racine d'attribution. Les tests de gel (`BrowserFetchFreezeWiringTest` et
equivalents camoufox) changent de nature : ils figent le **worker** (ou le
navigateur sous le worker) et verifient zero survivant, zero thread
supplementaire dans le parent, latence du fetch suivant inchangee. C'est le test
d'acceptation de F1 (M4).

## Ce qu'il faut MESURER avant d'engager T1

| Id | Mesure | Decide |
|---|---|---|
| M1 | Cout de `sys.executable -m <worker>` jusqu'a « pret a lancer », image `autonomous`, 10 repetitions : import de `patchright.sync_api` seul, import de `camoufox.sync_api` seul, spawn complet | si > 50 % du fetch nominal (1,3-2,4 s), T4 (option B) passe de « conditionnelle » a « planifiee » |
| M2 | Apres `killpg(SIGKILL)` sur le groupe d'un worker browser puis camoufox en pleine navigation : survivants a 1 s et 5 s, avec et sans `tini -s` | si des zygotes ou le driver survivent au groupe, la seconde passe par marqueur (D4) est obligatoire, sinon elle devient un simple filet |
| M3 | RSS d'un worker « chaud » sans navigateur (apres import) | dimensionne l'option B ; sans effet sur A |
| M4 | Sonde `probe_growth.py` de 963a777e rejouee avec gel (SIGSTOP du navigateur) x 5 puis 5 fetchs normaux : latence des fetchs normaux, threads du parent, processus survivants | critere d'acceptation de F1 : latence stable, 0 thread, 0 survivant |
| M5 | T4-2 et T4-10 en image avec le worker | preuve que l'attribution tient (D8) |
| M6 | Taille de stdout pour la plus grosse fiche du catalogue (MercadoLivre : 1 055 964 octets mesures, ADR 0004) via `communicate` | confirme que le transport JSON sur pipe n'ajoute pas de latence mesurable |

## Plan de tranches

- **T0 -- Mesures** M1, M2, M3, M6 (sondes dans `~/.agent-forge/scratch/0778a9bc/`,
  pas de code produit). Sortie : les chiffres dans cet ADR, statut inchange.
- **T1 -- Module commun + tier browser.** `autolycos/adapters/_liveness.py`
  (marqueur, arbre par marqueur, `kill_and_wait`, plafond D5 : la partie de 6f235a20
  qui survit a l'ADR) et `_fetch_worker.py` ; `BrowserFetcher.fetch` devient
  parent-only ; tests de gel reecrits (D8) ; M4 et M5 executes en image. Les
  branches crash et read-budget de `browser.py` disparaissent avec le thread.
- **T2 -- Tier camoufox.** Meme worker, `tier=camoufox` ; `_kill_after_deadline` et
  la seconde passe par nouveaute de PID disparaissent (le groupe de processus les
  remplace ; M2 dit si la passe par marqueur reste). `_check_final_document` et
  `_is_hostname_shaped` factorises au passage (6f235a20, appends du 2026-10-09).
- **T3 -- Nettoyage.** Suppression du thread proprietaire dans browser et camoufox,
  mise a jour de `tiers.py` selon Q2, ADR passe en ACCEPTED, carte 6f235a20 close
  par cet ADR (sauf uc).
- **T4 -- Worker chaud (option B), conditionnelle a M1.**

Chaque tranche est un gate complet (reviewer + security-auditor sur T1 et T2 :
le worker est une nouvelle surface d'execution qui recoit une requete du parent).

## Consequences

Positives : une seule mecanique de liveness pour deux tiers ; chaque classe
d'incident (crash, gel, timeout, driver mort, proxy bloque) a le meme remede ;
le processus long ne porte plus aucun thread Playwright ; les tests de gel
deviennent des tests de processus, reproductibles sans `_HangingBrowser`.

Negatives : un demarrage d'interpreteur par fetch (M1) ; un protocole JSON a
maintenir ; une surface de plus pour le security-auditor (le worker lit stdin) ;
les tests unitaires du cycle navigateur passent par un sous-processus ou par un
appel direct de la fonction du worker (les deux sont a prevoir : l'appel direct
garde les tests rapides sur Windows).

Risques residuels : un navigateur qui change de session (`setsid`) echappe au
groupe (M2, filet par marqueur) ; un worker qui ecrit un document `result` puis
se fige tient la porte jusqu'au budget restant (D4, resultat conserve).

## Questions ouvertes

- **Q1 (operateur)** : M1 au-dela de quel seuil declenche T4 ? Proposition : 50 %
  du fetch nominal.
- **Q2 (operateur, gel PyPI)** : les *termes* rendus par `BrowserBudget.check` et
  `CamoufoxBudget.check` font-ils partie du contrat gele, ou seulement les
  signatures et `TermName` ? Si les termes sont geles, `tiers.py` garde les termes
  actuels jusqu'a la 0.2.0 et l'ADR note l'ecart ; sinon T3 les met a jour.
- **Q3 (challenger)** : le worker doit-il refaire `validate_target` (defense en
  profondeur, un DNS de plus par fetch) ou faire confiance au parent (le proxy
  re-pinne de toute facon au CONNECT) ? Position de l'ADR : confiance au parent,
  le proxy est le controle primaire et il tourne dans le worker.
- **Q4 (challenger)** : `start_new_session=True` detache aussi le worker du
  terminal de controle et de la propagation de SIGTERM par `tini` au groupe
  d'uvicorn. A l'arret du conteneur, un worker en vol serait tue par le kill en
  bloc du parent (atexit) ou par la mort de PID 1. A verifier en image
  (`docker stop -t 30`, mesure deja faite une fois a 0,42 s en d8b7b8fd).
