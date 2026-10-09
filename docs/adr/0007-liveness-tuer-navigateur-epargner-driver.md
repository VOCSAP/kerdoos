# ADR 0007 -- Liveness des tiers navigateur : tuer le navigateur, epargner le driver

- **Statut** : ACCEPTED (2026-10-09, decision operateur), carte roadmap `0778a9bc`.
  PROPOSED le meme jour sous la forme « un sous-processus worker par fetch »
  (commit `8def026`), rejetee apres mesures.
- **Amende** : ADR 0002 Decision 1 (contrat du plafond d'abandon de d8b7b8fd,
  renverse, voir D3) ; ADR 0004 Decision 5 (plafond camoufox, inchange en sens,
  confirme).
- **Livree par** : cartes `963a777e` (branche crash du tier browser, `main`
  `0e84a1e`) et `7a8b430a` (branches read-budget et deadline du tier browser,
  deadline du tier camoufox, `main` `7afed5c`).
- **Liens** : `6f235a20` (factorisation du motif de liveness, toujours ouverte),
  `7e7d6465` (termes de budget de `tiers.py`, gele PyPI).
- **Sources de verite** : Kleos #21229, #21230 (diagnostic), #21246, #21247
  (mesures T-a, T-b, T-c), #21235 (premiere decision operateur), code de `main`
  `7afed5c`.

## Contexte

Les tiers `browser` (patchright, Chromium) et `camoufox` (Firefox) executent chaque
fetch dans un thread proprietaire du cycle lancement -> navigation -> fermeture,
borne par un `join(timeout=fetch_timeout_seconds)` externe, parce que l'API sync de
Playwright n'est utilisable que depuis le thread qui a ouvert `sync_playwright()`
(MESURE, d8b7b8fd).

Fait mesure (Kleos #21229, #21230, image `a06a916`) : si le driver Node de
Playwright est tue pendant que ce thread est dans un appel sync, le thread ne sort
jamais. Il boucle dans `_sync_base.py:91-92` (`while not task.done():
self._dispatcher_fiber.switch()`), brule environ un coeur, tient le GIL et son
egress-proxy. Deux de ces threads font passer un fetch browser normal de 1,3-2,4 s a
7-8 s. Classe amont : playwright-python#3222. Jusqu'a 963a777e, chaque branche de
sortie anormale (crash, read-budget, deadline) tuait l'arbre entier, driver compris.

## Option rejetee -- un sous-processus worker par fetch

L'idee : deplacer le cycle navigateur dans un processus jetable, tue en bloc par
`killpg`, pour qu'aucun thread ne reste dans l'interpreteur long. Trois mesures
en image (`main` `0e84a1e`, patchright 1.61.2, playwright 1.61.0, camoufox 0.5.6,
Kleos #21246, #21247) l'invalident :

- **T-a** : dans les deux tiers, le navigateur est **leader de sa propre session**
  (PGID = SID = son PID ; `processLauncher.ts` lance avec `detached: true`). Le
  driver Node, lui, reste dans le groupe du processus Python. Un `killpg` sur le
  groupe d'un worker n'atteint donc jamais le navigateur.
- **T-b** : worker tue par `killpg` -> driver mort, navigateur gele (SIGSTOP)
  survivant a l'etat T, reparente a PID 1, **invisible** a `psutil
  children(recursive=True)` du parent, donc hors de portee de la passe par marqueur
  (`browser.py`, descendants de `os.getpid()`). Tuer seulement le PID du worker :
  sur EOF le driver ferme un navigateur qui repond, rien en 15 s s'il est gele.
- **T-c** : a l'echeance, tuer **seulement l'arbre du navigateur** en epargnant le
  driver libere le thread aussitot : 0 spinner, 0 enfant survivant, 3/3 par tier.

Le sous-processus ajoutait un niveau de processus, un transport et une surface
d'execution pour un cas (navigateur gele) que la discipline mesuree en T-c resout
dans le processus long. Rejet, decision operateur du 2026-10-09.

## Decision

### D1 -- Discipline « tuer le navigateur, epargner le driver »

Sur toute sortie anormale d'un fetch navigateur, le thread principal :

1. lit l'arbre du lancement par marqueur **avant** tout kill, et en separe le
   driver : c'est le parent du processus marque dont la ligne de commande porte
   l'argument exact `run-driver`. Le token textuel `patchright`/`playwright` est
   proscrit : le chemin de profil Firefox (`/tmp/playwright_firefoxdev_profile-*`)
   le porte aussi, et un chemin d'installation peut ne pas le porter ;
2. tue l'arbre navigateur seul (SIGKILL + attente bornee `_KILL_WAIT_SECONDS`) ;
   le driver echoue l'appel en cours et le thread se deroule de lui-meme ;
3. joint le thread sous une grace bornee ;
4. en dernier recours, si le thread vit encore, tue le driver (capture a l'etape 1,
   il n'est plus decouvrable par marqueur une fois le navigateur mort) et compte
   le thread au plafond.

La porte navigateur n'est relachee qu'apres ces etapes. La grace vaut
`min(budget restant, _KILL_WAIT_SECONDS)` sur les branches crash et read-budget
du tier browser, et `_KILL_WAIT_SECONDS` sur sa deadline (budget epuise, un
`min()` nul escaladerait aussitot et recreerait le spinner). Le tier camoufox
applique la meme discipline a sa deadline : passe 1 sans le driver, join sur la
grace existante (`late_sweep_seconds`), passe 2 complete.

### D2 -- Perimetre

`browser` : crash, read-budget, deadline. `camoufox` : deadline. `uc` : intact,
deprecie (ADR 0004 Decision 9). La factorisation des copies du motif reste la
carte `6f235a20`.

### D3 -- Contrat du plafond d'abandon, renverse

d8b7b8fd ne comptait qu'un kill non confirme (le thread, sans ressource OS, ne
comptait pas). Desormais **un thread vivant apres la grace compte**, jusqu'a sa
sortie ou, s'il ne sort jamais, jusqu'au redemarrage du processus : le risque
compte est le thread lui-meme (coeur, GIL, proxy), pas un processus. Le refus au
plafond reste une `FetchError` journalisee en ERROR, qui nomme cette permanence.
Camoufox comptait deja tout abandon jusqu'a la sortie du thread : inchange.

### D4 -- Tenue de porte, pire cas

`fetch_timeout + 3 x _KILL_WAIT_SECONDS` (attente de mort du navigateur, grace,
attente de mort du driver), atteint seulement sur le chemin d'escalade ; cas
typique sous `fetch_timeout + _KILL_WAIT_SECONDS`. `BrowserBudget.check`
(`tiers.py`, gele PyPI) declare encore un nettoyage nul : suivi `7e7d6465`, a la
prochaine ouverture du contrat.

## Residuel

Le gel du driver Node lui-meme n'est pas mesure. S'il survient, l'escalade de D1
le tue, le thread reste et compte au plafond ; le tier se refuse a partir de
`max_abandoned_fetches` threads vivants, jusqu'au redemarrage. Un redemarrage
volontaire du processus au plafond (compose `restart: unless-stopped`) est une
option **non decidee** : a proposer en carte, pas a acter ici.
