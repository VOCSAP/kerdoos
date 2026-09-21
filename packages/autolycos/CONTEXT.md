# Autolycos (recuperation de pages sous protection anti-bot)

Le contexte de la recuperation : obtenir le HTML d'une URL sur un site protege,
au cout le plus bas qui passe, sans jamais juger ce que la page contient. Ce
contexte ignore le metier de l'appelant : aucun terme de produit, de prix ni de
notification n'y a sa place.

## Recuperation

**Fetcher** :
La capacite de rendre le HTML d'une URL. Un fetcher rapporte ce qu'il a obtenu
et ce qu'il a rencontre, il ne conclut rien.
_Avoid_ : scraper, client, downloader

**Fetch result** :
L'issue d'une tentative : le HTML, le code HTTP BRUT, la methode employee, et
si la reponse portait un challenge. Le code HTTP n'y est pas un verdict :
traduire un resultat en verdict est le travail de l'appelant.
_Avoid_ : reponse, verdict, statut

## Tiers, noms et adaptateurs

Trois angles volontairement distincts du meme palier. Ne pas les confondre :
l'un est une decision, l'autre une clef, le troisieme du code.

**Tier** :
Un palier de cout et de politique. Les paliers sont ordonnes par cout croissant
(`http`, `tls`, `browser`, `uc`, `camoufox`) mais cet ordre n'est pas un
parcours : aucune escalade automatique, chaque site declare le palier le moins
couteux qui passe chez lui. Le mot ne designe jamais un palier de prix.
_Avoid_ : niveau, strategie, mode, fallback

**Fetcher name** :
La clef de lookup d'un tier, telle qu'une configuration l'ecrit et qu'un router
la resout. C'est une chaine, pas une politique.
_Avoid_ : tier (dans une signature), type de fetcher

**Adapter** :
L'implementation concrete qui encapsule UN outil externe derriere le port
Fetcher. C'est le seul endroit du systeme ou le nom d'un outil apparait.
_Avoid_ : driver, backend, plugin

**Router** :
La politique de selection : d'un fetcher name vers un fetcher. Couche distincte
des adaptateurs, qui n'en connaissent aucune.
_Avoid_ : factory, dispatcher, selecteur

**Tier availability** :
Le fait qu'un tier soit reellement utilisable ici, sa dependance optionnelle
etant importable et son binaire present. Distinct de l'existence du tier, qu'un
router connait toujours.
_Avoid_ : tier supporte, tier installe

## Protection rencontree

**Challenge** :
Une reponse qui n'est pas fiable comme contenu : blocage dur du serveur,
interstitiel anti-bot, ou page trop courte pour etre plausible. Concept UNIQUE,
delibere : l'appelant traite les trois identiquement, comme un indetermine, et
une reponse challengee ne doit jamais etre lue comme une absence de produit.
_Avoid_ : bloque, banni, refuse, captcha

**Challenge marker** :
Une empreinte textuelle dans le HTML qui trahit un dispositif de protection
actif. Propre a un dispositif, pas a un site.
_Avoid_ : signature, pattern, marker (nu, voir launch tag)

**Chrome error page** :
Le signal distinct que le navigateur n'a PAS atteint le site. Ce n'est pas une
protection servie par le site : ne pas le compter comme un challenge.
_Avoid_ : page d'erreur, echec de navigation

## Surete reseau

**Navigation allowlist** :
Le controle anti-SSRF PRIMAIRE : la liste des domaines vers lesquels
naviguer est autorise, injectee par l'appelant. Ce contexte ne code en dur aucun
domaine legitime.
_Avoid_ : domaines autorises (nu), whitelist, liste de sites

**Subresource domain** :
Un domaine de CDN dont le navigateur peut charger une sous-ressource de rendu,
en PLUS du domaine de navigation. Defense en profondeur propre aux tiers
navigateur, jamais un elargissement de la navigation autorisee.
_Avoid_ : domaine autorise, allowlist, domaine tiers

**Validated target** :
Une cible qui a passe tous les controles de surete, avec l'adresse a epingler.
Resolue UNE fois pour fermer la fenetre de re-resolution DNS.
_Avoid_ : URL validee, cible sure

**Pinned address** :
Le couple hote-port deja resolu et valide qu'un tunnel accepte d'ouvrir. Meme
garantie qu'une validated target, autre point d'application.
_Avoid_ : adresse resolue, IP cible

**Pinning proxy** :
Le mandataire local qui epingle l'adresse pour les tiers navigateur, parce
qu'un navigateur lance localement ne doit jamais resoudre lui-meme. C'est le
controle primaire pour ces tiers, pas un confort.
_Avoid_ : proxy, tunnel, mandataire sortant

## Concurrence et budgets

**Browser gate** :
Le jeton partage qui borne le nombre de navigateurs lances simultanement, tous
tiers navigateur confondus. Le mot gate est reserve a ce sens : un obstacle pose
par un site se nomme un challenge.
_Avoid_ : semaphore, verrou, limite

**Budget** :
L'ensemble des durees d'un tier navigateur, et la coherence exigee entre elles.
Un budget ne mesure rien a l'execution : il declare ce qui doit tenir ensemble.
_Avoid_ : timeouts, limites, quotas

**Budget term** :
Une duree nommee d'un budget, avec sa multiplicite. C'est un sommant, pas un
reglage independant.
_Avoid_ : timeout, parametre, delai

**Budget warning** :
Le constat qu'un budget est mal forme : une duree englobante peut expirer avant
ce qu'elle englobe, ou une attente peut retenir la porte partagee trop
longtemps. Un avertissement structure, jamais un message deja redige.
_Avoid_ : erreur de config, alerte

**Launch tag** :
L'etiquette unique injectee dans les arguments de lancement d'un fetch, qui
permet de retrouver exactement l'arbre de processus de CE fetch au nettoyage.
Sans rapport avec les challenge markers.
_Avoid_ : marker, id de lancement, uuid
