# Kerdoos (coeur)

Le contexte metier : ce qu'un tenant surveille, ce qui a ete observe, et ce qui
est notifie. Il ne connait aucun outil de recuperation de pages, seulement des
ports.

## Tenant et identite

**Owner** :
Le tenant. Proprietaire exclusif de ses produits, de ses sources et de ses
digest jobs ; porte l'adresse d'envoi des digests.
_Avoid_ : tenant, client, compte, utilisateur

**Principal** :
L'identite appelante deja resolue par l'authentification, reduite a un owner et
un role. Seule source legitime d'un `owner_id` : jamais le corps d'une requete.
_Avoid_ : utilisateur courant, session, acteur

## Catalogue surveille

**Site** :
La fiche d'un e-commercant dans le catalogue global, partagee par tous les
owners : le tier de recuperation qu'il exige et le parser qui sait lire ses
pages.
_Avoid_ : marchand, boutique, domaine, vendeur

**Product** :
Un article qu'un owner suit, independamment de l'endroit ou il est vendu. Un
produit sans aucune source n'est pas une rupture de stock : il n'est pas
surveille.
_Avoid_ : article, item, reference

**Product key** :
L'identifiant d'un produit, choisi par l'owner et non genere. Unique dans le
perimetre de son owner seulement.
_Avoid_ : product id, id de produit, SKU

**Source** :
Le couple concret produit-sur-un-site, avec son URL. C'est la seule chose qui
se scrape, et l'unite a laquelle tout l'historique est rattache. Son
identifiant est derive de son contenu, jamais choisi.
_Avoid_ : lien, URL surveillee, cible, annonce

**Registry** :
La vue chargee pour un owner : le catalogue global de sites joint a ses propres
produits et sources.
_Avoid_ : catalogue, inventaire

## Observation

**Extract** :
Ce qu'un parser a lu sur une page, avant tout jugement : les prix trouves, la
disponibilite affichee, la devise. Un champ vide y signifie absent de la page,
et non pas zero.
_Avoid_ : parse result, donnees brutes

**Availability** :
La disponibilite telle qu'ECRITE sur la page. Distincte du verdict : une page
lisible qui annonce une rupture, et une page qu'on n'a pas su lire, ne sont pas
le meme fait.
_Avoid_ : stock, dispo

**Scrape status** :
Le verdict a trois valeurs d'une tentative de lecture : `ok`,
`indeterminate`, `unavailable`. `indeterminate` ne se replie JAMAIS sur
`unavailable` : un blocage anti-bot ou un 503 isole n'est pas une rupture de
stock.
_Avoid_ : code de statut, code HTTP, etat

**Scrape** :
Une tentative de lecture datee sur une source, conservee qu'elle ait reussi ou
non. L'historique est une suite de scrapes, jamais un etat courant ecrase.
_Avoid_ : releve, mesure, check

**Membership price** :
Le prix reserve aux membres d'un programme du marchand, par opposition au prix
public. C'est un axe de PRIX : ne jamais l'appeler un tier, mot reserve a
l'echelle de cout de recuperation.
_Avoid_ : tier, tier 2, pricing tier, prix palier

## Notification

**Digest job** :
La regle declarative d'un owner : quelles sources, a quelle cadence, dans quel
template. C'est de la configuration, pas de l'etat.
_Avoid_ : notification rule, regle de notification, alerte, abonnement

**Job options** :
Les reglages metier d'un digest, choisis dans une liste blanche fermee. Un
digest ne recoit jamais un jeu d'options libre.
_Avoid_ : parametres, settings, config du job

**Template** :
Un rendu fourni par le serveur, designe par une clef d'une liste blanche.
L'owner choisit et coche, il n'ecrit jamais de template.
_Avoid_ : theme, layout, modele libre

**Window** :
La borne de la fenetre planifiee qu'une execution consomme, quantifiee dans le
fuseau du job. C'est la clef d'idempotence d'un envoi, pas l'instant reel du
declenchement.
_Avoid_ : tick, creneau, horaire d'envoi

**Job run** :
Une execution d'un digest job pour une window donnee. Une fenetre porte au plus
une execution ; une execution ecrite consomme sa fenetre, meme en echec.
_Avoid_ : envoi, execution planifiee, firing

**Digest view** :
Le modele de presentation aplati donne au rendu : des chaines uniquement, aucun
objet de domaine. C'est le point de passage oblige avant tout templating.
_Avoid_ : payload, contexte de rendu

## Cadence

**Required period** :
La periode de scrape d'une source, DERIVEE a chaque evaluation comme la plus
frequente parmi les digest jobs actifs qui la referencent. Jamais stockee comme
une propriete de source.
_Avoid_ : frequence de la source, intervalle configure

**Best-available-latest** :
La regle de lecture d'un digest : il rend l'etat le plus recent disponible au
moment de l'envoi, sans jamais attendre un scrape frais. La fraicheur est garantie
en amont par la cadence, pas par l'attente.
_Avoid_ : etat frais, donnees a jour
