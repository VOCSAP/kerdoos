# Carte des contextes

Deux contextes, un par paquet du workspace uv. La frontiere n'est pas
cosmetique : elle est unidirectionnelle et physique.

## Contextes

- [Kerdoos](./packages/kerdoos/CONTEXT.md) : ce qu'un owner surveille, ce qui a
  ete observe, ce qui est notifie. Domaine, cadence, digests, multi-tenant.
- [Autolycos](./packages/autolycos/CONTEXT.md) : obtenir le HTML d'une URL sur
  un site protege, au cout le plus bas qui passe. Tiers, routage, surete
  reseau, budgets.

## Relations

- **Kerdoos -> Autolycos** : le coeur appelle le port Fetcher et injecte la
  navigation allowlist. La dependance ne va que dans ce sens : Autolycos
  n'importe jamais Kerdoos, et aucun de ses types ne porte un terme du metier
  (produit, prix, disponibilite, digest, owner).
- **Traduction de frontiere** : un fetch result porte un code HTTP brut et un
  challenge ; le coeur seul en derive un scrape status. Tout challenge devient
  `indeterminate`, jamais `unavailable`. Collapser les deux fabriquerait un faux
  retour en stock.
- **Seule valeur partagee** : le fetcher name. La fiche de site du coeur declare
  le tier exige, Autolycos le resout. Les budgets de tier sont publies par
  Autolycos ; le coeur les consomme sans les rejouer.

## Collisions de vocabulaire a connaitre

Trois mots changent de sens selon le contexte. Chaque glossaire les tranche pour
son cote ; les citer sans qualificatif dans un document commun est une erreur.

- **tier** : un palier de cout de recuperation (Autolycos). L'axe de prix
  reserve aux membres se nomme membership price cote Kerdoos, jamais un tier.
- **gate** : le jeton de concurrence navigateur (Autolycos). Un obstacle pose
  par un site se nomme un challenge.
- **marker** : une empreinte de protection dans le HTML (challenge marker). Une
  etiquette de processus se nomme un launch tag.
