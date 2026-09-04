# ADR 0000 -- Decisions fondatrices : versioning, orchestration, persistance

- **Statut** : ACCEPTED (2025-07) -- decisions anterieures a
  [ADR 0001](./0001-plateforme-post-mvp-webui-mcp-multitenant.md), prises
  pendant la phase de conception initiale (spike + design). Redigees ici
  apres coup pour leur donner le meme format que les ADR suivants.
- **Date** : 2025-07
- **Portee** : trois decisions negatives (ce que Kerdoos ne fait pas) qui ont
  cadre l'architecture avant que les phases d'implementation ne commencent.
  Aucune n'a ete revisitee depuis.
- **Sources de verite** : conception initiale du projet (design de depart,
  aujourd'hui remplace par `docs/adr/` comme source de verite architecture).

## Contexte

Avant la premiere ligne de code, trois choix structurels ont ete tranches et
n'ont plus ete rediscutes : comment versionner le sous-systeme anti-bot par
rapport au coeur, si un outil d'orchestration de veille existant pouvait
servir de base, et quel mecanisme de persistance porter pour l'etat de
scrape. Les trois partagent la meme forme : rejeter une option "evidente" au
profit d'une option plus simple mais moins prestigieuse.

## Decision 1 -- Pas de submodule git, monorepo-first

**Probleme.** Le sous-systeme anti-bot (aujourd'hui `autolycos`) devait-il
vivre dans un depot Git separe, relie au coeur par un submodule, des le
depart ?

**Decision : monorepo au demarrage, avec une frontiere de module nette,
concue pour extraction ulterieure en package versionne. Pas de git
submodule.**

**Pourquoi rejeter le submodule.** Un submodule ne se justifie que pour un
composant deja partage entre plusieurs depots avec un cycle de release
independant. Au demarrage, il n'a qu'un seul consommateur et n'apporte que
de la friction (HEAD detache, pointeur a committer, CI plus complexe) sans
aucun benefice : la bonne frontiere n'est pas un depot, c'est une **API de
package** (le port `Fetcher`). Un depot separe des le demarrage etait
egalement premature : gerer une dependance inter-depots pour un seul
consommateur est un cout sans contrepartie tant que la frontiere n'est pas
stabilisee.

**Regle retenue : monorepo-first, extract-later.** Le sous-systeme anti-bot
reste un package interne du workspace **sans dependance vers le coeur**
(invariant 2), donc extractible sans refactor le jour ou la frontiere est
stable et ou l'extraction apporte une valeur reelle (publication PyPI,
reutilisation communautaire). Cette extraction reste ouverte
(`docs/adr/0002-productionisation.md` Decision 8) mais n'a jamais ete la
decision de depart.

## Decision 2 -- Pas de fork ni d'adoption de changedetection.io

**Probleme.** `changedetection.io` est un outil de veille de pages existant,
avec registre de watches, planification et notification deja construits.
Pouvait-il devenir le centre de gravite de Kerdoos, ou etre force pour
couvrir les besoins specifiques (fetch `tls`, contournement Akamai) ?

**Decision : ne pas en faire le centre de gravite, ne pas le forker.**

**Pourquoi rejeter l'adoption/le fork.** L'outil ne portait nativement ni le
fetch `tls` (necessaire pour au moins un site de la matrice initiale), ni le
contournement d'un anti-bot Akamai (necessaire pour un autre). Le routeur
anti-bot dynamique et le mode de veille large que Kerdoos visait n'y
seraient entres qu'au prix d'un fork -- un cout de maintenance permanent
(treadmill anti-bot) pour un outil qui n'est pas concu pour ce cas d'usage.

**Regle retenue.** L'outil reste pertinent comme **adaptateur d'orchestration
possible** pour de la surveillance generique de pages (changements non lies
au prix), et pour son support natif de solveurs Cloudflare -- mais Kerdoos
construit son propre orchestrateur leger plutot que d'heriter d'une couche
d'acces qu'il n'aura jamais.

## Decision 3 -- SQLite plutot que des fichiers plats

**Probleme.** Quel mecanisme de persistance pour l'historique de scrape
(succes et echecs, base du suivi de prix et des deltas de digest) : fichiers
plats (JSON, CSV) ou une base relationnelle ?

**Decision : SQLite des le depart pour l'etat de scrape (`StateStore`).**

**Pourquoi rejeter les fichiers plats.** Le besoin est relationnel des le
premier jour : un historique complet par source, avec des requetes
(tendances de prix, variations d'une periode a l'autre, filtrage par statut)
que JSON ou CSV ne servent qu'au prix d'une reecriture complete de la couche
de persistance des qu'une interface d'administration devient necessaire.

**Regle retenue.** SQLite ne demande aucun serveur au demarrage, et la
migration vers Postgres (si la concurrence ou l'echelle l'exigent un jour)
se fait sans changer le schema ni la couche `StateStore` (repository
pattern) -- l'abstraction absorbe le changement de moteur, pas le coeur.
Cette meme discipline s'applique a `ConfigStore` (invariant 7 : config et
etat physiquement separes).

## Consequences

- Le sous-systeme anti-bot est un package du workspace, pas un submodule ;
  son extraction en depot separe reste une decision differee, jamais
  bloquante pour le coeur (invariant 2).
- Aucune dependance vers un outil de veille tiers pour le coeur de Kerdoos ;
  un tel outil resterait, au mieux, un adaptateur optionnel derriere un
  port.
- `ConfigStore` et `StateStore` sont tous deux portes par SQLite, chacun
  derriere sa propre abstraction (invariant 7), ce qui rend une migration
  Postgres locale a la couche de persistance.
