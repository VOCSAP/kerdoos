# ADR 0006 -- source_id sans owner_id

- **Statut** : ACCEPTED (2026-10-06, valide par l'operateur), carte roadmap `02843ecd`
- **Historique** : PROPOSED le 2026-10-06 (revision 2, owner retire du `source_id`)
- **Amende** : ADR 0001, lignes 312-319 (format de `make_source_id`)
- **Invariant concerne** : 10 (`owner_id` jamais serialise vers le client)

## Contexte

`make_source_id` (`registry/ports.py:239`) renvoie
`{owner}:{product_key}:{site}:{sha256(url)[:12]}`. Le `source_id` atteint le
client (HTML, chemins `/history/{sid}` et `/sources/{sid}`, mail de digest),
donc `owner_id` aussi.

La revision 1 de cet ADR hachait l'owner avec une cle stockee dans config.db.
Elle est abandonnee pour deux raisons :

- L'owner ne figure dans le `source_id` que pour garder `sources.source_id`
  unique entre tenants. Toutes les lectures et ecritures filtrent deja par
  owner, et aucun code ne decoupe le format.
- Une cle dans config.db cassait l'aller-retour `config export` /
  `config import` que l'ADR 0001 (lignes 324-325) designe comme sauvegarde.

L'operateur a confirme qu'aucune donnee n'existe en production : il n'y a pas
de migration de donnees a concevoir.

## Decision

### D1 -- Format

```
source_id = {product_key}:{site}:{sha256(url)[:12]}
make_source_id(product_key, site, url)
```

Le `source_id` identifie une source **a l'interieur d'un owner**. Il n'est
plus unique entre tenants et ne doit jamais etre utilise sans l'owner. Deux
owners qui suivent la meme URL partagent le meme `source_id`.

Consequence utile : un reimport du YAML dans un config.db neuf redonne les
memes `source_id`, donc l'historique de state.db se rattache de nouveau.

### D2 -- Unicite par cle composite (config.db)

```sql
CREATE TABLE sources (
    source_id    TEXT NOT NULL,
    owner_id     TEXT NOT NULL,
    product_key  TEXT NOT NULL,
    site         TEXT NOT NULL,
    url          TEXT NOT NULL,
    PRIMARY KEY (owner_id, source_id),
    UNIQUE (owner_id, product_key, site, url),
    FOREIGN KEY (owner_id, product_key) REFERENCES products (owner_id, product_key),
    FOREIGN KEY (site) REFERENCES sites (name)
);

CREATE TABLE digest_job_sources (
    owner_id   TEXT NOT NULL,
    job_id     TEXT NOT NULL,
    source_id  TEXT NOT NULL,
    PRIMARY KEY (job_id, source_id),
    FOREIGN KEY (job_id) REFERENCES digest_jobs (id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id, source_id)
        REFERENCES sources (owner_id, source_id) ON DELETE CASCADE
);
```

`add_source` passe a `ON CONFLICT(owner_id, source_id) DO NOTHING`.

Sans la cle composite, retirer l'owner du `source_id` ferait perdre en silence
la source du second owner (`ON CONFLICT(source_id) DO NOTHING`). La cle
etrangere composite apporte en plus une garantie physique : un job ne peut pas
etre lie a la source d'un autre owner.

state.db ne change pas : `scrapes` filtre deja par `owner_id` et `source_id`.

### D3 -- config.db existant a l'ancien schema

`CREATE TABLE IF NOT EXISTS` ne modifie pas une table existante : une base
anterieure garderait l'ancienne cle primaire, et chaque `add_source`
echouerait avec `ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE
constraint`.

Regle, appliquee a l'ouverture de `SqliteConfigStore`, avant toute instruction
de schema : des que l'ancien schema est detecte par sa forme (`PRAGMA
table_info(sources)` : `source_id` seul en cle primaire), l'ouverture leve une
`ConfigError` nommee qui demande de recreer config.db puis de relancer
`kerdoos config import`. Rien n'est supprime, renomme ni cree.

Refus inconditionnel retenu (arbitrage team-lead) : les seules bases a
l'ancien schema sont des bases de developpement sans source, ou un `config
export` bloque ne perd rien. La recreation des tables vides est ecartee : elle
exige du code de suppression de table pour un cas qui n'existe pas en
production.

`_SCHEMA_VERSION` de config.db passe a 5. Celui de state.db ne bouge pas.

### D4 -- URL

`GET /history/{sid}` renvoie **404** quand la source n'appartient pas au
registre de l'owner : source inexistante, source d'un autre owner et ancienne
URL au format a owner donnent la meme reponse. Aujourd'hui cette route renvoie
200 avec une page vide dont le titre reprend le parametre de chemin
(`web.py:148-159`).

Aucune redirection depuis les anciennes URL : elles portent `owner_id`, et les
garder en service le ferait reecrire dans les journaux du reverse proxy a
chaque acces.

`DELETE /sources/{sid}` reste un no-op silencieux sur un `sid` inconnu
(comportement actuel, sans oracle d'existence).

### D5 -- Libelles

- `DigestLineView.source_label` (`digest/view.py:81`) vaut
  `{nom du produit} -- {site}`, jamais le `source_id`.
- Le digest texte (`digest/render.py:122`) suit la meme regle.
- Le tableau de bord n'affiche plus le `source_id` d'un enregistrement sans
  source au registre (`web.py:99`) : libelle neutre a la place.

### D6 -- ADR 0001

Les lignes 312-319 de l'ADR 0001 sont remplacees par :

> **`source_id` n'inclut pas l'owner** (ADR 0006) :
> `make_source_id(product_key, site, url) = f"{product_key}:{site}:{sha256(url)[:12]}"`.
> L'unicite entre tenants est portee par la cle primaire composite
> `(owner_id, source_id)` de `sources`. **Contrat gate** : l'`owner` vient
> TOUJOURS du `Principal` resolu, jamais d'un champ du body ; un `source_id`
> n'est jamais utilise sans lui ; `product_key` rejette le separateur `:`.

## Lot unique pour le developer

Fichiers touches :

| Fichier | Changement |
|---|---|
| `packages/kerdoos/src/kerdoos/registry/ports.py` | `make_source_id(product_key, site, url)`, docstrings |
| `packages/kerdoos/src/kerdoos/registry/sqlite_store.py` | schema D2, `_migrate` D3, `ON CONFLICT`, `_SCHEMA_VERSION` |
| `packages/kerdoos/src/kerdoos/core/app/services.py` | appel de `make_source_id` (ligne 235) |
| `packages/kerdoos/src/kerdoos/digest/view.py` | `source_label` |
| `packages/kerdoos/src/kerdoos/digest/render.py` | libelle du digest texte |
| `packages/kerdoos/src/kerdoos/digest/smtp_sender.py`, `digest/sender.py`, `core/evaluator.py`, `interfaces/cli/main.py` | fournir nom de produit et site aux deux rendus, si leur signature change |
| `packages/kerdoos/src/kerdoos/interfaces/web/routers/web.py` | 404 de `/history`, libelle neutre ligne 99, preview |
| `docs/adr/0001-plateforme-post-mvp-webui-mcp-multitenant.md` | D6 |
| `tests/test_persistence.py`, `tests/test_tenancy.py`, `tests/test_config_import.py` | format et signature |
| `tests/test_web_auth.py` | `OwnerIdNeverRenderedInHtmlTest` avec sources |
| `tests/test_digest_view.py`, `tests/test_digest.py`, `tests/test_smtp_sender.py` | libelles |
| `tests/test_migration.py` ou nouveau fichier | D3 |

Non touches : `packages/autolycos` (aucune occurrence de `source_id`),
`persistence/sqlite_store.py`, `interfaces/mcp` (carte `88d38672`).

Tests obligatoires :

1. **Deux owners, meme `product_key` / site / URL.** Chacun ajoute la source
   par `AppService.add_source` ; chacun la voit dans son registre ; chacun a
   son propre historique ; supprimer celle de l'un laisse celle de l'autre.
2. **Lien inter-owner impossible.** Lier a un job la source d'un autre owner
   ne cree aucune ligne.
3. **Aucune fuite d'`owner_id`.** Compte seede par le vrai `add_source`, avec
   un `owner_id` distinctif, une source, un scrape et un job : `GET /`,
   `/products`, `/notifications`, `/history/{sid}`,
   `/notifications/{id}/preview`. L'`owner_id` est absent des corps, des
   en-tetes et de `Location`. Meme assertion sur le digest HTML et le digest
   texte.
4. **Controle negatif.** Avec l'ancien `make_source_id` remis en place, le
   test 3 echoue. A constater une fois, a consigner dans le rapport du lot.
5. **Test structurel.** Aucun fichier de `templates/**/*.html` ne contient
   `owner_id`.
6. **404.** `/history/{sid inconnu}` et `/history/{ancien format}` renvoient
   404, corps sans le parametre de chemin.
7. **D3.** Base a l'ancien schema : `ConfigError` nommee, base intacte (table
   et lignes inchangees).
8. **Idempotence de l'import.** Deux `config import` successifs ne levent pas
   et ne dupliquent rien.

## Hors perimetre

- `mcp/auth.py:31-32` (`owner_id` dans `AccessToken`) : carte `88d38672`.
