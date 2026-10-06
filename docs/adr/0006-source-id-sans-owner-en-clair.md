# ADR 0006 -- source_id sans owner_id en clair

- **Statut** : PROPOSED (2026-10-06), carte roadmap `02843ecd`
- **Amende** : ADR 0001, ligne 313 (format de `make_source_id`)
- **Invariants concernes** : 7 (config et etat separes), 10 (`owner_id` jamais serialise)

## Contexte

`make_source_id` (`registry/ports.py:239`) renvoie
`{owner}:{product_key}:{site}:{sha256(url)[:12]}`. Le `source_id` atteint le
client (HTML, chemins `/history/{sid}` et `/sources/{sid}`, mail de digest),
donc `owner_id` aussi. L'operateur a tranche : le format interne change et les
donnees existantes sont migrees (l'alias opaque a la frontiere est ecarte).

Faits mesures qui contraignent la decision :

- Les `owner_id` crees par le CLI sont `uuid4().hex[:12]` (48 bits), et
  `config import --owner` accepte une chaine arbitraire (`cli-import` par
  defaut cote Principal, `bootstrap` cote backfill de state.db). Un hachage
  sans cle est donc inversible par enumeration.
- `sources.owner_id` n'a pas de cle etrangere vers `owners` : un owner peut
  avoir des sources sans ligne `owners`.
- `KERDOOS_SESSION_SECRET` n'est exige que par `create_app`. Les commandes CLI
  (`run`, `config import`, evaluateur de digest) tournent sans secret.
- `make_source_id` n'a qu'un appelant (`AppService.add_source`). Un
  `source_id` est calcule a la creation puis relu en base, jamais recalcule.
- state.db contient des `source_id` herites sans prefixe owner
  (`legacy:kabum:1`, `amazon:1`), rattaches a l'owner `bootstrap`.

## Decision

### D1 -- Schema

```
tag       = HMAC-SHA256(cle, b"kerdoos/source-id/owner/v1\0" + owner_id)[:32 hex]
source_id = {tag}:{product_key}:{site}:{sha256(url)[:12]}
```

`derive_owner_tag(key, owner)` et `make_source_id(owner_tag, product_key,
site, url)` restent des fonctions pures de `registry/ports.py`. 128 bits de
tag : une collision entre deux owners ferait perdre en silence l'ajout du
second (`ON CONFLICT(source_id) DO NOTHING`), d'ou l'absence de troncature
courte.

### D2 -- Ou vit la cle

La cle (32 octets aleatoires) est generee une fois et stockee dans
**config.db**, table `meta`. Elle ne sort pas de l'adaptateur : le port expose
`owner_tag(owner) -> str`, pas la cle.

Options ecartees :

- **Cle en variable d'environnement.** Elle imposerait un secret au CLI, qui
  n'en demande aucun aujourd'hui. Deux processus aux environnements divergents
  produiraient deux tags pour le meme owner, sans erreur. Son cycle de vie
  serait distinct de celui des sources qu'elle nomme.
- **Sel aleatoire par owner.** La table `owners` ne couvre pas tous les owners
  (pas de cle etrangere), et la migration de state.db devrait recevoir une
  table de correspondance au lieu d'une fonction.
- **Reutiliser `KERDOOS_SESSION_SECRET`.** Sa rotation est une operation
  normale (invalider les sessions) ; elle renommerait toutes les sources.

Consequences assumees :

- La cle n'a pas de rotation. La changer ne modifie pas les `source_id`
  existants (ils sont stockes), mais les nouveaux porteraient un autre tag.
- Perdre config.db, c'est perdre la cle et les sources ensemble. Reimporter le
  YAML dans un config.db neuf ne rattache plus l'historique de state.db
  (regression par rapport au format deterministe actuel). La restauration
  passe par la sauvegarde du fichier config.db.
- state.db enregistre une empreinte de la cle. Si elle differe de celle de
  config.db au demarrage, le processus refuse de demarrer avec une erreur
  nommee.

### D3 -- Migration sur deux bases sans transaction commune

La reecriture est une fonction pure de donnees presentes dans chaque ligne :

```
nouveau = owner_tag(owner_id) || substr(source_id, length(owner_id) + 1)
   pour les lignes ou substr(source_id, 1, length(owner_id) + 1) = owner_id || ':'
```

Les lignes heritees sans prefixe owner ne correspondent pas et restent
intactes. Chaque base porte son propre marqueur `meta.source_id_scheme`,
ecrit dans la meme transaction que sa reecriture.

Ordre, execute par une fonction de la couche application appelee aux deux
racines de composition (`_build_app_service`, `create_app`) avant la
construction d'`AppService` :

1. config.db : generer la cle si absente, commit.
2. state.db : `BEGIN IMMEDIATE`, relire le marqueur, reecrire `scrapes`,
   ecrire marqueur et empreinte de cle, commit.
3. config.db : `BEGIN IMMEDIATE`, `PRAGMA defer_foreign_keys = ON`, reecrire
   `sources` puis `digest_job_sources`, ecrire le marqueur, commit.

Proprietes :

- **Reprise** : un arret entre 2 et 3 laisse state.db migre et config.db non
  migre, cle presente. Le demarrage suivant saute 2 et execute 3. Aucun trafic
  n'est servi dans l'etat mixte, la fonction s'executant avant `AppService` et
  levant en cas d'echec.
- **Idempotence** : marqueur relu dans la transaction ; base neuve = zero
  ligne reecrite, marqueur pose.
- **Retour arriere** : la reecriture est symetrique (remplacer le tag par
  `owner_id`, present dans chaque ligne). Une commande CLI l'applique avant un
  retour a une image anterieure. Aucune table de correspondance n'est stockee.
- **Invariant 7** : state.db ne lit jamais config.db. La couche application
  lui passe la fonction `owner_tag` et l'empreinte.

Le marqueur n'est pas `PRAGMA user_version` : les deux stores l'ecrasent sans
condition a chaque ouverture.

### D4 -- Anciennes URL

`/history/{ancien_sid}` et `/sources/{ancien_sid}` ne sont pas redirigees.
Une redirection garderait vivantes des URL qui portent `owner_id` : chaque
acces le reecrirait dans les journaux du reverse proxy et dans le Referer, ce
qui est le vecteur que la carte ferme. `GET /history/{sid}` renvoie 404 quand
la source n'appartient pas au registre de l'owner, meme reponse que pour une
source inexistante. Aujourd'hui cette route renvoie 200 avec une page vide
dont le titre reprend le parametre de chemin.

### D5 -- Libelle du digest

`DigestLineView.source_label` vaut `{nom du produit} -- {site}`, jamais le
`source_id`. Le digest texte (`render_digest`) suit la meme regle.

## Hors perimetre

- `mcp/auth.py:31-32` (`owner_id` dans `AccessToken.client_id` / `subject`) :
  carte separee, voir la note de conception de la carte `02843ecd`.
- `packages/autolycos` : aucune occurrence de `source_id`.
