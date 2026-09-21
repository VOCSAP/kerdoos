# Documentation de domaine

Comment les skills d'ingénierie doivent consommer la documentation de domaine
de ce dépôt avant d'explorer le code.

## À lire avant d'explorer

- **`CONTEXT-MAP.md`** à la racine : il pointe vers un `CONTEXT.md` par
  contexte. Lire ceux qui touchent le sujet en cours.
- **`docs/adr/`** à la racine : décisions à l'échelle du système
  (0000 décisions fondatrices, 0001 plateforme post-MVP, 0002
  productionisation, 0003 digest jobs, 0004 tier camoufox, 0005 serveur MCP).
  Lire les ADR qui touchent la zone de travail.
- **`packages/<paquet>/docs/adr/`** : décisions propres à un contexte, quand
  elles existent.

Si un de ces fichiers n'existe pas, **continuer en silence**. Ne pas signaler
son absence, ne pas proposer de le créer en amont. Le skill `/domain-modeling`
les crée paresseusement, quand un terme ou une décision est réellement tranché.

## Structure

Kerdoos est un workspace uv multi-contexte (`[tool.uv.workspace] members =
["packages/*"]`) :

```
/
├── CONTEXT-MAP.md
├── docs/adr/                          <- décisions système
└── packages/
    ├── kerdoos/                       <- coeur : domaine, scheduler, digest
    │   ├── CONTEXT.md
    │   └── docs/adr/                  <- décisions propres au coeur
    └── autolycos/                     <- sous-système anti-bot
        ├── CONTEXT.md
        └── docs/adr/                  <- décisions propres à autolycos
```

La frontière des deux contextes n'est pas cosmétique : `autolycos` n'importe
jamais `kerdoos` (invariant 2 de `CLAUDE.md`) et est destiné à vivre dans son
propre dépôt. Un terme du glossaire `autolycos` ne doit pas emprunter le
vocabulaire métier de `kerdoos`.

## Utiliser le vocabulaire du glossaire

Quand une sortie nomme un concept du domaine (titre de carte, proposition de
refactor, hypothèse, nom de test), employer le terme tel que défini dans le
`CONTEXT.md` du contexte concerné. Ne pas dériver vers un synonyme que le
glossaire écarte explicitement.

Si le concept n'est pas encore au glossaire, c'est un signal : soit on invente
un langage que le projet n'emploie pas (reconsidérer), soit il y a une vraie
lacune (la noter pour `/domain-modeling`).

## Signaler les conflits avec un ADR

Si une sortie contredit un ADR existant, le dire explicitement plutôt que de
l'écraser en silence :

> _Contredit l'ADR-0004 (tier camoufox par défaut), mais mérite réouverture
> parce que..._
