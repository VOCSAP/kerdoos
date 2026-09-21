# Issue tracker -- roadmap partagée claude-peers

Les issues, tickets et specs de Kerdoos vivent dans la **roadmap partagée**
exposée par le serveur MCP `claude-peers`, scopée à ce dépôt et partagée
entre toutes les sessions Claude, présentes et futures. Ni GitHub Issues
(le dépôt public n'en utilise pas comme file de travail), ni fichiers locaux.

## Opérations

| Intention | Outil |
|---|---|
| Créer un ticket | `mcp__claude-peers__roadmap_add` |
| Lister / filtrer | `mcp__claude-peers__roadmap_list` |
| Lire une carte | `mcp__claude-peers__roadmap_get` |
| Modifier (statut, priorité, tags) | `mcp__claude-peers__roadmap_update` |
| Annoter sans écraser | `mcp__claude-peers__roadmap_append_context` |
| Clore définitivement | `mcp__claude-peers__roadmap_archive` |

Une carte est adressée par son id ou un préfixe d'id unique (8 caractères
suffisent en général). Il n'y a **pas** de numéro `#N` : ne jamais inventer
de référence de type issue GitHub.

## Conventions de carte

- `kind` : `feature` | `bug` | `debt` | `idea` | `chore`.
- `priority` : MoSCoW (`must` | `should` | `could` | `wont`), défaut `could`.
- `status` : `idea` -> `planned` -> `in_progress` -> `done`.
  `in_progress` **verrouille** la carte sous le peer_id courant : ne le poser
  qu'au démarrage réel du travail, et repasser à `planned` si le travail
  s'arrête avant la fin.
- `context` : **toujours rempli**. C'est le briefing pour une session future
  qui n'aura aucun contexte de celle-ci -- objectif, périmètre, fichiers et
  tests concernés, critères d'acceptation, décisions déjà prises.
- `tags` : porte aussi le vocabulaire de triage (`docs/agents/triage-labels.md`).
- Langue : titres et contenus en français, identifiants de code en anglais,
  jamais de tiret cadratin.

## Quand un skill dit « publier dans l'issue tracker »

Créer une carte via `roadmap_add`, `context` rempli.

## Quand un skill dit « récupérer le ticket concerné »

`roadmap_get <id>` ; si l'id est inconnu, `roadmap_list` avec un filtre
(`q`, `statuses`, `kinds`) plutôt qu'un listing complet du board.

## Pull requests comme surface de requête

**Non.** Le dépôt est public mais les PR externes ne passent pas par la file
de triage. Basculer ce drapeau à `oui` ici si cela change.

## Ce qui ne vit PAS dans le tracker

`task_plan.md` (plan de phases historique), `findings.md` et `progress.md`
sont des traces de développement locales non trackées. Les faits non évidents
et décisions vont dans Kleos, pas en carte. Les ADR vont dans `docs/adr/`.
