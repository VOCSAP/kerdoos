# Libellés de triage

Les skills parlent en cinq rôles canoniques. La roadmap `claude-peers` n'a pas
de champ « label » : ces rôles sont portés dans le champ **`tags`** de la
carte. Les chaînes sont identiques aux rôles.

| Rôle dans mattpocock/skills | Tag de carte | Signification |
| --- | --- | --- |
| `needs-triage` | `needs-triage` | Le mainteneur doit évaluer cette carte |
| `needs-info` | `needs-info` | En attente d'information du rapporteur |
| `ready-for-agent` | `ready-for-agent` | Entièrement spécifiée, prête pour un agent AFK |
| `ready-for-human` | `ready-for-human` | Demande une implémentation humaine |
| `wontfix` | `wontfix` | Ne sera pas traitée |

Quand un skill évoque un rôle (« applique le libellé AFK-ready »), écrire la
chaîne correspondante dans `tags` via `roadmap_update`. Un tag de triage est
exclusif des quatre autres : retirer l'ancien en réécrivant la liste complète,
`roadmap_update` remplace le champ.

`wontfix` ne remplace pas l'archivage : marquer le tag, puis
`roadmap_archive` quand la décision est définitive.

Éditer la colonne du milieu si le vocabulaire change.
