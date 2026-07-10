# Self-hosted fonts -- IBM Plex

Buildless self-host (no CDN at runtime, no bundler). These `woff2` are the
Latin subsets of IBM Plex, vendored so the WebUI serves them from `/static`.

| File | Family / weight | Role |
|---|---|---|
| `IBMPlexSans-Regular.woff2`  | Sans 400  | UI body |
| `IBMPlexSans-Medium.woff2`   | Sans 500  | labels, nav |
| `IBMPlexSans-SemiBold.woff2` | Sans 600  | headings |
| `IBMPlexMono-Regular.woff2`  | Mono 400  | tabular data (prices, deltas, timestamps) |
| `IBMPlexMono-Medium.woff2`   | Mono 500  | emphasised data |
| `IBMPlexSerif-Regular.woff2` | Serif 400 | digest preview only |

`@font-face` declarations live in `../css/tokens.css` with `font-display: swap`
and a system fallback stack, so the UI renders immediately (and stays usable if
an asset is ever missing).

## License

IBM Plex is licensed under the SIL Open Font License 1.1
(https://github.com/IBM/plex). Redistribution of the `woff2` is permitted under
the OFL. Source of these subsets: the `@fontsource/ibm-plex-*` v5 packages.
