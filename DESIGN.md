# Kerdoos WebUI -- Design Guide

Visual design guide for the Kerdoos WebUI: intent, tokens, typography,
per-surface state matrix, and shell layout. For architecture and backend
design, see `docs/adr/`.

---

## 1. Intent

**Tenant.** A price/availability tracker for Brazilian marketplaces
(MercadoLivre, Magalu, Terabyte, Pichau, ...). The tenant typically arrives
from the morning digest email. They open the app once a day to answer one
question: *"what moved, and what is blocked (not out of stock)?"*. They
manage their watchlist (add/remove products and sources) and their API
access (bearer tokens).

**Admin.** A more technical operator: enrolls a site into the registry
(fetcher configuration), revokes tokens and sessions.

**Task.** Tenant: *triage the watchlist's health* -- spot price movements
and, above all, indeterminate states. Admin: *enroll a site*, *revoke
access*.

**Feel.** An observation room / a pre-dawn watch post (the hour the digest
is cut). Precise, alert, but calm. Neither a trading terminal (too noisy)
nor a meditation app (too soft). An instrument for reading a signal.

### Signature (the one element that could only exist for Kerdoos)

**The three-state determinacy signal** `{ok, indeterminate, unavailable}`
(architecture invariant: never confuse a transient anti-bot block with a
real stock-out). Every generic price tracker is binary (in stock / out of
stock). Kerdoos explicitly models a **third state** because an anti-bot
block is not a stock-out. The UI renders `indeterminate` as a first-class
citizen -- distinct color and glyph, never collapsed into `ok` or
`unavailable`. This status token is reused identically everywhere
(dashboard, history, digest preview).

**Secondary motif:** the **fetcher escalation scale**
(`http -> tls -> browser -> uc`) rendered as a 4-step micro-indicator --
"how hard we had to work to see this price". Supporting detail, not a hero
element.

### Explicitly rejected defaults

| Generic default | Replaced by |
|---|---|
| Binary green/red status dot | Three-state signal, `indeterminate` as a first-class misty indigo |
| Row of KPI cards (icon-left / big number / small label) | A "briefing" line leading with the count of items *to act on* (indeterminates + movements) |
| Colored sidebar with an active pill | Same-background sidebar, bronze active indicator (rule + weight), observatory feel |

---

## 2. Token foundation (`:root`, CSS custom properties)

**Depth strategy: borders-first + micro-shift of surface.** A dense
monitoring tool has no room for dramatic shadows; hierarchy comes from
low-opacity rules and small lightness jumps. One strategy, applied
consistently.

**Color world.** Cold slate neutrals (a pre-dawn watch post, not a warm
cream default). Warm bronze brand accent (Hermes epithet Kerdoos, "bringer
of gain"; the caduceus): warm, stands out against the cold slate, used very
sparingly (wordmark, active nav, primary action). The three-state semantic
is kept separate from the brand, maximally distinct:

- **ok** (read succeeded): calm, low-saturation aqua -- "clear channel",
  understated because it is the majority state.
  <br>
- **indeterminate** (the signature): **misty indigo** -- uncertainty
  rendered as fog, not as alert-yellow. Draws the eye (it is the actionable
  ambiguity).
- **unavailable** (confirmed out of stock): desaturated clay/rose -- an
  "empty shelf" state, calm, not alarming.

The semantics go through a layer of indirection (`--state-*`): a future
dark mode only needs to override the primitives under
`:root[data-theme="dark"]`, without touching any consuming surface.

```css
:root {
  /* --- Cold slate neutrals: surfaces (borders-first, micro-shift) --- */
  --bg-canvas:        #f4f6f8;  /* app background, off-white slate-tinted */
  --surface-1:        #ffffff;  /* card / panel */
  --surface-2:        #eef1f4;  /* inset input (darker than surroundings) */
  --surface-raised:   #ffffff;  /* dropdown/popover: +1 level, rule + subtle shadow */

  /* --- Text: 4 levels (never 2) --- */
  --text-primary:     #1b2430;  /* very dark slate, not pure black */
  --text-secondary:   #45535f;  /* supporting text */
  --text-tertiary:    #6b7885;  /* metadata, timestamps */
  --text-muted:       #9aa6b2;  /* disabled / placeholder */

  /* --- Borders: progression (low-opacity rules) --- */
  --border-subtle:    rgba(27,36,48,.06);  /* soft separation */
  --border-default:   rgba(27,36,48,.10);  /* standard */
  --border-strong:    rgba(27,36,48,.16);  /* emphasis */

  /* --- Brand: Hermes bronze, absolute restraint --- */
  --brand:            #9a6a3c;  /* bronze */
  --brand-hover:      #855a31;
  --brand-contrast:   #ffffff;  /* text on bronze */

  /* --- Three-state semantic (the signature system) --- */
  --state-ok:         #2f8f8a;  /* calm aqua */
  --state-ok-bg:      #e2f0ef;
  --state-indet:      #5b57b8;  /* misty indigo: first-class */
  --state-indet-bg:   #e7e6f5;
  --state-unavail:    #b0596a;  /* poised clay */
  --state-unavail-bg: #f4e4e7;

  /* --- System semantic (distinct from the 3 product states) --- */
  --danger:           #c0453f;  /* revoke, delete */
  --warning:           #b7791f;
  --success:           #2f8f5b;  /* successful action (toast) */

  /* --- Controls (dedicated tokens, never reuse surface tokens) --- */
  --control-bg:       var(--surface-2);
  --control-border:   rgba(27,36,48,.14);
  --focus-ring:       #5b57b8;  /* aligned with indigo, 2px + offset */

  /* --- Spacing: base 4px --- */
  --space-1: 4px;  --space-2: 8px;  --space-3: 12px; --space-4: 16px;
  --space-5: 24px; --space-6: 32px; --space-8: 48px; --space-10: 64px;

  /* --- Radius: scale (crisp = instrument) --- */
  --radius-sm: 4px;   /* inputs, buttons */
  --radius-md: 8px;   /* cards */
  --radius-lg: 12px;  /* modals */

  /* --- Type: scale + roles (see section 3) --- */
  --font-ui:   "IBM Plex Sans", system-ui, sans-serif;   /* self-hosted @font-face */
  --font-data: "IBM Plex Mono", ui-monospace, monospace; /* tabular data */
  --font-doc:  "IBM Plex Serif", Georgia, serif;         /* digest preview only */

  --text-xs: 12px; --text-sm: 13px; --text-base: 14px;
  --text-lg: 16px; --text-xl: 20px; --text-2xl: 28px;
}
```

**Dark mode ("night watch") is a fast-follow, not part of the initial
light-only WebUI.** It arrives later without a refactor: same hues,
inverted lightness, shadows deprioritized in favor of rules, three-state
semantics slightly desaturated. Toggled via `:root[data-theme="dark"]`
(buildless, one class on `<html>`). **Structuring constraint to respect from
the start:** every surface consumes semantic tokens (`--surface-*`,
`--text-*`, `--state-*`, `--border-*`), never a hardcoded hex value -- dark
mode only overrides the primitives under `[data-theme="dark"]`.

**Assets to produce:**
1. Self-hosted IBM Plex fonts (Sans/Mono/Serif), woff2 subsets via
   `@font-face` (no build step). Plex shares metrics across cuts, so mixing
   them stays coherent. **Serif is reserved for the digest preview** (the
   "morning bulletin" content). Provide `font-display: swap` and a fallback
   stack.
2. The hex palette above.

---

## 3. Typography (roles, not just sizes)

- **UI / body**: `--font-ui` (Plex Sans), humanist and precise, warmer than
  Inter/Geist. Weights 400/500/600.
- **Data**: `--font-data` (Plex Mono), **tabular figures**
  (`font-variant-numeric: tabular-nums`) for column alignment of price /
  delta / timestamp / tier. This is the visual hero of a monitoring tool:
  data aligns to the pixel.
- **Doc / digest**: `--font-doc` (Plex Serif), used **only** on the digest
  preview (the "bulletin"). Ties form to content.
- Headings: Plex Sans 600, tight tracking (`-0.01em`), no separate display
  face -- contrast comes from weight and the mono data, not a decorative
  typeface.

---

## 4. State matrix by surface

Every interactive element: default / hover / focus / active / disabled.
Every data surface: loading / empty / error. Plus the security-driven
states, rendered at the router level but designed here.

| Surface | default | hover | focus | active | disabled | loading | empty | error |
|---|---|---|---|---|---|---|---|---|
| **Auth / login** | email+identifier form (hybrid mode) | -- | 2px indigo ring on field | button in progress | button greyed if field empty | inline spinner on submit | -- | `--danger` banner "Invalid credentials" (interface voice, no apology) |
| **Dashboard (watchlist)** | table + briefing row at the top | row highlight `--surface-2` | ring on focusable row | selected row, bronze rule | -- | skeleton rows (no central spinner) | "No products tracked. Add one." + CTA | per-row error inset if a fetch fails, never collapsed into unavailable |
| **Three-state signal** (token) | glyph+color ok/indet/unavail | tooltip = reason (tier, last read) | -- | -- | -- | pulsing "in progress" dot (transient indeterminate) | -- | indeterminate is the default state of doubt, not an error |
| **Product history** | price curve + table | hovered point = value+date | ring on point/row | -- | -- | skeleton curve | "No history yet." | "History unavailable." + retry |
| **Add/remove forms** | fields (shapes are implementation-specific) | -- | indigo ring | submit in progress | submit greyed while invalid | inline on submit | -- | field error under the field, actionable message |
| **Profile (email + tokens + sessions)** | identity block + tokens table + sessions table | token row highlight | ring | -- | "Revoke all" greyed if 0 tokens | skeleton tables | "No active tokens." + create CTA | "Action failed." |
| **Digest preview** | rendered bulletin (serif), read-only | -- | -- | -- | -- | skeleton bulletin | "Nothing to report today." (an invitation, not a bleak empty state) | "Preview unavailable." |
| **Admin add-site + revoke** | bronze "ADMIN" eyebrow + form + revoke table | row highlight | ring | submit in progress | -- | skeleton | "No sites enrolled." | fetcher config validation error |
| **401 unauthenticated** | redirect to login (a full surface, not a flash) | -- | -- | -- | -- | -- | -- | "Session expired, please log in again." |
| **403 non-admin on admin route** | dedicated "Forbidden" surface: bronze eyebrow, clear message, back to dashboard | -- | -- | -- | -- | -- | -- | "Access restricted to administrators." (interface voice, no apology) |

> Security reminder: templates render the admin UI conditionally on
> `principal.role`, but **template-hiding is never the actual guarantee**
> -- the router, the role guard, and the SQL `owner_id` scoping are. The
> 401/403 surfaces are designed as full screens, not error flashes.

---

## 5. Shell layout hierarchy

**App shell (common).**
```
+----------------------------------------------------------+
| topbar : bronze wordmark | tenant | "digest cut at 06:00" |
+--------+-------------------------------------------------+
| SIDEBAR|  MAIN CANVAS                                     |
| (same  |                                                  |
|  bg,   |  [content per surface]                           |
|  right |                                                  |
|  rule) |                                                  |
| Dash   |                                                  |
| Products|                                                 |
| Digest |                                                  |
| Profile|                                                  |
| ------ |  (ADMIN section shown if principal.role=admin)   |
| ADMIN  |                                                  |
+--------+-------------------------------------------------+
```
- Sidebar shares the canvas background (no fragmenting "sidebar world"),
  right rule `--border-default`, active indicator = bronze rule + weight
  600.
- Topbar: context (tenant + time of the next digest cut) = the observatory's
  temporal anchor.

**Tenant dashboard (primary surface).**
```
Briefing: "3 indeterminate, 2 price drops since the last digest."
-----------------------------------------------------------------
Product          | Source     | Signal | Price   | Delta | Tier | Seen
-----------------------------------------------------------------
RTX 4070         | Terabyte   |  ok    | R$3,499 | -4%   | tls  | 06:00
Ryzen 7 7800X3D  | Pichau     | INDET  |   --    |  --   | uc   | 06:00  <- indigo, salient
SSD 2TB          | Magalu     | unavail|   --    |  --   | http | 06:00
```
- Leads with the **briefing line** (count of items to act on), not 4 KPI
  cards.
- Data columns in Plex Mono, tabular. `INDET` is salient (misty indigo). The
  `Tier` column shows the escalation reason (a supporting, understated
  detail).

**Admin screen.** Same visual world (no separate color scheme),
differentiated by a **bronze "ADMIN" eyebrow** at the top plus an add-site
form and a revoke table. The distinction is semantic and enforced at the
router, not chromatic.

**Profile.** Identity block (email / identifier, hybrid mode) at the top,
then a bearer-tokens table (create / revoke / revoke-all), then an
active-sessions table. Destructive actions (`revoke`) use `--danger`, and
require confirmation.

---

## 6. Self-critique (mandate checks)

- **Swap test**: replacing the three-state signal with a green/red dot would
  break the determinacy invariant -- the design stands on its signature, not
  on a template.
- **Squint test**: hierarchy reads through low-opacity rules and micro-shift;
  nothing jumps out (bronze and indigo are the only accents, everything else
  is calm slate).
- **Signature test**: the three-state signal appears on the dashboard,
  history, digest, and tooltip; the tier motif appears on the dashboard;
  5+ anchor points overall.
- **Token test**: `--state-indet`, `--brand` (Hermes bronze), `--bg-canvas`
  slate evoke a market watch post, not a generic project.
