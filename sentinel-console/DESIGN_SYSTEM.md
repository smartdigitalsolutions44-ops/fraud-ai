# SENTINEL design system

The console should read as a serious operations tool: dark graphite, layered panels, thin
borders, and colour used only to carry meaning. It aims for the look of an instrument
panel, not a film set. There is no Matrix rain, glitch, neon or game UI. The polish comes
from alignment, rhythm and restraint.

All values below are CSS custom properties in `src/styles/tokens.css`. Components use the
tokens, never raw values.

## 1. Surfaces and borders

| Token | Use |
|---|---|
| `--surface-0` `#0a0c0f` | the page, behind a faint 48 px grid and 3.5 % noise (`.backdrop`) |
| `--surface-1` | navigation, top bar, status bar, inputs |
| `--surface-2` | panels and cards |
| `--surface-3` | hover, raised rows, chips |
| `--surface-4` | selected and pressed |
| `--border-subtle` / `--border` / `--border-strong` | the 1 px hierarchy: inside panels / around controls / on hover |
| `--focus` | the 2 px focus ring |

## 2. Semantic colour

Colour is **semantic only**. Every coloured element also carries text and a glyph, so
colour is never the only signal (WCAG 1.4.1).

| Colour | Meaning | Examples |
|---|---|---|
| green `--green` | verified, allowed, online | ALLOW ✓, signature Verified, ONLINE ● |
| amber `--amber` | monitoring, degraded, attention | ALLOW · monitor ◐, DEGRADED, stale data, DEMO MODE |
| orange `--orange` | step-up, review | Step-up ▲, Manual review ◆, at/above threshold |
| red `--red` | high risk, block, failure | Temporary block ■, High/Extreme band, OFFLINE, broken chain |
| blue `--blue` / cyan `--cyan` | system and model information | the selected row, the case event, model score bars, analyst assistance |
| neutral | everything else | not used, below threshold, unknown values |

Each colour has a `-tint` (about 10 % alpha) for backgrounds. The `.tone-*` classes combine
text, tint and border. On `--surface-2`, body text has a contrast ratio of 15.1:1,
secondary text 8.4:1 and muted text 5.0:1.

## 3. Type

| Role | Font |
|---|---|
| UI text | **Inter** (variable, self-hosted via @fontsource; no external font requests) |
| IDs, scores, times, hashes | **JetBrains Mono** (`.mono`) |

* The scale runs from `--text-2xs` 10.5 px to `--text-3xl` 30 px, with body text at
  13.5 px and a line height of 1.45.
* Labels are small uppercase with 0.08 em tracking (`.label`).
* Numbers use tabular figures, so columns and counters do not jitter while polling.

## 4. Space, radii, layout

| Tokens | Values |
|---|---|
| spacing, on a 4 px grid | `--space-1` 4 px … `--space-10` 40 px |
| radii | `--radius-xs` 3, `-sm` 4, `-md` 6, `-lg` 8 px (panels) |
| shell | nav 212 px, top bar 48 px, status bar 26 px |
| rows | `--row-height` 36 px; 30 px in compact density, which the command palette toggles |

The console is desktop-first:

* At 1920×1080 and 1440p it uses the full width, up to 1880 px.
* The metric grid has 8 columns, dropping to 4 below 1560 px and 2 below 760 px.
* The case workspace has three columns: timeline, investigation, decision. Below 1480 px
  it has two, with the timeline moving underneath. Below 1080 px it has one.
* Below 900 px the navigation collapses to icons.
* Long IDs are shortened, with the full value on hover and a copy button. Long reasons
  and values wrap (`overflow-wrap: anywhere`) rather than overflow.

## 5. Motion

| Token | Duration |
|---|---|
| `--dur-fast` | 150 ms |
| `--dur-base` | 220 ms |
| `--dur-slow` | 300 ms |

All use the easing `cubic-bezier(0.2, 0.7, 0.2, 1)`. Motion is functional only:

* hover and press;
* dialogs fading in;
* new rows briefly tinted when they arrive in a poll;
* the start-up trace line;
* the pulse of the live dot.

`prefers-reduced-motion: reduce` sets every duration to 0 and stops the shimmer, trace and
pulse. There is no startup sound.

## 6. Components

| Component | Purpose |
|---|---|
| `StatusBadge` | system checks (CHECKING / ONLINE / DEGRADED / OFFLINE / NOT USED), review status, resolution, step-up result |
| `RiskBadge` | the policy's risk band, verbatim. Its title says it is a band, not a probability |
| `DecisionBadge` | the policy decision, verbatim. Unknown values are shown as-is |
| `MetricCard` | one number from the API, with a tone rail, a unit and a sub-line; "—" when not reported |
| `CaseRow` | one review-queue row. The row opens the case and carries no actions |
| `TimelineEvent` | one account event. The case event is highlighted, events after the decision are dimmed, and VPN, proxy and Tor are marked as signals |
| `ModelComparison` | each model's stored score against its own threshold, with calibrated score, role, shadow agreement and shadow policies. **No consensus score** |
| `EvidencePanel` / `IndicatorPanel` | reason codes with the service's descriptions, rule evidence, and device, network and behaviour indicators |
| `SystemStatus` | the check list |
| `CommandPalette` | Ctrl/⌘ K: navigation, ID lookup, refresh, density. No consequential commands |
| `LoadingCheck` | one start-up check line |
| `ConfirmDialog` | the modal for consequential actions. Cancel has default focus, Esc cancels, and focus is trapped |
| `LiveIndicator` | Live, Stale, Offline or Paused, with the data's age |
| `Skeleton` / `SkeletonRows` | loading placeholders shaped like the content. There are no full-screen spinners |
| `ErrorState` / `Notice` / `Empty` | error, informational and empty states |

## 7. Wording

* **Say** "risk signal", "flagged for review", "model assessment", "model score",
  "analyst decision" and "policy decision".
* **Never say** "AI confirmed fraud", "guaranteed fraud", "fraud prevented" or "money
  saved".
* A passed step-up is "evidence, not proof of legitimacy".
* A VPN, proxy or Tor exit is "a signal, not proof of fraud".
* The reference template is named as a template, not a language model.

## 8. Accessibility

* Every control is reachable by keyboard and has a visible focus ring.
* A skip link leads to the main content.
* Tables have captions and scoped headers.
* Live regions announce liveness and start-up progress.
* Charts are SVG with a text summary (`role="img"` and `aria-label`) and a visually hidden
  data table.
* Dialogs use `aria-modal`, and focus returns to the trigger when they close.
