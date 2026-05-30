# Dashboard Next Visual Language

Dashboard-next follows an operational-console interpretation of IBM Carbon,
not a generic dark admin template. Carbon is the primary reference because it
is built around enterprise UI shell, dense data tables, Gray 100 dark surfaces,
Blue 60 interactive states, and an 8px/2x layout rhythm. Material responsive
navigation remains the secondary reference for compact screens: persistent
navigation on larger viewports, bottom navigation on phones, and split
summary/detail layouts when width allows.

References:

- IBM Carbon 2x Grid: `https://carbondesignsystem.com/elements/2x-grid/overview/`
- IBM Carbon color tokens: `https://carbondesignsystem.com/elements/color/tokens/`
- IBM Carbon data table usage: `https://v10.carbondesignsystem.com/components/data-table/usage/`
- Material responsive layout: `https://m1.material.io/layout/responsive-ui.html`
- Material navigation rail: `https://m2.material.io/components/navigation-rail`

The visual rules are:

- Prefer shell, command bars, dense tables, split panes, lists, and dialogs.
- Use cards only for repeated items or explicit framed tools.
- Keep panels flat and square-edged; avoid decorative shadows and gradients.
- Make primary actions solid blue, secondary actions quiet, and status tags
  small enough not to compete with real content.
- Treat names, prefixes, endpoints, trace IDs, and cert/key IDs as data rows,
  not prose.
- Do not duplicate the same action in multiple loud visual treatments.

The dashboard uses a carbon-black operational theme with electric-blue accents.
Color semantics:

- Green: trusted, enabled, completed.
- Blue: selected, live, informational.
- Amber: degraded, confirmation, pending restart.
- Red: failed, blocked, unsafe.

NDN concepts get stable visual treatment: names use monospace path rows, trust
uses chain/audit glyphs, cache/PIT use compact counters and fan-out marks,
strategies use route/path glyph rows, and traces use timeline strips plus
correlated evidence tables. The old dashboard's broad feature coverage remains
valuable, but dashboard-next keeps spacing dense and uses drawers, dialogs, and
tables instead of large explanatory cards.

Desktop, tablet, and phone screenshots are covered by the dashboard-next
browser witness specs under `testbed/tests/browser/`.
