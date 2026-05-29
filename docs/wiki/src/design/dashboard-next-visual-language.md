# Dashboard Next Visual Language

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
