# 0005 · Retire the audit-witness scripts in favour of nextest

**Status:** Accepted

## Context

Early ndn-rs development accumulated a `testbed/tests/audit/` directory of ~290
shell "witness" scripts, indexed by a status ledger (`EXPECTED_FAILURES.md`).
Each script tied a named audit finding to a check. Two problems emerged:

- Most scripts were one of two low-value shapes. ~45 were **GREP-PROOF** — they
  asserted that some *source text* was present or absent (e.g. "the string
  `experimental` no longer appears near the BLAKE3 constant"). That tests the
  code's spelling, not its behaviour, and silently rots: after the monorepo
  split many grepped paths that no longer exist and passed vacuously through
  `2>/dev/null`. Another ~215 were thin wrappers around `cargo test -p <crate>`,
  fully redundant with the Rust suite they invoked.
- None of them ran in CI, and the whole thing was slow and did not inspire
  confidence — precisely the opposite of what a test suite is for.

## Decision

Make `cargo nextest` the single source of truth for in-repo behaviour, and
retire the witness system:

- Delete the GREP-PROOF and cargo-test-wrapper scripts. The Rust tests they
  wrapped stay; the source-text assertions are discarded as untrustworthy.
- Preserve the **history**: `EXPECTED_FAILURES.md` is frozen verbatim as the
  audit ledger (every finding, severity, and resolution remains on record), and
  all recorded transcripts — including live interop pcaps — are kept under
  `testbed/transcripts/`.
- Keep the genuinely-unique scripts — those that test against **real external
  peers** (Dockerized NFD/ndnd/NDNCERT/C++ PSync) or spawn sibling-repo
  binaries across process/socket boundaries — as an explicitly **opt-in**
  `testbed/interop/` suite, since nextest cannot cover them.
- Add property-based tests and fuzzing for the wire surface (the invariants the
  GREP-PROOFs gestured at but could not actually check).

## Consequences

- **Positive:** the default test signal is fast (~25s for ~1800 tests),
  parallel, isolated, and runs on every PR. A green run means something.
- **Positive:** behaviour is tested by exercising behaviour, not by grepping
  source; the tests survive refactors that move code around.
- **Positive:** the audit findings are not lost — they are archived where they
  belong (a ledger and transcripts), not masquerading as a live suite.
- **Cost:** the external-interop scripts still carry pre-split path rot and must
  be revalidated before their class is wired into a scheduled job. This is
  called out in `testbed/interop/README.md`.

## Alternatives considered

- **Fix the 290 scripts in place.** Rejected: the GREP-PROOF shape is
  unfixable — it tests the wrong thing by construction — and fixing the
  cargo-test wrappers just re-creates the Rust suite in bash.
- **Delete everything, including the ledger.** Rejected: the audit findings and
  interop transcripts are real, hard-won evidence; discarding the provenance
  would lose genuine value along with the dead scripts.
