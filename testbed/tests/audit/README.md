# Audit Witness Tests

One script per audit finding from
[`docs/notes/spec-compliance-audit-2026-04-20.md`](../../../docs/notes/spec-compliance-audit-2026-04-20.md).

The audit lists each finding with a severity, a file-line
citation, and a spec reference. Each finding that can be
observed as a wire-level event has a matching script in this
directory named `<phase><number>_<slug>.sh` (e.g. `a01_blake3_name_component.sh`
witnesses finding A.01).

## Purpose

Before-and-after evidence for audit fixes. When a BLOCKER gets
fixed, the PR description needs:

1. The failing transcript from the witness script **before** the
   fix (showing the spec violation).
2. The passing transcript from the same script **after** the fix.
3. A line in [`EXPECTED_FAILURES.md`](../../EXPECTED_FAILURES.md)
   flipping the finding from `EXPECTED-FAIL` to `RESOLVED`.

## Exit codes

Following the testbed convention (see `../interop/run_all.sh`):

- `0` — PASS: ndn-rs behaviour matches the spec.
- `1` — FAIL: ndn-rs behaviour violates the spec (the expected
  state today for unresolved findings).
- `2` — SKIP: dependencies missing (e.g. `ndncert-ca-server`
  not installed in the container). Documented in
  `EXPECTED_FAILURES.md` as `BLOCKED-BY-INTEROP`.

## How to add a witness test

1. Copy `_template.sh` to `<phase><number>_<slug>.sh`.
2. Fill in the four header fields: finding, severity, spec-ref,
   what-is-witnessed.
3. Write the test body: emit a packet via ndn-rs, have a
   reference peer (ndn-cxx, NFD) observe it, assert the
   spec-correct behaviour.
4. Run it from the testclient container: expect FAIL today.
5. Add a row to `../../EXPECTED_FAILURES.md`.
6. Add a row to `../../README.md`'s audit-to-test map.

## Running

```bash
# All witness tests — produces a summary of expected vs actual
# failures:
docker compose -f testbed/docker-compose.yml exec testclient \
    bash /testbed/tests/audit/run_all.sh

# A single finding:
docker compose -f testbed/docker-compose.yml exec testclient \
    bash /testbed/tests/audit/a01_blake3_name_component.sh
```

When the testbed is first run on a new host, the first pass
will produce a ground-truth baseline that updates the "Last
seen" column in `EXPECTED_FAILURES.md`. Divergences from that
baseline should be investigated: either the fix landed (flip
to RESOLVED) or a regression was introduced (open an issue).

## Non-witnessable findings

Some audit findings cannot be observed as a single packet
exchange — e.g. the **absence** of NLSR (G.04), or silent
fail-open behaviour in LVS user functions (C.16). These are
tracked as `NOT-WITNESSABLE` in `EXPECTED_FAILURES.md` and
require either:

- Unit-level tests inside the crate (`cargo test -p
  ndn-security`), or
- A roadmap item that's tracked as a GitHub issue rather than
  as a testbed test.

The witness-test table in `../../README.md` lists these
explicitly so the omission is intentional, not an oversight.
