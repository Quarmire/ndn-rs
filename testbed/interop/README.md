# Interop / end-to-end suite (opt-in)

The scripts here are the survivors of the retired audit-witness system: the
ones that test something a `cargo nextest` run cannot — behavior against
**real external peers** or across **real process/socket boundaries**.

They are deliberately *not* part of the PR gate. Everything that used to be a
`GREP-PROOF` (assert source text) or a `cargo test -p …` wrapper was deleted
when nextest became the single source of truth for in-repo behavior; the
findings those scripts once witnessed live on in
[`../EXPECTED_FAILURES.md`](../EXPECTED_FAILURES.md) (frozen ledger) and
[`../transcripts/`](../transcripts/) (recorded evidence, including live
interop pcaps).

## Script classes

| Class | Scripts | Needs |
|---|---|---|
| External interop | `g03_psync_interop`, `g04_nlsr_interop`, `g05_dv_interop`, `c13_ndncert_live_interop`, `c12_mgmt_*`, `nfdc_interop_face_list`, `wt02_ndnd_interop`, `c09_safebag_ndnsec_interop`, `acme_dns01`, `x07_reliability_udp_loss`, `d01`/`d02`/`e04`/`e05`/`n12` docker legs | Docker (reference NFD / ndnd / NDNCERT CA / C++ PSync images) |
| Sibling-binary e2e | `quic01_interfwd_roundtrip`, `e01_signed_mgmt_ndn_fwd`, `mgmt_*`, `obs_phase*`, `ndnctl_*`, `sec_safebag_cli_roundtrip`, `custodian_signed_mgmt_live`, `d_localhop_signed_register`, `dashboard_next_*` | a full `ndn-workspace` checkout — the `ndn-fwd`, `ndn-dashboard` binaries these spawn live in sibling repos |

## Status caveat

These scripts were written before the monorepo split; several still reference
pre-split paths (`crates/<name>` instead of `crates/<layer>/<name>`, or
`binaries/` now in `ndn-fwd`). Each script must be revalidated — and its paths
fixed — before its class is wired into a scheduled workflow. Exit code `2`
(SKIP) is the correct behavior when a prerequisite is missing; a script that
cannot even locate its subject should be fixed to SKIP loudly, never to pass
vacuously.

## Running

```sh
./run_all.sh                # everything
./run_all.sh psync ndncert  # name-filtered subset
```
