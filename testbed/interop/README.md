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
| Reference-library interop | `c07_certv2_ndncxx_interop` | `cargo` and ndn-cxx 0.9 — from the environment or via `nix-shell` ([`ndncxx/shell.nix`](ndncxx/shell.nix)); no Docker |

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

## `c07_certv2_ndncxx_interop` — Certificate Format v2 against ndn-cxx

```sh
./c07_certv2_ndncxx_interop.sh        # or: ./run_all.sh certv2
```

**Prerequisites:** `cargo`, a C++17 compiler, and ndn-cxx (`ndnsec` on `PATH`,
`libndn-cxx` known to `pkg-config`). Without ndn-cxx in the environment the
script enters [`ndncxx/shell.nix`](ndncxx/shell.nix), which pulls ndn-cxx,
boost, openssl, sqlite and pkg-config from nixpkgs (witnessed with ndn-cxx
0.9.0). With neither available it exits `2` (SKIP). The C++ helper
[`ndncxx/ndncxx-interop.cpp`](ndncxx/ndncxx-interop.cpp) is compiled on demand
into `target/ndncxx-interop/` and rebuilt when its source or the ndn-cxx store
path changes.

**What it proves.** The ndn-rs example
`crates/security/ndn-security/examples/certv2_interop_chain.rs` issues, with
the public `SecurityManager` API (`generate_ecdsa_p256` / `generate_ed25519`,
`issue_self_signed`, `certify_as`), an ECDSA-P256 and an Ed25519 namespace
chain: root `/<ns>/KEY/<kid>/self/v=…`, CA `/<ns>/CA/KEY/<kid>/NA/v=…`
certified by the root, device `/<ns>/member/dev/KEY/<kid>/NDNCERT/v=…`
certified by the CA, and a Data signed by the device key. Every KeyLocator
names the signer's *key*. ndn-cxx then shows, for both algorithms:

- `ndnsec cert-dump` parses every certificate, and ndn-cxx decodes each as a v2
  `Certificate`: version component last, ContentType KEY, a validity period
  covering now, and a KeyLocator equal to the issuer's key name (a
  certificate-name KeyLocator fails the run);
- every chain hop verifies, ECDSA through ndn-cxx `verifySignature`, Ed25519
  through OpenSSL over ndn-cxx's `extractSignedRanges`;
- ECDSA: the ndn-cxx `Validator` (offline certificate fetcher) accepts the
  device certificate and the Data, and refuses a copy of the Data with one
  content byte flipped;
- Ed25519: ndn-cxx 0.9 has no Ed25519 verifier, so its `Validator` lines are
  `UNSUPPORTED` (expected, not a failure); a tampered Data fails the OpenSSL
  hop check.

The script prints each expectation as `PASS:`/`FAIL:` and exits `0` only when
all hold. The tampered runs are expected to print `FAIL` lines; that refusal
is what they assert.

**Validator policy.** The witness's Validator rule admits any KEY- or
certificate-name KeyLocator under the trust anchor. NFD's stock
`hierarchical` rule refuses `/<ns>/CA` certifying `/<ns>/<role>/…`, because
the CA identity is not a prefix of the device identity. That is how the
namespace layout is designed: the namespace's trust schema governs who may
certify whom, not `hierarchical`. The script still runs the `hierarchical`
rule and expects exactly that refusal (`NOTE` lines).

[`ndncxx/check.sh`](ndncxx/check.sh) also works alone on any certificate
chain, for example packets fetched from a live ndn-fwd:
`ndncxx/check.sh [-K] [-d DATA] [-a ANCHOR] CERT [ISSUER_CERT...]`. Files may
be raw TLV or ndnsec base64.
