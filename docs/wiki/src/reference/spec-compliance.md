# Spec compliance

ndn-rs's compliance with the NDN Packet Specification and the
NDNCERT specification is tracked in the audit at
`docs/notes/spec-compliance-audit-2026-04-20.md` and the
cross-reference at
`docs/notes/spec-compliance-cross-reference-2026-05-01.md`. Live
witness scripts under `testbed/tests/audit/` exit non-zero when a
compliance claim regresses.

This page summarises which areas are covered; the audit doc is the
authoritative record.

## Coverage areas

| Area | Spec source | Audit section | Witness prefix |
|---|---|---|---|
| Name and component types | Packet spec §2 (Name) | A.01 – A.04 | `a*_blake3_*`, `a19_a20_uri_*` |
| Interest TLV | Packet spec §3 | A.05 – A.08 | `a05_a18_tlv_strictness` |
| Data TLV | Packet spec §4 | A.09 – A.16 | `a10_databuilder_build_sig` |
| Signature types | Packet spec §5 | A.16, A.17, BLAKE3 | `a16_signature_value_length`, `a17_blake3_registered` |
| KeyLocator rules | Packet spec §5.5 | A.15 | `a15_keylocator_rules` |
| LP TLV (NDNLPv2) | LP spec | A.11, A.12 | `a11_nack_reason_documented`, `a12_nack_lp_only` |
| Nonce length | Packet spec §3 | A.13 | `a13_nonce_length_rejected` |
| FinalBlockId / UriComponent | Naming convention | A.19, A.20 | `a19_a20_uri_finalblockid` |
| Signed Interests | Packet spec §3 (signed) | A.09 | `a09_signed_interest_verify` |
| Persistent-state Interest | Persistent Interest design | (interop) | `persistent_interest_*` |
| NDNCERT issued cert | NDNCERT spec | C.07, C.08, C.18, N.13 | `acme_dns01.sh`, `cert_*` |
| Architectural cleanup | Phase 2 ARCH-1..20 | (ARCH-N) | `arch*` (per-item witnesses) |
| Tiered API surface | Phase 3 §3 | tier docs | `phase3_*` |

The audit file enumerates every (finding, witness) pair. Reading
order:

1. `docs/notes/spec-compliance-audit-2026-04-20.md` — findings with
   severity and disposition.
2. `docs/notes/spec-compliance-cross-reference-2026-05-01.md` —
   cross-references to reference impls on disk.
3. `testbed/tests/audit/*.sh` — runnable witnesses.

## Reading the witnesses

Each witness is a shell script with exit-code semantics:

- `0` — finding passes / claim holds.
- `1` — finding fails / claim regressed; the script prints the
  exact diagnostic.

```sh
# Run a single witness:
bash testbed/tests/audit/a17_blake3_registered.sh ; echo exit=$?

# Run every audit witness:
for w in testbed/tests/audit/*.sh ; do
    name=$(basename "$w" .sh)
    if bash "$w" >/dev/null 2>&1 ; then
        echo "PASS $name"
    else
        echo "FAIL $name"
    fi
done
```

The audit harness scaffold is `testbed/tests/audit/_template.sh`;
new findings follow the same shape (project memory
`feedback_witness_first_compliance`).

## Cross-impl on-disk references

The audit cross-reference doc cites file:line in the reference
implementations under `~/Documents/Dev/`. Per project memory
`feedback_cross_reference_standard`, every finding cites the source
implementation it tracks. These references live in the audit doc;
this wiki page links to the audit rather than duplicating it.

## TLV codepoint allocations

ndn-rs's own TLV allocations are tracked in
`docs/notes/ndn-rs-tlv-allocations-2026-05-20.md`. The doc
distinguishes:

- IANA / registry codes ndn-rs implements (forwarding).
- ndn-rs-internal codes used only on in-process or shared-memory
  faces (no wire reach).
- Codes reserved for v0.1.x.

## Releasing under v0.1.0

The audit's green state is a precondition for v0.1.0. The audit
doc records findings status; release-readiness is gated on every
critical-severity finding being closed (project memory
`project_audit_honesty_pass`).

## See also

- `docs/notes/spec-compliance-audit-2026-04-20.md` — authoritative.
- `docs/notes/spec-compliance-cross-reference-2026-05-01.md` —
  per-finding cross-reference.
- `testbed/tests/audit/` — runnable witness scripts.
- [Phase 4 release notes](../releases/v0.1.0.md) — what shipped.
