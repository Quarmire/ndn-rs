# Spec conformance matrix

ndn-rs speaks the **real NDN wire format** — the byte-exact TLVs of the NDN
Packet Format v0.3 and the surrounding specs, not an ndn-rs dialect. That is a
foundational decision recorded in
[ADR 0001](./adr/0001-real-ndn-wire-format.md); this page is its evidence. For
each spec area it names the implementing crate and one or more **real tests**
(verify them with `cargo nextest run -p <crate>`) that pin the behaviour to the
spec.

## Type numbers are the spec's, verbatim

The TLV type-number assignments live in the `tlv_type` module of
`crates/core/ndn-packet/src/lib.rs`. A sample, showing they are v0.3's numbers
and not a re-mapping:

| Field | Type | | Field | Type |
|---|---|---|---|---|
| `INTEREST` | `0x05` | | `DATA` | `0x06` |
| `NAME` | `0x07` | | `NAME_COMPONENT` | `0x08` |
| `ImplicitSha256Digest` | `0x01` | | `ParametersSha256Digest` | `0x02` |
| `CAN_BE_PREFIX` | `0x21` | | `MUST_BE_FRESH` | `0x12` |
| `NONCE` | `0x0a` | | `INTEREST_LIFETIME` | `0x0c` |
| `HOP_LIMIT` | `0x22` | | `APP_PARAMETERS` | `0x24` |
| `META_INFO` | `0x14` | | `CONTENT` | `0x15` |
| `SIGNATURE_INFO` | `0x16` | | `SIGNATURE_VALUE` | `0x17` |
| `INTEREST_SIGNATURE_INFO` | `0x2C` | | `INTEREST_SIGNATURE_VALUE` | `0x2E` |
| `LP_PACKET` | `0x64` | | `LP_PIT_TOKEN` | `0x62` |
| `VALIDITY_PERIOD` | `0xFD` | | `NOT_BEFORE` / `NOT_AFTER` | `0xFE` / `0xFF` |

(A handful of non-spec extensions — `SUBSCRIPTION_REQUEST`, `REFLEXIVE_NAME` —
are marked provisional in source and live outside the standard number space.)

## The mapping

Every test name below is a real `#[test]`/`#[tokio::test]` function; the file it
lives in is given so you can read the assertion. Paths are relative to the repo
root.

| NDN spec area | Crate | Representative tests (file) | Status |
|---|---|---|---|
| **Packet Format v0.3 — TLV codec** (varint, type-length, minimal-form, critical-type rules) | `ndn-tlv` | `varu64_roundtrip_9byte`, `read_varu64_rejects_non_minimal_3byte` (`src/reader.rs`); `read_tlv_never_panics` (`tests/props.rs`) | Conformant |
| **Interest** | `ndn-packet` | `decode_with_all_fields`, `decode_with_forwarding_hint`, `decode_with_hop_limit` (`src/interest.rs`); `interest_roundtrip` (`tests/props.rs`) | Conformant |
| **Data** | `ndn-packet` | `decode_meta_info_freshness`, `implicit_digest_is_sha256_of_raw`, `signed_region_excludes_sig_value` (`src/data.rs`); `data_roundtrip` (`tests/props.rs`) | Conformant |
| **Signed Interest (§5.4)** — AppParameters + InterestSignatureInfo/Value + ParametersSha256Digest | `ndn-packet`, `ndn-security` | `decode_signed_interest_sig_info`, `a02_decode_rejects_app_params_without_psdc`, `a02_a21_decode_rejects_psdc_not_last` (`ndn-packet/src/interest.rs`); `c11_validate_signed_interest_returns_valid` (`ndn-security/src/validator/mod.rs`) | Conformant |
| **NDNLPv2** — LpPacket, fragmentation/reassembly, PitToken, Nack | `ndn-packet`, `ndn-transport` | `encode_decode_lp_nack_roundtrip`, `n03_lp_decode_rejects_out_of_order_headers` (`ndn-packet/src/lp/decode.rs`); `multi_fragment_roundtrip`, `out_of_order_reassembly` (`ndn-packet/src/fragment.rs`); `lp_link_service_fragments_at_mtu` (`ndn-transport/src/link_service/mod.rs`) | Conformant |
| **Certificate v2 (§10)** — NDN cert Data, ValidityPeriod, DER SPKI content | `ndn-security`, `ndn-cert` | `c07_keychain_ephemeral_cert_name_has_four_trailing_components`, `c08_cert_content_body_is_der_spki`, `c18_cert_validity_period_is_iso8601_inside_signature_info` (`ndn-security/tests/cert_format.rs`); `n13_serialize_cert_returns_parseable_data_tlv` (`ndn-cert/tests/n13_serialize_data.rs`) | Conformant |
| **NDNCERT 0.3** — CA protocol, challenges, ECDH channel | `ndn-cert` | `new_request_body_is_self_signed_cert`, `challenge_request_is_envelope_with_selected_challenge_first` (`src/client.rs`); `ecdh_key_agreement_produces_same_session_key` (`src/ecdh.rs`); `f7_default_policy_issues_cert` (`tests/f7_issuance_policy.rs`) | Conformant |
| **RDR** (Realtime Data Retrieval — `32=metadata`) | `ndn-app` | `metadata_roundtrip`, `metadata_name_appends_keyword` (`src/rdr.rs`); `fetch_object_reassembles_publish_object` (`tests/rdr_round_trip.rs`); `verified_fetch_object_rejects_unsigned` (`tests/rdr_verified.rs`) | Conformant |
| **Naming conventions** (segmenting, versioning, typed components, URI) | `ndn-foundation-types`, `ndn-packet` | `append_segment`, `version_roundtrip`, `keyword_component_roundtrip`, `a19_uri_roundtrip_canonical_typed_form` (`ndn-packet/src/name.rs`); `name_canonical_order_is_total` (`ndn-packet/tests/props.rs`) | Conformant |
| **SVS** (State Vector Sync — v2 ndn-svs, v3 ndnd) | `ndn-sync` | `encode_svs_data_byte_level`, `process_sync_accepts_new_boot` (`src/svs_local.rs`); `v2_roundtrip_ignores_boot`, `v3_roundtrip_carries_boot`, `dialects_are_not_cross_decodable` (`src/dialect.rs`); `hmac_rejects_tampered_state_vector` (`src/security.rs`) | Conformant (v2 + v3) |
| **PSync** (IBF set reconciliation) | `ndn-sync` | `ibf_cell_vector_matches_psync_cpp`, `reconcile_one_sided_difference`, `g03_reconcile_n20` (`src/psync.rs`); `hash_name_matches_psync_cpp` (`src/psync_sync.rs`); `psync1_huge_count_rejected_without_allocating` (`src/psync_bloom.rs`) | Conformant |

A recurring pattern in these tests is **wire-compatibility against the reference
implementation**: `ibf_cell_vector_matches_psync_cpp` and
`hash_name_matches_psync_cpp` assert byte-identical output with the C++ PSync;
`encode_svs_data_byte_level` pins the ndnd v3 encoding; `dialects_are_not_cross_decodable`
guards that a v2 vector never silently decodes as v3.

## Robustness, not just round-trips

Wire fidelity includes rejecting malformed and adversarial input safely. The
`a0x`/`n0x`/`w1` tests encode audit findings as behaviour:
`a03_interest_decode_rejects_unknown_critical_tlv_in_body`,
`interest_decode_huge_length_does_not_panic` (`ndn-packet/tests/w1_overflow.rs`),
`n01_oversized_frag_count_does_not_allocate`, and
`psync1_huge_count_rejected_without_allocating` all assert a decoder refuses or
bounds hostile input rather than panicking or over-allocating. The four
[fuzz targets](./testing.md#fuzzing-the-wire-surface) (`decode`, `name`, `tlv`,
`mgmt_wire`) extend this coverage continuously.

## Interop transcripts

Byte-level tests prove ndn-rs matches the spec on paper; the
`testbed/transcripts/` directory holds the evidence it matches real peers *on the
wire*. It is a flat archive of ~119 recorded interop runs (paired
`*_before.txt`/`*_after.txt`), including two live pcaps:
`c13_ndncert_live_interop_after.pcap` (NDNCERT against a live CA) and
`g04_nlsr_interop_after.pcap` (NLSR). These back the opt-in
[interop suite](./testing.md#interop-external-peers); the frozen audit ledger is
`testbed/EXPECTED_FAILURES.md`.

## Keeping the matrix honest

When you touch a wire path — a new TLV field, a new packet shape, a codec change
— add or extend the round-trip/property tests **and add a row (or test name)
here**. The CI `book` job fails on a broken link, and the `test` job fails on a
broken assertion, but neither notices a spec area that silently loses coverage.
That is a review responsibility; see
[the contribution workflow](./contributing.md).
