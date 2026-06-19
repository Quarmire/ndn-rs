# ndn-rs Service Layer Specification

**Status:** Draft (living document)
**Editor:** ndn-rs contributors
**Repository:** https://github.com/ndn-rs/ndn-rs
**Latest version:** This document
**Relationship:** Reference reimplementation target = NDN Service Framework (NDNSF)
and NAC-ABE; this spec defines an ndn-rs-native service layer that is
*protocol-compatible* with them and adds an alternative, lower-latency path.

---

## Abstract

This document specifies a layered service/RPC architecture for ndn-rs. It has two
goals that share one set of primitives:

1. **Compatibility** with the NDN Service Framework (NDNSF) and NAC-ABE at the
   *protocol* level — names, Interest/Data, SVS v3 sync, the four-phase service
   exchange, service discovery, and the Named-data Access Control (NAC) key
   distribution protocol — so an ndn-rs node behaves like a C++ NDNSF node on the
   wire, with the explicit exception of the ABE ciphertext bytes (§7.3).

2. An **alternative ("v2") path** that corrects what is locally optimal but not
   optimal in NDNSF: it routes point-to-point RPC as one signed Interest → one
   signed Data (≈ one RTT) instead of through a multi-party sync-pub/sub layer,
   models authority as published signed Data rather than a live endpoint, and
   separates the three access-control concerns NDNSF fuses (invocation
   authorization, content confidentiality, key distribution).

Both are built on the same shared primitives, so the substrate is written once
and only the interaction-pattern crates diverge.

---

## 1. Introduction

### 1.1 What "service" means here

Three distinct interaction patterns are commonly conflated under "service":

- **(a) one-to-one RPC** — "execute this command on that node";
- **(b) one-of-N selection** — "any object-detector, fastest wins";
- **(c) many-to-many collaboration** — session-scoped pub/sub with shared keys.

NDNSF implements all three on a single SVS-pub/sub substrate with a mandatory
four-phase protocol, so the simple case (a) carries the machinery of the hard
case (c). This spec separates them into composable tiers so a caller pays only
for the pattern it uses.

### 1.2 The structural premise

NDNSF's published end-to-end RPC floor is ~166 ms, dominated by four one-way
SVS/NFD delivery legs (~46–50 ms each). That per-leg cost is mostly sync
suppression/periodic-timer + epidemic convergence, not wire propagation. Routing
point-to-point RPC through a many-party convergence layer is therefore the cost,
not the crypto or the forwarding software.

The Tier-0 path defined here (§3.1) is one Interest/Data exchange to a known
provider. The `examples/tier0-rpc-latency` harness measures its **software floor**
— a full secure call (producer signature + RTT + consumer verification) over an
in-process face — and finds the whole software path is tens of microseconds, i.e.
negligible against any network leg.

> **Note on justification.** The argument for the v2 default is *structural* (one
> RTT vs four convergence legs), not benchmark-based. The software-floor numbers
> show only that dispatch/sign/verify are not the bottleneck. No cross-stack
> speedup figure is claimed in this spec: a fair NDNSF comparison requires both
> stacks on the same testbed, and even then the numbers are supporting evidence,
> not the primary case. See §8.

---

## 2. Architecture and crate layout

### 2.1 Tiers

| Tier | Concern | Substrate |
|---|---|---|
| **Tier 0** | typed request/response to a *known* provider | one signed Interest → Data (≈ 1 RTT) |
| **Tier 1** | find / select a provider | SVS sync (discovery only) |
| **Tier 2** | session-scoped many-to-many collaboration | SVS pub/sub |
| **Tier 3** | authorization, confidentiality, key distribution | signed objects + AEAD/ABE |

A Tier-0 call never touches sync. Tier-1 produces a provider set; the call itself
drops back to Tier-0. Tier-2 is the one tier for which sync is the correct
substrate.

### 2.2 Crate map (locked)

```
CORE (ndn-rs) — shared primitives
  crates/protocols/ndn-sync                          SVS v3 data plane            [exists; + suppression/periodic timers, sync-interest batching]
  crates/security/ndn-security/src/abe               CP + KP + MA crypto          [exists; + KP-ABE, + own TLV container (§5.2)]
  crates/security/ndn-security/src/confidentiality   CK indirection (AEAD)        [NEW module]
  crates/security/ndn-security/src/capability        simple key-bound capability  [NEW module]

EXT (ndn-ext) — shared service substrate
  crates/service/ndn-service-core                    Service/Carrier/SelectCarrier/Dispatch/Frame traits (§12)  [built — traits]
  crates/service/ndn-service-macro                   #[ndn_service] proc-macro over ndn-service-core (§11.2/§12)        [NEW — ratified, not built]
  crates/service/ndn-rpc                             Tier-0 typed Interest/Data RPC; provides RpcCarrier (§12, proven)   [built]
  crates/compute/ndn-compute                         specialization of ndn-rpc ("the handler is a pure function")  [refactor onto ndn-rpc]
  crates/discovery/ndn-discovery::service_discovery  Tier-1 find/select               [exists; extend]
  crates/service/ndn-nacabe                          NAC protocol: AA serves PubParams/DKEY, ParamFetcher, CK-data naming  [NEW]

EXT (ndn-ext) — compat layer (faithful)
  crates/service/ndn-ndnsf                           NDNSF four-phase + roles + KP-ABE controller; provides NdnsfCarrier (§12)  [roles/driver built]

EXT (ndn-ext) — v2 layer (alternative)
  crates/service/ndn-service                         Tier-1 selection + Tier-2 collab; authority-as-signed-Data; scoped authorities; v2 carrier + typed Topic<T>  [NEW]
```

`ndn-ndnsf` (compat) and `ndn-service` (v2) depend on the *same* shared
primitives (`ndn-rpc`, `ndn-nacabe`, `ndn-sync`, `confidentiality`, `capability`,
`abe`). Only the interaction-pattern crates differ.

### 2.3 Reuse decisions (locked)

- **D1.** `ndn-rpc` is the generic invocation core *extracted from* `ndn-compute`
  (codec, synthetic face, client, registration, wire spec). `ndn-compute` becomes
  the specialization where the handler is a deterministic pure function. One RPC
  stack, two front-ends — no duplicated codec/face/client.
  - *Status:* **done for the dispatch core.** The generic Tier-0 core is
    `ndn-ext/crates/service/ndn-rpc` — `RpcHandler (&Interest -> Data)` + LPM
    `RpcRegistry` + `RpcError` (4 witnesses). `ndn-compute` now *consumes* it:
    `registry.rs` deleted; `ComputeHandler`/`ComputeRegistry`/`ComputeError` are
    aliases of the `ndn_rpc` types (compute's public vocabulary preserved);
    `compute()`→`handle()`, `ComputeFailed`/`BadArguments`→`HandlerFailed`/
    `BadRequest`. Behavior-preserving (all previously-passing compute tests pass;
    one pre-existing sealed-params failure unrelated to this change). No
    duplicated dispatch core.
  - *Boundary note (corrected):* `codec` (`ArgComponent`/`ComputeArgs`/
    `ComputeValue`) is the **typed-argument framing of the compute specialization**
    and stays in `ndn-compute` — it is not generic RPC. The synthetic `ComputeFace`
    is generic in spirit but pulls `ndn-engine`/`ndn-transport`; whether to lift a
    serve-a-registry-over-a-face helper into `ndn-rpc` (vs. the engine-side serving
    the v2 Tier-0 path will use) is a deliberate later decision, not a blind lift.
    `ComputeClient` is mostly compute-specific (it frames typed args).
- **D2.** The content-key (CK) primitive and the capability primitive are
  **modules in core `ndn-security`**, not separate crates: both are lightweight
  (AEAD + signatures, already its dependencies) and are genuinely core security
  primitives, kept shared and wasm-reachable.
- **D3.** Large/streamed RPC responses use **NDN's existing layers** — NDNLP
  fragmentation at the link layer and segmentation/RDR (`fetch_object` /
  `publish_object`) at the object layer. No bespoke bulk transport. (`ndn-pipes`
  is explicitly **not** a dependency of the service layer at this time.)

---

## 3. Tier definitions

### 3.1 Tier 0 — `ndn-rpc`

A call to a known provider is a single Interest/Data exchange:

- The request rides as an `ApplicationParameters` payload (and/or name
  components) in a (signed, when authorization is required) Interest.
- The response is a signed Data. If it exceeds one packet, it is published as a
  segmented object (RDR) and fetched with the existing object-fetch path (D3).
- Names are typed (newtypes over `Name`) and constructed/parsed structurally; no
  regex parsing of stringly-typed names.
- Request/response payloads implement a framing trait (TLV encode/decode) so
  encoding errors are compile-time. The framing reuses `ndn-compute`'s `codec`.

Authorization (when present) is a capability presented and proven by the
signature on the request Interest (§6.3) — verified offline by the provider, no
call to any authority on the hot path.

### 3.2 Tier 1 — service discovery / selection

Built on `ndn-discovery::service_discovery` (which already provides auth,
browsing, encryption, FIB auto-population, measurements, records). Discovery is
where SVS earns its place: "who offers service X" is a genuine many-party
state-convergence problem. Selection strategies (FirstResponding, FastestResponse,
All, Random) yield a provider set; the call then drops to Tier 0. The forwarder's
Measured strategy / SignalStore (RTT, congestion per face) MAY inform
fastest-provider selection at the forwarding layer instead of an application-level
ACK round-trip.

### 3.3 Tier 2 — collaboration (`ndn-service`)

Session-scoped many-to-many: sessions, role/key scopes, topic pub/sub, artifact
provisioning. This is genuinely many-to-many and stays on SVS pub/sub. Scope keys
use the shared CK primitive (§6.1); topics are SVS-PS subscriptions; roles and
scopes are typed rather than string-keyed.

---

## 4. Authority and trust model

### 4.1 Authority is a signed-Data publisher, not a live endpoint

The central design correction relative to NDNSF: an authority's decisions are
**signed, named, cacheable Data objects**, not real-time responses from a running
service. Authority stays centralized (only the authority's key can sign a valid
grant); availability decentralizes as far as NDN caching reaches.

- The authority signs permission/policy/key objects and publishes them under its
  namespace.
- A node fetches `<authority>/.../v=N`, validates the signature against the
  authority's certificate, and checks freshness (validity period / epoch). It
  does **not** require the authority to be online — only that the object is
  validly signed and fresh.
- Objects are cacheable, so a node MAY bootstrap from a peer or a repo even if the
  authority is unreachable or gone.

### 4.2 Late-authority bootstrap (no restart)

A node provisions itself by expressing a **persistent Interest**
(`SubscriptionRequest`, TLV `0x230`; see `ndn-packet/src/subscription.rs`) for its
permission/key objects. If the authority is down, the Interest stays pending; when
the authority publishes, the Data flows back over the pending Interest and the
node configures itself live. Construction is **non-blocking**: a node comes up in
an explicit *unprovisioned* state (it may perform anything not gated by the
authority) and transitions to *provisioned* when the signed grant arrives. There
is no blocking bootstrap loop and no "restart to re-pull" failure mode.

### 4.3 Scoped, named authorities

"Controller" splits into two roles, each governing an explicit named scope:

- **`PolicyAuthority`** — signs permission/policy grants over a namespace prefix
  it is trust-rooted for (`PolicyAuthority::for_scope("/muas/group")`).
- **`KeyAuthority`** — issues ABE/decryption keys (the NAC AA, §6.2/§7).

They MAY be co-located (and usually are) but are named separately so they can be
operated, rotated, or replicated independently. A service's governing authority is
discoverable by longest-prefix match of the service name against registered
scopes, exactly as NDN trust schemas resolve signing authority. Multiple
authorities for multiple scopes compose; cross-scope access is an explicit
delegation between authorities (where MA-ABE or cross-signing enters, §6).

> NDNSF's "multiple controllers" are key-sharing hot-spare *replicas* of one
> authority (same signing key ⇒ interchangeable signed objects), not independent
> authorities. This spec models that as replication of a single authority, and
> independent-authority federation as a separate, explicit construct.

---

## 5. Wire formats

### 5.1 RPC name scheme (Tier 0)

Service invocation names are typed and structural. The canonical shape:

```
/<service-prefix>/<method>[/<request-id>]
```

with the request body in `ApplicationParameters`. `<service-prefix>` is the
routable provider/service name; `<method>` selects the operation; `<request-id>`
(optional) disambiguates otherwise-identical concurrent calls (analogous to
`ndn-compute`'s opaque-function nonce, required because the engine strips the
`ParametersSha256DigestComponent` and cannot use it as a PIT multiplexing key).
This name scheme is the one piece of this spec proposed as a candidate
cross-implementation convention (§9).

### 5.2 ABE ciphertext container

The ABE ciphertext is carried in an ndn-rs-owned TLV container (replacing the
current `bincode`-of-rabe-types blob). Because the ABE ciphertext bytes are **not**
interoperable with openabe (§7.3), the container is **not** constrained to mirror
openabe's serialization — it is a clean, self-owned, versioned TLV structure.

Container fields (provisional): `scheme-id` (CP/KP/MA), `schema-version`,
`policy-or-attributes` (CP: policy expression; KP: attribute set), `kgc-refs`
(authority/master-params provenance), and the wrapped payload. The container MUST
bind `scheme-id`, `policy-or-attributes`, and `kgc-refs` (and the CK-data name
when present) into the CK's AEAD associated data, and the decrypt path MUST verify
`kgc-refs` against the supplied key's provenance before attempting unwrap, so the
metadata is tamper-evident locally rather than relying on the outer Data
signature. The inner ABE blob (rabe's curve-point encoding) is treated as opaque,
explicitly versioned bytes, pinned by known-answer test vectors.

### 5.3 Capability

A capability is a signed, NDN-TLV, content-addressed object authorizing a **named
key** to perform a **named operation**, bounded in time. Minimum field set:

- `grantee` — the NDN identity/key name the capability authorizes;
- `operation` — the service name / method (and optional `NamePrefixPattern` scope)
  it authorizes;
- `not-before` / `not-after` — validity window;
- `issuer` signature — chains to a trust-rooted authority.

It is verified **offline** against the issuer's certificate. Possession of the
capability object is necessary but **not** sufficient: the caller must also sign
the request Interest with the key the capability names (proof-of-possession), so a
captured capability is useless without the grantee's private key. Revocation is by
validity window + authority epoch (bump the epoch, old capabilities stop
validating); the engine's `ReplayGuard` provides nonce/timestamp anti-replay for
one-time semantics. See §6.3 for the security rationale.

> This is deliberately the *simple* capability, not NDF's grant/manifest/
> requirement/match/attestor-tier machinery. Simplicity here is a security
> property (one signature to verify, offline, least-privilege), not a weakness.
> The richer attestation/discovery model is out of scope and would, if ever
> needed, be an optional separate layer.
>
> **Implemented** in `ndn-security::capability` as a pure value type +
> `authorizes` predicate: `grantee` matches when the request's verified signer
> key is *under* it (an identity owns its keys); `operation` is a plain Name
> prefix; the window is `not_before ≤ now < not_after`. Crucially it adds **no
> new crypto** — signing uses the existing `Signer`, and verification the existing
> `Validator`/`SignatureType` dispatch (so Ed25519/ECDSA-P256/RSA all work
> unchanged). 8 witnesses cover encode/decode, grantee match (identity-prefix and
> exact-key), scope, the validity window, and malformed/truncated input.

---

## 6. Confidentiality and access control

The two senses of "NAC" are kept distinct throughout:

- **Confidentiality tier** ("encrypt on top of sign") — the principle that NDN
  signs for authenticity and a separate layer encrypts for confidentiality.
- **NAC protocol** — the specific named key-distribution scheme (authority serves
  public params and decryption keys over NDN; content-key indirection).

The content-key (CK) indirection is the mechanism both share.

### 6.1 Content-key indirection (`ndn-security::confidentiality`)

Content is sealed under a random **ChaCha20-Poly1305** content key (CK); the CK is
wrapped (by ABE or by per-recipient AEAD key-wrap) into a separately-nameable,
cacheable `CkData` object. This separates the expensive operation (key wrap) from
the cheap one (AEAD seal), so a producer wraps once and seals many payloads — and
re-keys without re-wrapping for unchanged policy. NDNSF's `HybridMessageCrypto`
(epoch-rotated keys, wrapped, with all metadata bound into the AAD) is the
reference for rotation policy (60 s / 10 000 uses) and AAD discipline.

> **Cipher note.** The CK uses ChaCha20-Poly1305, not NDNSF's AES-256-GCM. Since
> ABE/encrypted content does not interoperate with the C++ stack regardless
> (§7.3), there is no reason to match its cipher, and ChaCha20-Poly1305 is the
> already-present `ndn-crypto-core` AEAD baseline (`no_std`, no-alloc, wasm-safe,
> constant-time). The CK primitive delegates its AEAD to that baseline. Implemented
> in `ndn-security::confidentiality` (`ContentKey`, `Sealed`, `wrap_ck`/`unwrap_ck`,
> `RotatingKey`/`EpochPolicy`); 12 witnesses cover round-trip, AAD/tamper/wrong-key
> rejection, wrap/unwrap, and age/use rotation.

### 6.2 Three ABE models → three access-control topologies

All three live in `ndn-security::abe`; only the model needed by a given deployment
is exercised.

| Model | Who decides access | Used for |
|---|---|---|
| **CP-ABE** (BSW) | the producer (ciphertext carries policy) | producer-owned content confidentiality |
| **KP-ABE** | a central authority (key carries policy) | centrally-governed read-access to content streams; the faithful NDNSF controller model (§7) |
| **MA-ABE** (AW11) | multiple independent authorities | cross-domain / federated deployments |

KP-ABE is required for the faithful NDNSF reimplementation (§7); whether the v2
layer uses it for centrally-governed *decryption* (its only surviving niche once
capabilities own *invocation*) is deferred (§9, O3).

> **Implemented.** All three schemes live in `ndn-security::abe`. KP-ABE landed
> via `scheme_kp` (rabe `lsw`) — `lsw_setup`/`lsw_keygen(policy)`/
> `lsw_encrypt(attrs)`/`lsw_decrypt`, plus typed `encrypt_kp`/`decrypt_kp`. The
> `AbeCiphertext` TLV container gained a structured `attributes` field (schema
> v2) carrying the KP ciphertext-side selector for inspection and AAD binding,
> with `AbeSchemeId::KpAbe` (wire disc 3). Witnesses cover the wrapper round-trip,
> the unsatisfied-policy negative, the container round-trip, and the typed
> end-to-end path.

### 6.3 Capabilities vs ABE — the split

Capabilities and ABE are not competitors; they answer different questions:

- **Capabilities** authorize *invocation* — "may this key call this operation
  now?" Cheap (one signature), offline-verifiable, the default for Tier-0 RPC.
  This replaces NDNSF's `UserToken`/`ProviderToken` bearer strings and most of
  what KP-ABE permission attributes did for access control.
- **ABE** provides *confidentiality* — "who can decrypt this content?" Expensive
  (pairing crypto), used only when policy-based encryption to many recipients is
  genuinely needed.

The non-negotiable capability rule: **never a bearer token.** A capability
authorizes a named key, proven by signature, verified offline, bounded in time,
checked against the engine's `ReplayGuard` for freshness. A bearer capability
(possession = authorization) flowing through NDN's caching/multicast fabric would
be a real security regression and is prohibited.

---

## 7. Compatibility layer (`ndn-ndnsf`, `ndn-nacabe`)

### 7.1 Scope of compatibility

Protocol/behavioral compatibility on a Rust-native stack: same NDN naming,
Interest/Data framing, SVS v3 wire (`StateVectorEntry(Name, SeqNoEntry(
BootstrapTime, SeqNo))`), the NDNSF message taxonomy and four-phase
REQUEST→ACK→SELECTION→RESPONSE flow, service discovery, and the NAC named
exchanges (PubParams / DKEY / CK-data naming). An ndn-rs node behaves like a C++
NDNSF node at these layers.

### 7.2 Roles

- `ServiceProvider` / `ServiceUser` — the four-phase RPC participants, over SVS
  pub/sub (faithful), built on `ndn-rpc`'s codec and `ndn-sync` (`ndn-ndnsf::roles`,
  wrapping the `driver`; see the ergonomic surface in §11.2 mode 1).
- `ServiceController` — the attribute authority. NDNSF uses **KP-ABE**: the
  controller reads an identity→permissions policy, converts each identity's
  permissions into an OR-join attribute key-policy, and issues it
  (`KpAttributeAuthority`-equivalent); content (the hybrid session keys) is tagged
  with service/permission attributes. This is why KP-ABE (§6.2) is required.

### 7.3 What does NOT interoperate

The ABE **ciphertext bytes** do not interoperate with NAC-ABE/openabe. ndn-rs uses
`rabe` (pure-Rust, `rabe-bn` curve); NAC-ABE uses `openabe` (RELIC, BN254). Even
for the same scheme, the pairing library, curve parameters, and group-element
serializations differ, so a Rust node cannot decrypt content a C++ node
ABE-encrypted, and vice versa. Consequence: in a mixed deployment, the service
protocol, discovery, sync, and NAC key-distribution *naming* interoperate, but
ABE-encrypted *content* is exchanged only between same-implementation peers. Full
ciphertext interop would require an feature-gated `libopenabe` FFI backend; it is
**out of scope** per the protocol-level-interop decision.

---

## 8. Performance

The case for the v2 default is structural: a Tier-0 call is one Interest/Data RTT;
an NDNSF call is four sync-convergence legs. Eliminating ~three legs and the sync
suppression/periodic-timer waits is the win, independent of any single
measurement.

The `examples/tier0-rpc-latency` harness establishes the **software floor** only:
running the engine in-process (isolating software cost from transport), a full
secure call (producer signature + RTT + consumer verification) costs tens of
microseconds, of which consumer verification is the larger share. This shows
dispatch/sign/verify are not the bottleneck; a real call's latency is dominated by
its single network RTT.

Constraints on performance claims:

- **No cross-stack ratio is asserted in this spec.** A same-environment NDNSF
  comparison is testbed-pending (the C++ stack is not built in CI). Until then,
  perf claims are limited to (a) the structural one-RTT-vs-four-legs argument and
  (b) the absolute in-process software floor.
- When a testbed exists, the comparison must run both stacks on the same medium;
  even then the numbers are supporting evidence, not the primary justification.

### 8.1 Observability (latency, traceable)

The service layer is instrumented with `tracing` spans at the latency boundaries
— ABE keygen/wrap/unwrap (`ndn-security::abe`), DKEY issuance
(`ndn-nacabe::authority`), the over-NDN `ParamFetcher` legs, and the four phase
transitions (`ndn-ndnsf::flow` `on_request`/`on_selection`). These spans flow
into `ndn-observability`'s OTLP-over-NDN pipeline (completed spans → OTLP Span
protobufs served as Data; cross-router stitching via `TraceContextFeature`), so a
service call yields an **OpenTelemetry waterfall** of exactly where time goes —
the per-leg breakdown the structural thesis (one RTT vs four convergence legs)
predicts, now measurable per deployment rather than asserted. Fail-closed
rejections emit `warn` events for rate/anomaly metrics. This is research
infrastructure: it makes latency and coordination behaviour visualizable without
a bespoke profiler.

---

## 9. Open questions and testbed-dependent items

- **O1 (testbed).** Same-environment Tier-0 vs NDNSF "targeted mode" measurement.
  Until available, §8's structural argument stands alone.
- **O2 (rabe KP-ABE).** ✅ Resolved. `rabe` 0.4.2 ships `lsw` (Lewko-Sahai-Waters)
  KP-ABE — the inverse of CP-ABE (key carries policy, ciphertext carries
  attributes), same `PolicyLanguage` and BN-254 curve as the existing CP-ABE path,
  and serde/bincode-serializable (verified by a round-trip + wire-round-trip
  witness, `abe::tests::lsw_kp_abe_round_trips_and_serializes`). The KP-ABE wrapper
  mirrors the BSW (CP-ABE) wrapper with the keygen/encrypt arguments swapped; its
  ciphertext rides in the same self-owned TLV container (§5.2), pinned by KATs.
- **O3 (v2 KP-ABE niche).** Decide, when the UAS roadmap is clearer, whether the
  v2 layer needs the authority to govern *decryption* (KP-ABE's only surviving
  niche once capabilities own invocation), or whether CP-ABE/AEAD suffice.
- **O4 (security invariants).** ✅ Extracted into
  `docs/specs/ndnsf-invariants.md` — a traceable catalogue (20 invariants, stable
  IDs, threat model, per-invariant ndn-rs enforcement mapping) **and the gate**:
  `ndn-nacabe`/`ndn-ndnsf` MUST NOT land until the invariants mapped to them have
  passing witnesses. The primitive-subset invariants (capability TTL/expiry/
  binding, content-key fail-closed) are runnable today —
  `ndn-security/tests/ndnsf_invariants_witness.rs` + the `nsf01_security_invariants.sh`
  audit script (6 witnesses, passing). The protocol-level invariants are the
  acceptance criteria for the layers that will enforce them.
- **O5 (cross-impl convention).** Decide whether to publish the §5.1 RPC name
  scheme (and possibly the §5.2 container) as a narrow proposed NDN convention,
  kept separate from this ndn-rs architecture spec. The rest of this document is
  ndn-rs application architecture, not a proposed change to NDN itself.

---

## 10. Implementation sequence

1. Tier-0 experiment (done — `examples/tier0-rpc-latency`).
2. Shared primitives: `ndn-security::confidentiality` (CK), `abe` KP-ABE + TLV
   container, `ndn-rpc` extracted from `ndn-compute`, `ndn-security::capability`.
3. Extract NDNSF security invariants into witnesses (O4) — gate before crypto/
   collab.
4. `ndn-nacabe` (NAC protocol) on the shared crypto. *In progress:*
   - **CK-data core** (`CkData`, `seal_cp`/`open_cp`, `seal_kp`/`open_kp`,
     fail-closed) + NAC naming (`PUBPARAMS`/`DKEY`/`CK`/`ENC-BY`).
   - **Authority issuance + ParamFetcher key-recovery** (`authority`):
     `CpAuthority`/`KpAuthority` hold the master secret + per-identity grants,
     issue a decryption key for an authorized requester (**fails closed** for an
     unenrolled one, NSF-A2/F5), and **seal** it to the requester's ephemeral
     X25519 key via `ndn-sealed-box` (confidential delivery, NSF-F3); the
     `ParamFetcher` side (`open_cp_dkey`/`open_kp_dkey`) opens it. End-to-end
     witnessed (issue→seal→open→unwrap-CK→decrypt-content for CP and KP;
     unenrolled fails closed; a DKEY sealed to one recipient won't open for
     another). 10 witnesses, clippy-clean.
   - **Over-NDN serve/fetch shell** (feature `service`): `serve_cp`/`serve_kp`
     run the authority on an `ndn-app` Producer (serve `PUBPARAMS`; validate
     signed `DKEY` Interests — NSF-A1 — and issue to the *validated signer's*
     identity — NSF-A2 — failing closed otherwise); the `ParamFetcher` fetches
     and verifies both. End-to-end witnessed over an in-proc engine
     (`aa_paramfetcher_witness`): signed request → validated → key sealed to the
     requester → decrypts NAC content. **Step 4 complete** (the F1/F2
     failure-callback/log semantics are NDNSF-runtime concerns that land with
     `ndn-ndnsf`).
5. Compat: `ndn-ndnsf` (four-phase + KP-ABE controller). *In progress:* sans-IO
   core landed — `tokens` (the provider-token/pending-state machine: one-time
   consume, TTL expiry, idempotent bounded cleanup; closes O4 NSF-T1/T3/T4/T5/T6
   + NSF-S1–S5, 7 witnesses), `names` (the V2 four-phase name builders), and
   `messages` (the four-phase message TLV taxonomy — Request/Ack/Selection/
   Response at types 128–131, faithful sub-field numbers, tolerant decode for
   interop), and `flow` (the sans-IO four-phase orchestration core: `ProviderEngine`
   issues a single-use token on `on_request`→ACK and consumes it on
   `on_selection`, running the handler and building the RESPONSE, **failing
   closed** on a replayed/forged/expired token — the token-gated coordination),
   and `driver` (feature-gated) — the async SVS pub/sub binding: `serve_provider`
   + `call` run the four-phase flow over `SvsPubSub`, dispatching by the
   `NDNSF/<phase>` name marker and routing by token (only the issuing provider
   consumes a SELECTION). **Witnessed end-to-end over real SVS convergence**
   (`four_phase_over_svs`: two `SvsPubSub` nodes, broker-crossed medium, a full
   REQUEST→ACK→SELECTION→RESPONSE round-trip). Per-phase spans flow to OTLP/NDN
   (§8.1). **KP-ABE access control wired** (`access`): the provider NAC-seals
   payloads under the service's attributes and only a holder of a satisfying
   `ServiceController`-issued key decrypts — unauthorized fails closed
   (`secure_four_phase_over_svs` witness). This closes the NAC-ABE-authorization
   half of NSF-A3. **Selection strategies + request modes landed:** the message
   taxonomy now carries `strategy` (155), `request_mode` (189), and
   `target_provider` (161); `flow::select_providers` implements `FirstResponding`
   / `RandomSelection` / `AllSelected` (unit-witnessed multi-provider), and the
   driver's `select_and_call` collects ACKs over a window and honors the
   strategy (the plain `call` remains the single-provider `FirstResponding`
   convenience). **Targeted fast path landed** (`bootstrap_targeted` issues a
   token pool; `call_targeted` invokes a provider directly, REQUEST→RESPONSE, no
   ACK/SELECTION; invalid token fails closed — `targeted_over_svs` witness).
   **Policy-file model landed** (`policy`): a TOML `ServicePolicy`
   (providers/users + `allowed_services`) compiles each principal's services
   into the OR-join KP-ABE policy and grants it on the `KpAuthority`
   (`apply_to`). **Per-message trust-validation mechanism landed** (`trust`):
   `sign_message` (publish as signed Data) + `verify_message` (validate against
   trust anchors and require the signer be under the message's expected sender,
   fail closed) — the NDNSF `MessageValidator` analog, reusing the real
   `ndn_security::Validator` (4 witnesses). **Remaining for full fidelity:**
   thread `sign_message`/`verify_message` through every driver leg (cleaner
   long-term home: `SvsPubSub`-level signing + the `IngestValidator` seam), the
   unsigned-discovery posture (NSF-A4), and the F1/F2 callback/log runtime
   semantics.
6. v2: `ndn-service` (Tier-1 selection + Tier-2 collab, authority-as-signed-Data).

---

## 11. User-facing API and developer ergonomics

> Status: **partially built**. Mode 1 (the closure/role surface — `ServiceProvider`
> / `ServiceUser`) is **landed and witnessed** (`ndn-ndnsf::roles`,
> `roles_ergonomics` test). The underlying *pieces* for the rest exist and are
> tested (typed handler API in `ndn-rpc`/`ndn-compute`; KP-ABE policy backing in
> `ndn-nacabe`, O4-witnessed; the fuel-metered wasm sandbox in `ndn-compute`).
> Still **planned**: the `#[ndn_service]` macro, the PyO3/boltffi *service*
> surface, and the TOML policy parser — a deliberate later phase that wraps the
> role surface, not a precursor to it. **Worked examples are added as each piece
> lands** (the `roles_ergonomics` witness is the mode-1 worked example).

### 11.1 Stance: don't choose between codegen and scripting

The latest C++ NDNSF replaced its IDL **code generator** with a **Python
interface** — a decorator-over-subprocess wrapper (`@provider.handler` driving
the C++ binaries, with a `policy_file` for the controller). That trades a
toolchain + stale-stub problem for runtime scripting, at the cost of static
types and an extra process boundary.

Rust lets us avoid the choice. A **proc-macro is an in-language code generator**
(typed, no separate toolchain, no stub drift), and **PyO3/boltffi give the
scripting front-end over the *embedded* engine** (no subprocess shuttle). The
macro serves typed-native developers; the bindings serve scripting developers;
both target one forwarder.

| Axis | NDNSF | ndn-rs plan | Verdict |
|---|---|---|---|
| Handler definition | `@provider.handler` decorator (untyped `bytes→bytes`) | closure/trait handler, compile-time typed (shape of `ndn-rpc`/`ndn-compute`) | match + types |
| Codegen | abandoned IDL generator | `#[ndn_service]` proc-macro on a trait → message types, dispatch, name routing, client stub | improve (typed, no toolchain/stub drift) |
| Scripting | Python wrapper that spawns C++ | PyO3 (`ndn-python`) + boltffi (mobile) over the embedded engine | match + improve (no subprocess) |
| Service policy | policy file → KP-ABE controller | same KP-ABE model (`ndn-nacabe::KpAuthority`, O4-witnessed), authored as TOML (`ndn-config` convention) or a typed `PolicyBuilder` | match workflow, improve backing |
| Dynamic code | unsandboxed Python handlers | wasm sandbox (`ndn-compute` `wasm-exec`) for untrusted; native closures for trusted | improve (real isolation) |

### 11.2 Three definition modes, one wire

A service is definable three ways, all over the same protocol:

1. **Closures / roles** (quickest, **built**) — `ServiceProvider::new(..).serve(|coord, req| ..)`
   and `ServiceUser::new(..).call(provider, payload)`, the typed analogue of
   NDNSF's decorator. The role structs bundle the *stable* fields (pub/sub,
   identity, service, group, `TrustCtx`) so a call supplies only what *varies*;
   request ids are auto-assigned; `.signed(signer, validator)` flips on NSF-A3
   message trust. See `ndn-ndnsf::roles` and the `roles_ergonomics` witness.
2. **`#[ndn_service]` trait** (typed, multi-method, *planned*) — the macro emits the
   message taxonomy, dispatch, and a typed client **generic over a `Carrier`**
   (§12), so one definition runs over Tier-0, the NDNSF four-phase, or v2
   unchanged. Unary operations only (topics are a separate primitive). This is the
   *service definition mechanism*: a trait is the IDL, checked by the compiler.
3. **PyO3 decorator / Kotlin-Swift** (*planned*) — `@provider.handler` (or the mobile
   equivalent) bound to the embedded engine via `ndn-python` / boltffi.

> What mode 1 taught us (feeds the v2 design / steps 5–6):
> - The **stable/varying split** is the right decomposition and is what the macro
>   and bindings should wrap — they emit typed methods *over a role*, not over the
>   raw driver.
> - **Request-id management is protocol bookkeeping** the caller should never see;
>   auto-assignment belongs in the surface, not the handler.
> - The closure handler is **sync `&Bytes -> Bytes`** — the real ceiling (typed
>   `Req`/`Resp`, `async`, error returns, multi-method) is exactly the gap mode 2
>   fills; mode 1 is the floor it builds on.
> - A role owns one `SvsPubSub`; a node vending *several* services over one
>   engine wants a `ServiceNode` that mints roles sharing the group. **Built**
>   (`ServiceNode::provider`/`user` over one `Arc<SvsPubSub>`); this surfaced a
>   latent driver gap — `serve_provider` did not filter by `serviceName`, so
>   co-located services would cross-answer. Now the driver routes each REQUEST/
>   SELECTION to the provider serving its service (witness `service_node_multi`).
>
> _TODO (add when mode 2/3 land): the same echo service as a `#[ndn_service]` trait
> and a Python decorator, shown interoperating on the wire with mode 1._

### 11.3 Service policy

Access policy stays KP-ABE-backed (the `ServiceController` model already built
and held to the O4 invariants): an identity→permissions mapping compiled to
KP-ABE key-policies and issued by `ndn-nacabe`'s `KpAuthority`. Authoring is
file-driven (a TOML policy in the `ndn-config` convention, matching NDNSF's
`policy_file` workflow) or via a typed `PolicyBuilder`.

> _TODO (add when built): a sample `policy.toml` and the equivalent
> `PolicyBuilder` code, plus the controller wiring._

### 11.4 Dynamic code

Trusted handlers are native closures/trait methods. Untrusted or operator-supplied
dynamic handlers run in the fuel-metered wasm sandbox (`ndn-compute`'s
`wasm-exec`) — an improvement over NDNSF's unsandboxed Python business logic.

> _TODO (add when built): a worked wasm-handler example (compile a kernel, register
> it, invoke it under a fuel budget)._

### 11.5 What exists vs planned

- **Exists, tested:** the **role surface** (`ndn-ndnsf::roles` —
  `ServiceProvider`/`ServiceUser` + `ServiceNode` for multi-service-per-engine,
  mode 1, `roles_ergonomics` / `service_node_multi` witnesses); typed
  handler/registry (`ndn-rpc`, `ndn-compute`); KP-ABE policy backing
  (`ndn-nacabe::KpAuthority`); wasm sandbox (`ndn-compute`).
- **Planned:** the `#[ndn_service]` proc-macro (mode 2, emitted over the
  **carrier seam** of §12 — not over one transport); the PyO3/boltffi *service*
  surface (mode 3); the TOML policy parser; the remaining worked examples above.

---

## 12. Service trait and pluggable carriers (the v2 core)

> Status: **seam built and proven** (2026-06-19). `ndn-service-core` (the traits)
> and the Tier-0 `RpcCarrier` over `ndn-rpc` are landed, with a hand-written
> rendering of the macro's output (`ndn-rpc/tests/carrier_proof.rs`) round-tripping
> a typed two-op service over the carrier (+ fail-closed on unknown op/service).
> Still to build: the `NdnsfCarrier`, the v2 carrier, the `#[ndn_service]` macro
> (§11.2 mode 2), and `SelectCarrier` impls. This generalises the role surface
> (§7.2, `ndn-ndnsf::roles`, built) into a transport-independent service
> abstraction the compat layer **and** v2 **and** Tier-0 all share.

### 12.1 The seam: contract vs carrier

Separate the **typed contract** (what the service *is*) from the **carrier** (how
an invocation is *named, transported, multiplexed across providers, and trusted*).
This is the split every durable RPC system keeps (tarpc/tonic/Cap'n Proto), and
NDN makes it cleaner: a response is fundamentally a **named, signed, cacheable
Data object**, so a "carrier" is really a naming + retrieval model — exactly what
differs between NDNSF four-phase, Tier-0 Interest/Data, and v2.

### 12.2 The primitive set (small and orthogonal — the anti-"do-everything" line)

- **`Operation`** — one **unary** typed method `async fn op(Req) -> Result<Resp>`.
  The *only* RPC primitive. Streaming/bidi is a **non-goal**: it is where RPC
  systems rot, and it is expressible by composing topics.
- **`Carrier`** — the pluggable backend; owns naming, transport, multiplicity, and
  trust:
  ```rust
  trait Carrier {
      // client: invoke `op` of `svc` with a request blob → a response.
      async fn invoke(&self, svc: &ServiceId, op: &OpId, req: Bytes) -> Result<Response>;
      // server: run a macro-generated Dispatch (decode op → typed handler) until closed.
      async fn serve(&self, dispatch: Arc<dyn Dispatch>);
  }
  struct Response { producer: Name, payload: Bytes, /* freshness, … */ }
  // server-side context the carrier hands each invocation:
  struct Invocation { op: OpId, request: Bytes, requester: Option<Name> /* for access */ }
  trait Dispatch { async fn dispatch(&self, inv: Invocation) -> Result<Bytes>; }
  ```
- **Selection is a carrier *refinement*, not a contract concern** —
  `trait SelectCarrier: Carrier { async fn invoke_select(.., Strategy) -> Vec<Response>; }`.
  The generated client always exposes `op(req) -> Resp`; it *also* exposes
  `op_select(req, Strategy) -> Vec<(Name, Resp)>` **only where `C: SelectCarrier`**
  (a per-method `where`-bound). Compile-time depth-as-needed: a Tier-0
  known-provider carrier literally cannot call the multi-provider form.
- **Topics (pub/sub) are a *separate* primitive** (typed `Topic<T>` over SVS), not
  a trait member. Tier-2 collaboration = services **+** topics *composed*. This is
  the boundary that keeps `#[ndn_service]` from drifting into gRPC.

### 12.3 The three carriers (one definition, three backends)

| Carrier | Backend | Multiplicity | `SelectCarrier`? |
|---|---|---|---|
| `RpcCarrier` | Tier-0 `ndn-rpc`: signed Interest → signed Data, 1 RTT; idempotent via the Content Store | one known provider | no |
| `NdnsfCarrier` | NDNSF four-phase over `ndn-ndnsf::ServiceNode`/driver; token coordination; `TrustCtx` | many providers | yes (FirstResponding/Random/All) |
| v2 carrier | `ndn-service` (Tier-1 selection / Tier-2 collab); authority-as-signed-Data | per pattern | per pattern |

### 12.4 What the macro generates

From a unary trait, `#[ndn_service]` emits: the per-op `Req`/`Resp` message types
(TLV framing, §12.5), a type-erased `Dispatch` impl that routes an `OpId` to the
right typed handler method, and a client `EchoClient<C: Carrier>` whose methods
call `carrier.invoke`. The client is **generic over the carrier** — the same
`Echo` definition runs over `RpcCarrier`, `NdnsfCarrier`, or the v2 carrier
unchanged. The trait is the IDL, checked by the compiler.

### 12.5 The three disciplines (these are the design, not decoration)

1. **TLV framing with skippable unknown fields** — never positional encoding.
   Services evolve by appending optional fields; old and new peers interoperate.
   (Reuses the project's TLV convention; *not* bincode.)
2. **Idempotency + dedup** — a carrier may retry or multicast, so operations are
   contractually idempotent, and multi-provider carriers enforce once-only
   execution (NDNSF's token model already does). Documented per service.
3. **Secure by default** — a carrier is constructed *with* trust (a `TrustCtx` /
   capability verifier); running unauthenticated requires an explicit
   `.insecure()`. Large responses segment via the object/RDR path inside the
   carrier; the contract is oblivious to packet size.

### 12.6 Abuse analysis (eyes-open)

- **The `Carrier` surface is make-or-break.** Bare-`Bytes` returns can't carry
  provider identity (selection), freshness, or ABE-sealed payloads; hence
  `Response`/`Invocation` are the minimal-but-richer shapes above. Getting this
  context object right is the crux of the build.
- **Carrier-semantics leakage** — a service assuming exactly-once over an
  at-least-once carrier. Defense: the idempotency contract + token-enforced
  once-only execution on multi-provider carriers.
- **Scope creep** toward streaming/bidi. Defense: explicit non-goal; compose two
  topics.

### 12.7 Crate layout (extends §2.2; preserves "extract once")

The traits and macro are **shared substrate**, depended on by both compat and v2
(so compat never depends on v2):

```
EXT (ndn-ext) — shared service substrate
  crates/service/ndn-service-core    Service/Carrier/SelectCarrier/Dispatch/Invocation/Response + Frame trait  [built]
  crates/service/ndn-service-macro   the #[ndn_service] proc-macro (emits over ndn-service-core)               [not built]
```

Carriers live with their transports: `RpcCarrier` in `ndn-rpc` (**built + proven**),
`NdnsfCarrier` in `ndn-ndnsf` (wrapping `ServiceNode`, not built), the v2 carrier
in `ndn-service` (not built). No duplication: `ndn-rpc` stays the Tier-0
mechanism; `ServiceNode` stays the four-phase engine; the carrier is the uniform
façade over them.

The `RpcCarrier` proof (`ndn-rpc/tests/carrier_proof.rs`) hand-writes the macro's
output — a `Frame` request/response pair, a `Dispatch` routing two `OpId`s to a
typed service impl, and a client generic over `C: Carrier` — and round-trips it
over real `Interest`/`Data` through the `RpcRegistry`. It is an **in-process
loopback** (invoke dispatches through the same registry serve mounted into); a
face-backed `RpcCarrier` (Interest over a `Consumer`, registry served by a
`Producer` on an engine) is the same impl wired to a transport, deferred — that
engine plumbing is already witnessed in `ndn-nacabe`.
