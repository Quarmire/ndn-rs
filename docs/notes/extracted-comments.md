# Extracted Comments

Design rationale and architectural context extracted from inline comments during
comment cleanup. These may be incorporated into proper design docs or the wiki
later.

## ndn-engine / rib.rs — RIB vs discovery route ownership

Discovery protocols (link-local neighbor discovery) write directly to the FIB
via `EngineDiscoveryContext`. Those routes are **not** tracked in the RIB. For a
given prefix, the RIB and discovery subsystem should not both manage the same
face — in practice they target disjoint prefix ranges (`/ndn/local/…` for
discovery, global prefixes for routing protocols).

Multiple concurrent routing protocols coexist via distinct origin values. All
their routes coexist in the RIB; the FIB sees only the best computed result.
Stopping a protocol with `flush_origin` removes its routes and recomputes the
FIB for affected prefixes, revealing routes from other protocols that may have
been shadowed.

## ndn-engine / engine.rs — outbound send queue design

The pipeline pushes packets to a per-face send queue via `try_send`
(non-blocking) and a dedicated per-face send task drains the queue, calling
`face.send()` sequentially. This decouples pipeline processing from I/O,
preserves per-face ordering (critical for TCP framing), and provides bounded
backpressure.

Queue capacity (2048 slots): with NDNLPv2 fragmentation, a single Data packet
may expand to ~6 fragments, each occupying one slot. 2048 slots ≈ ~340 Data
packets — enough headroom for sustained bursts over high-throughput links
without silent drops.

## ndn-transport / congestion.rs — CUBIC with_window regression

A consumer that called `CongestionController::cubic().with_window(64).with_ssthresh(64)`
would see the first `on_data()` call drop the window from 64 to ~1.4 — because
`with_window` didn't update `w_max` (it stayed at the default 2.0), and the
cubic formula's "recovery target" was therefore ~2, which the code assigned to
`*window` unconditionally. At pipe=64 this turned a 60 ms fetch into a 4.5
second fetch because `window.floor()` was 1 for most of the subsequent
slow-start recovery.

The fix has two parts: `with_window` now updates `w_max` for Cubic, and
`on_data`'s cubic branch clamps the result to `max(cwnd, W_cubic, W_est)` so
successful data delivery can never shrink the window.

## ndn-security / file_tpm.rs — Ed25519 sentinel suffix

The on-disk format for RSA and ECDSA-P256 keys is bit-for-bit compatible with
`ndnsec` (ndn-cxx `tpm-file` backend, pinned to ndn-cxx-0.9.0, commit
`0751bba8`, `back-end-file.cpp` lines 51–229).

Ed25519 is not supported by ndn-cxx `tpm-file` — its `d2i_AutoPrivateKey` path
only autodetects RSA and EC from ASN.1 tags, and `BackEndFile::createKey`
rejects anything else (`back-end-file.cpp:130-139`). To preserve Ed25519 as a
first-class algorithm without breaking ndn-cxx interop, keys use a sentinel
filename suffix:

- `<HEX>.privkey`         → RSA / ECDSA, exactly as ndn-cxx writes
- `<HEX>.privkey-ed25519` → ndn-rs Ed25519 PKCS#8, ignored by ndnsec
