# 0003 · Share native + embedded logic through sans-IO seed crates

**Status:** Accepted

## Context

ndn-rs targets everything from datacenter forwarders to bare-metal
microcontrollers. The native engine is async (tokio), allocates freely, and
uses `DashMap`/`RwLock`. A microcontroller forwarder is `#![no_std]`, often
no-alloc, single-threaded, and has no async runtime. Naively these are two
separate implementations of the same protocol — and two implementations of
"longest-prefix match" or "is this Data still fresh?" will drift apart, and the
bugs will differ per target.

## Decision

Extract the pure, **sans-IO** protocol logic — the parts that are neither async
nor I/O-bound nor allocation-dependent — into `#![no_std]` "seed" crates that
both the native and embedded builds depend on:

- `ndn-fwd-core` — the forwarding *rules*: FIB longest-prefix-match selection,
  freshness predicates (absolute and wrapping-relative), conformance checks,
  pipeline seeds. No async, no I/O, no tracing.
- `ndn-crypto-core` — the security primitives: one Ed25519 sign/verify and one
  ChaCha20-Poly1305 AEAD, no-alloc, shared byte-for-byte.

The wire layer (`ndn-tlv`, `ndn-packet`, `ndn-foundation-types`) is likewise
`no_std`+alloc so the same encoder/decoder runs on both. The native engine
wraps these rules in its async, sharded machinery; the embedded forwarder wraps
the *same* rules in a synchronous, `heapless` loop.

## Consequences

- **Positive:** a forwarding-rule bug is fixed once and both targets get the
  fix. The rules have one test suite, not two.
- **Positive:** the boundary is enforced in CI — a dependency-direction guard
  keeps the `spec`-classified crates closed under dependency, and the riscv32
  `no_std` build compiles the seed chain on every PR, so an accidental `std` or
  `tokio` edge into a seed crate breaks the build immediately.
- **Cost:** the seed crates are constrained — no async, no allocation in the
  hot predicates, no convenient `std` types. Writing there is more work.
- **Cost:** some logic that *could* be shared isn't worth the constraint and is
  duplicated deliberately; that trade-off is made case by case.

## Alternatives considered

- **One `std` implementation, no embedded target.** Rejected: embedded NDN
  (IoT, BLE meshes) is a first-class use case, not an afterthought.
- **Two independent implementations.** Rejected: guaranteed drift between the
  native and embedded forwarding decisions, with per-target bugs that are
  miserable to reconcile.
- **A `std`/`no_std` cfg-split inside one crate.** Rejected for the core rules:
  the cfg soup obscures which logic is actually shared; a separate crate makes
  the shared surface explicit and testable in isolation.
