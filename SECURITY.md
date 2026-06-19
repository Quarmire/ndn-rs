# Security Policy

## Status

`ndn-rs` is **pre-1.0 and not yet proven correct**. It has undergone an
evidence-based security and spec-compliance audit, but it is **not** a reference
implementation of NDN. Do not deploy it where a compromise would be costly
without your own review. See the
[spec-compliance summary](docs/wiki/src/reference/spec-compliance.md).

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
unfixed vulnerability.

- Preferred: open a [GitHub private security advisory](https://github.com/Quarmire/ndn-rs/security/advisories/new)
  on this repository.
- Alternatively, contact the maintainer directly via the email on the
  maintainer's GitHub profile.

Please include:

- the affected crate(s) and version / commit,
- a description of the issue and its impact,
- a minimal reproduction (a crafted packet, input, or test) where possible,
- whether the issue is reachable from the network / an untrusted face.

We aim to acknowledge a report within a few days and will coordinate a fix and
disclosure timeline with you.

## Scope

In scope: the crates in this repository (the core library — TLV/packet codecs,
security/trust, the forwarding engine, faces, sync). The highest-value reports
are **anything reachable from a network byte** that can panic, over-allocate, or
admit unverified data into the forwarding/Content-Store path.

Out of scope here (separate repositories, report there): `ndn-ext`, `ndn-fwd`,
`ndn-dashboard`, `ndn-mobile`, `ndn-repo`, the BLE/Wi-Fi face crates.

## What we treat as release-blocking

- Remote-reachable panics, unbounded allocations, or memory-unsafety.
- Unverified data being accepted as authenticated.
- Trust/validation bypasses.

## Hardening notes for operators

- Enable the `ndn-ratelimit` inbound hook on any face that accepts Interests
  from untrusted peers — the PIT is not hard-capped (see
  [security pitfalls](docs/wiki/src/guides/security-pitfalls.md)).
- Prefer the SQLite Content-Store backend for persistent caches.
- Keep `require_signed_commands = true` (the default) on the management plane.
