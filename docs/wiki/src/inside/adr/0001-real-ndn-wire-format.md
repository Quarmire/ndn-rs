# 0001 · Target the real NDN wire format, not a private dialect

**Status:** Accepted

## Context

A clean-slate NDN stack could define its own packet encoding — simpler to
implement, free to evolve. But NDN already has a published wire specification
(NDN Packet Format v0.3) and a decade-old ecosystem of interoperating
implementations: NFD and ndn-cxx (C++), python-ndn, NDNts (TypeScript),
NDN-DPDK (Go), ndnd (Go), and a running global testbed. A private dialect would
be an island.

## Decision

Encode and decode the **real** NDN Packet Format v0.3 and NDNLPv2, byte for
byte, and treat interoperation with the existing ecosystem as a correctness
requirement rather than a nice-to-have.

Concretely, the type numbers in `ndn-packet` are the spec's: Interest `0x05`,
Data `0x06`, `LpPacket 0x64`, the signed-Interest TLVs `0x2C`/`0x2E`, and so on.
The NFD management wire codec in `ndn-mgmt-wire` is cross-checked against
ndn-cxx's `tlv-nfd.hpp`; strategy names carry NFD's `/v=N` version convention;
the trust-schema loader imports python-ndn's LightVerSec binary format; and the
NDNCERT and sync codecs are validated against recorded interop transcripts
(`testbed/transcripts/`, including live pcaps).

## Consequences

- **Positive:** ndn-rs forwarders and apps can, in principle, join the existing
  testbed and talk to NFD/ndnd peers. The conformance surface is checkable
  against an external spec, not just internally consistent
  (see the [conformance matrix](../conformance-matrix.md)).
- **Positive:** the wire layer is a stable contract, which makes fuzzing and
  property-testing it worthwhile (they encode the spec's invariants).
- **Cost:** we inherit the spec's quirks — evolvability critical-bit rules,
  non-minimal-encoding rejection, the URI naming conventions — and must
  implement them faithfully even where a private format would be simpler.
- **Cost:** experimental/provisional TLV types must be chosen in the even
  (non-critical) range so stock forwarders ignore rather than reject them.

## Alternatives considered

- **A private, simpler encoding.** Rejected: it would forfeit the entire reason
  to build an NDN stack — interoperation with the data-centric ecosystem — for
  a one-time implementation saving.
- **Spec-compatible "mostly".** Rejected: partial compatibility is the worst of
  both worlds; a peer that *almost* interoperates fails in the field in ways
  that are expensive to debug.
