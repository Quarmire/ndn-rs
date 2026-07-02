# 0002 · Make data-centric verification compiler-enforced (`SafeData`)

**Status:** Accepted

## Context

NDN's central security thesis is *secure the data, not the channel*: every Data
packet is signed, and a consumer must verify that signature against a trust
anchor before trusting the bytes. In the reference stacks this is a discipline —
the API hands you the Data and you are expected to call the validator. Nothing
stops you from skipping it, and "did I actually verify this?" is answerable only
by reading the call site.

For a security-first stack that is too weak. Unverified data flowing into
application logic is the single most likely security bug, and it should not be
possible to write it by accident.

## Decision

Make verification a **type transition the compiler enforces**, in
`ndn-security`:

- The trusted payload type is `SafeData`. Its constructor is crate-private — the
  *only* way to obtain one is to pass a `Validator` and have the signature
  check succeed.
- The consumer surface returns `Unverified<Data>`, which has exactly two exits:
  `.verify(validator)` (yields `SafeData` or an error) or the deliberately
  loud, greppable `.trust_unchecked()`. There is no silent path to usable bytes.
- A bare SHA-256 digest does **not** count as authentication: `verify` rejects
  `DigestSha256`-only packets with `UnauthenticatedDigest` unless the caller
  explicitly opts in. Integrity is not identity.
- Validators default to *deny* (hierarchical trust schema), never accept-all.

## Consequences

- **Positive:** "unverified data used as if trusted" becomes a type error, not a
  code-review finding. Auditing reduces to grepping for `trust_unchecked`.
- **Positive:** the type discipline is strongest at the app/consumer boundary,
  where `SafeData` is the only currency. Inside the forwarder the equivalent
  guarantee is enforced dynamically — a `PacketContext::verified` flag set by
  the validation stage, with Data dropped on a validating face if it isn't set
  — rather than by the type, because the pipeline moves wire bytes, not
  `SafeData` values.
- **Cost:** the API is slightly more ceremonious than "fetch returns bytes" —
  every consumer path names the verification step. This is intended friction.
- **Cost:** an escape hatch must exist (`trust_unchecked`) for the genuinely
  unauthenticated cases (opportunistic caching, digest-addressed content); its
  visibility is the mitigation.

## Alternatives considered

- **Validator-as-function, verification-by-convention** (the ndn-cxx model).
  Rejected: it makes the safe path and the unsafe path look identical at the
  call site.
- **Mandatory verification with no escape hatch.** Rejected: some NDN patterns
  (digest-named immutable content, in-network caching of not-yet-trusted data)
  legitimately handle unverified bytes; forbidding it outright would push
  users to unsafe work-arounds that hide the fact.
