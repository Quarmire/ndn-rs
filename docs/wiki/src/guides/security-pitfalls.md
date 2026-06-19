# Security pitfalls

The security model is sound, but a few defaults and habits let you wire an
insecure path without noticing. Each pitfall below names the mistake and the
checked alternative. See [Trust, first](../start/trust-first.md) for the model
and [Trust policies](../reference/trust-policies.md) for the policy catalog.

## Consuming data without verifying it

`Consumer::fetch` and `Consumer::get` return raw `Data` / bytes. They do **not**
validate the signature — an application that uses their result has accepted
unauthenticated data.

Use the checked surfaces instead:

- `fetch_verified(name, &validator)` returns `SafeData` only when the signature
  verifies and the trust schema accepts it. This is the default to reach for.
- `fetch_unverified(name)` returns `Unverified<Data>`, which has no way out
  except `.verify(&validator)` (yielding `SafeData`) or `.trust_unchecked()` (a
  deliberate, greppable bypass). You cannot use the data by accident.

A full worked example is the `secure_fetch` integration test in `ndn-app`.

## Treating "signed" as "trusted"

A valid signature is necessary, not sufficient. Two specific traps:

- **`DigestSha256` is integrity, not identity.** It proves the bytes match their
  own digest — anyone can compute one. It identifies no signer. Do not accept it
  as authentication for data that crosses a trust boundary.
- **A permissive schema accepts too much.** An empty or `accept_all` schema will
  pass packets you did not mean to trust. Validation is only as strong as the
  schema you give the `Validator`.

## Storing an identity is not trusting it

Loading or creating a `KeyChain` for an identity does **not** make that
identity's data trusted. Trust comes from **pinning an anchor**: add the
certificate to the `Validator` (`add_trust_anchor`, or `KeyChain::trust_only`),
then the schema decides what that anchor may sign. Forgetting the anchor makes
verification fail (or silently pass nothing), which is easy to misread as "it
works."

## Shipping test-only trust into production

These exist for tests and degraded/offline modes and must never reach
production:

- `InsecureTrust` — accepts without checking.
- `accept_all` schema / `AcceptAllPolicy` — skips schema enforcement.
- `AcceptAllIssuance` — a CA that issues to anyone.

They are loud in the API for a reason; confirm none survive into a deployed
build.

## Confusing adoption with enrollment

These are different acts with different outcomes:

- **Adopting** a trust context gives you the anchors to **verify** its data. It
  does not let you sign as a member.
- **Enrolling** gets you a certificate so you can **be verified** by others. It
  does not, by itself, give you anchors to verify *them*.

If verification of incoming data fails, check that you adopted (have the anchor),
not only that you enrolled.

## Running an open forwarder without flood protection

The Pending Interest Table is **not hard-capped** (the same as NFD): a fixed
ceiling would have to drop in-flight Interests. Reaping is time-based, so a
spoofed-name Interest flood from an untrusted face grows the PIT to roughly
`rate × InterestLifetime` and can exhaust memory.

If a forwarder accepts Interests from untrusted faces, **enable the `ndn-ratelimit`
inbound hook** for per-face / per-prefix admission control — it is the
PIT-exhaustion defence and is opt-in (off by default). The Dead Nonce List and
the signed-Interest replay guard *are* capacity-bounded, but they do not bound
the PIT itself. Treat a forwarder with no rate limiter on a public face the way
you would treat a bare NFD with no face/strategy limits.

## "Verified" in the Content Store includes DigestSha256

The forwarder caches Data once `ctx.verified` is set, and a correct
`DigestSha256` (a bare content hash, no signer) counts as verified for that
*integrity* gate — the same as NFD, which caches DigestSha256 Data. This is
**integrity, not authenticity**: it proves the bytes match the digest, not that
any identity vouched for them. The application layer still refuses to treat
DigestSha256 as authenticated (`Unverified::verify` rejects it by default). So
read "only verified Data is cached/forwarded" as "*integrity*-checked at the
engine; *authenticity* is the app's `verifying()` decision."

## Browser trust uses the client wall-clock

On `wasm32` the security timestamp source is `web-time`, i.e. `Date.now()` — a
wall-clock the user can change. Certificate validity-window checks and the
signed-Interest `SignatureTime` replay defence on an in-browser engine therefore
trust the client clock. The cryptographic chain still verifies; but a user who
moves their clock can affect validity-window and replay-window decisions. Don't
rely on browser-side time for security-critical freshness; anchor those decisions
on a trusted forwarder where it matters.

## See also

- [Trust, first](../start/trust-first.md) — why a valid signature is not trust.
- [Trust policies](../reference/trust-policies.md) — the schema/policy catalog.
- [NDNCERT setup](./ndncert-setup.md) — issuance and challenge configuration.
