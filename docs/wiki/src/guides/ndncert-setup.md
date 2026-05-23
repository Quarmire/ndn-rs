# NDNCERT setup

NDNCERT automates certificate issuance: an applicant requests a
certificate under some name; a CA challenges them (token, e-mail,
proof-of-possession); on success the CA signs and returns the cert.
This guide covers running an NDNCERT CA, joining as a user, and the
invite-token flow.

The implementation lives in `crates/ndn-cert/`. The CA binary
is `binaries/tooling/enroll-ndncert/`. Tokens are managed by
`binaries/ndn-fwd-tokens/`.

## Run a CA

A CA is an `InstallableProtocol` that registers `/ca/<ca-name>/CA`
and serves the NDNCERT verbs.

```sh
cargo run -p enroll-ndncert -- ca \
    --identity /lab/ca \
    --listen /tmp/ndn-fwd.sock \
    --policy issue-all-under /lab
```

What this does:

- Opens the default `KeyChain`, ensures `/lab/ca` exists with a
  self-signed cert.
- Connects to the running forwarder at `/tmp/ndn-fwd.sock`.
- Registers the CA prefix and starts serving NEW / CHALLENGE / etc.
- Issues certs only for names under `/lab` (the `--policy` flag).

The CA's `IssuancePolicy` decides whether an authenticated
applicant gets a cert. See
`crates/ndn-cert/src/issuance_policy.rs`. The default is
`AcceptAllIssuance` — fine for lab deployments, not for production.

## Join as a user

```sh
cargo run -p enroll-ndncert -- join \
    --ca /lab/ca \
    --identity /lab/alice \
    --challenge token \
    --token <TOKEN>
```

Walkthrough:

1. Generate a key under `/lab/alice` if one doesn't exist.
2. Send NEW to `/lab/ca/CA/NEW` carrying the key.
3. CA replies with a session ID and a challenge list.
4. Send CHALLENGE with the token.
5. CA verifies the token, signs the cert, returns it.
6. Joiner imports the cert into its `KeyChain` and persists the
   identity as a `SafeBag`.

The resulting `SafeBag` is spec-canonical and importable via
`ndnsec import`.

## Invite tokens

Tokens turn the joiner-side step into a copy-paste flow. The
operator generates a token, hands it (QR or paste) to the joiner,
and the joiner runs `enroll-ndncert join`.

Generate a token:

```sh
cargo run -p ndn-fwd-tokens -- generate \
    --ca /lab/ca \
    --identity-prefix /lab/alice \
    --ttl 7d \
    --max-uses 1
```

Print as QR:

```sh
cargo run -p ndn-fwd-tokens -- generate --qr ...
```

Tokens are stored on the operator's machine; revocation is
single-use or TTL-bounded.

## Challenge types

| Challenge | Joiner proves | Use |
|---|---|---|
| `token` | Possession of a one-time secret | Operator-issued invites. |
| `proof-of-possession` | Holds a private key for a previously-issued cert | Renewal. |
| `email` | Receives a mail token | Public deployments (with an SMTP-aware adapter). |
| `acme-dns01` | Wins an ACME DNS-01 challenge | Domain-bound names; see `testbed/tests/audit/acme_dns01.sh`. |

The challenge surface is in `crates/ndn-cert/src/challenge/`.

## Issuance policy

The post-challenge gate. An `IssuancePolicy` impl returns:

- `Accept(cert)` — sign and return the cert.
- `Reject(reason)` — refuse, with a human-readable reason.
- `Defer(callback)` — out-of-band hold (admin approval, etc.).

Built-ins in `crates/ndn-cert/src/issuance_policy.rs`:
`AcceptAllIssuance` (default), `NamespacePolicy`,
`ChallengeHandler` (three-stage seam recorded in
`project_f7_issuance_policy`).

## Configuration

CA-side `ndn-fwd.toml` section:

```toml
[ndncert.ca]
identity = "/lab/ca"
allow-namespace = ["/lab"]
challenge = ["token", "proof-of-possession"]
issuance-policy = "accept-all"
```

Run as a system service via the docker-compose stack — see
[Self-hosting](./self-hosting.md).

## Renewal

A holder of `cert-N` proves possession of its key to obtain
`cert-N+1`. The Producer can be configured to auto-renew before
expiry; see `crates/ndn-cert/src/auto_renew.rs`.

## Challenge attestations

A CA can record *how* a challenge was satisfied directly in the
issued certificate. The record rides in the cert's
`SignatureInfo` → `AdditionalDescription` (the non-critical
extension point used for cert metadata), so it is covered by the
CA's signature and skipped cleanly by verifiers that don't read it.

It is off by default — issued certs are byte-identical to the
plain flow until you opt in:

```rust,ignore
let config = CaConfig::new(/* … */).emit_attestations(true);
```

With it enabled, a token-challenge cert carries a single-leaf set
naming `token`. Composite challenges record one leaf per satisfied
sub with that sub's own evidence: `all-of` carries every sub,
`nofm` carries the `n` that were met, and `any-of` carries the one
that won. A cross-process `device-approval` leaf additionally
carries the approving device's identity and signature, verifiable
independently of the CA. The dashboard's trust-path inspector
renders the leaves, and `security/validate` returns them under
`challenge_attestations`.

The wire shape and the per-handler evidence each leaf carries are
documented in `docs/ndncert-attestations.md`; see
`crates/ndn-cert/src/attestation.rs` for the types.

## See also

- [Identity and keys](../concepts/identity-and-keys.md) — KeyChain
  surface that NDNCERT writes into.
- [Trust policies](../reference/trust-policies.md) — what a
  consumer checks against the cert chain.
- [Self-hosting](./self-hosting.md) — running CA and forwarder as
  containers.
- `crates/ndn-cert/` — implementation and protocol shape.
