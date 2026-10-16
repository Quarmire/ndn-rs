# NDNCERT setup

NDNCERT automates certificate issuance: an applicant requests a
certificate under some name; a CA challenges them (token, e-mail,
proof-of-possession); on success the CA signs and returns the cert.
This guide covers running an NDNCERT CA, joining as a user, and the
invite-token flow.

The implementation lives in `crates/security/ndn-cert/`. The CA binary
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
`crates/security/ndn-cert/src/policy.rs`. The default is
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

The challenge surface is in `crates/security/ndn-cert/src/challenge/`.
Every client runs the one NEW → CHALLENGE driver, `ndn_cert::client::enroll`,
over a `CaExchange` transport (PROBE is not sent; it is optional in NDNCERT
0.3). `ndn_identity::NdncertClient` is the `Consumer`-backed client; standard
token and possession challenges have typed `ChallengeParams` helpers, and named
custom challenges can pass their challenge identifier plus structured
parameters through the same session.

## Issuance policy

The post-challenge gate. An `IssuancePolicy` impl returns:

- `Accept(cert)` — sign and return the cert.
- `Reject(reason)` — refuse, with a human-readable reason.
- `Defer(callback)` — out-of-band hold (admin approval, etc.).

Built-ins in `crates/security/ndn-cert/src/policy.rs`:
`AcceptAllIssuance` (default), `NamespacePolicy`,
`ChallengeHandler` (three-stage seam recorded in
`project_f7_issuance_policy`).

## Configuration

`ndn-fwd` embeds a CA through its `[demo_ca]` section (full key list in the
[configuration reference](../operations/config-reference.md)). On a hub,
`ndn-fwd init --profile hub` writes the root anchor, a `/<ns>/CA` signing
identity certified by it, and the hub node's own identity `/<ns>/hub`
(`--node-name` picks another last component) into the node PIB, and prints
the `[security]` lines (`identity`, `pib_path`) that make the forwarder load
the node identity. The CA loads its identity, so the certs it issues chain to
the same root across restarts, and it persists issued certs, revocations and
redeemed tokens (hashed) under `<pib_path>/ca/`:

```toml
[demo_ca]
enabled  = true
prefix   = "/home/bob"      # serves /home/bob/CA/{INFO,NEW,CHALLENGE}
identity = "/home/bob/CA"   # signing identity loaded from the PIB

[[demo_ca.challenge]]
kind   = "token"
tokens = ["<one-time invite>"]

[[demo_ca.challenge]]
kind = "device-approval"     # approve via /localhost/nfd/ca/approve
```

A CA with no challenge refuses to start; `kind = "nop"` (auto-approve) must be
listed explicitly. `ephemeral = true` replaces the PIB identity with a
throwaway self-signed key for demos.

`/<prefix>/CA/REVOKE` revokes a cert this CA issued
(`ndn_cert::client::revoke`): the request carries a signature over the cert
name by the cert's own key (its holder) or by the CA's signing key; any other
key gets `Unauthorized`. A revoked cert is no longer served on cert-fetch and
its key is not re-certified, also after a restart.

Library users get the same pieces from `NdncertCa::builder()`:
`signing_identity` fixes the signing key (`CaConfig::signing_key`), and
`store(Arc::new(FileCaStore::open(dir)?))` makes issued certs and revocations
durable; `TokenStore::with_store(store)` does the same for token redemptions.

Run as a system service via the docker-compose stack — see
[Self-hosting](./self-hosting.md).

## Renewal

A holder of `cert-N` proves possession of its key to obtain
`cert-N+1`. The background renewal task watches a cert's remaining
validity and re-runs enrollment before expiry; see
`crates/security/ndn-identity/src/renewal.rs` (`start_renewal` +
`NdncertRenewer`).

## Challenge attestations

A CA can record *how* a challenge was satisfied directly in the
issued certificate. The record rides in the cert's
`SignatureInfo` → `AdditionalDescription` (the non-critical
extension point used for cert metadata), so it is covered by the
CA's signature and skipped cleanly by verifiers that don't read it.

It is off by default — issued certs are byte-identical to the
plain flow until you opt in. `CaConfig::new` takes the CA prefix,
an info string, the default and maximum validity windows, the
challenge handlers, and the pre-challenge namespace policy;
`emit_attestations(true)` is a builder method on the result:

```rust,ignore
use std::time::Duration;
use ndn_cert::ca::CaConfig;
use ndn_cert::challenge::token::{TokenChallenge, TokenStore};
use ndn_cert::policy::HierarchicalPolicy;

# fn build() -> CaConfig {
let prefix: ndn_packet::Name = "/lab/ca/CA".parse().unwrap();
let config = CaConfig::new(
    prefix,
    "lab CA".to_string(),
    Duration::from_secs(30 * 24 * 3600), // default validity
    Duration::from_secs(90 * 24 * 3600), // max validity
    vec![Box::new(TokenChallenge::new(TokenStore::new()))],
    Box::new(HierarchicalPolicy),
)
.emit_attestations(true);
# config
# }
```

`CaConfig::new` defaults the post-challenge `IssuancePolicy` to
`AcceptAllIssuance`; set `config.issuance` afterward to install a
stricter gate.

With it enabled, a token-challenge cert carries a single-leaf set
naming `token`. Composite challenges record one leaf per satisfied
sub with that sub's own evidence: `all-of` carries every sub,
`nofm` carries the `n` that were met, and `any-of` carries the one
that won. A cross-process `device-approval` leaf additionally
carries the approving device's validated signer name and the
signature value of its signed approval Data
(`<cert>/ndncert-approve/<request-id>`, checked against the CA's
trust schema before recording). The dashboard's trust-path inspector
renders the leaves, and `security/validate` returns them under
`challenge_attestations`.

The wire shape and the per-handler evidence each leaf carries are
documented in `docs/ndncert-attestations.md`; see
`crates/security/ndn-cert/src/attestation.rs` for the types.

## See also

- [Identity and keys](../concepts/identity-and-keys.md) — KeyChain
  surface that NDNCERT writes into.
- [Trust policies](../reference/trust-policies.md) — what a
  consumer checks against the cert chain.
- [Self-hosting](./self-hosting.md) — running CA and forwarder as
  containers.
- `crates/security/ndn-cert/` — implementation and protocol shape.
