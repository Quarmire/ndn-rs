# NDNCERT setup

NDNCERT automates certificate issuance: an applicant requests a
certificate under some name; a CA challenges them (token, e-mail,
proof-of-possession); on success the CA signs and returns the cert.
This guide covers running an NDNCERT CA, enrolling as a user, and the
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

## Enroll as a user

With an invite link (`ndn-trust://invite/…`) from the CA's operator, the
running daemon enrolls the node:

```sh
ndn-fwd enroll <invite-link> --device alice
```

For a bare CA with a PIN challenge, `enroll-ndncert --face-socket <sock>
--ca-prefix /lab/ca --name /lab/alice [--pin <PIN>]` runs the same exchange.

Walkthrough:

1. Generate a key under `/lab/alice` if one doesn't exist.
2. Send NEW to `/lab/ca/CA/NEW` carrying the key.
3. CA replies with a session ID and a challenge list.
4. Send CHALLENGE with the token.
5. CA verifies the token, signs the cert, returns it.
6. The enrollee imports the cert into its `KeyChain` and persists the
   identity as a `SafeBag`.

The resulting `SafeBag` is spec-canonical and importable via
`ndnsec import`.

## Invite tokens

Tokens turn the enrollee-side step into a copy-paste flow. The
operator generates a token, hands it (QR or paste) to the enrollee as an
invite, and the enrollee runs `ndn-fwd enroll <invite-link>`.

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

| Challenge | Applicant proves | Use |
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

Built-ins in `crates/security/ndn-cert/src/policy.rs`:
`AcceptAllIssuance` (default), `RequireAttestationKind` (names under a
prefix need a given challenge leaf) and `RolePolicy` (the namespace
role layout, below), behind the pre-challenge `NamespacePolicy` and the
`ChallengeHandler` (three-stage seam recorded in
`project_f7_issuance_policy`).

### Roles in a namespace

A namespace `/<ns>` created by `ndn-fwd init` names every device
`/<ns>/<role>/<device>` with role `admin`, `member`, `node` (a relay) or `guest`
(`ndn_cert::roles`; design: `docs/specs/personal-namespace.md`).
`RolePolicy::new(ns)` issues only device keys `/<ns>/<role>/<device>/KEY/<id>`
and only when the satisfied challenge fits the role:

| Role | Issued on |
|---|---|
| approval roles (`[ca] approval_roles`, default `admin`, `node`) | an admin's `device-approval`, plus a redeemed invite token when `approval_requires_invite` is set — never a token alone |
| `member` | a `device-approval`, or an invite token that is unscoped or scoped inside `/<ns>/member` |
| `guest` | a `device-approval`, or an invite token scoped inside `/<ns>/guest` |

The policy is advertised in the trust context's enrollment hint, so a
device knows before asking whether its role needs an approval (see
[Enrollment by approval](../reference/enrollment-by-approval.md)).

Other challenges (pin, email, nop) admit no role. A scoped token records its
scope in its attestation leaf (evidence `scope`), which is how the policy tells
a guest invite from a member invite.

A device identity holds one certified key at a time
(`IssuancePolicy::single_key_identity`): the CA refuses a new key for
`/<ns>/<role>/<device>` while a valid certificate it issued for that name to
another key is unrevoked, unless the satisfied challenge carries a
`device-approval` leaf. A request that only a `device-approval` could admit is
refused before its challenge runs (NDNCERT error 5, NameNotAllowed), so a
token presented with it is not redeemed.

## Configuration

`ndn-fwd` embeds a CA through its `[ca]` section (full key list in the
[configuration reference](../operations/config-reference.md)). On the root
device, `ndn-fwd init --namespace /<ns>` writes the root anchor (the root key
itself into its root store, `--root-store`; see
[root custody](../concepts/identity-and-keys.md#root-custody-where-a-namespace-root-key-lives)), a
`/<ns>/CA` signing identity certified by it, and the root device's admin
identity `/<ns>/admin/<device>` (`--device` names it; default: the host name,
sanitized) certified by the CA into the node PIB, stores the root-signed
trust context carrying the generated role schema, and prints the
`[security]` lines (`identity`, `pib_path`) that make the forwarder load the
device identity. The CA loads its identity, so the certs it issues chain to
the same root across restarts, and it persists issued certs, revocations and
redeemed tokens (hashed) in its own directory, `<pib_path>/ca/<hex of the
trusted prefix>/` (`<pib_path>/ca/` for the one CA of an older PIB). A device
that is the root of several trusted prefixes runs one CA each: one `[[ca]]`
table per CA instead of `[ca]`. A PIB-backed `/<ns>/CA`
certified by the namespace root issues under `RolePolicy::new(/<ns>)` (combined with
`require_attestation` when that is set too):

```toml
[ca]
enabled  = true
prefix   = "/home/bob"      # serves /home/bob/CA/{INFO,NEW,CHALLENGE,APPROVAL,PENDING}
identity = "/home/bob/CA"   # signing identity loaded from the PIB

[[ca.challenge]]
kind = "device-approval"     # optional here: a namespace CA offers it anyway
```

Every CA offers the `token` challenge over its invites. Invites are made at
runtime against the running daemon (`ndn-fwd-tokens -c <config> new --role
member|guest [--namespace <ns>] [--ttl 7d] [--device <name>]`; `list` and
`withdraw <id>` too), recorded under `invites/` of the CA's directory and
kept across restarts. They are never configured.

A namespace CA offers `device-approval` even when `[[ca.challenge]]` does not
list it (the log says so). Pending requests are kept in
`approvals/` of the CA's directory and survive restarts. Decide with `ndn-fwd
approvals list`, `approve <id|code>`, `deny <id|code> [--reason <text>]`: on
the CA host it decides as the local operator; on another node holding an
admin certificate of the namespace it signs the decision with that admin key
and pushes it to `/<prefix>/CA/APPROVAL` (listing via `/<prefix>/CA/PENDING`).

Invites carry their role. `ndn-fwd-tokens -c <config> new --role
member|guest` (default `member`) makes a `member-<hex>` or `guest-<hex>`
token, and the CA scopes it to `/<ns>/<role>`, so it cannot certify another
role. `--role admin` (and `node`) is refused with the code
`invite-role-needs-approval`: those certificates need an admin's approval
(`ndn-fwd enroll <anchor link> --role admin` on the device,
`ndn-fwd approvals approve <code>` by an admin). Because every invite is
scoped, a request for a name it cannot certify is refused before it is
spent.

A CA that lists no challenge admits by invite only. `kind = "nop"` (auto-approve) must be
listed explicitly. `ephemeral = true` replaces the PIB identity with a
throwaway self-signed key for demos; an ephemeral CA keeps issuing any
challenge-passing name under its prefix (no `RolePolicy`).

### Inspecting the schema

`ndn-fwd schema show [--pib <dir>] [--namespace <ns>]` prints the adopted
context's schema: the LVS binary decoded back to LVS rules (with rule names),
then the native rules OR'd with it. `ndn-fwd schema explain <data-name>
<key-name>` says whether the key may sign the name under the context
governing it, and which rule decides (exit status 1 on deny):

```text
$ ndn-fwd schema explain /home/bob/member/tablet/KEY/k1/ndncert-approve/req-1 \
      /home/bob/admin/laptop/KEY/device --pib ~/.ndn/pib
rule           = LVS rule #approve: /"home"/"bob"/_/_device/"KEY"/_/"ndncert-approve"/_ <= #admin: /"home"/"bob"/"admin"/_device/"KEY"/_
verdict        = allow
```

`#deny` (`…/"ndncert-deny"/_`) and `#pending` (`/<ns>/"CA"/"PENDING"/_`) are
likewise signed by `#admin`.

`ndn-fwd schema update [--namespace <ns>] [--accept-narrowing]` on the root
device signs a new trust-context version carrying the current generated
schema, so a namespace made by an earlier release gains the rules added
since (`#deny`, `#pending`) without a re-init. It prints the rules added and
removed, and refuses to drop a rule devices hold unless `--accept-narrowing`
is given ([schema updates](../reference/context-updates.md#schema-updates-ndn-fwd-schema-update)).

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
validity and renews it before expiry on the one renewal schedule,
`RenewalSchedule`; see `crates/security/ndn-identity/src/renewal.rs`
(`start_renewal` + `NdncertRenewer`) and, for a device taking part in a
namespace, `crates/security/ndn-namespace/src/renewal.rs`.

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
that won. A `device-approval` leaf carries `request_id`, `code`,
`approver_kind` (`admin-key` or `local-operator`), `approved_by` and
`invite`; for an admin key's approval it also carries the signature value
of the signed decision Data (`<key>/ndncert-approve/<request-id>`,
validated under the namespace's trust context before recording). A local
operator's approval (on the CA host) carries no signature, so under
`require_signed` it counts only with `[ca.require_attestation]
accept_local_operator = true`. The dashboard's trust-path inspector
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
