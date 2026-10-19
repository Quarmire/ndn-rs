# Enrolling with an invite (`ndn-fwd enroll`)

One command turns a device that holds nothing into one that holds a
certificate for `/<ns>/<role>/<device>` issued by the namespace's CA, and
signs with it:

```sh
ndn-fwd enroll 'ndn-trust://invite/…' [--device <name>] [--force] [-c ndn-fwd.toml]
```

## Concept

An invite (`ndn-fwd-tokens new --ca /<ns> --namespace /<ns> --anchor-fp <fp>
--role member|guest`) carries the CA prefix, the identity namespace
`/<ns>/<role>`, a one-time token the CA scopes to that role, and the
fingerprint of the namespace's root anchor. Enrolling with it does two
things:

1. **Adopt the trust context** for `/<ns>` if the device holds none — the
   same check as `ndn-fwd adopt` with a fingerprint-only link (see
   [context adoption](./context-adoption.md)). An invite names no context
   version, so no version floor applies to this first adoption; the keyring's
   anti-rollback still does. A context already held must be signed by the
   root the invite expects, else the enrollment is refused.
2. **Enroll** (NDNCERT 0.3, `token` challenge): a key generated on the
   device is certified by `/<ns>/CA` as `/<ns>/<role>/<device>/KEY/<id>`.

A token admits only `member` or `guest`; admin and node certificates need an
admin's approval. A role-carrying token (`member-…`, `guest-…`) must match
the invite's role (checked locally), and the CA refuses any request outside
the token's scope. `ndn-fwd-tokens qr` for a token without a role prefix
makes a member invite (the namespace CA scopes such a token to members).

An invite expires when its token was minted with `ndn-fwd-tokens new --ttl
<dur>`: the token carries its expiry (`…-until<unix-secs>`), so the CA, which
reads `[ca] tokens` from its config, refuses it after that time, and `ndn-fwd
enroll` refuses the invite before contacting the CA. A token minted without
`--ttl` stays redeemable until it is used.

A device name holds one certified key at a time. The namespace CA (`RolePolicy`)
refuses to certify a key for `/<ns>/<role>/<device>` while it holds a valid,
unrevoked certificate it issued for that name to another key, unless an admin
approves the new key (`device-approval`). So a member token cannot be used to
enroll as an existing device and publish under its name. The CA checks this
before running the token challenge, so a refused request does not redeem the
token: enroll again under another `--device` name, or revoke the old
key first ([`ndn-fwd revoke`](./revocation.md) on the root device frees the
name). Certifying the same key again is not refused. Of two
requests for one device name running at once, the CA reserves the name for
the first before its challenge runs; the second is refused before its own
challenge runs, so it spends no token either.

Certificates last what the namespace CA issues for the role: `[ca]
cert_validity_days` (default 90; per role, e.g. `guest = 7`). The request names
no lifetime, so the CA's setting alone decides it, and the enroll output states
the expiry issued. Before expiry the daemon renews the certificate for the same
key without an invite, if the CA renews the role — see
[Certificate renewal](./renewal.md).

## Flow and packets

| Step | Who | What |
|---|---|---|
| 1 | CLI | reads the invite, derives `/<ns>/<role>/<device>` (device default: the host name, sanitized), sends `security/enroll` (Uri = invite, Name = identity, Flags bit 1 = force) over the daemon's Unix socket |
| 2 | daemon mgmt | trust-admin gate: the peer credentials must be the daemon's user, root, or a `[security] trust_admin_groups` member; a `/localhop` enroll command is refused outright |
| 3 | daemon | context held: checks the namespace for a newer version first, through the `context refresh` path ([Trust-context updates](./context-updates.md)): adopted only under the continuity rule, stored and published. It waits at most two exchanges (a catch-up across several versions is left to `ndn-fwd context refresh`) |
| 3a | daemon | refuses if its PIB already holds a valid certificate in `/<ns>` (unless `--force`); a certificate whose chain the context — as checked in step 3 — revokes does not count. When the check could not confirm the held version is the newest, the refusal says it judged against that version |
| 4 | daemon | generates `/<ns>/<role>/<device>/KEY/<16 hex>` (Ed25519) in its PIB |
| 5 | daemon → root device or relay | context not held: RDR metadata + context fetch; the forwarder admits only the expected context |
| 6 | daemon → CA | `/<ns>/CA/NEW` and `/<ns>/CA/CHALLENGE/<id>` signed Interests (device key), token challenge; replies signed by `/<ns>/CA/KEY/…`, validated by the device's forwarder under the adopted context |
| 7 | daemon → CA | fetches the issued certificate by the name the CA reports in the CHALLENGE response (`<key>/NDNCERT/v=<ms>`, NDN Certificate Format v2), and the CA's certificate; checks the certificate certifies the device key, is valid now, and chains to the root under the context's schema |
| 8 | daemon | stores the certificate (signed Data, as issued) under the key's `certs/`; only a node without an identity yet records it as the PIB's default identity |
| 9 | daemon | adds the key to the engine's key store: Data under `/<ns>` is signed with it from the next packet on, the node's other trusted prefixes keep their keys; a node that ran on its ephemeral key also signs its management responses and discovery records with it |

A failure at any step after 4 deletes the new key; the node's identities
and its signer stay as they were. A context adopted in step 5 is kept (it passed
the fingerprint check on its own); the refusal says so, or why storing it
failed. Once the CA has issued (step 7–8) the token is spent: a failure to
store the certificate says so; a failure to store the adopted context keeps
the certificate and reports that the context is held for this run only.

After enrolling, the answer lists the other certificates the node holds in
the namespace — still valid, or unusable because the context revokes their
chain — judged against the context held now (the one checked in step 3, or
the one adopted in step 5, checked then if there is anything to judge). The
check itself is in the answer (`context_check`); when it did not confirm the
version held is the newest (no answer, a failure, or an upstream serving an
older one), the CLI says the listing reflects version `N` held.

If the CLI gets no answer within its wait (the context check plus the
longest the daemon's enrollment can take: every exchange timing out), it says
the daemon may still complete the enrollment and to check `ndn-ctl status`
before retrying.

## Where state lives

```
<pib>/keys/<hash>/private.pkcs8.der   device key (never leaves the daemon)
<pib>/keys/<hash>/certs/<hash>.data   each certificate of the key (signed Data, as issued; a renewal adds one)
<pib>/default-identity                the identity loaded when [security] identity is unset
<pib>/contexts/<ns-hex>.tc            the adopted context (newest version)
<pib>/contexts/<ns-hex>.versions/     every version of it held, by version
<pib>/issuers/<hash>.data             issuer certificates of the device's chain (sent with a renewal)
```

The config file is never edited. At start the daemon loads every PIB
identity with a currently valid certificate, and signs its own packets as
its node identity: `[security] identity` if set, else the PIB's default
identity, else its identity in a namespace whose root it holds, else the
first enrolled, else an ephemeral key (logged, and reported by
`security/identity-status` as `node_identity_source=`). Enrolling in a
second trusted prefix adds an identity and never changes the node identity;
`ndn-fwd node-identity <identity>` does (from the next start).

## Signing by name, and the node signer

Data a producer on the node publishes is signed with the key its name
chooses (`SecurityManager::signer_for`, `Producer::with_signers`,
`ndn-put --pib` without `--identity`): the node's identity in the trusted
prefix covering it. A prefix the node only follows is refused with what to
do. `ndn-ctl status` lists the trusted prefixes and how the node takes part
in each (`security/memberships`).

Management responses and discovery records sign through one shared
`ndn_security::ActiveSigner`, the node signer (`ndn-fwd`
`active_identity.rs`). Each packet takes one snapshot and uses it for both
its KeyLocator and its signature, so a packet always names the key that
signed it (`ndn-ctl status` shows `signing: identity=… key=…`). It changes
only for a node's first identity, or at the next start after
`ndn-fwd node-identity`.

DV routing with `[routing.dv.trust] mode = "static"` or `"lvs"` keeps signing
with the key the node started with: its neighbours accept only the keys in
their `trusted_keys`, so a new node key would silently cut the node off from
routing. It signs with the new node key after the next start; the enroll
output reminds the operator to add that key to every DV neighbour's
`trusted_keys` first.

## Refusals

| Situation | Status | Says |
|---|---|---|
| malformed / not an invite / bad names | 400 | what is wrong; ask for a new invite |
| token role ≠ invite role, admin/node invite | 400 | the invite was altered or minted wrongly |
| invalid device name | 400 | the rule; choose another `--device` |
| already holds a certificate in `/<ns>` | 409 | lists it with its validity end; `--force` with another `--device` enrolls another key, the old certificate stays valid until it expires or is revoked. A held certificate whose chain the trust context revokes (its key, its CA key or the root above, e.g. after `recover --old-root compromised`) does not count: it validates nowhere, and `enroll` lists it as unusable |
| the CA already certified this device name to another key | 409 | the certificate holding it; choose another `--device`, revoke that certificate first, or enroll by an admin's approval ([Enrollment by approval](./enrollment-by-approval.md)). The token is not redeemed |
| held context from another root | 403 | the two fingerprints |
| no route / no answer | 504 | the device needs a link and a route for `/<ns>` toward a forwarder that serves it (an invite carries no host, so enrolling never creates them) |
| invite expired (`--ttl`) | 400/403 | the expiry; ask for a new invite (refused by the CLI before anything is sent, and by the CA) |
| token spent or out of scope | 403 | the CA's reason; ask for a new invite |
| unauthorized local user | 403 | who may enroll and how to grant it |

## Code

| Part | Where |
|---|---|
| Invite parsing, protocol, checks | `ndn-cert` `invite.rs` (`InviteLink`, `enroll_with_invite`, `ensure_invite_context`, `InviteEnrollError`) |
| Engine binding | `ndn_identity::enroll_with_invite_via_engine` |
| Management verb | `ndn-mgmt` `security/enroll`, `TrustAdminMgmtBackend::enroll`, `EnrollOutcome` |
| Client | `ndn_ipc::MgmtClient::security_enroll` |
| Daemon backend | `ndn-fwd` `enroll.rs`, `context_adopt.rs` (`TrustAdmin`), `active_identity.rs` |
| Startup selection | `ndn-fwd` `security_init.rs`; `FilePib::{set,get}_default_identity`, `store_issued_cert` |
| CLI | `ndn-fwd` `onboard.rs` (`run_enroll`) |
| Mobile | `NdnEngine::enroll_with_invite(invite_uri, device, persist_password)`; the result's `adopted_context` (or `NdnError::EnrollmentFailed`'s) carries the context to persist and pass to `adopt_context` at launch |

## See also

[Enrollment by approval](./enrollment-by-approval.md): admin and node
devices, and any role the namespace's policy reserves for an admin's
approval, enroll with `ndn-fwd enroll <anchor link> --role <role>` (or
`<invite link> --role <role>` when the namespace also requires an invite);
the same verb answers `state = pending` with a verification code.
