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
the token's scope.

## Flow and packets

| Step | Who | What |
|---|---|---|
| 1 | CLI | reads the invite, derives `/<ns>/<role>/<device>` (device default: the host name, sanitized), sends `security/enroll` (Uri = invite, Name = identity, Flags bit 1 = force) over the daemon's Unix socket |
| 2 | daemon mgmt | trust-admin gate: the peer credentials must be the daemon's user, root, or a `[security] trust_admin_groups` member |
| 3 | daemon | refuses if its PIB already holds a valid certificate in `/<ns>` (unless `--force`) |
| 4 | daemon | generates `/<ns>/<role>/<device>/KEY/<16 hex>` (Ed25519) in its PIB |
| 5 | daemon → hub | context not held: RDR metadata + context fetch; the forwarder admits only the expected context |
| 6 | daemon → CA | `/<ns>/CA/NEW` and `/<ns>/CA/CHALLENGE/<id>` signed Interests (device key), token challenge; replies signed by `/<ns>/CA/KEY/…`, validated by the device's forwarder under the adopted context |
| 7 | daemon → CA | fetches the issued certificate and the CA's certificate; checks the certificate certifies the device key, is valid now, and chains to the root under the context's schema |
| 8 | daemon | stores `cert.data` (signed Data, as issued) and the summary beside the key, then sets the PIB's default identity — the last step |
| 9 | daemon | switches the signer of its management responses and discovery records to the new key; the key also enters the engine's key store |

A failure at any step after 4 deletes the new key; the default identity and
the signer stay as they were. A context adopted in step 5 is kept (it passed
the fingerprint check on its own). A failure after the CA issued (step 7–8)
spends the token: the message says so.

## Where state lives

```
<pib>/keys/<hash>/private.pkcs8.der   device key (never leaves the daemon)
<pib>/keys/<hash>/cert.ndnc           certificate summary (validity, public key)
<pib>/keys/<hash>/cert.data           the issued certificate Data
<pib>/default-identity                the identity loaded when [security] identity is unset
<pib>/contexts/<ns-hex>.tc            the adopted context
```

The config file is never edited. At start the daemon loads `[security]
identity` if set, else the PIB's default identity, else an ephemeral key.
With `[security] identity` set, enrolling stores and selects the identity in
the PIB but the configured one keeps signing; the answer says so.

## Live signer switch

Management responses and discovery records sign through one switchable
signer (`ndn-fwd` `active_identity.rs`), so they use the new key at once
(`ndn-ctl status` shows `signing: identity=… key=…`). DV routing was built
with the startup key and switches at the next start; the answer lists it.
Each run holds its earlier signers for the lifetime of the process (eight
slots); beyond that a newly enrolled key applies at the next start.

## Refusals

| Situation | Status | Says |
|---|---|---|
| malformed / not an invite / bad names | 400 | what is wrong; ask for a new invite |
| token role ≠ invite role, admin/node invite | 400 | the invite was altered or minted wrongly |
| invalid device name | 400 | the rule; choose another `--device` |
| already holds a certificate in `/<ns>` | 409 | lists it; `--force` enrolls another key, the old one stays valid until revoked |
| held context from another root | 403 | the two fingerprints |
| no route / no answer | 504 | the device needs a face and a route for `/<ns>` toward a forwarder that serves it |
| token spent, expired or out of scope | 403 | the CA's reason; ask for a new invite |
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
| Mobile | `NdnEngine::enroll_with_invite(invite_uri, device, persist_password)` |

## Not yet

Enrollment by an admin's approval (asynchronous) will answer the same verb
with a `pending` state (`EnrollOutcome` is tagged by `state` for that).
