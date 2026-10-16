# Personal network pairing — design

Status: **draft for review**. Scope: how an owner sets up, grows, repairs and
shares a personal NDN network. Every flow is defined headless (CLI + mobile FFI)
first; the TUI is a thin skin over the same calls.

## 1. Principles

1. **Flows before surfaces.** A flow is done when it works from `ndn-fwd` /
   FFI end to end, with a two-process test. Presentation comes after.
2. **Support, don't decide.** Where reasonable owners differ (recovery kit
   format, where they keep copies), the system offers every supported option
   and the owner picks. No option is pre-selected by the library.
3. **One root of authority.** The owner's root key signs the trust context.
   Everything else — CA, admins, members, super nodes — holds a delegated key
   whose authority the root can withdraw by bumping the context.
4. **Names carry roles.** Authorization is expressed in names so the trust
   schema can check it without new mechanism. Owners never write the schema;
   it is generated (§4).
5. **Nothing is adopted silently.** Every trust decision is a TOFU check
   against an expected fingerprint (QR / short code) or a signature chain to
   the adopted root.

## 2. Actors and where keys live

| Actor | Name | Key | Lives on | Online? |
|---|---|---|---|---|
| Root | `/<ns>/KEY/root` | Ed25519, root-signed self cert | primary device (owner's choice of store) + recovery kit | rarely needed |
| CA | `/<ns>/CA` | delegated, cert issued by root | super node (preferred) or primary device | always, if on super node |
| Admin device | `/<ns>/admin/<device>` | per device, cert issued by CA | owner's devices marked admin | sometimes |
| Member device | `/<ns>/member/<device>` | per device, cert issued by CA | everything else | sometimes |
| Super node | `/<ns>/node/<name>` | per node, cert issued by CA | VPS / home server; QUIC listener; relay | always |
| Guest | `/<ns>/guest/<who>` | guest's key, short-lived cert | friend's device | — |

The primary device is the first admin. Root key storage options on it (owner
picks): OS keyring / secure enclave custodian, YubiKey PIV, or a `FilePib`
directory. A super node never holds the root.

## 3. Wire objects (all exist today unless marked NEW)

- **Trust context** — `SignedTrustContext`, root-signed Data at
  `/<ns>/32=trust-context/v=N`: anchors, schema, CA endpoints, revocations.
  Distributed by envelope (first contact), by name over RDR (any `ndn-fwd`
  publishes the contexts in its store, **have**: see
  `docs/wiki/src/reference/trust-context-publication.md`) and `context_sync`
  (updates).
- **Envelope** — `ndn-trust://` (`ndn-trust-envelope`): `anchor` (signed
  context or fingerprint pointer: namespace + expected fingerprint +
  version), `invite` (CA prefix + namespace + token + expected fingerprint),
  `capability`, `delegation`, `recovery`, `bag`.
- **Enrollment** — NDNCERT 0.3 via `ndn_cert::client::enroll`; challenges
  `token` (from an invite) and `device-approval` (admin approves).
- **Revocation** — context revocation list (authoritative, root-signed) and
  CA revocation set (immediate, CA-signed REVOKE).
- **Recovery kit** — NEW wrapper: see §6.

## 4. Generated trust schema

Produced from the role layout; carried in the context as LVS binary (portable
to ndnd/NDNts/python-ndn) with a native-text twin for the rules LVS cannot
express (**have**: `ndn_cert::roles::network_schema`, emitted by `init`).

```
/<ns>/KEY/<k>, /<ns>/32=trust-context/<v>  signed by  /<ns>/KEY/<k>        (root)
/<ns>/CA/KEY/<k>                     signed by  /<ns>/KEY/<k>           (the root)
/<ns>/<role>/<dev>/KEY/<k>           signed by  /<ns>/CA/KEY/<k>        role ∈ {admin, member, node, guest}
/<ns>/<role>/<dev>/<**data>          signed by  /<ns>/<role>/<dev>/KEY/<k>   (devices publish under their own name, never under their KEY subtree)
/<ns>/CA/<**data>                    signed by  /<ns>/CA/KEY/<k>        (CA service data: INFO, NEW, …)
<requested key>/ndncert-approve/<id> signed by  /<ns>/admin/<dev>/KEY/<k>    (only admins approve; the name is the requester's key name, which binds the approval to that request)
/<ns>/shared/<**data>                signed by  /<ns>/{admin,member}/<dev>/KEY/<k>
```

The fixed-shape rows (root, context, CA and device keys, approvals) are LVS.
The `<**data>` rows are native rules OR'd with it: LVS patterns are
fixed-length, and "the device's own key" needs data/key tag equality, which the
in-tree compiler does not lower nor the evaluator check. Signers are key names
(`…/KEY/<k>`), as ndn-rs signs and names certificates. The context is
*schema-authoritative*: no hierarchy floor (approvals and `shared` are
cross-identity by design) and the schema is checked on every certificate hop,
so a device cannot self-issue keys. For a short namespace the inline anchor
envelope still fits one QR code (≤ 2953 bytes); the fingerprint-only form
(`anchor_uri_fp`, ~125 bytes) always does (**have**, F2).

A tool (`ndn-fwd schema show|explain <data-name> <key-name>`, **have**)
renders the schema and answers "would this be accepted, and by which rule".
Hand-written schemas remain possible (native rules or LVS text via
`compile_lvs`); the generated one is the default.

## 5. Flows

Each flow lists steps, what is stored where, failure handling, and status
(**have** = implemented, **gap** = to build).

### F1 Set up a network (primary device)
1. `ndn-fwd init --profile hub --namespace /<ns> [--device <name>]` → root, CA,
   the primary device as `/<ns>/admin/<dev>` (CA-certified; device name
   defaults to the sanitized host name), root-signed context carrying the
   generated schema, all in the PIB (**have**).
2. Recovery kit offered immediately (F7). The owner may decline; the UI keeps
   reminding until one exists.
3. Optional: delegate the CA to a super node (F3).

### F2 Add a device
- **By invite (token):** an admin creates an invite (`ndn-fwd-tokens new
  --role member|guest`, **have**; the token carries its role and the CA
  scopes it to `/<ns>/<role>`) → QR/link carries CA prefix, namespace, token,
  expected fingerprint. New
  device: `join <invite>` = fetch the context by name, check it against the
  expected fingerprint, adopt, enroll with the token (**have**: fetch by
  name, `ndn_cert::fetch_context`, served by `ndn-fwd`; adoption from a
  fingerprint-only link by the running daemon, `ndn-fwd adopt` /
  `security/context-adopt` / `ndn_identity::adopt_anchor_link_via_engine`,
  with the joiner's forwarder admitting only the expected context while it
  runs, the version floor from the link, and the daemon trusting, storing and
  publishing it at once — see `docs/wiki/src/reference/context-adoption.md`;
  authorized by the management socket's peer credentials
  (`[security] trust_admin_groups`); **gap**: the single `join`
  command/FFI call that adopts and enrolls).
- **By approval:** new device scans the anchor QR, requests enrollment with
  `device-approval`; an admin sees the pending request (`ca list-approvals`)
  and approves on an admin device (**have** in daemon; **gap**: approve from a
  remote admin device, not only the CA host's mgmt socket).
- Role: the device enrolls as `/<ns>/<role>/<dev>`; issuing an admin (or
  super node) cert requires an admin approval, never a token alone; tokens
  admit members, and guests only when guest-scoped (**have**:
  `ndn_cert::RolePolicy`, the default for a hub CA in `[demo_ca]`).

### F3 Delegate the CA to a super node
1. Super node generates `/<ns>/CA` key locally; produces a cert request.
2. Primary device signs it with the root (QR/file round trip, or over NDN
   while paired) and bumps the context with the new CA endpoint.
3. Super node starts `[demo_ca]` from its PIB (**have**: PIB-backed CA).
Gap: the request/sign round trip and config naming (`[ca]` instead of
`[demo_ca]` once this path is the norm).

### F4 Lose a member device
1. Any admin: `devices revoke <name>` → CA REVOKE (immediate at the CA, cert no
   longer served) (**have** at the CA level; **gap**: admin-side command).
2. Next time the root is available: context bump with the revocation entry,
   propagated by `context_sync` so every node refuses the key (**gap**: revoke
   command that edits, re-signs and publishes the context).

### F5 Lose an admin device
As F4, plus: pending approvals signed by that device are refused after the
bump. If it was the primary device, continue with F8.

### F6 Super node compromised
1. Root bump: revoke `/<ns>/CA` cert and the node cert, add a new CA endpoint.
2. Devices keep their certs (issued before compromise) unless the owner
   chooses to re-enroll everything; the UI asks.
3. QUIC pins for that super node are dropped from peers' configs.

### F7 Create a recovery kit
The owner chooses one or more formats; all are supported equally:
- **Encrypted file** — passphrase-encrypted SafeBag of the root key
  (format exists: `ndn-sec export`), wrapped as an `ndn-trust://bag` envelope.
- **Word list** — the root key seed encoded as words with a checksum, for
  paper or a password manager (**gap**: encoder/decoder; NEW TLV-free format).
- **Hardware** — a second YubiKey holding a root copy, where the owner's
  hardware allows import.
Each kit also carries the public context name and fingerprint so restoration
can find and verify the network. Kits never leave the device unencrypted
except as the owner-chosen word list.

### F8 Restore after losing the primary device
1. New device: `recover <kit>` → root key restored into the chosen store.
2. Root bump: revoke the lost primary device's admin cert; the new device
   enrolls itself as admin.
3. Everything else keeps working; no re-pairing of other devices.

### F9 Share with a friend (scoped, time-limited)
1. Admin issues a guest cert `/<ns>/guest/<who>` with short validity, plus a
   `capability` envelope listing what it may publish/fetch (**have**: envelope
   kind and `ndn_security::Capability`).
2. Reading private data requires content keys: guests receive keys only for
   the shared scope (confidentiality module; ABE optional).
3. Expiry needs no action; early end = F4.

### F10 Rotate keys
Device keys renew through NDNCERT renewal (`ndn_identity::start_renewal`,
**have**) before expiry. Root rotation = new root signs a context that lists
both roots for one version, then drops the old one (**gap**).

### F11 Travel / carrier-grade NAT
Devices always dial out to a super node (QUIC, or WebTransport from browsers
and restrictive networks); the super node forwards. Nothing in pairing
depends on inbound reachability.

## 6. Storage layout (per node PIB directory)

```
<pib>/                FilePib keys + certs (default); ndnsec-compat may read ~/.ndn
<pib>/contexts/*.tc   adopted signed contexts (loaded at startup, re-verified,
                      published by name unless [security] serve_contexts = false)
<pib>/ca/             CA cert, anchor cert, node cert, issued/, revoked/,
                      redeemed-tokens/   (CA hosts only)
$XDG_STATE_HOME/ndn-fwd/tls/   persistent self-signed listener certs
```

## 7. Build order

1. Generated schema + role naming in `init` and enrollment (F1, F2 roles) — **have**.
2. `join` (fetch-by-fingerprint + adopt + enroll) and remote admin approval (F2).
3. `devices list|revoke` + context bump/publish (F4, F5).
4. Recovery kit formats + `recover` (F7, F8).
5. CA delegation round trip (F3), then F6 tooling.
6. Guest flow (F9), root rotation (F10).
7. Two-process testbed scenario covering F1→F2→F4→F8.
8. TUI over the finished commands.

## 8. Owner-configurable policy

Admission policy is the CA's challenge configuration, chosen by the owner,
not fixed by the design: token-only, approval-only, or token AND approval for
members. Admin certificates always require an admin approval. Recovery kit
formats (§F7) and root key storage (§2) are likewise the owner's choice.
