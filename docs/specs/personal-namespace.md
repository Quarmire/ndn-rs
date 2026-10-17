# Personal namespace: trust, enrollment and links — design

Status: **draft for review**. Scope: how an owner creates, grows, repairs and
shares a personal NDN namespace. Every flow is defined headless (CLI + mobile
FFI) first; the TUI is a thin skin over the same calls.

There is no "network" to "join". A device **adopts** the namespace's trust
context (it accepts Data under `/<ns>` signed by keys chaining to the
namespace root, under the namespace's schema) and, to produce, **enrolls**
(gets a certificate for its key under `/<ns>/<role>/<device>` from the
namespace's CA). Reaching other devices is a separate matter: forwarders form
**links** (faces) to other forwarders, a **relay** is a forwarder at a
reachable address others link to, and **routes** say which prefixes go over
which links (§9).

Terms used throughout:

| Term | Meaning |
|---|---|
| namespace | a name prefix `/<ns>` owned by a root key |
| root device | the device that creates the namespace's root and CA (`ndn-fwd init`) |
| trust context | the root-signed statement of the namespace's anchors and rules |
| adopt | accept a namespace's trust context (`ndn-fwd adopt`) |
| enroll | obtain a certificate under the namespace (`ndn-fwd enroll`) |
| invite | a one-time token plus a pointer to the trust context |
| link | a face between two forwarders |
| relay | a forwarder at a reachable address others link to (role `node`) |
| route | which prefixes go over which links |

## 1. Principles

1. **Flows before surfaces.** A flow is done when it works from `ndn-fwd` /
   FFI end to end, with a two-process test. Presentation comes after.
2. **Support, don't decide.** Where reasonable owners differ (recovery kit
   format, where they keep copies), the system offers every supported option
   and the owner picks. No option is pre-selected by the library.
3. **One root of authority.** The owner's root key signs the trust context.
   Everything else — CA, admins, members, relays — holds a delegated key
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
| Root | `/<ns>/KEY/<k>` (`root` from `init`, a fresh id after a recovery) | Ed25519 (P-256 on a YubiKey), root-signed self cert | root device (owner's choice of store) | rarely needed |
| Recovery key | `/<ns>/KEY/r<hex>` | separate key, self-signed anchor marked a recovery anchor in the context | recovery kit, offline (words / sealed file / second YubiKey) | only to replace a lost root device |
| CA | `/<ns>/CA` | delegated, cert issued by root | relay (preferred) or root device | always, if on a relay |
| Admin device | `/<ns>/admin/<device>` | per device, cert issued by CA | owner's devices marked admin | sometimes |
| Member device | `/<ns>/member/<device>` | per device, cert issued by CA | everything else | sometimes |
| Relay | `/<ns>/node/<name>` | per relay, cert issued by CA | VPS / home server at a reachable address (QUIC listener) | always |
| Guest | `/<ns>/guest/<who>` | guest's key, short-lived cert | friend's device | — |

The root device (the primary device) is the first admin. The root key lives
in a **root store** the owner picks at `ndn-fwd init --root-store`, recorded
in `<pib>/root/store.toml` (**have**, `ndn_cert::root_store`):

| Store | Private key | Unlock per root operation |
|---|---|---|
| `os-keyring` (default when a keychain is reachable) | SafeBag `<pib>/root/root-keychain.safebag`, sealed by a random secret kept in the OS keychain (Secret Service / macOS Keychain / Windows Credential Manager) | none (the user's login) |
| `sealed-file` | SafeBag `<pib>/root/root.safebag` (PBES2: PBKDF2-SHA256 600k, AES-256-CBC) under the owner's passphrase | the passphrase |
| `yubikey-piv` | generated on a PIV slot (P-256, non-exportable; PIN policy `always`, touch policy recorded) | the PIN (+ touch) |
| `file` | plaintext PKCS#8 in the FilePib (namespaces made before root stores; tests) | none — unprotected; the daemon warns |

Root operations (`init`, `revoke`, `ndn-trust-context build --sign-key`)
take the passphrase / PIN from the operator per operation (env var, a
`--passphrase-file`/`--pin-file`, else the terminal; never argv). The secret
never leaves the command: `revoke` and `recovery-kit` sign the new context
version in the CLI and hand only the signed Data to the daemon
(`security/context-update`). Whether a node is the root device is decided
from the descriptor and the context's anchor public keys, never by loading
the key. `ndn-fwd
root-key move --to <store>` moves a software root (new store signs first,
then the plaintext copy is overwritten and deleted); a software (Ed25519)
root cannot move onto PIV, so a hardware root is a new namespace or F10.
The CA key and admin device keys stay in the FilePib: the daemon uses them
unattended. A relay never holds the root.

## 3. Wire objects (all exist today unless marked NEW)

- **Trust context** — `SignedTrustContext`, root-signed Data at
  `/<ns>/32=trust-context/v=N`: anchors, schema, CA endpoints, revocations.
  Distributed by envelope (first contact), by name over RDR (any `ndn-fwd`
  publishes the contexts in its store, **have**: see
  `docs/wiki/src/reference/trust-context-publication.md`). Updates are pulled
  by name and republished by each holder, adopted only if signed by an anchor
  of the held version and strictly newer (**have**: `ndn-fwd context refresh`,
  `[security] context_refresh_secs`; see
  `docs/wiki/src/reference/context-updates.md`); the root device also pushes
  each version over the namespace's SVS group, adopted under the same rule
  (**have**: `[security] context_sync`, `ndn-fwd` `context_sync.rs`).
- **Envelope** — `ndn-trust://` (`ndn-trust-envelope`): `anchor` (signed
  context or fingerprint pointer: namespace + expected fingerprint +
  version), `invite` (CA prefix + namespace + token + expected fingerprint),
  `capability`, `delegation`, `recovery`, `bag`.
- **Enrollment** — NDNCERT 0.3 via `ndn_cert::client::enroll`; challenges
  `token` (from an invite) and `device-approval` (admin approves).
- **Revocation** — context revocation list (authoritative, root-signed) and
  CA revocation set (immediate, CA-signed REVOKE).
- **Recovery kit** — a separate recovery key whose anchor the context lists
  with role `recovery-anchor` (context TLV `KeyRole`, 0x041E); file kits are
  an `ndn-trust://bag` envelope that also names the namespace and its
  expected fingerprint (**have**: F7).

## 4. Generated trust schema

Produced from the role layout; carried in the context as LVS binary (portable
to ndnd/NDNts/python-ndn) with a native-text twin for the rules LVS cannot
express (**have**: `ndn_cert::roles::namespace_schema`, emitted by `init`).

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
(`…/KEY/<k>`): KeyLocators name the key, and each certificate of it is
`<key>/<issuer-id>/<version>` (NDN Certificate Format v2; issuer `self`,
`NDNCERT` from the CA, `NA` for the CA's cert from the root). The context is
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

### F1 Create a namespace (root device)
1. `ndn-fwd init --namespace /<ns> [--device <name>] [--root-store <store>]`
   → root (in its root store, §2), CA, the primary device as
   `/<ns>/admin/<dev>` (CA-certified; device name defaults to the sanitized
   host name), root-signed context carrying the generated schema, in the
   PIB (**have**).
2. Recovery kit offered immediately (F7): `init` prints the command, and
   `ndn-fwd root-key status` counts the recovery anchors and keeps
   recommending one while there is none (**have**). The owner may decline.
3. Optional: delegate the CA to a relay (F3).

### F2 Add a device
- **By invite (token):** an admin creates an invite (`ndn-fwd-tokens new
  --role member|guest --anchor-fp <fp> [--ttl <dur>]`, **have**; the token
  carries its role and, with `--ttl`, its expiry, and the CA scopes it to
  `/<ns>/<role>` and refuses it once expired) → QR/link carries CA prefix,
  namespace, token, expected root fingerprint. New device: `ndn-fwd enroll
  <invite> [--device <name>]` = adopt the trust context by namespace +
  expected fingerprint if not held (no version floor: an invite names none),
  generate the device key in the daemon's PIB, enroll with the token, check
  the issued certificate's chain to the root, store it and make the identity
  the PIB's default (loaded at start unless `[security] identity` names
  another), and switch the running daemon's signer for its management
  responses and discovery records (DV with `static`/`lvs` trust keeps its
  startup key until a restart) (**have**:
  `ndn_cert::enroll_with_invite`, `ndn_identity::enroll_with_invite_via_engine`,
  `security/enroll` gated like `security/context-adopt` by the management
  socket's peer credentials and never accepted over `/localhop`, mobile
  `NdnEngine::enroll_with_invite`, which returns the adopted context for the
  app to persist — see
  `docs/wiki/src/reference/enrollment-by-invite.md`; adoption from a
  fingerprint-only link: `docs/wiki/src/reference/context-adoption.md`).
- **By approval:** new device scans the anchor QR, requests enrollment with
  `device-approval`; an admin sees the pending request (`ca list-approvals`)
  and approves on an admin device (**have** in daemon; **gap**: approve from a
  remote admin device, not only the CA host's mgmt socket).
- Role: the device enrolls as `/<ns>/<role>/<dev>`; issuing an admin (or
  relay) cert requires an admin approval, never a token alone; tokens
  admit members, and guests only when guest-scoped (**have**:
  `ndn_cert::RolePolicy`, the default for the namespace CA in `[ca]`).
- One key per device name: the CA refuses a new key for `/<ns>/<role>/<dev>`
  while a valid certificate it issued for that name to another key is
  unrevoked, unless an admin approves the new key; the refusal comes before
  the token is redeemed, also for the loser of two concurrent requests for
  one name (**have**: `IssuancePolicy::single_key_identity`, the CA's
  in-flight reservation).
- Lifetime: certificates from the namespace CA last their role's `[ca]
  cert_validity_days` (default 90; e.g. `guest = 7`); a device's request names
  no lifetime, so the CA's setting decides. Devices renew before expiry (F10).

### F3 Delegate the CA to a relay
1. The relay generates `/<ns>/CA` key locally; produces a cert request.
2. The root device signs it with the root (QR/file round trip, or over NDN
   while paired) and bumps the context with the new CA endpoint.
3. The relay starts `[ca]` from its PIB (**have**: PIB-backed CA).
Gap: the request/sign round trip.

### F4 Lose a member device
On the root device: `ndn-fwd revoke /<ns>/<role>/<dev>` (or a key or
certificate name) (**have**; see `docs/wiki/src/reference/revocation.md`):
1. Context bump, in the CLI: version `N+1` lists the device's key names as
   revoked, signed by the root key unlocked there for that one signature,
   and is handed to the daemon of the same PIB (`security/context-update`,
   continuity rule), which stores and publishes it. Every node refuses a
   chain through those keys once it holds `N+1`, which it pulls at its next
   refresh and republishes for the nodes behind it (`context_refresh_secs`,
   default 300 s, or `ndn-fwd context refresh`). A node that adopts the
   revoking version evicts from its Content Store the Data the revoked key
   signed (and that key's certificate) at once, so it never serves them from
   cache afterwards; a node still on the old version may, but every node
   holding the new version refuses that Data.
2. CA, following the signed version: whenever a node running the namespace
   CA keeps a version (handed over, refreshed, adopted) and when the CA
   starts, the CA marks every certificate it issued that the version revokes
   (`<pib>/ca/revoked/`): no longer served, the key is never certified
   again, the device name is free to enroll with a new key. The CA acts on
   the signed version only, never on a separate request.
Gap: revoking from an admin device other than the root device (the root key
signs the bump, so the command runs where the root key is).

### F5 Lose an admin device
As F4: `ndn-fwd revoke /<ns>/admin/<dev>` (**have**). Approvals are given on
the CA host's management socket (`ca approve`), not signed by a device, so
there are no device-signed approvals to refuse yet; when remote admin approval
(F2 gap) exists, its approvals chain through the admin key and the bump
refuses them like any other Data. If it was the root device, continue with F8.

### F6 Relay compromised
1. Root bump: revoke the relay's node key (**have**: `ndn-fwd revoke
   /<ns>/node/<name>`). Revoking `/<ns>/CA` and adding a new CA endpoint is a
   **gap**: `revoke` refuses the CA's own key, since every device certificate
   chains to it; replacing the CA needs F3's round trip first.
2. Devices keep their certs (issued before compromise) unless the owner
   chooses to re-enroll everything; the UI asks.
3. QUIC pins for that relay are dropped from the links peers configure to it.

### F7 Create a recovery kit (**have**)
A kit holds a **separate recovery key**, never a copy of the root: a
hardware root cannot be exported, and a copy of the root written as words
would be the root itself. On the root device, `ndn-fwd recovery-kit create
--format words|file|yubikey` makes the key and the root (unlocked from its
store for this one signature) signs version `N+1` listing its self-signed
certificate as an extra anchor, marked `recovery-anchor` (context TLV
`KeyRole`; carried over by every later version). The key is named
`/<ns>/KEY/r<first 8 bytes of SHA-256(public key), hex>`, so a word list
alone rebuilds it. All formats are supported equally; several may coexist:
- **Word list** — Ed25519 from a 32-byte seed shown once as 24 BIP39 English
  words (the checksum refuses a mistyped word); nothing is stored.
- **Encrypted file** — the key in a SafeBag sealed by a kit passphrase
  (PBES2 as the root store), in an `ndn-trust://bag` envelope that also
  carries the namespace and its expected fingerprint, written `0600`.
- **Hardware** — P-256 generated on a second YubiKey's PIV slot (default
  `9d`, PIN policy `always`, touch policy chosen), non-exportable; refused on
  the root's own token and over a slot that holds a key unless the operator
  says it is not needed (`--replace-slot`).
`recovery-kit list` shows the anchors of the held context, `check <kit>`
opens a kit and confirms its key is a recovery anchor (signs nothing),
`revoke <key>` has the root sign a version without that anchor and revoking
its key. The CLI signs and hands the version to the running daemon that uses
the same PIB (`security/context-update`, adopted under the continuity rule,
stored, published); only the daemon's refusal undoes the CLI's work, never a
missing answer. A recovery anchor is root-equivalent by design: keep it
offline.

### F8 Restore after losing the root device (**have**)
On a replacement device whose daemon holds the namespace's context (linked
through a relay, say): `ndn-fwd recover --kit words|<file>|yubikey
--old-root destroyed|compromised [--keep-kit <key>]… [--root-store …]
[--device <name>]`.
1. The daemon fetches the newest version by name (as `context refresh`); a
   device holding none adopts it with a file kit's expected fingerprint, or
   is told to adopt first (a context with nothing to check it against could
   be a forgery the recovery key would then sign). The kit's key must be a
   recovery anchor of that version.
2. A new root (in the chosen store; never on the kit's token), a new CA key
   `/<ns>/CA/KEY/<id>` and a new admin identity `/<ns>/admin/<device>`, all
   with fresh key ids; the recovery key signs `N+1`: anchors = new root +
   the recovery anchors kept (+ the old root when `destroyed`); the CA
   endpoint stays `/<ns>/CA`; the new root device's CA and admin keys get the
   `root-device` role. The new root then
   signs `N+2`, the same content (`ndn_cert::reissue_version`), so the newest
   version is root-signed and the new root's fingerprint is the namespace's
   expected fingerprint for anchor links and invites from then on (an
   expected fingerprint authenticates the signer of the version adopted,
   never merely an anchor the fetched context lists).
3. `destroyed`: every certificate the old root and CA issued stays valid;
   devices renew with the new CA, which accepts a current, unrevoked
   certificate of the namespace issued by an earlier CA of `/<ns>/CA` that
   still validates under its context, and serves that CA's certificate from
   then on. `compromised`: `N+1` revokes the old root, the old CA key and the
   old root device's admin key (the `root-device` keys); devices whose
   certificates chain through the old CA stop validating and enroll again
   with invites from the new root device. It also keeps only the recovery
   anchors the operator vouches for — the kit used and those named with
   `--keep-kit` — and removes and revokes the rest: whoever held the old root
   could have added a kit of their own, and a kit is root-equivalent.
   `destroyed` keeps every recovery anchor.
4. `N+1`, then `N+2`, go to the daemon, which adopts, stores and publishes
   each; every node holding `N` adopts both by the continuity rule (`N+1`
   signed by an anchor of `N`, `N+2` by an anchor of `N+1`). A node that
   missed them — offline across the recovery and later root-signed versions —
   follows the versions in between by exact name, oldest first, each under
   the continuity rule from the one before (`ndn_cert::follow_versions`, at
   most 128 versions); every node keeps and serves each version it held
   (`<pib>/contexts/<hex(ns)>.versions/`), so the chain of signed versions,
   not the timing of refreshes, carries it. The operator restarts the daemon
   with the printed `[security]` and `[ca]` lines.
Gaps: the old root's admin key of a namespace made before root-device roles
were recorded must be revoked by hand; a store written before versions were
kept serves only the versions held since.

### F9 Share with a friend (scoped, time-limited)
1. Admin issues a guest cert `/<ns>/guest/<who>` with short validity, plus a
   `capability` envelope listing what it may publish/fetch (**have**: envelope
   kind and `ndn_security::Capability`).
2. Reading private data requires content keys: guests receive keys only for
   the shared scope (confidentiality module; ABE optional).
3. Expiry needs no action; early end = F4.

### F10 Rotate keys
Device certificates renew before expiry without an invite (**have**:
`ndn_cert::renew_certificate` against the CA's built-in `renewal` challenge,
proof of possession of the current certificate's key; same key re-certified
under a new certificate name, the old one kept until it expires;
refused for an expired certificate, a revoked key or a non-renewable role —
guests by default; per-role lifetimes and `[ca] renewable_roles` in
`ndn_cert::RolePolicy`; renewal goes to the namespace's CA and carries the
issuer chain the device kept, so after a recovery the new CA key renews an
earlier CA's certificate — `ndn-fwd` keeps the chain in `<pib>/issuers/`, a
phone persists `NdnEnrolledIdentity::issuers` and passes it back to
`renew_certificate`; the `ndn-fwd` renewal timer `[security] renew_before`
and `ndn-fwd renew`; mobile `NdnEngine::renew_certificate` /
`certificate_validity`; see the wiki's reference/renewal.md). Rotating to a
new device key is a new enrollment (invite or admin approval) (**gap**: no
rotation-by-renewal). Root rotation = new root signs a context that lists both
roots for one version, then drops the old one (**gap**).

### F11 Travel / carrier-grade NAT
Devices dial out to a relay (a configured link over QUIC, or WebTransport from
browsers and restrictive networks) and route `/<ns>` over that link; the relay
forwards. Adoption and enrollment do not depend on inbound reachability, but
they do need that link and route whenever the context or the CA is not on the
local segment (§9).

## 6. Storage layout (per node PIB directory)

```
<pib>/                FilePib keys + certs (default); ndnsec-compat may read ~/.ndn
<pib>/keys/*/certs/*.data  each certificate of the key as the CA returned it
                      (`<key>/<issuer-id>/<version>`; legacy cert.data still loads)
<pib>/default-identity  identity loaded when [security] identity is unset
                      (set by `ndn-fwd enroll`)
<pib>/contexts/*.tc   adopted signed contexts, newest version per namespace
                      (loaded at startup, re-verified, published by name
                      unless [security] serve_contexts = false)
<pib>/contexts/*.versions/<N>.tc  every version held, served by exact name
                      so nodes behind can follow version by version
<pib>/ca/             CA cert, anchor cert, node cert, issued/, revoked/,
                      redeemed-tokens/   (CA hosts only)
<pib>/root/           root store of a root device: store.toml (kind, key,
                      public key, anchor cert), root.safebag /
                      root-keychain.safebag (sealed roots)
$XDG_STATE_HOME/ndn-fwd/tls/   persistent self-signed listener certs
```

Everything under `<pib>/` is owner-only: directories `0700`, files `0600`,
each file created with its mode before any byte is written, so a namespace's
root key minted by `init` is never readable by another local user, whatever
the umask. Opening a PIB (`FilePib::new`/`open`, also `FileCaStore::open` for
`ca/`) tightens group/other-accessible entries with a warning, and refuses
entries owned by another uid as well as symlinks inside the PIB. The
self-signed TLS cache is `0700`/`0600` too. On non-unix targets nothing is
enforced: files inherit the parent directory's ACL, so keep the PIB inside
the user's profile (see `ndn_security::secure_fs`).

## 7. Build order

1. Generated schema + role naming in `init` and enrollment (F1, F2 roles) — **have**.
2. `adopt` by fingerprint + `enroll` by invite (**have**) and remote admin approval (F2).
3. `revoke` + context bump/publish + pulled updates (F4, F5) — **have**;
   `devices list` is still to build.
4. Recovery kit formats + `recover` (F7, F8) — **have**.
5. CA delegation round trip (F3), then F6 tooling.
6. Guest flow (F9), root rotation (F10).
7. Two-process testbed scenario covering F1→F2→F4→F8.
8. TUI over the finished commands.

## 8. Owner-configurable policy

Admission policy is the CA's challenge configuration, chosen by the owner,
not fixed by the design: token-only, approval-only, or token AND approval for
members. Admin certificates always require an admin approval. Recovery kit
formats (§F7) and root key storage (§2) are likewise the owner's choice.

## 9. Links, relays and routes vs trust and enrollment

Two separate planes, configured separately:

- **Host-centric: links, relays, routes.** A link is a face between two
  forwarders (`[[face]]`, `ndn-ctl face create`); it names a host and port.
  A relay is a forwarder at a reachable address (a VPS, a home server with a
  forwarded port) that other forwarders link to. A route (`[[route]]`,
  `ndn-ctl route add`) says which prefixes go over which links. None of this
  knows about namespaces' keys: a link carries any Interest the routes send
  it.
- **Data-centric: trust and enrollment.** Adopting a trust context decides
  which signed Data under `/<ns>` this node accepts; enrolling gives this
  node's key a certificate under `/<ns>/<role>/<device>`. Both are statements
  about names and keys, not about hosts; they work over whatever links and
  routes exist, or over none (an inline anchor link needs no fetch).

Consequences:

- **A link never forms from an invite or an anchor link.** Neither carries a
  host: an invite holds a CA prefix, a namespace, a token and a fingerprint;
  an anchor link holds a namespace, a fingerprint, a version and optionally
  the signed context. Adopting or enrolling adds no face and no route.
- On one segment, multicast/discovery faces usually reach the root device
  already, so a fingerprint-only adoption or an enrollment just works.
- **Across NATs or the internet**, a device needs a configured link to a
  relay and a route for `/<ns>` (and the CA prefix) over it before a
  fingerprint-only adoption or an enrollment can reach the context or the
  CA. The relay itself only forwards; it need not hold the CA (F3 is
  optional) and never holds the root.
