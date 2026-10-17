# Revoking a device (`ndn-fwd revoke`)

A lost or compromised device keeps its private key and its certificate. To
stop the namespace from trusting it, the owner **revokes** the device's key on
the namespace's **root device**: the node where `ndn-fwd init --namespace …`
ran, which holds the namespace root key in its root store and runs the namespace's
CA. Revocation happens in two places:

| Where | Effect | When it takes effect |
|---|---|---|
| The namespace CA | the CA stops serving the key's certificates, never certifies that key again, and the device name is free for a new key | at once, on the root device |
| The trust context | version `N+1` of the namespace's context lists the key name as revoked, signed by the root key | on each node once it holds `N+1`, which it fetches at its next refresh ([context updates](./context-updates.md)) |

The CA side alone is not enough: a node that already has the certificate
(fetched earlier, or carried in a KeyLocator chain) would keep accepting it.
The context entry is what every validator checks, and only the root key can
add one.

Design: `docs/specs/personal-namespace.md`, flows F4 (lose a member device)
and F5 (lose an admin device).

## Unlocking the root

The root signs the new context version, so a revocation unlocks it for that
one signature. `ndn-fwd revoke` asks the daemon (`security/identity-status`,
`root_unlock=`) what its root store needs:

| Root store (`ndn-fwd root-key status`) | `revoke` asks for |
|---|---|
| `os-keyring` | nothing — the OS keychain releases the sealing secret to the logged-in user |
| `sealed-file` | the passphrase: `NDN_ROOT_PASSPHRASE`, else `--passphrase-file <path>`, else the terminal (no echo) |
| `yubikey-piv` | the PIV PIN: `NDN_ROOT_PIN`, else `--pin-file <path>`, else the terminal; then a touch if the policy says so |
| `file` | nothing (plaintext, unprotected; seal it with `ndn-fwd root-key move --to os-keyring`) |

The secret is never taken from the command line. The CLI sends it with the
command over the local management socket (peer-credential gated, refused over
`/localhop`), in the command's ApplicationParameters — never in its Name. The
daemon decrypts or unlocks the root, signs, and drops the key (zeroed). The
passphrase or PIN itself is zeroed where it is held as a secret value (the
CLI's prompt result, the decoded command parameter); the packet buffers that
carry it between the two processes are freed without being overwritten.

## What a revocation entry covers

A context entry is a **key name** `/<identity>/KEY/<key-id>`. The validator
checks every hop of a certificate chain (`walk_to_anchor`): a chain through a
certificate whose KeyLocator or issuer name *starts with* a revoked entry is
refused with `certificate revoked in trust context: <entry>`. So one entry
covers:

- every certificate of that key, `/<identity>/KEY/<key-id>/<issuer>/<version>`
  (a renewed certificate is a new one under the same key), whether a
  KeyLocator names the key or a full certificate name;
- certificates of that key issued later;
- Data signed by any key whose chain passes through it.

The identity itself is never an entry, so the same device name can enroll
again with a new key: `ndn-fwd enroll <invite> --device <same name>` works
without `--force`, because the "already enrolled" check skips keys the held
context revokes.

## What `revoke` does

`ndn-fwd revoke <name> [-c <config>]` sends `security/revoke` (the name in
`ControlParameters.Name`) to the running daemon. `<name>` is one of:

- a device identity, e.g. `/home/bob/member/phone`: every key the CA issued a
  certificate for to exactly that identity;
- a key name, e.g. `/home/bob/member/phone/KEY/eba4f4f2af5d697b`, also for a
  key this CA did not certify;
- a certificate name: reduced to its key name.

The daemon, under one lock shared with the context refresh:

1. Finds the held context whose namespace is the longest prefix of the name,
   and its signed Data as stored in `<pib_path>/contexts/`.
2. Checks it can sign the next version: the PIB must hold the private key of
   the anchor that signed the held version, with the same public key. Nothing
   changes otherwise.
3. Checks it runs the namespace's CA (`[ca]` with identity `<ns>/CA`).
4. Works out the key names (above). The CA's own key and any name covering a
   root anchor are refused.
5. Makes version `N+1` (`ndn_cert::bump_context_revoking`): the held Content
   decoded verbatim — anchors, schema blobs, CA endpoints, earlier
   revocations — plus the new entries, signed with the root key. Keys already
   revoked are not added twice; when all are, no new version is made.
6. CA, immediate: records each key name revoked in `<pib_path>/ca/revoked/`
   (kept across restarts) — covering every certificate it issued for the
   key, and any it would issue later — and drops them from its certificate
   cache (`CaState::revoke_issued_under`).
7. Context: adopts `N+1` into its keyring (`Keyring::adopt_update`, strictly
   newer), stores it in `<pib_path>/contexts/` as the newest version (`N`
   stays stored beside it), and publishes it by name (unless `[security]
   serve_contexts = false`).

The root device refuses the key at once. Every other node refuses it once it
has fetched `N+1`; see [context updates](./context-updates.md).

## Who may revoke

`security/revoke` is a trust-admin verb (`TRUST_ADMIN_VERBS` in
`ndn-mgmt/src/auth.rs`): only the daemon's own user, root, or a member of a
group in `[security] trust_admin_groups` may send it over the management
socket, and it is refused (`403`) over `/localhop`, whoever signed it. See
[Adopting a trust context](./context-adoption.md#who-may-adopt).

The network NDNCERT `REVOKE` request (a device revoking its own certificate
with a possession proof) is unchanged and shares the CA's store; it does not
make a new context version.

## Usage

```sh
# on the root device
ndn-fwd revoke /home/bob/member/phone -c root.toml
# ndn-fwd revoke (by the running daemon at <management socket>)
namespace        = /home/bob
revoked_key      = /home/bob/member/phone/KEY/eba4f4f2af5d697b
ca_revoked       = /home/bob/member/phone/KEY/eba4f4f2af5d697b (no longer served by the CA)
trust_context    = v1 -> v2 (signed by the root, stored and published)
stored           = <pib>/contexts/2f686f6d652f626f62.tc

# This node and its CA refuse the key now. Every other node refuses it once it
# holds v2: it fetches it at its next refresh ([security]
# context_refresh_secs, default 300 s), or at once with `ndn-fwd context refresh`.
# The device name is free to enroll again with a new key.
```

On another node, after its refresh, Data signed by the revoked key is dropped:

```text
validation: FAILED name=/home/bob/member/phone/data/photo2/… error=certificate revoked in trust context: /home/bob/member/phone/KEY/eba4f4f2af5d697b
```

## Cached Data

A forwarder validates Data once, before its Content Store admits it, and
answers later Interests from the CS without validating again. A revocation
still reaches what is cached, through a stamp on each entry:

- The keyring counts the adoptions that revoke something
  (`Keyring::revocation_epoch`, moved after the new version is in force). The
  validation stage reads the count before it validates a Data packet, and the
  CS insert stage stores it with the entry.
- On every CS hit, the lookup compares the entry's stamp with the current
  count: one atomic load. Only when they differ is the entry judged against
  the revocations held now. It is kept only when it is known clear: it is no
  revoked certificate, and its chain, followed from its KeyLocator through
  the node's certificate cache, reaches a trust anchor without passing a
  revoked key or certificate. Then it is stamped with the current count, so
  it is not judged again until the next revoking adoption. Otherwise it is
  evicted and the Interest goes on as a miss — also when the chain cannot be
  followed that far, as after a restart, when the certificate cache holds
  only the node's own certificates: the Data is then fetched and validated
  afresh. Under a context that revokes nothing, every entry is clear.

So once a node has adopted a revoking version, it never serves from its CS
Data that the version's revocations cover, whether that Data was cached before
the adoption, validated before it and cached after, or cached while it ran.
A persistent CS (`fjall`, `sqlite`) keeps its entries across restarts, but the
count starts again at 0 in each process. Each open of the store takes a new
generation, stored with every stamp, so an entry stamped by an earlier
process is judged once at its first hit. A store file written before entries
carried stamps is emptied on open. Data cached without validation (for
example with `cs_admit_unverified`) carries no stamp and is not judged.

When the keyring adopts the revoking version, the engine also evicts at once,
under that context's namespace, every entry not known clear, stamped or not,
so they stop taking cache space. It finishes before the
adoption returns for the in-tree stores (`lru`, `sharded-lru`, `sqlite`,
`fjall`) and logs `trust context revokes keys: evicted the cached Data they
signed … evicted=<n>`. Serving does not depend on it.

A node that has not yet adopted the new version still serves what it cached,
but a downstream node that holds the new version refuses it. The node also
stops serving its own certificate for a revoked key. Data validated before
the adoption that reaches the CS after it is still forwarded to the faces
whose Interests were waiting for it, since it was valid when it arrived; the
first hit on its cached copy evicts it.

## Refusals

| Status | Cause | What to do |
|---|---|---|
| 401 | this node's root store holds no anchor of the held context (not the root device) | run `ndn-fwd revoke` on the root device |
| 401 | the root store needs its passphrase / PIN and none came with the command | run `ndn-fwd revoke` (it asks), or set `NDN_ROOT_PASSPHRASE` / `NDN_ROOT_PIN` |
| 403 | wrong passphrase, or the YubiKey refused the PIN | retry with the right one; nothing was signed |
| 503 | the OS keychain is not reachable, or lost the root's entry | unlock the keychain (log in to the desktop session) |
| 404 | this node holds no context for a namespace containing the name | run it on the root device of that namespace |
| 404 | this node runs no CA for the namespace | run it on the root device, which runs the CA |
| 404 | the CA issued no certificate for that identity | pass the identity as enrolled (`/<ns>/<role>/<device>`) or a key name |
| 400 | the name is not a key name under the namespace, or covers a root anchor | revoke a device key, never the root |
| 400 | the name is the CA's own key | replacing the CA (F6, a compromised relay) is not built; revoke the devices one by one |
| 409 | the context changed while the revocation ran | revoke again |
| 500 | the stored context is unreadable, or differs from the held version | restart the daemon so both agree, then revoke again |

A refusal changes nothing: neither the CA store nor the context.

`ca_not_persisted` in the answer means the CA marked the certificate revoked
in memory but could not write `<pib_path>/ca/revoked/`; the context entry is
still made, and the CA refusal lasts until it restarts.

## Code

| Part | Where |
|---|---|
| Revocation check in the chain walk (prefix match) | `ndn_security::SignedTrustContext::is_revoked`, `validator/chain.rs` |
| Key name of a certificate name | `ndn_cert::key_name_of` |
| New version with revocations | `ndn_cert::bump_context_revoking` (`ndn-cert/src/context_update.rs`) |
| Strictly-newer adoption | `ndn_security::Keyring::adopt_update` |
| Revocation epoch, eviction hook | `ndn_security::Keyring::{revocation_epoch, on_revocation}` |
| Entry stamp; hit-time re-check | `CsInsertStage`, `CsLookupStage` (`ndn-engine` `stages/cs.rs`); `revocation_purge::recheck` |
| Stamp storage | `ndn_store::{CsEntry::revocation_epoch, ContentStore::restamp, EARLIER_PROCESS_EPOCH}`; store generation in `ndn-store` `cs_keycodec.rs` |
| CS eviction on adoption | `ndn-engine` `revocation_purge.rs` (`install`) |
| CA side | `ndn_cert::CaState::{issued_under, revoke_issued_under}` |
| Stored context | `ndn_cert::read_stored_context` |
| Management verb | `ndn-mgmt` `security/revoke`, `RevokedInfo`; `ndn-ipc` `MgmtClient::security_revoke` |
| Daemon | `ndn-fwd` `revoke.rs`; CLI `onboard.rs` (`run_revoke`) |

## See also

- [Trust-context updates](./context-updates.md) — how version `N+1` reaches
  every node.
- [Enrolling with an invite](./enrollment-by-invite.md)
- [Trust-context publication (RDR)](./trust-context-publication.md)
