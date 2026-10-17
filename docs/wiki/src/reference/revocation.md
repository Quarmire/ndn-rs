# Revoking a device (`ndn-fwd revoke`)

A lost or compromised device keeps its private key and its certificate. To
stop the namespace from trusting it, the owner **revokes** the device's key on
the namespace's **root device**: the node where `ndn-fwd init --namespace …`
ran, which holds the namespace root key in its root store and runs the namespace's
CA. A revocation is one thing — a new, root-signed version of the trust
context — and two parties act on it:

| Who | Effect | When it takes effect |
|---|---|---|
| Every validator | refuses a chain through the key | on each node once it holds version `N+1`, which lists the key name as revoked; other nodes fetch it at their next refresh ([context updates](./context-updates.md)) |
| The namespace CA | stops serving the key's certificates, never certifies that key again, and the device name is free for a new key | as soon as the daemon running the CA holds `N+1`: at once on the root device |

The CA side alone would not be enough: a node that already has the
certificate (fetched earlier, or carried in a KeyLocator chain) would keep
accepting it. The context entry is what every validator checks, and only the
root key can add one. The CA acts on that signed entry, never on a separate
request ([the CA follows the trust context](#the-ca-follows-the-trust-context)).

Design: `docs/specs/personal-namespace.md`, flows F4 (lose a member device)
and F5 (lose an admin device).

## Unlocking the root

The root signs the new context version, so a revocation unlocks it for that
one signature — in the `ndn-fwd revoke` command itself, which opens the root
store of the PIB (`--pib`, or `[security] pib_path` of `-c <config>`) and asks
for what it needs:

| Root store (`ndn-fwd root-key status`) | `revoke` asks for |
|---|---|
| `os-keyring` | nothing — the OS keychain releases the sealing secret to the logged-in user |
| `sealed-file` | the passphrase: `NDN_ROOT_PASSPHRASE`, else `--passphrase-file <path>`, else the terminal (no echo) |
| `yubikey-piv` | the PIV PIN: `NDN_ROOT_PIN`, else `--pin-file <path>`, else the terminal; then a touch if the policy says so |
| `file` | nothing (plaintext, unprotected; seal it with `ndn-fwd root-key move --to os-keyring`) |

The secret is never taken from the command line, and never leaves the
command: it unlocks the root there, the root signs, and the key is dropped
(a software key zeroed). The daemon receives only the signed version. Every
check that needs no key runs before the secret is asked for (see
[refusals](#refusals)), so a refused revocation never asks.

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

`ndn-fwd revoke <name> [--pib <dir> | -c <config>]`, on the root device.
`<name>` is one of:

- a device identity, e.g. `/home/bob/member/phone`: every key the namespace
  CA issued a certificate for to exactly that identity, read from the CA
  store in the PIB (`<pib_path>/ca/issued/`);
- a key name, e.g. `/home/bob/member/phone/KEY/eba4f4f2af5d697b`, also for a
  key this CA did not certify;
- a certificate name: reduced to its key name.

The command, before asking for any secret:

1. Opens the PIB's root store and the context stored for its namespace
   (`<pib_path>/contexts/`); the root store must hold an anchor of that
   version (`RootStore::holds_anchor_of`, public keys only), else this is not
   the root device.
2. Works out the key names (above). A name in the namespace CA's identity
   (`<ns>/CA`), a name outside the namespace, and a key covering a root
   anchor are refused (`ndn_cert::revocations_to_add`).
3. Keys the held version revokes already are not added again; when it
   revokes all of them, nothing is signed and the command says so.
4. When a daemon listens on the management socket, checks it uses the same
   PIB (`security/identity-status` `pib_path=`).

Then it unlocks the root, makes version `N+1`
(`ndn_cert::bump_context_revoking`: the held Content decoded verbatim —
anchors, schema blobs, CA endpoints, earlier revocations — plus the new
entries, signed with the root key) and hands it to the daemon with
`security/context-update`, as `ndn-fwd recovery-kit` does
([versions made on this device](./context-updates.md#versions-made-on-this-device-securitycontext-update)):
the daemon adopts it under the continuity rule (signed by an anchor of the
held version, strictly newer), stores it in `<pib_path>/contexts/` as the
newest version (`N` stays stored beside it), and publishes it by name
(unless `[security] serve_contexts = false`). With no daemon listening, the
version is stored there for the daemon's next start.

The outcome comes from the daemon's answer: a refusal means nothing was
revoked (the context and the CA are unchanged); without an answer, the
command says it does not know, and running it again once the daemon is idle
reports the keys revoked if the daemon took the version, or signs it again if
not.

The root device refuses the key at once. Every other node refuses it once it
has fetched `N+1`; see [context updates](./context-updates.md).

## The CA follows the trust context

Whenever the daemon keeps a version of a context — handed over by a CLI,
fetched by a refresh, adopted by link — and the node runs the CA of that
namespace (`[ca]` with identity `<ns>/CA`), the CA follows the version
(`TrustAdmin::keep` → `revoke::ca_follow`): every certificate it issued under
a name the version revokes is recorded in `<pib_path>/ca/revoked/` (kept
across restarts) and dropped from its certificate cache
(`CaState::revoke_issued_under`): no longer served, that key is never
certified again, and the device name is free for a new key. When the CA
starts, it follows the versions loaded from `<pib_path>/contexts/` the same
way (`revoke::ca_follow_held`), which covers a version stored for the next
start and a revocation its store could not record. Following a version
again changes nothing. The CA's state is therefore derived from the signed
context alone: a CA on a relay that refreshes the context follows a
revocation made on the root device, too.

## Who may revoke

Only the holder of the root key signs a revocation. Handing the version to
the daemon (`security/context-update`) is a trust-admin verb
(`TRUST_ADMIN_VERBS` in `ndn-mgmt/src/auth.rs`): only the daemon's own user,
root, or a member of a group in `[security] trust_admin_groups` may send it
over the management socket, and it is refused (`403`) over `/localhop`,
whoever signed it. See
[Adopting a trust context](./context-adoption.md#who-may-adopt).

The network NDNCERT `REVOKE` request (a device revoking its own certificate
with a possession proof) is unchanged and shares the CA's store; it does not
make a new context version.

## Usage

```sh
# on the root device (sealed-file root: asks for the passphrase)
ndn-fwd revoke /home/rv/member/phone -c root.toml
# ndn-fwd revoke
namespace      = /home/rv
revoked_key    = /home/rv/member/phone/KEY/4c60a77af0f3ce14
trust_context  = v1 -> v2 (signed by the root /home/rv/KEY/root)
handed_over    = the daemon at <management socket> adopted v2 (signed by /home/rv/KEY/root/self/v=…, an anchor of v1); stored <pib>/contexts/2f686f6d652f7276.tc and published; this node's CA no longer serves /home/rv/member/phone/KEY/4c60a77af0f3ce14/NDNCERT/v=… (the version revokes their keys) and their device names are free for a new key

# The CA of /home/rv stops serving the certificates of these keys once its
# daemon holds v2, and the device name is free to enroll again with a
# new key. Every other node refuses the keys once it holds v2: at its next
# refresh ([security] context_refresh_secs, default 300 s), or at once with
# `ndn-fwd context refresh`.
```

Data the revoked key signed is refused wherever v2 is held, the root device
included:

```text
WARN security: validation: REFUSED — certificate revoked in trust context name=/home/rv/member/phone/data/note/v=…/seg=0 error=certificate revoked in trust context: /home/rv/member/phone/KEY/4c60a77af0f3ce14 in_face=face#2
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

Before the root is unlocked (nothing is asked, nothing signed):

| Cause | What to do |
|---|---|
| the PIB holds no namespace root, or its root store holds no anchor of the held context (not the root device) | run `ndn-fwd revoke` on the root device (`--pib` / `-c` naming its PIB) |
| the PIB holds no trust context for the root's namespace | adopt it first (`ndn-fwd adopt <link>`) |
| the name is outside the namespace | name a device, key or certificate of that namespace |
| the name is the namespace CA or one of its keys | replacing the CA (F6, a compromised relay) is not built; revoke the devices one by one |
| the name is not a key name under the namespace, or covers a root anchor | revoke a device key, never the root |
| the CA issued no certificate for that identity | pass the identity as enrolled (`/<ns>/<role>/<device>`) or a key name |
| the daemon on the socket uses another PIB | pass `-c` with that daemon's config, or `--pib` with its PIB |

Unlocking: a wrong passphrase, a refused PIN, or an unreachable OS keychain
fails before anything is signed; retry with the right one (or unlock the
keychain by logging in to the desktop session).

Handing over: the daemon refuses a version that is not signed by an anchor of
the version it holds or not newer than it (`403`, the root signed a version
made from a context the daemon no longer holds: run `revoke` again), or when
the context changed meanwhile (`409`). A refusal changes nothing — neither
the context nor the CA.

When the CA cannot record a revocation in `<pib_path>/ca/revoked/`, the
daemon's answer says so: the CA stops serving the certificate for this run,
and follows the stored context again when it next starts.

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
| Checks before signing | `ndn_cert::revocations_to_add` |
| CA following the context | `ndn-fwd` `revoke.rs` (`ca_follow`, `ca_follow_held`), called from `TrustAdmin::keep` (`context_adopt.rs`) and the CA's start (`ca.rs`); `ndn_cert::CaState::{issued_under, revoke_issued_under}` |
| Stored context | `ndn_cert::read_stored_context` |
| Hand-over | `security/context-update` (`ndn-ipc` `MgmtClient::security_context_update`; daemon `context_refresh::apply_update`) |
| CLI | `ndn-fwd` `revoke.rs` (`run`); hand-over `recovery_kit.rs` (`hand_over`) |

## See also

- [Trust-context updates](./context-updates.md) — how version `N+1` reaches
  every node.
- [Enrolling with an invite](./enrollment-by-invite.md)
- [Trust-context publication (RDR)](./trust-context-publication.md)
