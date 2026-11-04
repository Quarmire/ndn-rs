# Revoking a device (`ndn-fwd revoke`)

A lost or compromised device keeps its private key and its certificate. To
stop the namespace from trusting it, the owner **revokes** the device's key on
the namespace's **root device**: the node where `ndn-fwd init --namespace …`
ran, which holds the namespace root key in its root store and runs the namespace's
CA. A revocation is one thing — a new, root-signed version of the trust
context — and two parties act on it:

| Who | Effect | When it takes effect |
|---|---|---|
| Every validator | refuses a chain through the key, and the Data the key signed — except, when the version carries the key's **revocation cut**, the Data the cut accepts | on each node once it holds version `N+1`, which lists the key name as revoked; other nodes fetch it at their next refresh ([context updates](./context-updates.md)) |
| The namespace CA | never certifies that key again, and the device name is free for a new key; stops serving the key's certificates, unless it was revoked with a cut (then they stay served for its in-cut Data) | as soon as the daemon running the CA holds `N+1`: at once on the root device |

The CA side alone would not be enough: a node that already has the
certificate (fetched earlier, or carried in a KeyLocator chain) would keep
accepting it. The context entry is what every validator checks, and only the
root key can add one. The CA acts on that signed entry, never on a separate
request ([the CA follows the trust context](#the-ca-follows-the-trust-context)).

Design: `docs/specs/personal-namespace.md`, flows F4 (lose a member device)
and F5 (lose an admin device); the cut and how Data is judged:
`docs/specs/trust-context.md` §3.3.12 and §6.3, `docs/specs/data-layer.md`
§8.

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
- Data signed by any key whose chain passes through it, except Data the
  key signed itself that the key's revocation cut accepts
  ([below](#revocation-cut)).

The identity itself is never an entry, so the same device name can enroll
again with a new key: `ndn-fwd enroll <invite> --device <same name>` works
without `--force`, because the "already enrolled" check skips keys the held
context revokes.

## Revocation cut

A revocation alone refuses everything the key ever signed: also the notes
a lost phone wrote honestly before it was lost. A **revocation cut** keeps
exactly those. It is part of the same signed version, beside the key's
entry (`RevocationCut`, TLV `0x0428`): per data collection the key wrote
into, the runs of its log entries that stay valid
(`<device>/32=log/<collection>/seq=<n>`, and `<device>/32=log/seq=<n>` for
snapshots). Every other packet of the key — a later entry, a backdated
one, an entry at an accepted seq in another collection, its summaries —
is refused.

The cut lists what the root device's data layer **holds verified** of the
key, never what a summary only listed. Make it on the root device, then
revoke with it:

```sh
# in the ndn-data host on the root device (ndn-tools)
cut /home/rv/member/phone/KEY/4c60a77af0f3ce14 phone.cut
# then
ndn-fwd revoke /home/rv/member/phone/KEY/4c60a77af0f3ce14 --cut phone.cut -c root.toml
```

The file holds the cut's TLV (`ndn_data::Device::revocation_cut`). `revoke`
prints it as `cut = <key>: <prefix> seq a..b,…; N exact packet(s)` (with
`(already)` when the held version has it). A cut is added only in the
version that revokes its key, and its runs never change afterwards; a cut
for a key the version does not newly revoke, or one listing a name outside
the key's device log `<device>/32=log`, is refused (`cut-refused`).

**Validity periods.** Data is judged without the validity period of any
certificate: the certificate proves the key was authorized, the cut proves
where that ended. So an expired certificate never refuses Data, and a key
ends for Data only by a revocation. Revoke a lost or retired device's key
even when its certificate has expired. Live uses — links, signed
Interests, enrollment, renewal — still end at expiry.

## Re-admitting a version

Honest work the cut left out — offline edits nobody had seen — is
refused, and the devices that refused it report each such version with
its full name, ending in its implicit digest. After looking at it, the
owner re-admits exact versions on the root device:

```sh
ndn-fwd readmit /home/rv/member/phone/KEY/4c60a77af0f3ce14 \
  /home/rv/member/phone/32=log/home/rv/32=data/notes/seq=312/sha256digest=… -c root.toml
```

`ndn-fwd readmit <key> <full-name>… [--namespace <ns>] [--pib <dir> | -c
<config>] [--passphrase-file <path> | --pin-file <path>]` unlocks the root
as `revoke` does and prints `namespace`, `key`, one `readmitted = <name>`
per name (`(already)` for one the cut holds), `trust_context = vN -> vN+1`
and `handed_over`. It signs `N+1` adding those names, digest included, to
the key's cut (`ndn_cert::bump_context_readmitting`).
Only those bytes at those names come back: never a range, a neighbouring
seq or other bytes at the name. Every device that holds or follows them
then applies them. Refused: a key revoked without a cut
(`readmit-no-cut`: revoke it with a cut first — which is possible only in
the version that revokes it), a name without a 32-octet digest or outside
the key's device log (`readmit-refused`); names already in the cut are
nothing to sign (`nothing-to-sign`).

## After a recovery

A recovery from a compromised root (`ndn-fwd recover … --old-root
compromised [--cut <file>]…`, [recovery kits](./recovery.md)) carries
every cut and may add one for each key it newly revokes, printing
`cut = …` per cut of the new version. It revokes the old CA key, an issuer
no cut excuses, so the new CA certifies again each key revoked with a cut,
from a certificate of it the PIB holds: `recertified = <cert>` per
certificate, `not_recertified = <key>` per key whose certificate was not
held (its in-cut Data stays refused). Such a certificate verifies the
key's in-cut Data only; the key stays revoked for everything else. Once
the missing certificates are found, `ndn-fwd recertify [<cert-file>]…
[--namespace <ns>] [--pib <dir> | -c <config>]` certifies them; the CA
records them in its store and serves them once its daemon restarts.

## What `revoke` does

`ndn-fwd revoke <name> [--cut <file>] [--pib <dir> | -c <config>]`, on the
root device.
`<name>` is one of:

- a device identity, e.g. `/home/bob/member/phone`: every key the namespace
  CA issued a certificate for to exactly that identity, read from the CA
  store in the PIB (`issued/` in the CA's directory, `<pib_path>/ca/<hex of the
  trusted prefix>/`; `<pib_path>/ca/` for the one CA of an older PIB);
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
   With `--cut`, the file must hold one `RevocationCut` whose key is one of
   the keys this version newly revokes (`cut-refused` otherwise).
4. When a daemon listens on the management socket, checks it uses the same
   PIB (`security/identity-status` `pib_path=`).

Then it unlocks the root, makes version `N+1`
(`ndn_cert::bump_context_revoking`: the held Content decoded verbatim —
anchors, schema blobs, CA endpoints, earlier revocations and their cuts —
plus the new entries and the cut given, signed with the root key) and hands
it to the daemon with
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
a name the version revokes is recorded in `revoked/` of the CA's directory (kept
across restarts): that key is never certified again (no enrollment, no
renewal), and the device name is free for a new key. A certificate of a key
revoked without a cut is also dropped from its certificate cache
(`CaState::revoke_issued_under`) and no longer served. A certificate of a key
revoked **with** a cut stays served: Data the cut accepts needs it to
verify. It serves nothing else — a revoked key admits no link, enrollment
or renewal, whichever certificate it shows. When the CA
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
included — all of it without a cut, and with a cut whatever the cut does not
accept:

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
  the revocations held now. It is kept only when it is known clear: its chain,
  followed from its KeyLocator through the node's certificate cache, reaches
  a trust anchor without passing a revoked key or certificate — except that
  the key that signed the entry itself may be revoked when the held
  context's cut of that key accepts the entry (the durable rule,
  `SignedTrustContext::refuses_data`) — and it is no certificate of a key
  revoked without a cut. Certificates of a key revoked with a cut are kept,
  for the in-cut Data. Validity periods are not checked: an expired
  certificate does not refuse Data. A clear entry is stamped with the
  current count, so
  it is not judged again until the next revoking adoption. Otherwise it is
  evicted and the Interest goes on as a miss — also when the chain cannot be
  followed that far, as after a restart, when the certificate cache holds
  only the node's own certificates: the Data is then fetched and validated
  afresh. Under a context that revokes nothing, every entry is clear.

So once a node has adopted a revoking version, it never serves from its CS
Data that the version refuses, whether that Data was cached before
the adoption, validated before it and cached after, or cached while it ran;
the in-cut Data of a revoked key it keeps serving.
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
stops serving its own certificate for a key revoked without a cut. Data validated before
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
| `--cut`: the cut's key is not one this version newly revokes, or the held version revokes it already (`cut-refused`) | give the cut with the revocation of its key; a key already revoked keeps the cut it has, and single versions come back with `ndn-fwd readmit` |
| `readmit`: the held version holds no cut for the key (`readmit-no-cut`) | a key not yet revoked: revoke it with a cut first (`ndn-fwd revoke <key> --cut <file>`); a key revoked without a cut has none to add to — a cut comes only with the revocation of its key — so its Data stays refused |
| `readmit`: a name does not end in its 32-octet implicit digest, or is not under the key's device log `<device>/32=log` (`readmit-refused`) | pass the full name a device reported, digest included |

Unlocking: a wrong passphrase, a refused PIN, or an unreachable OS keychain
fails before anything is signed; retry with the right one (or unlock the
keychain by logging in to the desktop session).

Handing over: the daemon refuses a version that is not signed by an anchor of
the version it holds or not newer than it (`403`, the root signed a version
made from a context the daemon no longer holds: run `revoke` again), or when
the context changed meanwhile (`409`). A refusal changes nothing — neither
the context nor the CA.

When the CA cannot record a revocation in `revoked/` of its directory, the
daemon's answer says so: the CA stops serving the certificate for this run,
and follows the stored context again when it next starts.

## Code

| Part | Where |
|---|---|
| Revocation check in the chain walk (prefix match) | `ndn_security::SignedTrustContext::is_revoked`, `validator/chain.rs` |
| Durable walk for Data (no validity periods; the signing key excused in its cut) | `ndn_security::Validator::{validate_durable, validate_durable_cached}`; `SignedTrustContext::{refuses_data, revocation_cut, revocation_cuts, with_revocation_cut}`; `ndn_security::{RevocationCut, CutRange}` |
| Making a cut | `ndn_data::Device::revocation_cut`; refused versions to re-admit: `ndn_data::Device::refused_by_revocation` |
| Re-admission | `ndn_namespace::root::readmit::{plan, readmit}`; `ndn_cert::{readmissions_to_add, bump_context_readmitting, device_log_of, split_full_name}`; CLI `ndn-fwd readmit` |
| Re-certifying cut keys after a recovery | `ndn_cert::{recertify_cut_keys, recertify_cut_keys_in_pib}`, `RecoveredNamespace::{recertified, record_recertified}`; `ndn_namespace::root::recover::recertify`; CLI `ndn-fwd recertify` |
| Key name of a certificate name | `ndn_cert::key_name_of` |
| New version with revocations | `ndn_cert::bump_context_revoking` (`ndn-cert/src/context_update.rs`) |
| Strictly-newer adoption | `ndn_security::Keyring::adopt_update` |
| Revocation epoch, eviction hook | `ndn_security::Keyring::{revocation_epoch, on_revocation}` |
| Entry stamp; hit-time re-check | `CsInsertStage`, `CsLookupStage` (`ndn-engine` `stages/cs.rs`); `revocation_purge::recheck` |
| Stamp storage | `ndn_store::{CsEntry::revocation_epoch, ContentStore::restamp, EARLIER_PROCESS_EPOCH}`; store generation in `ndn-store` `cs_keycodec.rs` |
| CS eviction on adoption | `ndn-engine` `revocation_purge.rs` (`install`) |
| Checks before signing | `ndn_cert::{revocations_to_add, check_cut}` |
| CA following the context | `ndn-fwd` `revoke.rs` (`ca_follow`, `ca_follow_held`), called from `TrustAdmin::keep` (`context_adopt.rs`) and the CA's start (`ca.rs`); `ndn_cert::CaState::{issued_under, revoke_issued_under}` |
| Stored context | `ndn_cert::read_stored_context` |
| Hand-over | `security/context-update` (`ndn-ipc` `MgmtClient::security_context_update`; daemon `context_refresh::apply_update`) |
| CLI | `ndn-fwd` `revoke.rs` (`run`); hand-over `recovery_kit.rs` (`hand_over`) |

## See also

- [Trust-context updates](./context-updates.md) — how version `N+1` reaches
  every node.
- [Enrolling with an invite](./enrollment-by-invite.md)
- [Trust-context publication (RDR)](./trust-context-publication.md)
