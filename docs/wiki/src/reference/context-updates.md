# Trust-context updates (`ndn-fwd context refresh`)

A namespace's trust context changes after nodes adopted it: a
[revocation](./revocation.md) makes version `N+1`, so does adding or revoking
a [recovery kit](./recovery.md), a [schema update](#schema-updates-ndn-fwd-schema-update)
(`ndn-fwd schema update`), and a recovery (`ndn-fwd recover`, signed by a
recovery key); later flows (CA delegation, root rotation) will too.
Every node that holds the context must
get the new version, and must never take a version the namespace root did not
make. A node does this by **refreshing**: it asks for the newest version by
name and adopts it only under the **continuity rule**.

## The continuity rule

A fetched version replaces the held version `N` only if all of these hold
(`ndn_cert::open_context_update`, then `Keyring::adopt_update`):

1. it is a self-consistent signed context
   (`SignedTrustContext::open_signed`): named `/<ns>/32=trust-context/v=<M>`,
   signed with a public-key signature (Ed25519, ECDSA, RSA) that verifies
   under one of the anchors it lists;
2. it is a context for the same namespace;
3. it is **strictly newer**: `M > N`;
4. the key that signed it is an anchor of the **held** version `N` (same
   public key).

Rule 4 is the one that matters. Rule 1 alone only proves that the context is
what *some* key signed: anyone can run `ndn-fwd init --namespace /home/bob`
and sign a `/home/bob` context listing their own root, even naming its key
`/home/bob/KEY/root`. The update must be authorized by the version it
replaces. A new version may list other anchors (a root rotation is signed by
the old root); those are trusted only after it is adopted.

Any anchor of the held version may sign — that is what lets a
[recovery kit](./recovery.md) replace a lost root device: its recovery key is
an anchor (marked `recovery-anchor`), so a version it signs is adopted by
every holder, and that version lists the new root. A version the new root
signs is not signed by an anchor of the versions before the recovery, so a
node that missed the recovery-signed version cannot take it directly; it
follows the versions in between one by one (below), each under the
continuity rule from the one before.

Rule 3 is strict: an equal version never replaces the held one either, so a
different context claiming the same version cannot slip in.
`Keyring::adopt_update` applies it atomically against a concurrent adoption;
a refresh, which checks its update without holding any lock (fetching may
take many round trips), adopts with `Keyring::adopt_update_from`: only if
the version it checked against is still the one held, so a version another
command adopted meanwhile is never skipped over. (`Keyring::adopt`, used
for first adoption, keeps its `≥` rule.)

A refused or failed refresh changes nothing: the held version stays in force.
A missed refresh only delays an update; it never weakens what is accepted.

## Catching up across versions

When the newest version is not signed by an anchor of the held version `N`
and there are versions between them, a refresh fetches `N+1`, `N+2`, … by
exact name, oldest first (`ndn_cert::follow_versions`): each must be signed
by an anchor of the version before it (the first by an anchor of `N`), and
the newest is adopted only if the walk reaches it. So a node offline across
a recovery holding `N` follows `N+1` (the recovery key, an anchor of `N`),
then `N+2` (the new root, an anchor of `N+1`), then whatever the new root
signed since. What carries it is the chain of signed versions, which every
holder keeps, not the timing of refreshes.

- **Every node keeps and serves every version it held.** The store keeps
  each version beside the newest
  (`<pib>/contexts/<hex(ns)>.versions/<N>.tc`, next to
  `<pib>/contexts/<hex(ns)>.tc`), the publisher serves each by its exact
  name, and a node that walked stores and publishes the versions it walked
  through, so the nodes behind it can follow the same way. A store written
  before versions were kept holds the newest only; versions are kept from
  then on.
- **A version nobody serves** (one that upstream never held, or never
  existed) is passed over, as long as a later one follows from the version
  reached. If none does, the refresh says which versions were missing.
- **A version that arrives and is refused** — forged, foreign, or not signed
  by an anchor of the version before it — ends the walk.
- **Bounded**: at most `MAX_CATCH_UP_VERSIONS` (128) versions are followed;
  a node further behind is refused before anything is fetched and adopts the
  namespace again from a current anchor link (one fetch). A version is one
  operator action, so 128 covers years of a namespace's changes. The walk
  also starts no fetch after `MAX_CATCH_UP_TIME` (40 s): an upstream that
  answers the newest version's name but lets every version time out ends the
  walk as unreachable, with nothing adopted, and the next refresh starts
  again from the held version.
- **All or nothing**: a walk that stops adopts nothing, so the held version
  stays in force, as for any refused refresh.

## Pull: how a node refreshes

`ndn_cert::refresh_context(keyring, forwarder, exchange, ns)`:

1. Metadata Interest `/<ns>/32=trust-context/32=metadata` (CanBePrefix,
   MustBeFresh) — the [RDR publication](./trust-context-publication.md) every
   holder serves — returns the newest version's name. Equal to the held
   version: `Current`; lower: `UpstreamOlder` (the node that answered has not
   refreshed yet). In both cases nothing else is fetched.
2. Before fetching, it tells the node's own forwarder to expect an update
   (`Validator::expect_context_update`): a Data named
   `/<ns>/32=trust-context/v=<M>` is admitted if it is signed by one of the held
   version's anchors, and dropped otherwise, with the reason recorded. This
   lets the context through a forwarder that does not itself hold the context
   (an app's embedded engine), and turns a dropped forgery into a refusal
   that says why instead of a timeout.
3. Fetches `/<ns>/32=trust-context/v=<M>`.
4. Applies the continuity rule. When the newest is not signed by an anchor
   of the held version (or the forwarder dropped it) and there are versions
   in between, follows them by exact name ([catching up](#catching-up-across-versions)),
   the forwarder told to expect each in turn as an update of the one before.
5. Adopts the newest, if the version it was checked against is still held
   (otherwise `RefreshError::ChangedMeanwhile`: nothing is adopted, and the
   next refresh starts from the version held then). The result carries the
   previous version, the new context, its signed Data byte for byte (to
   store and republish — the signature must stay intact), the anchor that
   signed it, the revocation entries it adds, and the versions walked
   through (`walked`, each with its signed Data, to store and republish too).

The daemon runs refreshes without its `context_change` lock (taken by
`security/context-update`), so a slow catch-up never holds it up.

`ndn_identity::refresh_context_via_engine(engine, keyring, ns)` runs it over a
short-lived consumer face of an engine, with the engine's validator as the
forwarder; the daemon and ndn-mobile both call it.

### Hop by hop through relays

After adopting, the daemon stores the new version in `<pib_path>/contexts/`
beside the versions it held before (and those it walked through), and
publishes it: the metadata names it, and every version stays served by its
exact name. The next node downstream then gets it from this node at its own
refresh. An update therefore travels hop by hop: root device → relay →
devices behind the relay, each hop checking the continuity rule against the
version it holds. No node needs a route to the root device.

While it fetches, the daemon withdraws the route from
`/<ns>/32=trust-context` to its own publisher
(`PublishedContexts::bypass`), so the Interests go upstream instead of being
answered with the version it holds.

The root device holds the root key; it makes new versions and does not fetch
its own namespace (state `source`).

### Stale metadata

The metadata carries a 1 s FreshnessPeriod, so a Content Store may answer a
MustBeFresh discovery Interest with the previous pointer for up to 1 s after
a new version. Two evictions keep a node's own store out of that:

- **Publishing purges.** When the newest version a node publishes changes
  (handed over, refreshed, pushed over sync), `PublishedContexts::publish`
  evicts `<ns>/32=trust-context/32=metadata/...` from the node's Content
  Store before it returns: the new set is swapped in first, then the store
  is purged, so no Interest after the publish is answered with the old
  pointer. The versioned contexts are immutable and stay cached.
- **Asking purges.** Before a refresh (and an adoption by fetch) the node
  drops the metadata it cached itself
  (`context_publisher::forget_cached_metadata`): the question is "what is
  newest now", not what it fetched a moment ago.

A relay in between may still answer from its own store for up to 1 s. When
the node's sync group announced a version newer than the answer (and the
node does not hold it), the refresh reports `behind` instead of `current` or
`upstream-older`, naming the member that announced it; nothing changes, and
refreshing again shortly after gets the new version.

### Versions made on this device: `security/context-update`

`ndn-fwd revoke`, `ndn-fwd schema update` and `ndn-fwd recovery-kit
create|revoke` (root device) and `ndn-fwd recover` (replacement device) sign
the new version in the CLI — the
root store, the kit, are opened there, and their passphrase or PIN never
leaves the command — and hand it to the running daemon with
`security/context-update` (the signed Data in `ControlParameters.ContextData`,
TLV `0xB4`, in ApplicationParameters). The daemon applies the same continuity
rule as a refresh, then stores and publishes it; a refusal leaves the held
version in force. It is a trust-admin verb like `context-refresh`.

However a version is adopted — handed over, refreshed, adopted by link — a
node running the namespace CA makes the CA follow it as it keeps it
(`TrustAdmin::keep`): the CA stops serving every certificate it issued that
the version revokes ([revocation](./revocation.md#the-ca-follows-the-trust-context)).

Its answer says what became of the version, so the CLI undoes its own work
(a file kit, a recovered root) only on a refusal: `200` once the version is
adopted (also when storing it then fails — the detail says so), and `200`
for a version the daemon already took and stores byte for byte. A CLI that
gets no answer in time hands the same version over again, and that request,
queued behind the first, answers what became of it. The CLI hands over only
to the daemon that uses the PIB it read the held version from (its
`security/identity-status` `pib_path`), so a version is never adopted by a
daemon whose PIB stays behind.

## Schema updates (`ndn-fwd schema update`)

A revocation or a recovery kit carries the schema over verbatim: revoking a
key must not change what the other devices may sign. So a namespace made by
an earlier `ndn-fwd init` keeps the generated schema of that release (one
made before enrollment by approval lacks the `#deny` and `#pending` rules)
until its operator updates it on the root device:

```text
$ ndn-fwd schema update -c /etc/ndn-fwd/ndn-fwd.toml
# ndn-fwd schema update
namespace      = /home/bob
trust_context  = v2 -> v3 (signed by the root /home/bob/KEY/…)
rules_added    = 2
  + #deny: /"home"/"bob"/_/_device/"KEY"/_/"ndncert-deny"/_ <= #admin
  + #pending: /"home"/"bob"/"CA"/"PENDING"/_ <= #admin
narrowed       = none (every rule of v2 is kept)
enrollment     = admin, node by an admin's approval; member, guest by invite
handed_over    = …
```

Version `N+1` (`ndn_cert::bump_context_schema`) carries the current
generated schema of the namespace (`ndn_cert::namespace_schema`), is
schema-authoritative, and carries the enrollment hint of the policy the
namespace's CA enforces: the held version's own hint when it advertises a
policy; for a context made before the hint named its approval roles, the
policy the CA enforces for it — `[ca] approval_roles` /
`approval_requires_invite` of `-c` (give the daemon's config), else the
default. A held hint that `[ca]` contradicts is refused, as the CA's start
refuses it. Anchors, CA endpoints, revocations and key roles are carried
over verbatim. It is checked, signed, handed over and stored like a
revocation (`--passphrase-file` / `--pin-file` unlock the root); with the
schema and hint current, nothing is signed.

**Never a silent narrowing.** The command compares every grant of the held
schema — each LVS rule's data pattern with each of its signers, by pattern
(rule names and node ids aside), and each native rule — with the new one
(`ndn_cert::schema_change`). When one is missing, it refuses before the
root is unlocked, listing the rules devices would lose; `--accept-narrowing`
signs anyway and prints them as `rules_removed`. Regenerating the schema of
a namespace made by an earlier `ndn-fwd init` only adds rules. It narrows
when the held schema is not the generated one: a custom schema signed in
with `ndn-trust-context`, or the key-name schema of the earliest releases
(its rules read differently even where they grant the same).

The namespace CA validates admins' decisions and pending listings under the
version its daemon holds, so it applies the new rules as soon as the
daemon adopts the update — no restart. Its enrollment policy does not
change: the hint states the policy it enforces. Other nodes judge by the new
version once they hold it (refresh, sync, or `ndn-fwd context refresh`).

## Push over the namespace's sync group

With `[security] context_sync = true` the daemon also joins each held
namespace's SVS group, `/<ns>/32=trust-context/32=sync`
(`ndn_identity::context_sync::group_prefix`), so a new version reaches it as
soon as the root device makes it instead of at the next refresh. The refresh
keeps running beside it.

- **Who is in the group.** Every namespace held at start, and every one
  adopted later (link, invite), is joined. Each node is the member
  `<group>/<member>`, where `<member>` is a hash of the machine's id and the
  PIB's path, so it stays the same across restarts.
- **Who publishes.** Every version the daemon keeps — a revocation, a version
  handed over with `security/context-update` (`ndn-fwd revoke`,
  `ndn-fwd recovery-kit`, `ndn-fwd recover`), a refresh — is handed to the
  group. When the node's root store holds an anchor key of that version (the
  root device; after a recovery, the replacement), it serves the version's
  signed Data, byte for byte, as the Content of `<group>/<member>/seg=<N>`
  (`context_sync::group_data`, DigestSha256), and advances its sequence
  number to `N`. Its stored versions are served the same way from start.
  Other members only subscribe.
- **What a member adopts.** It fetches the newest sequence a member
  announces and adopts it only under the [continuity
  rule](#the-continuity-rule) (`open_context_update` +
  `Keyring::adopt_update_from`). When the newest is not signed by an anchor
  of the held version, it follows the earlier sequence numbers (from the
  first newer than the held version) one by one, the [same
  walk](#catching-up-across-versions) as a refresh. A member that is not the
  namespace root therefore cannot produce an update anyone adopts, whatever
  it announces; a namespace not held yet is never adopted from the group.
- **What a member keeps.** An adopted version and the versions walked
  through are stored and published by the code a refresh keeps with
  (`ndn-fwd` `context_refresh::keep_update`), so the nodes behind it can
  fetch them by name.
- **A fetch that failed is tried again.** SVS reports each sequence number
  once. While a member's announced sequence number (the version it put into
  the group) is newer than the held version, a failed fetch — or a walk
  stopped by a version it could not fetch — is tried again after 1 s,
  doubling to once a minute (`context_sync::Retry`), each attempt logged at
  WARN with why it failed (`context-sync could not obtain an announced
  trust-context version; trying again`). It stops once the held version
  reaches that sequence number (from this retry, another member's
  announcement, or a refresh) or the version is refused. At most one retry
  is pending per member, and fetches run one at a time.
- **Refusals** are logged at WARN (`context-sync refused a trust-context
  update; the held version stays`) with the reason from the
  [table below](#refusals); a version not newer than the one held is logged
  at DEBUG.

### Routes

SVS floods each Sync Interest to every member (multicast strategy on the
group prefix), so the group needs a route both ways:

- **Up:** the group is routed over the non-local faces the namespace itself
  is routed over (the route a device has toward the root device or a relay),
  taken when the group is joined and again for each Sync Interest the node
  sends or receives.
- **Down:** each face a Sync Interest of the group arrives on is added to the
  group's route. The root device needs no route configured toward the
  devices: it learns their faces from their Sync Interests, sent when a
  device joins the group, every ~15 s, and when it announces something.

Each of those faces routes both the Sync Interests (`<group>/v=2`, the SVS
dialect's version) and the group Data (`<group>`). The node's own SVS face
routes the Sync Interests only: a neighbour's fetch of
`<group>/<member>/seg=N` passing through goes on toward the faces that lead
to the publisher, or is Nacked when there are none, and is never held by
the node's own SVS, which would leave the node's own fetch of the same
version aggregated onto it until both time out.

A new version is announced at once. A member that just (re)started
announces itself when it joins the group, once the face its route toward
the namespace names is up, so the root device reaches it at once; a lost
announcement is repeated within ~15 s. A relay between the root
device and a device carries the group only if it runs `context_sync` too;
otherwise the devices behind it get updates by refresh.

### Why pull stays on

- It reuses the RDR publication every holder already serves: no sync group, no
  per-namespace setup, no extra state.
- It crosses relays that only forward and hold the context, because each
  holder republishes what it adopted.
- Its failure mode is delay, bounded by the refresh period; correctness never
  depends on it.

Push only lowers the latency; both apply the same check, so neither can adopt
what the other would refuse.

## Usage

```toml
[security]
context_refresh_secs = 300   # default; 0 = only on `ndn-fwd context refresh`
context_sync = true          # default false: also join each namespace's sync group
```

The daemon checks every held context every `context_refresh_secs`; the first
check runs as soon as the route of each namespace it fetches has its face up
(at most `min(context_refresh_secs, 30)` seconds after start), so a node that
was off catches up at once. To check at once:

```sh
ndn-fwd context refresh [<namespace>] [-c <config>]
# ndn-fwd context refresh (by the running daemon at <management socket>)
/home/bob v1 -> v2: updated
  revoked /home/bob/member/phone/KEY/eba4f4f2af5d697b
  adopted v2 (signed by /home/bob/KEY/root, an anchor of v1); stored <pib>/contexts/2f686f6d652f626f62.tc and published
```

A node that was offline across a recovery reports the versions it followed:

```text
/home/bob v2 -> v4: updated
  adopted v4 (signed by /home/bob/KEY/<id>, an anchor of v3) through v3 (each signed by an anchor of the version before it); stored <pib>/contexts/2f686f6d652f626f62.tc and published
```

The command sends `security/context-refresh` (namespace, if given, in
`ControlParameters.Name`). It is a trust-admin verb: the same peer-credential
gate as `adopt`, `enroll` and `revoke` (`[security] trust_admin_groups`), and
refused over `/localhop`. It exits 1 if any namespace failed.

| State | Meaning |
|---|---|
| `updated` | a newer version was adopted, stored and published |
| `current` | the namespace serves the version held |
| `upstream-older` | the node that answered serves an older version; nothing changed |
| `behind` | the answer names a version older than one the node's sync group announced and the node does not hold: a cache answered with the previous metadata, or the upstream has not refreshed yet; nothing changed — refresh again |
| `source` | this node holds the root key; new versions are made here |
| `unreachable` | nothing answered for the namespace's newest version (no route, no reply); the held version stays |
| `failed` | a reply that could not be used, or a refused update (reason given); the held version stays |

Apps with an embedded engine (ndn-mobile) call
`NdnEngine::refresh_contexts(namespace)`, e.g. when the app comes to the
foreground. The engine keeps contexts in memory only: for each `updated`
entry the app persists `context` (the signed context and the root
fingerprint) in place of the stored one and passes it to `adopt_context` at
the next launch.

## Refusals

Each is reported as `refused a trust-context update for <ns>: <reason>; the
held version vN stays in force` and logged at WARN:

| Reason | Cause |
|---|---|
| `this node's forwarder dropped it: …` | the update is not signed by an anchor of the held version; dropped by the forwarder's expectation before it reached the refresh |
| `it is signed by <key>, which is not an anchor of the held version vN` | the same, caught by the continuity check (no validating forwarder in the path) |
| `it is version M, not newer than the held version N` | equal or older (also when a concurrent adoption got there first) |
| `it is a context for <other>, not <ns>` | a context of another namespace |
| an `open_signed` error | not named as a context, no content, no KeyLocator, signer not among its own anchors, not a public-key signature, or a bad signature |
| `vM does not follow from the held version vN directly, and following the versions in between failed: that is G versions, more than the 128 a refresh follows one by one; …` | the node is too far behind to walk; adopt the namespace again from a current anchor link |
| `… failed: vK was refused: <reason>. Whatever served it does not serve this namespace's versions; …` | a forged or foreign version at `vK` (the reason is one of the rows above) |
| `… failed: vA..=vB could not be fetched (…), and vK does not follow without them (…); …` | no node reached kept the versions that install `vK`'s signer; retry once one is reachable, or adopt again from a current link |
| `… failed: vK could not be fetched (…); retry once it is reachable` | the newest version went away during the walk |

Other failures: `could not check <ns> for a newer trust context (…)` (no route,
timeout, malformed metadata) and `no trust context is held for <ns>`.

## Code

| Part | Where |
|---|---|
| Continuity check, refresh | `ndn_cert::{open_context_update, refresh_context, UpdateRefusal, RefreshError}` (`ndn-cert/src/context_update.rs`) |
| Schema update | `ndn_cert::{bump_context_schema, schema_change, SchemaChange, SchemaBump, BumpError::Narrowing}`; CLI `ndn-fwd` `schema_cmd.rs` (`update`; test `a_schema_update_handed_over_lets_the_running_ca_take_remote_denials`); `ndn-cert/tests/approval.rs` `a_schema_update_gives_an_older_namespace_the_decision_rules` |
| Catching up | `ndn_cert::{follow_versions, VersionSource, ContextStep, CatchUpStop, MAX_CATCH_UP_VERSIONS, MAX_CATCH_UP_TIME}`, `ContextUpdate::walked` |
| Every version kept | `ndn_cert::{persist_context, read_stored_versions, context_version_path}` (`ndn-cert/src/context_store.rs`); served by `ndn-fwd` `context_publisher.rs` |
| RDR fetch steps | `ndn_cert::{fetch_context_pointer, fetch_versioned_context}` |
| Strictly-newer adoption | `ndn_security::Keyring::{adopt_update, adopt_update_from}` |
| Forwarder expectation | `ndn_security::Validator::expect_context_update` (`validator/expected.rs`) |
| Engine binding | `ndn_identity::refresh_context_via_engine` |
| Push over SVS | `ndn_identity::context_sync::{run, Retry, process_update, group_prefix, group_data}`; daemon groups, routes, root publishing: `ndn-fwd` `context_sync.rs` (tests `a_revocation_pushed_over_sync_is_adopted_and_a_forged_version_refused`, `a_neighbours_fetch_of_group_data_does_not_hold_up_this_nodes_own`) |
| Management verb | `ndn-mgmt` `security/context-refresh`, `security/context-update`, `ContextRefreshInfo`, `RefreshState`; `ndn-ipc` `MgmtClient::security_context_refresh`, `security_context_update` |
| Daemon, timer | `ndn-fwd` `context_refresh.rs` (`keep_update`, shared by refresh and sync; `apply_update` for `context-update`); CLI `onboard.rs` (`run_context`) |
| Mobile | `ndn-boltffi` `NdnEngine::refresh_contexts`, `NdnContextRefresh` |

## See also

- [Revoking a device](./revocation.md)
- [Trust-context publication (RDR)](./trust-context-publication.md)
- [Recovery kits and `ndn-fwd recover`](./recovery.md)
- [Adopting a trust context](./context-adoption.md)
