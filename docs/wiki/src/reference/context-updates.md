# Trust-context updates (`ndn-fwd context refresh`)

A namespace's trust context changes after nodes adopted it: a
[revocation](./revocation.md) makes version `N+1`, and later flows (CA
delegation, root rotation) will too. Every node that holds the context must
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

Rule 3 is strict: an equal version never replaces the held one either, so a
different context claiming the same version cannot slip in.
`Keyring::adopt_update` applies it atomically against a concurrent adoption.
(`Keyring::adopt`, used for first adoption, keeps its `≥` rule.)

A refused or failed refresh changes nothing: the held version stays in force.
A missed refresh only delays an update; it never weakens what is accepted.

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
4. Applies the continuity rule and adopts. The result carries the previous
   version, the new context, its signed Data byte for byte (to store and
   republish — the root's signature must stay intact), the anchor that signed
   it, and the revocation entries it adds.

`ndn_identity::refresh_context_via_engine(engine, keyring, ns)` runs it over a
short-lived consumer face of an engine, with the engine's validator as the
forwarder; the daemon and ndn-mobile both call it.

### Hop by hop through relays

After adopting, the daemon stores the new version in `<pib_path>/contexts/`
and publishes it in place of the old one. The next node downstream then gets
it from this node at its own refresh. An update therefore travels hop by hop:
root device → relay → devices behind the relay, each hop checking the
continuity rule against the version it holds. No node needs a route to the
root device.

While it fetches, the daemon withdraws the route from
`/<ns>/32=trust-context` to its own publisher
(`PublishedContexts::bypass`), so the Interests go upstream instead of being
answered with the version it holds.

The root device holds the root key; it makes new versions and does not fetch
its own namespace (state `source`).

## Push: `context_sync` over SVS

`ndn_identity::context_sync` is the alternative for fleets that already run an
SVS group per context. A publisher puts the context's signed Data (the same
bytes as the RDR publication) into the group at `<group>/<publisher>/seg=<N>`;
each subscriber fetches the newest sequence and adopts it under the same
continuity rule (`open_context_update` + `Keyring::adopt_update`). A group
member that is not the namespace root therefore cannot produce an update
anyone adopts, whether or not the group Data itself is validated. A namespace
the subscriber does not hold yet is never adopted from the group: first
adoption goes through a link or invite.

### Why pull is the default

- It reuses the RDR publication every holder already serves: no sync group, no
  per-namespace setup, no extra state.
- It crosses relays that only forward and hold the context, because each
  holder republishes what it adopted.
- Its failure mode is delay, bounded by the refresh period; correctness never
  depends on it.

Push gives lower latency when the group exists. The `ndn-fwd` daemon does not
run it.

## Usage

```toml
[security]
context_refresh_secs = 300   # default; 0 = only on `ndn-fwd context refresh`
```

The daemon checks every held context every `context_refresh_secs`; the first
check runs `min(context_refresh_secs, 30)` seconds after start, so a node that
was off catches up quickly. To check at once:

```sh
ndn-fwd context refresh [<namespace>] [-c <config>]
# ndn-fwd context refresh (by the running daemon at <management socket>)
/home/bob v1 -> v2: updated
  revoked /home/bob/member/phone/KEY/eba4f4f2af5d697b
  adopted v2 (signed by /home/bob/KEY/root, an anchor of v1); stored <pib>/contexts/2f686f6d652f626f62.tc and published
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
| `source` | this node holds the root key; new versions are made here |
| `failed` | no answer, or a refused update (reason given); the held version stays |

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

Other failures: `could not check <ns> for a newer trust context (…)` (no route,
timeout, malformed metadata) and `no trust context is held for <ns>`.

## Code

| Part | Where |
|---|---|
| Continuity check, refresh | `ndn_cert::{open_context_update, refresh_context, UpdateRefusal, RefreshError}` (`ndn-cert/src/context_update.rs`) |
| RDR fetch steps | `ndn_cert::{fetch_context_pointer, fetch_versioned_context}` |
| Strictly-newer adoption | `ndn_security::Keyring::adopt_update` |
| Forwarder expectation | `ndn_security::Validator::expect_context_update` (`validator/expected.rs`) |
| Engine binding | `ndn_identity::refresh_context_via_engine` |
| Push over SVS | `ndn_identity::context_sync` |
| Management verb | `ndn-mgmt` `security/context-refresh`, `ContextRefreshInfo`, `RefreshState`; `ndn-ipc` `MgmtClient::security_context_refresh` |
| Daemon, timer | `ndn-fwd` `context_refresh.rs`; CLI `onboard.rs` (`run_context`) |
| Mobile | `ndn-boltffi` `NdnEngine::refresh_contexts`, `NdnContextRefresh` |

## See also

- [Revoking a device](./revocation.md)
- [Trust-context publication (RDR)](./trust-context-publication.md)
- [Adopting a trust context](./context-adoption.md)
