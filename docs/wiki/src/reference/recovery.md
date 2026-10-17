# Recovery kits and `ndn-fwd recover`

The namespace root lives on one device, the **root device** (see
[root custody](../concepts/identity-and-keys.md#root-custody-where-a-namespace-root-key-lives)).
If that device is lost, broken or stolen, a **recovery kit** lets another
device become the root device without any node adopting the namespace again.

Design: `docs/specs/personal-namespace.md`, flows F7 (create a kit) and F8
(restore). Code: `ndn_cert::recovery` (library), `ndn-fwd`
`recovery_kit.rs` and `recover.rs` (CLI).

## A kit is a separate key, never a copy of the root

A kit holds a **recovery key** of its own. On the root device, the root
signs version `N+1` of the trust context with the recovery key's self-signed
certificate added as an extra anchor, marked with the `recovery-anchor` role
(context TLV `KeyRole`, `0x041E`, non-critical; every later version carries it
over). Why not a copy of the root:

- a hardware root (`yubikey-piv`) cannot be exported at all;
- the root written down as words would simply be the root, exposed;
- a separate key can be revoked alone, and several kits can coexist.

The continuity rule (an update must be signed by an anchor of the held
version, [context updates](./context-updates.md)) already lets *any* anchor
sign the next version. So the recovery key can sign the version that installs
a new root, and every node adopts it with no new trust machinery. A recovery
anchor is **root-equivalent by design**: whoever holds the kit can take over
the namespace. Keep it offline.

A recovery key is named `<ns>/KEY/r<hex>`, the hex being the first 8 bytes of
SHA-256 over its public key, so a word list alone rebuilds both the key and
its name.

## Formats

The owner chooses; all are supported equally.

| `--format` | Key | Where it lives | What opens it |
|---|---|---|---|
| `words` | Ed25519 from a 32-byte seed | 24 BIP39 English words, shown once; nothing is stored | the words (the last word's checksum refuses a mistyped list) |
| `file` | Ed25519 | `--out <path>` (`0600`): an `ndn-trust://bag` envelope with the key in a SafeBag (PBES2: PBKDF2-SHA256 600 000 rounds, AES-256-CBC), plus the namespace and its expected fingerprint | the kit passphrase |
| `yubikey` | P-256, generated on the token, never exportable | a second YubiKey's PIV slot (default `9d`; PIN policy `always`, `--kit-touch-policy` default `always`) | the PIV PIN (and a touch); build with `--features yubikey-piv` |

Kit secrets are read from `NDN_KIT_WORDS` / `NDN_KIT_PASSPHRASE` /
`NDN_KIT_PIN`, else `--words-file` / `--kit-passphrase-file` /
`--kit-pin-file`, else the terminal without echo — never the command line.

## Creating, listing, checking, revoking

On the root device (the root store unlocks for the one signature, as for
[revoke](./revocation.md#unlocking-the-root)):

```sh
ndn-fwd recovery-kit create --format words [--pib <dir> | -c <config>]
ndn-fwd recovery-kit create --format file --out /media/usb/bob.kit
ndn-fwd recovery-kit create --format yubikey [--kit-yubikey-serial <n>] [--kit-yubikey-slot 9d] [--replace-slot]
```

A YubiKey kit's token is chosen with `--kit-yubikey-serial` /
`--kit-yubikey-slot` (`--yubikey-*` always mean the root's token). Generating
a key replaces whatever the slot held, for good, so the kit is refused on the
root's own token (one lost token would lose both) and in a slot that already
holds a key — or whose firmware cannot tell (older than 5.2.3) — unless
`--replace-slot` says that key is not needed (`ndn_cert::SlotGuard`).

The CLI makes the key, the root signs `N+1`, and the CLI hands it to the
running daemon that uses the same PIB (`security/context-update`), which
adopts it under the continuity rule, stores it in `<pib>/contexts/` and
publishes it. A daemon of another PIB (its `security/identity-status`
`pib_path`) is refused before anything is sent: it may hold the namespace
too, and would adopt a version this PIB never stores — the next version made
here would then be a second, different one with the same number. With no
daemon listening on the socket, the version is stored for the daemon's next
start; any other socket error is a refusal that names it.

The outcome is the daemon's answer, never a timeout. A request it does not
answer in time (another change of the namespace may run there) is made again
with the same version; the daemon answers `200` for a version it already took
and stores byte for byte, so the answer always says what became of it. Only
a refusal undoes anything: a file kit is written before the root signs and
removed if the daemon refuses the version, so there is never an anchor
without its kit; when no answer says what happened, the kit is kept and
shown (words included) and `recovery-kit list` tells whether it is an
anchor. Other nodes adopt `N+1` at their next refresh.

`ndn-fwd init` prints a recommendation to create a kit right away, and
`ndn-fwd root-key status` shows `recovery_kits = <n>` (recommending one while
there is none).

```sh
ndn-fwd recovery-kit list [--namespace <ns>]     # any node holding the context
ndn-fwd recovery-kit check words|yubikey|<file> [--namespace <ns>]
ndn-fwd recovery-kit revoke <recovery-key-name>  # root device
```

`list` shows each anchor of the held context as `root` or `recovery-kit`
with its fingerprint, and the root device's keys. `check` opens the kit
(words, passphrase, or token and PIN) and confirms its key is a recovery
anchor of the held context; it signs nothing. `revoke` has the root sign a
version without that anchor that also revokes its key: from then on a version
the kit signs is refused by every node holding it.

## Recovering: `ndn-fwd recover`

On a **replacement device** whose own daemon runs and is linked to the
namespace (directly, or through a relay):

```sh
ndn-fwd recover --kit words|yubikey|<kit-file> --old-root destroyed|compromised \
    [--keep-kit <recovery-key-name>]… [--namespace <ns>] [--device <name>] \
    [--kit-yubikey-serial <n>] [--kit-yubikey-slot <slot>] \
    [--root-store <store>] [--yubikey-serial <n>] [--yubikey-slot <slot>] [--replace-slot] \
    [-c <config>] [--from-held]
```

The daemon must use the PIB recovered into (`-c` with its config, or
`--pib`); `recover` checks that first.

1. **The newest version, by name.** The daemon refreshes the context it holds
   (as `ndn-fwd context refresh`, continuity rule included). A device that
   holds none adopts it with a file kit's expected fingerprint; with a word
   or YubiKey kit it is told to adopt first (`ndn-fwd adopt <link>`). A
   context fetched with nothing to check it against could be a forgery that
   lists the kit's (public) anchor — the recovery key would then sign it and
   every node would adopt it. A failed refresh stops the recovery: recovering
   from an older version than the namespace serves would fork it.
   When **nothing answers** (no other node holding the namespace is
   reachable: the lost root device was the only one, or every member is
   offline), the refresh reports `unreachable` and `recover` stops with the
   same reason; `--from-held` then recovers from the version this device
   holds. The operator vouches that no newer version exists, and the output
   says `newest_check = not confirmed …`. A version that answers and is
   refused (forged, signed by a revoked key, an incomplete catch-up) still
   stops the recovery with `--from-held`.
2. **The kit.** It must open, and its key must be a recovery anchor of that
   version, else nothing is signed or written.
3. **The new root device.** A new root in the root store chosen with
   `--root-store` (as `init`; a `yubikey-piv` root never on the kit's token,
   which signs `N+1` after the root exists, and never over an occupied slot
   without `--replace-slot`), a new CA key `<ns>/CA/KEY/<id>` certified by
   it, and a new admin identity `<ns>/admin/<device>` certified by the new
   CA — all with fresh key ids, so nothing collides with, or is revoked with,
   the old keys. The recovery key signs `N+1`:
   - anchors: the new root, the recovery anchors kept, and — when
     `destroyed` — the old root;
   - recovery anchors kept: every one of `N` when `destroyed`; when
     `compromised`, only the kit used and those named with `--keep-kit`
     (kits the operator made and still holds) — the rest are removed and
     revoked, since whoever held the old root could have added one of their
     own, and a recovery anchor is root-equivalent. A `--keep-kit` that is
     no recovery anchor of `N` is refused (listing them) before anything is
     written, and so is `--keep-kit` with `destroyed`;
   - the new CA and admin keys replace the old ones' `root-device` role;
   - schema, CA endpoint (`<ns>/CA`, unchanged) and earlier revocations are
     carried over.

   `recover` prints every anchor `N+1` keeps and every key it revokes, so a
   key nobody expects stands out. Then the new root signs `N+2`, the same
   content (`ndn_cert::reissue_version`), so the newest version is signed by
   the root (see [the expected fingerprint](#the-expected-fingerprint-after-a-recovery)).
4. **Hand-over.** `N+1`, then `N+2`, go to the daemon, which adopts each by
   the continuity rule, stores and publishes it (as for `recovery-kit
   create`: the outcome is the daemon's answer). If it refuses `N+1`,
   everything step 3 wrote is removed again. If no answer says what became
   of `N+1`, nothing is removed — the daemon may still adopt it, and it
   names the new root — and `recover` says how to tell and what to do. If it
   took `N+1` but not `N+2`, the recovery stands (the new root is an anchor
   of `N+1`) and `recover` says so: the newest version stays signed by the
   recovery key until the root signs one (`ndn-fwd recovery-kit create`),
   and no anchor link is printed until then.

`recover` prints the `[security]` and `[ca]` lines to restart the daemon with
(copy the old root device's `[[ca.challenge]]` set): the replacement device
then signs as its admin identity and runs the namespace CA. Once `N+2` is
taken it also prints the anchor link, and the `ndn-fwd-tokens` line with the
new root's fingerprint.

### `--old-root destroyed` or `compromised`

There is no default; `recover` refuses without it and says why both exist:

| | `destroyed` | `compromised` |
|---|---|---|
| Use when | the old root device is gone for good | someone else may hold it |
| Old root | stays an anchor | removed and revoked |
| Old CA key, old admin key | valid | revoked (the `root-device` keys of `N`) |
| Recovery kits | all stay | the kit used and `--keep-kit` ones stay; the rest are removed and revoked |
| Devices enrolled under the old CA | keep working; renew with the new CA | stop validating once a node holds `N+1`; enroll again |

Keeping a compromised root valid would leave the namespace in its holder's
hands; revoking a destroyed one would cut off every device for nothing.

**Data after `destroyed`.** The old CA's certificate was served by the lost
root device; devices keep their issuer chain (`<pib>/issuers/`) and serve it.
A validating forwarder that misses a certificate asks the routes for it and,
when they have not answered within 50 ms, also the face the Data arrived on
(NDNLPv2 `NextHopFaceId`, as ndn-cxx's `CertificateFetcherDirectFetch`), so a
device's Data validates at any node with a cold cache, before it renews.
Where a certificate came from never makes it trusted: every hop of the chain
is verified up to an anchor (the old root, kept by `destroyed`).

**Renewal after `destroyed`.** The new CA renews a current, unrevoked
certificate of the namespace issued by an earlier CA of the same identity
`<ns>/CA` when it validates under the CA's held trust context (the device
sends its certificate and its issuer chain with the renewal), and serves that
earlier CA's certificate from then on, so validators that fetch it by name
still find it. See [certificate renewal](./renewal.md).

**Re-enrolling after `compromised`.** On the new root device mint invites
(`ndn-fwd-tokens new --ca <ns> --namespace <ns> --anchor-fp <new root
fingerprint> --role member`); on each device, once it holds `N+1`
(`ndn-fwd context refresh`), `ndn-fwd enroll <invite> --force`.

## How other nodes follow

Every node holding `N` adopts `N+1` by the continuity rule at its next
refresh: the recovery key that signed it is an anchor of `N`. It then adopts
`N+2` and every later version the new root signs: the new root is an anchor
of `N+1`. A version signed by a revoked old root (or by a revoked kit) is
refused, because its signer is not an anchor of the held version.

A node that was offline across the recovery — still at `N`, or older —
sees a newest version its held version's anchors did not sign. It follows
the versions in between by exact name, oldest first, each under the
continuity rule from the one before
([catching up](./context-updates.md#catching-up-across-versions)):
`N+1` (the recovery key), `N+2` (the new root), and on. Every node keeps and
serves the versions it held, so this works from any relay or member that
held them, whenever the node comes back; there is no window to keep `N+1` the
newest in. A forged version in between, or one nobody serves while no later
one follows without it, stops the walk and nothing changes.

### The expected fingerprint after a recovery

An anchor link or invite carries an expected fingerprint, and a device that
holds nothing adopts the newest version only if **its signer** has that
fingerprint — never because the fingerprint names some anchor the fetched,
not yet authenticated context lists (a forger could list any public key).

`N+1` is signed by the recovery key, so a link naming the new root could not
adopt it. That is why the new root signs `N+2` right away: from then on the
newest version is root-signed, and the new root's fingerprint (`anchor_fp`
in `recover`'s output) is the namespace's expected fingerprint again. The
anchor link `recover` prints carries it with `N+2` inline, and invites are
minted with it:

```sh
ndn-fwd-tokens new --ca /home/bob --namespace /home/bob --anchor-fp <new root fingerprint> --role member
```

Links and invites minted before the recovery carry the old root's
fingerprint: a device that already holds the context still enrolls with one
when the old root stays an anchor (`destroyed`), but a device that holds
nothing can no longer adopt with it. Mint new ones.

Rejected alternatives: accepting a link whose fingerprint names any anchor
of the fetched context (unauthenticated, see above); printing a link with
the recovery key's fingerprint (it stops working as soon as the root signs
anything, and puts the kit's fingerprint into circulation) — so when `N+2`
is not taken, `recover` prints no link at all.

## Refusals

| Message | Cause | What to do |
|---|---|---|
| `recover needs --old-root destroyed\|compromised …` | the choice was not made | say what happened to the old root device |
| `the kit's key … is not a recovery anchor of the trust context … held here (vN)` | a kit never added, revoked since, or of another namespace; nothing signed | use a kit that `ndn-fwd recovery-kit list` shows |
| `… is not a recovery anchor … (its recovery anchors: …)` | a `--keep-kit` names no recovery anchor of `N`; nothing written | name kits from the list |
| `kits to keep are named only when the old root is compromised …` | `--keep-kit` with `--old-root destroyed`, which keeps every kit | drop `--keep-kit` |
| `these recovery words are refused: …` | a word outside the BIP39 list (named by its position only), not 24 words, or a checksum mismatch (a mistyped or swapped word); nothing signed | type the words again |
| `the kit passphrase does not open …` | wrong passphrase; nothing signed | retry with the kit's passphrase |
| `… holds the root of … this already is a root device` | this PIB already holds a namespace root | recover on a replacement device whose PIB holds no root |
| `… exists: this PIB already holds a CA identity` | this PIB already holds a CA identity | recover into the PIB of a device that runs no CA |
| `the daemon at … uses the PIB …, not …` | the daemon on the socket keeps another PIB; nothing sent | `-c` with the config of the daemon that uses the PIB, or `--pib` with the daemon's |
| `YubiKey … holds …: a key generated on the same token is lost with it` | a kit on the root's token, or a recovered root on the kit's token | plug in (or select by serial) another token |
| `PIV slot … of YubiKey … already holds a key` (or `may hold a key`) | generating would destroy that key for good | choose a free slot, or `--replace-slot` if its key is not needed |
| `could not get the newest trust context …` | a refresh that answered failed or was refused; recovering from an older version would fork it | give the device a route to a node that holds the namespace, and retry |
| `nothing answered for the newest trust context … retry with --from-held` | no node holding the namespace is reachable | give the device a route to one, or vouch with `--from-held` that the held version is the newest |
| `this device's daemon holds no trust context …` | the namespace is not adopted here | adopt it first with the namespace's anchor link |
| `… recovery kits are made and revoked on the root device` | `create`/`revoke` on a node without the root | run it on the root device |

## Code

| Part | Where |
|---|---|
| Kit key naming, word kits, file kits, YubiKey kits | `ndn_cert::recovery::{recovery_key_name, RecoverySeed, seal_file_kit, FileKit, YubikeyKit}` |
| Not destroying a token's key | `ndn_cert::SlotGuard`, `ndn_security::YubikeyPiv::slot_state` |
| Context versions | `ndn_cert::recovery::{add_recovery_anchor, remove_recovery_anchor, recovery_version, reissue_version, kit_anchor}`, `RecoveryPlan::kept_kits` |
| Recovering into a PIB | `ndn_cert::recovery::recover_namespace_in_pib` (`RecoveredNamespace::{version, root_version}`), `RecoveredNamespace::undo` |
| Following a recovery | `ndn_cert::follow_versions` (refresh and `context_sync`); every version kept by `ndn_cert::context_store`, served by `ndn-fwd` `context_publisher.rs` |
| Key roles in the context | `ndn_security::KeyRole`, `SignedTrustContext::{with_key_role, key_roles, keys_with_role}` |
| `ndn-trust://bag` with namespace + fingerprint | `ndn_trust_envelope::TrustEnvelope::Bag` |
| Hand-over verb | `security/context-update` (`ndn-mgmt`), `MgmtClient::security_context_update`, `ndn-fwd` `context_refresh::apply_update`, `recovery_kit::hand_over` |
| Renewal at a later CA | `ndn_cert::CaState::accept_earlier_ca_certificates`, `ndn_cert::issuers`, `ndn_cert::renew_certificate` (kept issuers); ndn-mobile `NdnEnrolledIdentity::issuers` |
| CLI | `ndn-fwd` `recovery_kit.rs`, `recover.rs` |
| Asking the face the Data arrived on | `ndn_security::CertFetcher::{with_direct_fetch, fetch_from}`, `ndn_app::engine_direct_fetch_fn`, `ndn-engine` `ValidationStage::request_cert` |
| Tests | `ndn-cert/tests/recovery.rs` (incl. `a_compromised_recovery_keeps_no_kit_nobody_vouched_for`), `ndn-cert/tests/renewal_earlier_ca.rs`, `ndn-cert/tests/context_update.rs` (`a_failed_refresh_never_drops_a_good_context`), `ndn-fwd` `context_refresh::tests` (incl. `a_refresh_nobody_answers_is_unreachable_not_refused`), `ndn-identity` `context_sync::tests`, `ndn-security` `cert_fetcher::tests`, `ndn-app` `engine_cert_fetch::the_face_that_delivered_the_data_serves_its_issuer_chain` |

## See also

- [Trust-context updates](./context-updates.md)
- [Revoking a device](./revocation.md)
- [Certificate renewal](./renewal.md)
