# Config reference

> **STALE (2026-08-21).** This page predates the forwarder's move to the
> sibling repo [ndn-fwd](https://github.com/Quarmire/ndn-fwd) and the
> newer config subsystems (fec, rate limits, radio, listeners,
> `[extensions.*]`). The current truth is the annotated default config
> shipped with the forwarder — `binaries/ndn-fwd/ndn-fwd.default.toml`
> in the ndn-fwd repo — read its comments first, and treat any conflict
> with this page as this page being wrong. The schema itself lives in
> `crates/platform/ndn-config` (ndn-rs).

`ndn-fwd.toml` configures the forwarder. Options below are the older core
groups; consult `ndn-fwd/binaries/ndn-fwd/ndn-fwd.default.toml` for the
current set with defaults.

## File location

| Order | Path |
|---|---|
| 1 | `--config <path>` (highest precedence) |
| 2 | `$NDN_CONFIG` |
| 3 | `./ndn-fwd.toml` |
| 4 | `~/.config/ndn-rs/ndn-fwd.toml` |
| 5 | `/etc/ndn-fwd/ndn-fwd.toml` |

Absent file → defaults from `ndn-config`.

## `[engine]` — pipeline tuning

| Key | Default | Use |
|---|---|---|
| `cs_capacity_mb` | 64 | Content-store capacity (MiB). Deprecated alias for `[cs] capacity_mb`. |
| `pipeline_channel_cap` | 4096 | Depth of the inter-task pipeline channel. Increase under sustained load. |
| `pipeline_threads` | 0 | Pipeline parallelism. `0` = auto (CPU count). `1` = single-threaded inline. |

## `[cs]` — content store

| Key | Default | Values |
|---|---|---|
| `variant` | `lru` | `lru`, `sharded-lru`, `null`. |
| `capacity_mb` | 64 | Capacity in MiB. |
| `shards` | (auto) | Number of LRU shards (sharded-lru only). |
| `admission_policy` | `default` | `default` (PIT-bound) or `admit-all`. |
| `unsolicited_policy` | `drop-all` | Caching of Data with no pending PIT entry: `drop-all`, `admit-local`, `admit-network`, `admit-all`. Use `admit-network` on a broadcast/ad-hoc bearer. |

**Persistent backends (feature-gated).** For a CS that survives restarts, prefer
the **SQLite backend** in production: it implements true LRU eviction with
race-free byte/entry accounting. The fjall (LSM) backend currently evicts in NDN
key order rather than by recency, its accounting can drift under concurrent
insert, and eviction is O(N) per insert (a recency-indexed rewrite is tracked).
In-memory `lru` / `sharded-lru` remain the default and are unaffected.

## `[management]` — management socket

| Key | Default | Use |
|---|---|---|
| `face_socket` | `/run/nfd/nfd.sock` (Windows: `\\.\pipe\ndn`) | Unix socket (Named Pipe) on which apps, `ndn-ctl` and the dashboard connect and send management commands. |

## `[security.mgmt]` — who may manage this forwarder

On the local Unix socket the kernel reports who is connecting (peer
credentials). A **local operator** — the daemon's own user, root, or a member
of a group in `[security] trust_admin_groups` — is authenticated by that
alone: its commands are accepted without a signature, whatever the settings
below. Everyone else (another local user, or any network face) must sign.

| Key | Default | Use |
|---|---|---|
| `require_signed_commands` | `true` | Commands from anyone but a local operator must carry a key-backed signature that a key under `trust_anchor_pib` verifies; an unsigned (or DigestSha256-only) command is refused `403` with the reason and what to do. `false` accepts unsigned commands of the standard NFD modules (`faces`, `fib`, `rib`, `cs`, `strategy-choice`, `status`) from any caller; the ndn-rs extension modules (e.g. `security`) still need a local operator or a signature. Public read-only datasets (`*/list`, `status/general`, `cs/info`, …) are always served unsigned. |
| `trust_anchor_pib` | (none) | PIB whose anchors verify signed commands. Unset: only local operators can issue commands. Startup fails if set but unreadable or empty. |
| `localhop_trust_anchor_pib` | (none) | PIB whose anchors verify `/localhop/nfd/rib/{register,unregister}` from neighbours. Unset: every `/localhop` command is refused. Trust-changing verbs are refused over `/localhop` regardless. |

## `[[face]]` — face listeners

Repeated table. Order determines face index (used by `[[route]]`).

```toml
[[face]]
kind = "udp"
bind = "0.0.0.0:6363"

[[face]]
kind = "multicast"
group = "224.0.23.170"
port = 56363

[[face]]
kind = "webtransport"
listen = "0.0.0.0:4443"
cert = "/etc/ndn-fwd/wt.pem"
key  = "/etc/ndn-fwd/wt.key"

[[face]]
kind = "quic"
bind = "0.0.0.0:6367"
```

Face kinds: `udp`, `tcp`, `unix`, `multicast`, `ether`,
`webtransport`, `ws`, `webrtc`, `shm`, `serial`, `bluetooth`, `quic`.
See [Face transports](../reference/face-transports.md) for the per-kind options.

`kind = "quic"` is this device's QUIC link socket: it listens for links from
other devices, and the links this device dials (its `[[peer]]` entries) go
out from it, so other devices see this one at `bind`. `bind` is an address
and UDP port (`"0.0.0.0:6367"`; `"[::]:6367"` takes both IPv4 and IPv6);
anything that is not an address and port is refused. `listen = false`
(default `true`) makes it dial-only: it accepts no links, and a device picks
the address it dials from this way (`bind = "192.0.2.7:0"`, port `0` lets
the system pick the port); a dial-only socket with nothing to dial (no
`[[peer]] endpoint`, no `[[relay]]` and `[relays] namespace = false`) is
refused. Without a quic `[[face]]`, links are dialled from an
address and port the system picks. `advertise` (default none) lists public
`host:port` addresses that reach this socket, such as a router's port
forward (`advertise = ["203.0.113.7:6367"]`); they are offered to linked
devices as direct-path candidates, besides the addresses the device learns
by itself. An entry that is not `host:port` with a non-zero port is refused.
A daemon has at most one. Who may link
in is decided by the devices' keys, not by this entry. See
[QUIC links](../reference/face-transports.md#quic-links).

## `[[route]]` — static routes

```toml
[[route]]
prefix = "/lab"
face = 0          # face index from [[face]] order
cost = 100        # optional
```

A `[[route]]` cannot name a `kind = "quic"` face: that face is the link
socket rather than a link. Routes over a link go in its `[[peer]] routes`.

## `[[peer]]` — QUIC links

Repeated table: the devices this one links to over QUIC, or lets link in.
Each entry names one device; a link to it is identified by its key, never
by an address. See [Linking devices](../reference/links.md).

```toml
[[peer]]
device = "/home/node/relay"
endpoint = "relay.example.net:6367"
```

| Key | Default | Use |
|---|---|---|
| `device` | (none) | The peer's device name `/<namespace>/<role>/<device>` (at least three components). The link is admitted when the peer's certificate validates in a namespace this device holds and names this device. |
| `key` | (none) | Expected fingerprint of the peer's key: 64 hex digits, the SHA-256 of its public key, as the peer's daemon logs it at startup (`this device's link key`, `fingerprint=…`). For a device of another namespace, or one not enrolled or adopted yet. With `device` too, the key must match and a certificate that validates must name that device. |
| `endpoint` | (none) | Where to dial it: `"host:port"`, or a list tried in order. None: this device does not dial it — it is reached through `relay`, or it links in. |
| `relay` | (none) | The `device` or `key` of another `[[peer]]` or of a `[[relay]]`: reach this peer through that link. This peer's routes are installed on the relay's link at cost 10 (a direct link costs 0). |
| `routes` | see below | Prefixes routed over this link. |
| `persistent` | `true` | Keep the link up: redial whenever it drops, with backoff from 0.5 s to 30 s, and 60 s after the peer refused this device's key. |
| `reliability` | `false` | NDNLPv2 reliability (retransmission of lost frames) on this link. |
| `direct` | `true` | When this peer is reached through a relay, try a direct path to it (NAT hole punching), keeping the relay when it does not open; only when the namespace's link policy allows direct paths (`[ca] direct_paths`). `false`: always through the relay. |
| `mode` | `"always"` | When the link is up: `always`, `on-demand` or `off` — see [Link modes](#link-modes). |
| `idle_secs` | `60` | With `mode = "on-demand"`: close the link after this many seconds without traffic (10–86400). |
| `hold` | `false` | Ask this peer, when it is a relay, to hold Interests for this device while its link is asleep and deliver them when it is back (the relay must offer it: `[relay_service] hold`). |
| `wake_token` | (none) | Opaque token (UTF-8, 1–1024 bytes, such as a platform push token) registered with this peer, when it is a relay, so its `wake_command` can wake this device. Redacted from `config get`. |

When `routes` is unset: a peer that validates as a `node` device (a relay)
gets its namespace prefix `/<ns>`; any other peer that validates gets its
device name `/<ns>/<role>/<device>`; a peer admitted by `key` alone gets its
`device` if set, else no route. On an enrollment link (a device not
enrolled yet linking to a relay of its namespace, see
[Linking devices](../reference/links.md#add-a-device-that-is-only-reachable-over-quic)),
the device routes `/<ns>` over it and the relay installs no route. Routes
are installed when the link comes up and removed with it.

A `[[peer]]` with neither `endpoint` nor `relay` only says that device may
link in — useful with `key`, for a device the namespace does not vouch for.

Validation (the daemon refuses to start, naming the entry):

- each entry has `device` or `key`;
- `key` is exactly 64 hex digits; `device` is an NDN name of at least three
  components;
- each `endpoint` is `host:port` with a non-zero port;
- each of `routes` is an NDN name starting with `/`;
- `relay` names another `[[peer]]` (its `device` or `key`) that has an
  `endpoint`, or a `[[relay]]`;
- no two entries name the same device or key, and no `[[relay]]` names the
  same device or key as a `[[peer]]`;
- with `mode = "on-demand"`, `idle_secs` is 10–86400; `wake_token` is
  1–1024 bytes;
- unknown keys are refused.

Older QUIC configuration is refused: `[listeners]` takes only
`webtransport`, `webrtc` and `ble`, `[[face]] kind = "quic"` takes only
`bind`, `listen` and `advertise`, and a QUIC face dialled to an address is now a
`[[peer]]` with `endpoint` and the peer's `key`.

### Link modes

Each `[[peer]]`, each `[[relay]]` and the namespace's relays (`[relays]
mode`) have a mode. It trades reachability against battery and data:

| Mode | What it does | Battery and data |
|---|---|---|
| `always` (default) | Linked all the time; redialled when it drops. | A keep-alive every `[links] keep_alive_secs` (default 10 s) keeps NAT bindings — and the radio — awake: the device can be reached at any time, at the cost of a small, steady stream of packets that keeps a phone's radio from sleeping. |
| `on-demand` | Closed until there is traffic for it (an Interest that would go out over its routes, or the host says it is active); closed again after `idle_secs` without traffic. | No traffic at all while closed. The first Interest waits for the handshake (about one round trip plus the QUIC handshake). While it is closed, Interests *to* this device reach it only if the relay holds them for it (`hold`) or wakes it (`wake_token`), and only if the relay offers that. |
| `off` | Configured but closed until asked (`ndn-ctl link connect <label>`). | Nothing at all until asked. |

`ndn-ctl link mode <label> <always|on-demand[:idle_secs]|off>` changes a
link's mode until the daemon restarts; `ndn-ctl link disconnect <label>`
closes a link until it is connected again or its mode is set.

## `[relays]` — which relays this device uses

A relay forwards between devices that cannot reach each other directly. A
device uses the relays its namespace advertises in its trust context (signed
by the root device, so every member learns them) and the relays added with
`[[relay]]`. It links to the preferred one(s) and fails over to the next
when one is lost.

```toml
[relays]
count = 1
namespace = true
mode = "always"
```

| Key | Default | Use |
|---|---|---|
| `count` | `1` | Relays linked at once, preferred first (1–8); the others stand by and take over when one is lost. Each linked relay costs its keep-alives. |
| `namespace` | `true` | Use the relays the namespace advertises. `false` with no `[[relay]]`: no relays (LAN and `[[peer]]` links only). |
| `mode` | `"always"` | [Link mode](#link-modes) of the namespace's relays. |
| `idle_secs` | `60` | With `mode = "on-demand"`: idle close in seconds (10–86400). |
| `hold` | `false` | Ask the namespace's relays to hold Interests for this device while it is asleep. |

## `[[relay]]` — relays the user adds

Repeated table: an own server, a community relay or a hosted service,
identified by its key and dialled at its endpoints.

```toml
[[relay]]
key = "9f2c…"            # 64 hex digits
endpoint = ["relay.example.net:6367"]
preference = 0
```

| Key | Default | Use |
|---|---|---|
| `key` | (none) | Expected fingerprint of the relay's key (64 hex digits). Required unless `device` is a device of a namespace this device holds. |
| `device` | (none) | The relay's device name `/<namespace>/node/<device>`. |
| `endpoint` | (required) | Where to dial it: `"host:port"`, or a list tried in order. |
| `preference` | `0` | Lower is preferred; on a tie, user relays come before the namespace's. |
| `mode`, `idle_secs`, `hold`, `wake_token` | as `[[peer]]` | Same meaning as on a `[[peer]]`. |

Refused: an entry with neither `key` nor `device`, without `endpoint`, with
a malformed `key`, `device` or `endpoint`, two entries naming the same
device, and an entry naming the same device or key as a `[[peer]]` (one
device is one link: keep the `[[relay]]`, moving the peer's options to it,
or the `[[peer]]`).

**Privacy of a relay of another namespace.** A community or hosted relay
cannot read or forge your data — every Data packet is signed, and
encrypted content stays encrypted — but it sees the names it forwards and
which devices talk to which, and when. Use a relay you run, or your
namespace's own, when names or traffic patterns are sensitive.

## `[relay_service]` — serving as a relay

What this device does as a relay for other devices.

```toml
[relay_service]
serve = "listed"
roots = ["4b1d…"]        # root key fingerprints of the served namespaces
hold = true
wake_command = ["/usr/local/bin/ndn-wake", "--push"]
```

| Key | Default | Use |
|---|---|---|
| `serve` | `"own"` | `own`: devices of the namespaces this device holds a certificate in. `listed`: those, plus the namespaces whose root key fingerprint is in `roots`. `open`: any namespace whose certificate chain validates to its root, within the quotas. Devices named by a `[[peer]]` or `[[relay]]` are admitted whatever this says. |
| `roots` | `[]` | With `serve = "listed"` (required, and only there): root key fingerprints (64 hex digits). |
| `links_total` | `256` | Quota: links from devices of other namespaces, in total. |
| `links_per_namespace` | `32` (at most `links_total`) | Quota: links per other namespace. |
| `interests_per_key` | `100` | Quota: Interests per second from one device (burst twice that). |
| `interests_per_namespace` | `400` | Quota: Interests per second from one other namespace (burst twice that). |
| `hold` | `false` | Hold Interests for sleeping devices that ask, and deliver them when they are back. |
| `hold_per_device` | `64` | Most Interests held for one device (at least 1). |
| `hold_total` | `4096` | Most Interests held in total (at least `hold_per_device`). |
| `hold_secs` | `60` | Longest an Interest is held (1–3600), never past its lifetime. |
| `asleep_secs` | `86400` | How long a device that went asleep counts as asleep (60–604800); after that it is treated as gone. |
| `wake_command` | (none) | Program and arguments run once per wake of a sleeping device that registered a wake token. |

The quotas are always in force for `open`; for `listed` only when one of
them is set (the unset ones take their defaults); with `own` they are
refused (it serves no other namespace).

`wake_command` is run without a shell, with these environment variables:

| Variable | Value |
|---|---|
| `NDN_WAKE_TOKEN` | The device's wake token, hex. |
| `NDN_WAKE_DEVICE` | The device's name, or empty when it is known only by key. |
| `NDN_WAKE_KEY` | The device's key fingerprint, 64 hex digits. |
| `NDN_WAKE_HELD` | How many Interests are held for it. |

It runs in the background; one that has not exited after 10 s is killed.
Its output goes to the daemon's log. The library defines this interface
only — the command does the vendor-specific part (a push service, a
webhook, …).

## `[links]` — link timing

| Key | Default | Use |
|---|---|---|
| `keep_alive_secs` | `10` | Seconds between keep-alives on an idle link (2–60). Shorter costs battery and data; longer than the NAT's binding lifetime (often 30–120 s) and the device cannot be reached. |
| `idle_timeout_secs` | `30` | Seconds of silence after which a link counts as lost: at least 3 × `keep_alive_secs` (so two lost keep-alives do not drop it), at most 600. |

## `[direct]` — direct paths by membership

| Key | Default | Use |
|---|---|---|
| `membership` | `true` | Try direct paths with devices of this device's namespace met at a common relay, without a `[[peer]]` entry, where the trust context's role matrix allows them (default: admin, member and node devices, not guests). |
| `max_paths` | `8` | Most direct paths kept at once (1–64). |

## `[discovery]` — neighbour discovery

| Key | Default | Use |
|---|---|---|
| `enabled` | `true` | Run the autoconf discovery protocol. |
| `discovery_transport` | `udp` | `udp`, `ether`, `both`. |
| `interval_ms` | `5000` | HELLO interval. |

## `[security]` — trust contexts

| Key | Default | Use |
|---|---|---|
| `profile` | `"default"`; no `[security]` table at all: `"disabled"` | How Data from non-local faces is validated (local faces never are). `default`: the certificate chain must end at a trust anchor of the trust context governing the Data's name (the identity's PIB anchors, `trust_anchor`, adopted contexts); a chain no anchor ends is refused. An engine with no security manager has no anchors, so `default` fails closed there: every key-signed Data from a non-local face is refused `untrusted-root` at once (DigestSha256 Data still passes its digest check). ndn-fwd always has a security manager: the configured identity, the PIB's default identity, or an ephemeral key that is its own only anchor. `accept-signed`: the signature must verify against the signer's certificate (fetched if needed), which need not reach an anchor. `disabled`: no validation. A config with no `[security]` table forwards Data unvalidated, and the daemon says so at startup (WARN); add the table to validate. Any other value is a startup error. |
| `serve_contexts` | `true` | Publish every trust context in `<pib_path>/contexts/` by name over RDR: `/<ns>/32=trust-context/32=metadata` names the newest stored version, `/<ns>/32=trust-context/v=<N>` returns the stored signed Data of each version held, verbatim (so nodes behind this one can follow the namespace version by version). Read at startup. See [Trust-context publication](../reference/trust-context-publication.md). |
| `trust_admin_groups` | `[]` | Unix groups whose members are local operators on the management socket, alongside the daemon's own user and root. Only local operators may change this node's trust: the verbs in `TRUST_ADMIN_VERBS` (`ndn-mgmt/src/auth.rs`) — `security/context-adopt` (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`), `security/renew` (`ndn-fwd renew`), `security/context-refresh` (`ndn-fwd context refresh`) and `security/context-update` (`ndn-fwd revoke`, `ndn-fwd schema update`, `ndn-fwd recovery-kit`, `ndn-fwd recover`); everyone else is refused, and these verbs are always refused over `/localhop`. Local operators' other commands need no signature either (see [`[security.mgmt]`](#securitymgmt--who-may-manage-this-forwarder)). Membership is checked against the caller's kernel-reported socket credentials (primary gid, the group's member list, and on Linux the caller's supplementary groups). Read at startup. |
| `context_refresh_secs` | `300` | How often, in seconds, the daemon checks every held trust context for a newer version (RDR metadata upstream) and adopts one signed by an anchor of the held version and strictly newer — or, when a recovery installed a new root in between, follows the versions in between one by one — then stores and republishes it — how a [revocation](../reference/revocation.md) reaches this node. The first check runs as soon as the route of each namespace the node fetches has its face up, at most `min(context_refresh_secs, 30)` s after start. `0` disables the periodic check; `ndn-fwd context refresh` still works. A missed check only delays an update. The root device (whose PIB holds the root key) does not fetch its own namespace. See [Trust-context updates](../reference/context-updates.md). |
| `context_sync` | `false` | Also join every held namespace's trust-context sync group (SVS, `/<ns>/32=trust-context/32=sync`; a namespace adopted later is joined when it is adopted). The root device (whose root store holds an anchor key of the version) puts each version it keeps into the group — a revocation, a version handed over with `security/context-update`, a recovery — and every other member fetches it at once and adopts it under the same rule as `context_refresh_secs`, then stores and republishes it the same way. Refusals are logged with their reason. The group is routed over the faces the namespace is routed over and toward the faces members' Sync Interests arrive on; a relay between the root device and a device carries it only if it runs `context_sync` too. The periodic refresh keeps running beside it. See [Trust-context updates](../reference/context-updates.md#push-over-the-namespaces-sync-group). |
| `renew_before` | `0.333` | When the daemon renews the certificates a namespace CA issued to its keys: once the remaining validity falls below this. A number between 0 and 1 is a fraction of the lifetime; a string `"<n>d"` / `"<n>h"` / `"<n>m"` / `"<n>s"` is a fixed time before expiry (a time at least the lifetime the CA issues renews at a third of the lifetime instead, with a WARN); `0` turns the timer off (`ndn-fwd renew` still works). Failures retry with a jittered backoff (30–60 s doubling to 30–60 min; 30–60 min after a refusal) and log a WARN with the days left. See [Certificate renewal](../reference/renewal.md). |

## `[ca]` — embedded NDNCERT CA

This section was called `[demo_ca]` before; a config that still has a
`[demo_ca]` section is refused at startup with a message to rename it to `[ca]`
(keys unchanged).

Off by default; `enabled = true` runs an in-process CA serving
`/<prefix>/CA/{INFO,NEW,CHALLENGE/<id>,REVOKE}` and cert-fetch for the certs
it issued. See [NDNCERT setup](../guides/ndncert-setup.md).

| Key | Default | Use |
|---|---|---|
| `enabled` | `false` | Run the embedded CA. |
| `prefix` | `/demo` | CA namespace. The CA appends `/CA` itself (as do clients); a prefix ending in `/CA` is rejected at startup. |
| `identity` | `/demo/CA` | CA signing identity, loaded from the node PIB (`[security] pib_path`). |
| `ephemeral` | `false` | Mint a throwaway self-signed CA key at every start instead of loading `identity` (demo only; warned). |
| *(invites)* | — | Not configured. Every CA offers the `token` challenge over the invites made at runtime (`ndn-fwd-tokens -c <config> new`, management verb `ca/invite-create`). A leftover `tokens` key in `[ca]` or `[[ca.challenge]]` fails config load. |
| `emit_attestations` | `false` | Embed a challenge attestation in each issued cert. |
| `cert_validity_days` | `90` | Lifetime of the certificates the CA issues, in days: one number for every role, or a `[ca.cert_validity_days]` table with `admin` / `member` / `node` / `guest` and `default` for the roles not listed (e.g. `default = 90`, `guest = 7`). The longest is the maximum advertised in INFO. Enrollments and renewals name no lifetime, so they get their role's; `ndn-fwd enroll` / `ndn-fwd renew` print the expiry issued. `0` or an unknown role is refused at startup. |
| `renewable_roles` | `["admin", "member", "node"]` | Roles whose current, unrevoked certificates the CA renews for the same key without an invite ([Certificate renewal](../reference/renewal.md)). Guests are left out by default, so guest access ends at expiry. `[]`: the CA renews nothing. |

A device that is the root of several trusted prefixes runs one CA per
prefix: write one `[[ca]]` table per CA instead of the single `[ca]` table
(both forms parse into the same list; `[[ca.challenge]]` after a `[[ca]]`
belongs to that CA; two enabled entries with one identity or prefix are
refused, and an error names its entry, e.g. `[[ca]] #2 (/work/acme/CA)`).

Without `ephemeral`, a CA loads its key from the PIB and its certificate
(issued by the namespace root) from `ca-cert.data` in its directory,
`<pib_path>/ca/<hex of the namespace URI>/` (a PIB from before several CAs
keeps its one CA in `<pib_path>/ca/`); the root's anchor certificate is
`anchor-cert.data` there or a PIB trust anchor. `ndn-fwd init --namespace
<ns>` writes all three. Startup fails if they are missing, mismatched, or
the CA cert is not signed by the root. Issued certs, revocations and
invites (a SHA-256 hash of each token, never the token) persist under
`{issued,revoked,invites}/` of that directory. Issued certs are served again
after a restart and revoked ones are not. Invites keep their state: one made
before a restart is still redeemable, and one redeemed or withdrawn stays
refused.

`ndn-fwd init --namespace /<ns> [--device <name>]` (run on the root device)
also mints the root device's admin identity `/<ns>/admin/<device>` (default device
name: the host name, lowercased, first label, disallowed characters as `-`;
`KEY`, `CA` and the role words are refused; key
`/<ns>/admin/<device>/KEY/device`, cert issued by the CA, signed copy at
the CA's directory as `device-cert.data`), stores the root-signed trust context
carrying the generated role schema (`ndn-fwd schema show`), and prints the
`[security]` lines that load the device identity
(`identity = "/<ns>/admin/<device>"`, `pib_path = "<pib>"`); without them the
forwarder falls back to an ephemeral key. Init never edits config files.

The root key itself goes to the root store chosen with `init --root-store`
(`os-keyring` by default when an OS keychain is reachable, else refused with
advice; `sealed-file`, `yubikey-piv`, `file`), recorded per trusted prefix in
`<pib_path>/root/<hex of the prefix>/store.toml` (an older PIB's one root:
`<pib_path>/root/store.toml`). One PIB can hold the roots of several trusted
prefixes; root commands then take `--namespace <prefix>` — no config key selects it; see
[root custody](../concepts/identity-and-keys.md#root-custody-where-a-namespace-root-key-lives).
The daemon reports it in `security/identity-status` (`root_store=`,
`root_key=`; shown by `ndn-ctl status`) and warns at startup when it is
`file`. `ndn-fwd` builds with the `os-keyring` feature by default;
`yubikey-piv` is opt-in.

A PIB-backed CA whose identity is `/<ns>/CA`, certified by the namespace root
`/<ns>/KEY/…`, serves the namespace `/<ns>`: it issues only device keys
`/<ns>/<role>/<device>/KEY/<id>` (role `admin`, `member`, `node`, `guest`);
`admin` and `node` certs need a `device-approval`, tokens admit members and —
when guest-scoped — guests (`ndn_cert::RolePolicy`; see
[NDNCERT setup](../guides/ndncert-setup.md#roles-in-a-namespace)). A
device name holds one certified key at a time: a new key for a name that holds
a valid, unrevoked certificate is refused (before the token is redeemed) until
that certificate is revoked, unless the new key comes with a `device-approval`.
An ephemeral CA keeps issuing any challenge-passing name.

`[[ca.challenge]]` — explicit challenge set (replaces the `tokens`
shortcut). Each entry has `kind = "nop"|"token"|"pin"|"email"|"device-approval"`.
The CA refuses to start with no challenge configured; `nop` (auto-approve
every request) is only offered when listed explicitly.

```toml
[[ca.challenge]]
kind = "email"
ttl_secs = 300
smtp = { host = "smtp.example.com", port = 587, from = "ca@example.com", starttls = true }
```

`email` delivers via SMTP only with `--features smtp` (lettre); otherwise (or
with `smtp.log_only = true`) the code is logged. `device-approval` holds each
request in a durable record (`approvals/` of the CA's directory) until it is approved,
denied or expires: `ndn-fwd approvals list|approve|deny <id|code>` on the CA
host decides as the local operator (mgmt `ca/{list-approvals,approve,deny}`,
local socket only, never over `/localhop`); on an admin device it pushes a
decision signed by the admin key to `/<prefix>/CA/APPROVAL`, validated under
the namespace's trust context. See
[Enrollment by approval](../reference/enrollment-by-approval.md).

| Key | Default | Use |
|---|---|---|
| `approval_roles` | `["admin", "node"]` | Roles issued only on an admin's approval; the others enroll by invite. |
| `approval_requires_invite` | `false` | An approval request must also redeem one of this CA's invite tokens. |
| `approval_request_ttl_days` | `7` | How long a pending request waits; a decided record is kept as long again. `0` is refused. |
| `link_roles` | unset (context's; default: every role) | Roles whose devices may link (`[[peer]]` QUIC links). `[]`: every role. |
| `relay_roles` | unset (context's; default `["node"]`) | Roles a device may relay through; each must be in `link_roles` when that is not empty. |
| `enrollment_links` | unset (context's; default `true`) | A relay of the namespace admits an unknown device on an enrollment link that carries only its enrollment (CA endpoints, trust context); effective when the namespace has a CA. |
| `direct_paths` | unset (context's; default `true`) | Two devices of the namespace linked through a relay may try a direct path between them (NAT hole punching), keeping the relay when it does not open. Turning it off is a narrowing. |
| `direct_pairs` | unset (context's; default: every pair of `admin`, `member`, `node`; `guest` none) | Which role pairs may make direct paths, `"<role>:<role>"` unordered (`"member:member"`: two members); roles `admin`, `member`, `node`, `guest`. `[]`: no pair. Removing a pair is a narrowing. |
| `[[ca.relay]]` | unset (context's; default none) | Relays the namespace advertises in its trust context, so every member learns them without local configuration (each device decides whether to use them, `[relays] namespace`). `relay = []` in `[ca]`: none. Every device that holds the context sees their endpoints. |

`[[ca.relay]]` entry:

| Key | Default | Use |
|---|---|---|
| `device` | (required) | The relay's device name, normally `/<namespace>/node/<device>`. |
| `key` | unset | Its expected fingerprint, 64 hex digits (the link key its `ndn-fwd` prints). Required when `device` is not a device of the namespace (a community or hosted relay). |
| `endpoint` | (required) | `host:port`, or a list tried in order. |
| `preference` | `0` | Lower is preferred. |

```toml
[ca]
direct_pairs = ["admin:member", "member:member"]   # nodes always through the relay

[[ca.relay]]
device = "/home/bob/node/vps"
endpoint = ["vps.example.net:6367", "203.0.113.7:6367"]

[[ca.relay]]
device = "/club/node/relay"
key = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
endpoint = "relay.club.example.org:6367"
preference = 10
```

A namespace CA enforces the policy its trust context's enrollment hint
advertises (`ndn-fwd init` writes it from these keys, and `ndn-fwd schema
update -c <config>` for a context made before the hint named its approval
roles); `approval_roles` and
`approval_requires_invite`, if set, must agree with the hint or the CA
refuses to start (the message names the context's policy). With
`approval_requires_invite = true` the CA needs a `token` challenge, or it
refuses to start. A namespace CA offers `device-approval` even when
`[[ca.challenge]]` does not list it (logged).
The link keys are the trust context's link policy, never the CA's own, and
`[[ca.relay]]` are the relays it advertises:
`ndn-fwd init -c <config>` writes them (unset keys: the default) and prints
`link_policy = …` and the relays; `ndn-fwd schema update -c <config>` changes
them (unset keys: what the context says), refusing a narrowing — a role
that could link no longer can, `[]` turned into a list, a relay role
removed, enrollment links turned off, a direct pair removed, an advertised
relay dropped or given another `key` — unless `--accept-narrowing`. Adding
a relay, or changing its endpoints or preference, is not a narrowing. A
namespace CA whose link keys or relays disagree with its context refuses to
start, naming what the context states. Unknown roles, a relay role that may
not link, a relay without an endpoint, and a relay outside the namespace
without `key` are refused.
`[ca.require_attestation]` (`prefix`/`kind`/`require_signed`/
`accept_local_operator`) gates issuance on a challenge attestation (on a
namespace CA, on top of the role layout); under `require_signed` a local
operator's approval carries no signature and counts only with
`accept_local_operator = true` (default `false`).
`possession`/`yubikey` are wired in code.

## `[log]` — log filter

| Key | Default | Use |
|---|---|---|
| `filter` | `info` | `RUST_LOG`-style filter (`info,ndn_engine=debug`). |
| `format` | `compact` | `compact`, `json`, `pretty`. |
| `with_target` | `true` | Include the tracing target. |

## `[rate_limit]` — token-bucket rate limits

Per project memory `project_dashboard_multi_forwarder`.

## See also

- `ndn-fwd/binaries/ndn-fwd/ndn-fwd.default.toml` (sibling repo ndn-fwd) —
  the source of truth; annotated defaults with inline comments.
- [ndn-fwd](./ndn-fwd.md) — operator workflows.
- [Face transports](../reference/face-transports.md) — per-face
  configuration shapes.
