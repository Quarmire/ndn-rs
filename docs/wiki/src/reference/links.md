# Linking devices

A link joins two of your devices across networks — a laptop to the home
server, a phone to a relay on a VPS — so that `/<ns>` reaches every device
wherever it is. For you this is "link my devices" or "use my relay". Links
run over QUIC; the reference is [Face transports → QUIC links](./face-transports.md#quic-links)
and the fields are in the [config reference](../operations/config-reference.md#peer--quic-links).

A link knows a device by its key, not by its address. Devices enrolled in
the same namespace already vouch for each other through the namespace's
trust context, so linking them needs no fingerprints, certificates or
passwords — only an address to dial. Today the gesture is one config entry
per link; the namespace decides who is admitted.

## Use my relay

A relay is an `ndn-fwd` at an address the others can reach (a VPS, a home
server with a forwarded UDP port), enrolled in your namespace with role
`node`. On the relay, listen for links:

```toml
[[face]]
kind = "quic"
bind = "0.0.0.0:6367"
```

That is all. Every device of a namespace the relay holds may link in, and the
relay routes each device's name (`/<ns>/<role>/<device>`) over that device's
link.

Who may link is the namespace's **link policy**, signed in its trust context
so every device admits links by the same rule: which roles may link, which
may act as relays, and whether a relay admits an unknown device on an
enrollment link that carries only its enrollment (the CA endpoints and the
trust context) — default on when the namespace has a CA — and whether two
devices linked through a relay may try a direct path between them (default
on; `[[peer]] direct = false` keeps one peer on the relay), and for which
role pairs (default: every pair of `admin`, `member` and `node`; guests
none). The trust context also lists the relays the namespace advertises.
Set it on the root device with `[ca] link_roles`, `relay_roles`,
`enrollment_links`, `direct_paths`, `direct_pairs` and `[[ca.relay]]` in
`ndn-fwd init -c <config>`, or later with `ndn-fwd schema update -c
<config>`, which refuses a narrowing (a role pair or an advertised relay
removed, among others) unless `--accept-narrowing` (see the
[configuration reference](../operations/config-reference.md)). Default: any
role may link, relays are `node` devices, no relays are advertised.

On each device, link to the relay:

```toml
[[peer]]
device = "/home/node/relay"
endpoint = "relay.example.net:6367"
```

The device dials the relay, keeps the link up (it redials whenever the link
drops), and routes `/home` over it.

A device that only dials (a laptop, a phone) can pick the address it dials
from — on a host with several addresses the system's choice may not be the
one the relay should see:

```toml
[[face]]
kind = "quic"
bind = "192.0.2.7:0"   # port 0: the system picks the port
listen = false         # dial only; accept no links
```

Without such a `[[face]]`, a device dials from an address and port the
system picks.

## Add a device that is only reachable over QUIC

A new device need not share a network with the CA. Give it the `[[peer]]`
for the relay, start its daemon, and enroll it as usual (`ndn-fwd enroll
<invite link>`, or by an admin's approval): the relay admits the unknown
device on an **enrollment link**, which carries only its enrollment —
Interests for the namespace's CA endpoints, its trust context
(`/<ns>/32=trust-context/…`) and its certificates (`…/KEY/…`), and their
answers — and nothing else in either direction. The device, which cannot
confirm the relay before it holds the namespace, does the same on its side.
Both logs say so. An Interest an enrollment link does not carry is answered
with a Nack at once.

Once the device holds its certificate (its daemon switches to the enrolled
key), it closes the enrollment link and dials again: the relay sees an
enrolled device and the link is a full link, with no one doing anything.

A relay admits enrollment links for a namespace when its link policy allows
them (`enrollment_links`, default on), the trust context names a CA, and the
relay itself holds a certificate of a role the policy lets relay. It holds
at most 32 at once (4 from one address), rate-limits what each carries, and
closes one that carried nothing for 2 minutes (a device waiting for an
admin's approval keeps its link: it asks for its status within that time);
the device dials again by itself while it enrolls. A revoked key gets no
enrollment link.

## Relay-first

Two devices that cannot reach each other — both behind NATs, say — each link
to the same relay. The laptop's Interests for `/home/member/phone` go to the
relay (it routes `/home` there), and the relay sends them on over the phone's
link. Nothing more is configured: the relay forwards between the two links.

To dial a device directly when it does have a reachable address, give its
`[[peer]]` an `endpoint`. A `[[peer]]` with `relay = "/home/node/relay"` and
no endpoint routes that device's name over the relay's link instead.

## Relays and link modes

Which relays a device uses is the deployer's and the user's choice:

- **the namespace's relays** — the root device lists them in the trust
  context, so every member learns them, signed; used unless `[relays]
  namespace = false`;
- **relays you add** — `[[relay]]` with the relay's `key` (expected
  fingerprint) and `endpoint`: your own server, a community relay, a hosted
  service;
- **none** — `namespace = false` and no `[[relay]]`: LAN and `[[peer]]` links
  only.

The device links to its preferred relay (`[relays] count` of them), routes
through each by preference, and fails over to the next when one is lost: at
once when the relay says it is shutting down, otherwise once a redial of it
fails (it may only be restarting). A
relay of another namespace admits devices by its serving policy
(`[relay_service] serve`). It cannot read or forge your data — everything is
signed — but it sees the names it forwards and which devices talk to which.

Each link has a mode: `always` (keep-alives keep NAT bindings and the radio
awake; reachable at any time), `on-demand` (no traffic while closed; the
first Interest waits for a handshake; closed after `idle_secs` idle) or
`off` (closed until `ndn-ctl link connect`). While a device's link is
asleep, its relay can hold Interests for it (`hold`) and wake it through a
deployer's `wake_command` (`wake_token`), if the relay offers that. Keys,
defaults, bounds and trade-offs:
[Config reference](../operations/config-reference.md#link-modes).

```text
$ ndn-ctl link mode /home/node/relay on-demand:120
$ ndn-ctl link disconnect /home/node/relay
$ ndn-ctl link connect /home/node/relay
```

A mode set this way lasts until the daemon restarts. A command that cannot
be done says why and exits non-zero.

## Direct paths

A device reached through a relay gets a **direct path** when the networks
allow it. Name it, with the relay it is reached through:

```toml
[[peer]]
device = "/home/member/phone"
relay = "/home/node/relay"
```

Nothing else: no addresses. The laptop sends a signed punch request to
`/home/member/phone` through the relay with the addresses it may be reached
at (its interface addresses, the address the relay sees it at, and any
`[[face]] kind = "quic" advertise` addresses). The phone checks it the way it
checks a link — a device of a namespace it holds, allowed to link by the link
policy — and answers with its own. Both then send small probes from their
link sockets to each other's addresses, which opens the NATs on both sides,
and the device with the smaller key fingerprint dials. The phone needs no
`[[peer]]` for the laptop, and `listen = false` does not stop it: a socket
that does not listen accepts the punched connection, from the addresses the
laptop signed, while the punch runs.

The direct path joins the link as its second path. Its routes cost 0, so it
carries the traffic; the relay's routes (cost 10) stay. When the direct path
dies (8 s without an answer), its face and routes go and the relay carries the
traffic again; the laptop punches again after 5 s, then backs off to 5
minutes while punches fail.

When a device's network changes (the app calls `network_changed`, say on a
move from Wi-Fi to cellular), it closes its direct paths and punches each of
those devices again at once from its new address, through the relay. The
other device's old path closes when that punch reaches it. A QUIC
connection cannot follow the side that accepted it to a new address, so
without this the other device would keep sending into a dead path until its
8 s timeout. Behind a NAT, the relay may not have reported the device's new
outside address yet (it checks every 5 s); that punch can then fail, and the
next one, 5 s later, uses the new address.

Some networks cannot be punched — typically both devices behind NATs that
give each destination its own port (symmetric NATs, common on mobile
carriers). The link stays on the relay and `ndn-ctl link list` says why
(`direct not-possible …`). A punch the phone refuses (a key it does not let
link, `direct = false`, a replayed request) is answered with the reason and
causes no probe.

Turn direct paths off for one peer with `[[peer]] direct = false`, or for the
whole namespace with `[ca] direct_paths = false` on the root device and
`ndn-fwd schema update --accept-narrowing` (it is written into the trust
context, so every device follows it). The protocol is in
[ndn-link.md](../../../specs/ndn-link.md) §14.

## A device outside the namespace

A device of another namespace, or one not enrolled or adopted yet, is not
vouched for by your trust context. Name it by its key's fingerprint instead
— its **expected fingerprint**:

```toml
[[peer]]
key = "3f0c…64 hex digits…"
endpoint = "friend.example.org:6367"   # leave out to only let it link in
```

The other device needs the same for yours. Such a link is not tied to a
namespace, so a revocation does not close it: remove the `[[peer]]` entry to
end it.

An unenrolled device of *your* namespace needs no fingerprint to enroll
through a relay: see [enrollment links](#add-a-device-that-is-only-reachable-over-quic).

## Find a device's fingerprint

The daemon logs it at startup when its config has a QUIC listener or a
`[[peer]]`: look for the line `this device's link key` in its log; the
`fingerprint=` field is the 64 hex digits other devices put in
`[[peer]] key`. Links need the daemon's signing key, the device key it
signs with; without one the daemon says so and starts no links.
On a running daemon, the `key` line of [`ndn-ctl link list`](#link-status)
shows it too.

## Link status

`ndn-ctl link list` shows this device's links: for each device it links
with (or is configured to, or punched with), the paths that reach it and
whether a direct path is up, being tried, or why not. It asks the daemon for
the `/localhost/nfd/links/list` dataset. Run it as a local operator — the
daemon's user, root, or a member of `[security] trust_admin_groups` — on the
daemon's socket; anyone else is refused, with how to get access. Links run
whenever the device has a key (its namespace's relays need no config); a
daemon without one (`[security] profile = "disabled"`) says it runs no QUIC
links.

```text
$ ndn-ctl link list
key 3f0c9a…64 hex digits…
probes-sent 40
punches-refused 0
serve own
held-total 0
wakes-sent 0
link /home/node/relay
  key 8d21e4…64 hex digits…
  device /home/node/relay
  mode always
  relay linked source=namespace:/home preference=0
  path link face=5 remote=198.51.100.20:6367 rtt-ms=31.4 age-s=5400
  direct none
link /home/member/phone
  key c7a05b…64 hex digits…
  device /home/member/phone
  path direct face=9 remote=203.0.113.5:41236 rtt-ms=12.3 age-s=90
  path relay face=5 remote=198.51.100.20:6367 rtt-ms=31.4 age-s=5400 via=/home/node/relay
  direct up
```

The output is one item per line, for scripts as much as for people:

- `key` — this device's link key fingerprint (what other devices put in
  `[[peer]] key`), or `-` when it links with no key yet.
- `probes-sent`, `punches-refused` — totals since the daemon started: probe
  datagrams sent for direct paths, and punch requests this device refused.
- `serve <policy>` — this device's relay serving policy (when it reports
  one); `held-total`, `wakes-sent` — Interests it holds now for sleeping
  devices, and wakes it has sent since it started.
- `link <label>` — one block per device, named by its `[[peer]]` label,
  else its device name, else its key. Its `key` and `device` lines show `-`
  until they are known.
- `mode <always|on-demand|off>[ idle-s=<s>]` — a configured link's mode.
- `relay <state> source=<user|namespace:<ns>> preference=<n>[ <why>]` — the
  device is a relay this device uses: `linked`, `trying`, `down`, `standby`
  (a preferred relay is linked) or `off`.
- `asleep since-s=<s> held=<n> hold=<yes|no> wake=<yes|no> wakes=<n>` — on a
  relay: the device is asleep here, with the Interests held for it, whether
  it asked for holding and registered a wake token, and the wakes sent.
- `down <why>` — why a configured device is not linked now (closed after
  idle, off, dial failed and when it retries).
- `path <kind> face=<id> remote=<ip:port> rtt-ms=<ms> age-s=<s>` — one line
  per way the device is reached now (none when it is not): `direct`, a QUIC
  link a hole punch made; `link`, a QUIC link dialled to a configured
  endpoint or accepted; `relay`, routes over the link to the relay named by
  `via=`, whose face and address the line shows. `rtt-ms` is the
  connection's round-trip estimate and `age-s` how long the path has been
  up; `-` where nothing is known.
- `direct <state>[ retry-in-s=<s>][ <why>]` — the device's direct path:

| State | Meaning |
|---|---|
| `none` | No direct path is wanted: the device is not reached through a relay, or a link to it exists already. |
| `off` | Direct paths are off, by the namespace's link policy (`[ca] direct_paths`) or by `[[peer]] direct = false`; the sentence says which. |
| `trying` | A punch runs now. |
| `up` | A direct path is up; traffic takes it, the relay route stays as fallback. |
| `not-possible` | The last punch made no direct path (both NATs too strict, say); the sentence says why. Tried again in `retry-in-s`. |
| `refused` | The last punch was refused, by the other device or by this one; the sentence says why. Tried again in `retry-in-s`. |

## In an app (ndn-boltffi)

An Android or iOS app that embeds the engine (`ndn-boltffi`'s `NdnEngine`)
hosts links with the same library as the daemon — the same admission,
relays, modes, held Interests, wake tokens and direct paths. What the
daemon reads from its config, the app passes in calls:

| Daemon | App (`NdnEngine`) |
|---|---|
| `[[face]] kind = "quic"` (`bind`, `listen`) | `start_links(NdnLinksConfig { socket_fd, bind, listen, … })` — `socket_fd`: a UDP socket the platform bound to the network to use (Android `Network.bindSocket`) |
| `[relays]` (`count`, `namespace`, `mode`, `hold`) | `NdnLinksConfig.relay_count`, `use_namespace_relays`, `namespace_relay_mode`, `namespace_relay_hold` |
| `[links]` (`keep_alive_secs`, `idle_timeout_secs`) | `NdnLinksConfig.keep_alive_secs`, `idle_timeout_secs` (same bounds) |
| `[[relay]]` | `add_relay(NdnRelay { label, key, device, endpoints, preference, mode, hold, routes })`, `remove_relay(label)` |
| `mode` / `idle_secs` | `set_link_mode(label, NdnLinkMode::{Always, OnDemand { idle_secs }, Off})`; `connect_link` / `disconnect_link` |
| `wake_token` | `set_wake_token(label, token)` (a platform push token; `None` withdraws it) |
| — | `set_app_active(bool)` from the app's lifecycle: on-demand links link while active and close idle in the background |
| — | `network_changed(socket_fd)` on a network change (Wi-Fi ↔ cellular): links move to the new socket, dropped ones are dialled again, direct paths punched again now |
| `ndn-ctl link list` | `link_status()` |
| the daemon's key | the loaded identity: `start_links` refuses without one, or with an enclave key that signs only asynchronously (a TLS handshake signs at once); an identity installed later (an enrollment) is presented by the next link, and enrollment links become full links by themselves |

Persist the issuer chain an enrollment or renewal returns
(`NdnEnrolledIdentity.issuers`) and pass it as `NdnLinksConfig.issuers`: a
link hello carries it.

What each mode costs: `Always` keeps the link and wakes the radio for every
keep-alive (default every 10 s) — reachable at once, the most battery and
data. `OnDemand` costs nothing while closed; the phone is reachable while
the app is active or has something to send, and otherwise only through the
relay holding Interests (`hold`) and waking it (`set_wake_token`, if the
relay's operator runs a notifier). `Off` costs nothing until the app asks.

## When a link is refused

The device that refuses closes the link with a code and a sentence saying
why; both logs show it.

| Code | Meaning | What to do |
|---|---|---|
| `0x00` | The other device is shutting down. | Nothing; a `[[peer]]` redials when it is back. |
| `0x01` | A newer link to the same device took this one's place. | Nothing. |
| `0x02` | An enrollment link carried nothing for 2 minutes. | Nothing; the device dials again while it enrolls. |
| `0x03` | The device enrolled; it links again as an enrolled device. | Nothing. |
| `0x10` | Your key has no valid certificate in a namespace the other device holds, no `[[peer]] key` there expects it, and the other device admits no enrollment link (the refusal says why: not a relay of the namespace, enrollment links off in its link policy, or no CA). | Enroll this device in the namespace (through a relay that admits enrollment links, or on the CA's network), or add `[[peer]] key = "<this device's fingerprint>"` to the other device's config. |
| `0x11` | The certificate sent is for another key than the one the link proved. | The device's certificate and key do not belong together; enroll the device again. |
| `0x12` | The namespace revoked this device's key, or a certificate it chains to. | Only an admin of the namespace can let the device back in, by enrolling it again. |
| `0x13` | The namespace's link policy does not let this device's role link, or act as a relay. | A relay must be enrolled with a role in the policy's relay roles (default `node`); to change the policy, set `[ca] link_roles` / `relay_roles` and run `ndn-fwd schema update -c <config>` on the root device. |
| `0x14` | A valid device answered, but not the one the `[[peer]]` expects there. | Check the `endpoint` and the `device` or `key` of that `[[peer]]`. |
| `0x15` | The link messages were malformed. | Check that both devices run a current `ndn-fwd`. |
| `0x16` | Too many link attempts at once from this address, or in total; or the relay holds as many enrollment links as it takes. | Wait; a `[[peer]]` retries. |
| `0x17` | The device has no key it can link with (none, or one that only signs asynchronously, such as a hardware token). | Give the daemon a software device key. |

After a refusal of its key (any code but `0x00`–`0x03` and `0x16`), a
`[[peer]]` waits 60 s before it dials again.
