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
trust context) — default on when the namespace has a CA. Set it on the root
device with `[ca] link_roles`, `relay_roles` and `enrollment_links` in
`ndn-fwd init -c <config>`, or later with `ndn-fwd schema update -c
<config>`, which refuses a narrowing unless `--accept-narrowing` (see the
[configuration reference](../operations/config-reference.md)). Default: any
role may link, relays are `node` devices.

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
Hole punching (a direct path between the two NATed devices) is not done yet.

To dial a device directly when it does have a reachable address, give its
`[[peer]]` an `endpoint`. A `[[peer]]` with `relay = "/home/node/relay"` and
no endpoint routes that device's name over the relay's link instead.

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
