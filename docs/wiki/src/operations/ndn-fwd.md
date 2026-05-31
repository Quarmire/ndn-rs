# ndn-fwd

`ndn-fwd` is the standalone forwarder binary. This page covers
day-2 operation: starting, inspecting state, applying changes,
shutting down cleanly.

For first-run setup see [Running the forwarder](../quickstart/running-the-forwarder.md).
For containerised deployment see [Self-hosting](../guides/self-hosting.md).

## Lifecycle

```sh
ndn-fwd --config /etc/ndn-fwd/ndn-fwd.toml
```

`ndn-fwd` reads `--config` (or `$NDN_CONFIG`, or `./ndn-fwd.toml`),
opens its listeners, restores strategy and route pins from
`~/.ndn/strategy-choice.toml` and `~/.ndn/routes.toml`, and starts
serving.

`Ctrl-C` (or `SIGTERM`) triggers a clean shutdown: open faces drain,
the PIT is allowed to empty (up to a grace window), strategy and
route pins are persisted, the process exits 0.

The systemd unit at `deploy/systemd/ndn-fwd.service` (when using the
deploy stack) handles restart and journal capture.

## Inspecting state

`ndn-ctl` is the operator CLI. It speaks the TLV management
protocol against the running forwarder.

| Verb | What it shows |
|---|---|
| `ndn-ctl status` | Forwarder summary: NFD-compatible status, version, timestamps, uptime, table counts, and packet counters. |
| `ndn-ctl face list` | Every face with kind, scope, persistency, byte/packet counters. |
| `ndn-ctl fib list` | FIB entries by prefix with nexthops. |
| `ndn-ctl rib list` | RIB entries (registered prefixes, origin, expiry). |
| `ndn-ctl strategy list` | Per-prefix strategy choice. |
| `ndn-ctl cs info` | Content store size, hits, misses, eviction count. |
| `ndn-ctl routing status` | Active routing protocol and its typed status. |
| `ndn-ctl neighbor list` | Discovery-protocol neighbour table. |

Full verb catalogue: [Management verbs](../reference/mgmt-verbs.md).

The graphical equivalent is `ndn-dashboard`; see
[Running the dashboard](../guides/running-the-dashboard.md).

## Applying changes

Most knobs can be set at runtime via the mgmt protocol; restart is
only needed for `[engine]` and `[face.*]` listener changes.

| Change | Restart? |
|---|---|
| Add/remove a route | No — `ndn-ctl route add` / `route remove`. |
| Pin a strategy | No — `ndn-ctl strategy set`. |
| Adjust CS capacity | No (LRU resize) / Yes (variant change). |
| Add a new face listener | Yes — re-read `[face.*]`. |
| Change pipeline depth | Yes — `[engine]` knobs. |
| Change log filter | No — `ndn-ctl log set <filter>`. |

## Management trust & bootstrap

Privileged management commands (adding a trust anchor, importing a key,
editing the trust schema or routes) are **always** signed and validated
by the forwarder — even when `require_signed_commands = false`. A fresh
forwarder with no configured trust anchor therefore *refuses* them with
`403 … no validator is configured`. This is intentional: forwarder trust
cannot be bootstrapped over the unauthenticated management channel
(anyone with socket access could otherwise install anchors).

Bootstrap trust **out-of-band**, once per forwarder:

```bash
# 1. Create the operator identity + a self-signed trust anchor.
ndn-sec --pib /etc/ndn/mgmt-pib keygen --anchor /op/alice

# 2. Point the forwarder at that anchor PIB and restart.
#    [security.mgmt]
#    require_signed_commands = true
#    trust_anchor_pib = "/etc/ndn/mgmt-pib"

# 3. Export the operator identity to carry into the dashboard / another host.
ndn-sec --pib /etc/ndn/mgmt-pib export /op/alice -o op-alice.safebag
```

Now the operator can issue signed commands: `ndn-ctl` reads the PIB
directly, and the dashboard signs after you import `op-alice.safebag`
(its key is loaded into the dashboard keyring; commands validate against
the anchor configured in step 2). Read-only datasets (`*/list`,
`status/general`, `cs/info`) stay unsigned and work without any of this.

> **Mind the section.** `trust_anchor_pib` lives under `[security.mgmt]`
> — it configures *who may manage this forwarder*. It is **not** the same
> as `[security] identity`, which is the forwarder's *own* signing key (a
> separate role; you don't need it just to accept operator commands). A
> misplaced key is now rejected at startup with an `unknown field` error
> rather than being silently ignored.

## Faces and prefixes

Apps register their own prefixes via the IPC face. The operator
adds static routes for cross-host paths:

```sh
ndn-ctl face create udp://10.0.0.1:6363
ndn-ctl route add /lab faceid:<id>
```

The face ID comes from `face create`'s output; it is monotonic and
never recycled (project memory `feedback_face_id_no_recycle`).

Per-face NDNLPv2 options are toggled with `face update` (the `faces/update`
flag bits — 0 = LocalFields, 1 = LpReliability, 2 = CongestionMarking):

```sh
ndn-ctl face update <id> --flags 0x2   # enable LpReliability on a lossy link
```

Bits outside `--mask` (default: the bits in `--flags`) are preserved. See
[Per-face NDNLPv2 local fields](../reference/face-transports.md#per-face-ndnlpv2-local-fields).

## Logs

`ndn-fwd` writes structured logs to stderr (or the journal under
systemd). Filter and target taxonomy: [Logging](./logging.md).

## State that survives a restart

| Path | Contents |
|---|---|
| `~/.ndn/pib.db` | `KeyChain` identities, keys, certs. |
| `~/.ndn/strategy-choice.toml` | Per-prefix strategy pins. |
| `~/.ndn/routes.toml` | Static route pins added via `ndn-ctl route add --persist`. |
| `~/.ndn/measurements/` (optional) | Strategy measurement state. |

Move or back these up via `deploy/backup.sh`. Restore by copying
back before starting `ndn-fwd`.

## See also

- [Config reference](./config-reference.md) — every `ndn-fwd.toml` knob.
- [Logging](./logging.md) — log targets and filters.
- [Performance](./performance.md) — tuning under load.
- [Management verbs](../reference/mgmt-verbs.md) — one row per
  `nfdc`/`ndn-ctl` verb.
