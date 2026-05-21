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
| `ndn-ctl status` | Forwarder summary: uptime, version, mgmt prefix, face count. |
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

## Faces and prefixes

Apps register their own prefixes via the IPC face. The operator
adds static routes for cross-host paths:

```sh
ndn-ctl face create udp://10.0.0.1:6363
ndn-ctl route add /lab faceid:<id>
```

The face ID comes from `face create`'s output; it is monotonic and
never recycled (project memory `feedback_face_id_no_recycle`).

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
