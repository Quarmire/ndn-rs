# Config reference

`ndn-fwd.toml` configures the forwarder. The shipped example is
`examples/ndn-fwd.example.toml` — every option with
its default in a comment.

This page lists the option groups; consult `examples/ndn-fwd.example.toml`
for the full set with defaults.

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

## `[mgmt]` — management plane

| Key | Default | Use |
|---|---|---|
| `socket` | `/tmp/ndn-fwd.sock` | IPC socket the management protocol listens on. |
| `prefix` | `/localhost/ndn-fwd` | Management protocol prefix. |
| `auth.require` | `false` | Require signed mgmt commands on non-Unix faces. |
| `auth.signer` | (none) | Identity name allowed to sign mgmt commands. |

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
```

Face kinds: `udp`, `tcp`, `unix`, `multicast`, `ether`,
`webtransport`, `ws`, `webrtc`, `shm`, `serial`, `bluetooth`.
See [Face transports](../reference/face-transports.md) for the per-kind options.

## `[[route]]` — static routes

```toml
[[route]]
prefix = "/lab"
face = 0          # face index from [[face]] order
cost = 100        # optional
```

## `[discovery]` — neighbour discovery

| Key | Default | Use |
|---|---|---|
| `enabled` | `true` | Run the autoconf discovery protocol. |
| `discovery_transport` | `udp` | `udp`, `ether`, `both`. |
| `interval_ms` | `5000` | HELLO interval. |

## `[demo_ca]` — embedded NDNCERT CA

Off by default; `enabled = true` runs an in-process CA. See
[NDNCERT setup](../guides/ndncert-setup.md).

| Key | Default | Use |
|---|---|---|
| `enabled` | `false` | Run the embedded CA. |
| `prefix` | `/demo/CA` | CA prefix; issues under the parent namespace. |
| `tokens` | `[]` | Legacy: non-empty selects a token challenge (ignored when `challenge` is set). |
| `emit_attestations` | `false` | Embed a challenge attestation in each issued cert. |

`[[demo_ca.challenge]]` — explicit challenge set (replaces the `tokens`
shortcut). Each entry has `kind = "nop"|"token"|"pin"|"email"`:

```toml
[[demo_ca.challenge]]
kind = "email"
ttl_secs = 300
smtp = { host = "smtp.example.com", port = 587, from = "ca@example.com", starttls = true }
```

`email` delivers via SMTP only with `--features smtp` (lettre); otherwise (or
with `smtp.log_only = true`) the code is logged. `[demo_ca.require_attestation]`
(`prefix`/`kind`/`require_signed`) gates issuance on a challenge attestation.
`possession`/`yubikey`/`device-approval` are wired in code.

## `[log]` — log filter

| Key | Default | Use |
|---|---|---|
| `filter` | `info` | `RUST_LOG`-style filter (`info,ndn_engine=debug`). |
| `format` | `compact` | `compact`, `json`, `pretty`. |
| `with_target` | `true` | Include the tracing target. |

## `[rate_limit]` — token-bucket rate limits

Per project memory `project_dashboard_multi_forwarder`.

## See also

- `examples/ndn-fwd.example.toml` — the source of truth; every key with
  defaults and inline comments.
- [ndn-fwd](./ndn-fwd.md) — operator workflows.
- [Face transports](../reference/face-transports.md) — per-face
  configuration shapes.
