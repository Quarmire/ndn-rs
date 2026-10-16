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

Off by default; `enabled = true` runs an in-process CA serving
`/<prefix>/CA/{INFO,NEW,CHALLENGE/<id>,REVOKE}` and cert-fetch for the certs
it issued. See [NDNCERT setup](../guides/ndncert-setup.md).

| Key | Default | Use |
|---|---|---|
| `enabled` | `false` | Run the embedded CA. |
| `prefix` | `/demo` | CA namespace. The CA appends `/CA` itself (as do clients); a prefix ending in `/CA` is rejected at startup. |
| `identity` | `/demo/CA` | CA signing identity, loaded from the node PIB (`[security] pib_path`). |
| `ephemeral` | `false` | Mint a throwaway self-signed CA key at every start instead of loading `identity` (demo only; warned). |
| `tokens` | `[]` | Legacy: non-empty selects a token challenge (ignored when `challenge` is set). |
| `emit_attestations` | `false` | Embed a challenge attestation in each issued cert. |

Without `ephemeral`, the CA loads its key from the PIB and its certificate
(issued by the hub root) from `<pib_path>/ca/ca-cert.data`; the root's anchor
certificate is `<pib_path>/ca/anchor-cert.data` or a PIB trust anchor. `ndn-fwd
init --profile hub` writes all three. Startup fails if they are missing,
mismatched, or the CA cert is not signed by the root. Issued certs,
revocations and redeemed one-time tokens (SHA-256 hashes only) persist under
`<pib_path>/ca/{issued,revoked,redeemed-tokens}/`: issued certs are served
again after a restart, revoked ones are not, and a token redeemed before a
restart stays refused even while it is still listed in the config.

`ndn-fwd init --profile hub --namespace /<ns> [--node-name <name>]` also mints
the hub node's own identity `/<ns>/<name>` (default `hub`; key
`/<ns>/<name>/KEY/node`, cert issued by the root, signed copy at
`<pib_path>/ca/node-cert.data`) and prints the `[security]` lines that load
it (`identity = "/<ns>/<name>"`, `pib_path = "<pib>"`); without them the
forwarder falls back to an ephemeral key. Init never edits config files.

`[[demo_ca.challenge]]` — explicit challenge set (replaces the `tokens`
shortcut). Each entry has `kind = "nop"|"token"|"pin"|"email"|"device-approval"`.
The CA refuses to start with no challenge configured; `nop` (auto-approve
every request) is only offered when listed explicitly.

```toml
[[demo_ca.challenge]]
kind = "email"
ttl_secs = 300
smtp = { host = "smtp.example.com", port = 587, from = "ca@example.com", starttls = true }
```

`email` delivers via SMTP only with `--features smtp` (lettre); otherwise (or
with `smtp.log_only = true`) the code is logged. `device-approval` holds each
request until it is approved or denied over mgmt
(`/localhost/nfd/ca/{list-approvals,approve,deny}`; `uri` = `<id>` or
`<id>:<reason>`) or an approver device sends a signed approval to
`/<prefix>/CA/APPROVE-FEED` that validates against the node's trust contexts;
all three share one pending-approval store.
`[demo_ca.require_attestation]` (`prefix`/`kind`/`require_signed`) gates
issuance on a challenge attestation. `possession`/`yubikey` are wired in code.

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
