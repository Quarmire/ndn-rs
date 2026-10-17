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

## `[security]` — trust contexts

| Key | Default | Use |
|---|---|---|
| `serve_contexts` | `true` | Publish every trust context in `<pib_path>/contexts/` by name over RDR: `/<ns>/32=trust-context/32=metadata` names the newest stored version, `/<ns>/32=trust-context/v=<N>` returns the stored signed Data of each version held, verbatim (so nodes behind this one can follow the namespace version by version). Read at startup. See [Trust-context publication](../reference/trust-context-publication.md). |
| `trust_admin_groups` | `[]` | Unix groups whose members may change this node's trust over the local management socket: the verbs in `TRUST_ADMIN_VERBS` (`ndn-mgmt/src/auth.rs`) — `security/context-adopt` (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`), `security/renew` (`ndn-fwd renew`), `security/revoke` (`ndn-fwd revoke`), `security/context-refresh` (`ndn-fwd context refresh`) and `security/context-update` (`ndn-fwd recovery-kit`, `ndn-fwd recover`). The daemon's own user and root are always allowed; everyone else is refused, and these verbs are always refused over `/localhop`. Membership is checked against the caller's kernel-reported socket credentials (primary gid, the group's member list, and on Linux the caller's supplementary groups). Read at startup. |
| `context_refresh_secs` | `300` | How often, in seconds, the daemon checks every held trust context for a newer version (RDR metadata upstream) and adopts one signed by an anchor of the held version and strictly newer — or, when a recovery installed a new root in between, follows the versions in between one by one — then stores and republishes it — how a [revocation](../reference/revocation.md) reaches this node. The first check runs `min(context_refresh_secs, 30)` s after start. `0` disables the periodic check; `ndn-fwd context refresh` still works. A missed check only delays an update. The root device (whose PIB holds the root key) does not fetch its own namespace. See [Trust-context updates](../reference/context-updates.md). |
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
| `tokens` | `[]` | Legacy: non-empty selects a token challenge (ignored when `challenge` is set). A token `member-…` / `guest-…` (as `ndn-fwd-tokens new --role` mints them) is scoped to `<namespace>/<role>`. |
| `emit_attestations` | `false` | Embed a challenge attestation in each issued cert. |
| `cert_validity_days` | `90` | Lifetime of the certificates the CA issues, in days: one number for every role, or a `[ca.cert_validity_days]` table with `admin` / `member` / `node` / `guest` and `default` for the roles not listed (e.g. `default = 90`, `guest = 7`). The longest is the maximum advertised in INFO. Enrollments and renewals name no lifetime, so they get their role's; `ndn-fwd enroll` / `ndn-fwd renew` print the expiry issued. `0` or an unknown role is refused at startup. |
| `renewable_roles` | `["admin", "member", "node"]` | Roles whose current, unrevoked certificates the CA renews for the same key without an invite ([Certificate renewal](../reference/renewal.md)). Guests are left out by default, so guest access ends at expiry. `[]`: the CA renews nothing. |

Without `ephemeral`, the CA loads its key from the PIB and its certificate
(issued by the namespace root) from `<pib_path>/ca/ca-cert.data`; the root's anchor
certificate is `<pib_path>/ca/anchor-cert.data` or a PIB trust anchor. `ndn-fwd
init --namespace <ns>` writes all three. Startup fails if they are missing,
mismatched, or the CA cert is not signed by the root. Issued certs,
revocations and redeemed one-time tokens (SHA-256 hashes only) persist under
`<pib_path>/ca/{issued,revoked,redeemed-tokens}/`: issued certs are served
again after a restart, revoked ones are not, and a token redeemed before a
restart stays refused even while it is still listed in the config.

`ndn-fwd init --namespace /<ns> [--device <name>]` (run on the root device)
also mints the root device's admin identity `/<ns>/admin/<device>` (default device
name: the host name, lowercased, first label, disallowed characters as `-`;
`KEY`, `CA` and the role words are refused; key
`/<ns>/admin/<device>/KEY/device`, cert issued by the CA, signed copy at
`<pib_path>/ca/device-cert.data`), stores the root-signed trust context
carrying the generated role schema (`ndn-fwd schema show`), and prints the
`[security]` lines that load the device identity
(`identity = "/<ns>/admin/<device>"`, `pib_path = "<pib>"`); without them the
forwarder falls back to an ephemeral key. Init never edits config files.

The root key itself goes to the root store chosen with `init --root-store`
(`os-keyring` by default when an OS keychain is reachable, else refused with
advice; `sealed-file`, `yubikey-piv`, `file`), recorded in
`<pib_path>/root/store.toml` — no config key selects it; see
[root custody](../concepts/identity-and-keys.md#root-custody-where-a-namespace-root-key-lives).
The daemon reports it in `security/identity-status` (`root_store=`,
`root_unlock=`; shown by `ndn-ctl status`) and warns at startup when it is
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
request until it is approved or denied over mgmt
(`/localhost/nfd/ca/{list-approvals,approve,deny}`; `uri` = `<id>` or
`<id>:<reason>`) or an approver device sends a signed approval to
`/<prefix>/CA/APPROVE-FEED` that validates against the node's trust contexts;
all three share one pending-approval store.
`[ca.require_attestation]` (`prefix`/`kind`/`require_signed`) gates
issuance on a challenge attestation (on a namespace CA, on top of the role layout).
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
