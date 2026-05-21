# Self-hosting

This guide deploys the full ndn-rs stack — forwarder, NDNCERT CA,
signaling relay, dashboard — to your own host with
`docker-compose`. The artefacts live at `deploy/` in the repo.

Per project memory `project_self_hosted_stack`, the stack landed
2026-05-10 and is the canonical self-hosting recipe.

## Prerequisites

- Docker + docker-compose (or compatible: Podman, Colima).
- A host you can reach over UDP/6363 (or whichever face port you
  expose) and HTTPS/443 (for the dashboard).
- A domain name (optional but convenient).

## What ships in `deploy/`

| File | Purpose |
|---|---|
| `deploy/docker-compose.yml` | Forwarder + CA + relay + dashboard. |
| `deploy/ndn-fwd.example.toml` | Forwarder config; copy to `ndn-fwd.toml`. |
| `deploy/install.sh` | Bootstrap: pulls images, seeds identities, brings up the stack. |
| `deploy/backup.sh` | Snapshots PIB, KeyChain, and config. |
| `deploy/relay/Dockerfile` | Signaling relay for WebRTC datachannel face. |

## Bring up the stack

```sh
cd deploy/
cp ndn-fwd.example.toml ndn-fwd.toml
# edit ndn-fwd.toml for your host:
#   [mgmt] socket, [face.udp] listen, [face.ws] listen, [ndncert.ca] identity

./install.sh
```

`install.sh` runs (in order):

1. `docker-compose pull` — fetch images.
2. Generates a fresh CA identity if one does not exist under
   `data/ndn/`.
3. Brings up `ndn-fwd`, `ndncert-ca`, `signaling-relay`, and
   `ndn-dashboard` services.
4. Reports the URLs and the operator invite token.

## Persistent state

Mounted under `deploy/data/`:

| Path | Contents |
|---|---|
| `data/ndn/pib.db` | KeyChain identities + keys (back up regularly). |
| `data/ndn/certs/` | Issued certificates. |
| `data/ndn/strategy-choice.toml` | Per-prefix strategy pins. |
| `data/ndn/routes.toml` | Static route pins. |

`backup.sh` tars these into a single archive; restore by extracting
to the same paths before `install.sh`.

## Image policy

Per project memory `feedback_docker_rust_version`, the Dockerfiles
use `rust:slim` (latest stable), not pinned `rust:X.Y-slim`. The
MSRV is read from `rust-toolchain.toml`.

## Update

```sh
docker-compose pull
docker-compose up -d
```

The forwarder rolls cleanly: open faces drain, the engine restarts,
faces re-establish. Active app sessions over IPC are interrupted
and reconnect.

## Exposing only what you need

The default compose file exposes:

- UDP/6363 — NDN-over-UDP face.
- TCP/6363 — NDN-over-TCP face.
- TCP/443 — dashboard + WebSocket face (behind reverse proxy).
- Internal-only — Unix socket for IPC; CA `/CA` namespace; relay.

If you don't need the dashboard externally, drop the 443 export.
If you don't need cross-host faces, drop the 6363 export and run
the stack as a local NDN substrate only.

## Trust roots

The CA's self-signed cert is the trust anchor for everything else.
On first run, `install.sh` writes the cert to
`deploy/data/ndn/trust-root.cert`. Distribute that cert to clients
that need to verify identities under this CA's namespace.

## Operator key

The operator key is the identity that signs mgmt commands. By
default `install.sh` creates `/<your-ca>/operator` and stores it
encrypted under `data/ndn/operator.safebag`. To use it from another
machine, copy the SafeBag and import:

```sh
ndn-ctl identity import /tmp/operator.safebag
```

## See also

- [Running the dashboard](./running-the-dashboard.md) — dashboard
  modes.
- [NDNCERT setup](./ndncert-setup.md) — CA configuration in depth.
- [ndn-fwd](../operations/ndn-fwd.md) — forwarder ops surface.
- [Config reference](../operations/config-reference.md) — every
  `ndn-fwd.toml` knob.
