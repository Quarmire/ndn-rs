# Self-hosting ndn-rs

This page walks an operator from "fresh VPS" to "running NDN
forwarder with Let's Encrypt TLS, WebRTC peer rendezvous, and
auto-update on a stable release channel." Audience is anyone who
already self-hosts Mastodon, Matrix, Tailscale, or NextCloud — same
shape: a docker-compose file, a config, an installer, and an
upgrade story you can ignore.

## What you need

- A domain you control (`ndn.example.com`).
- A small Linux VPS — 1 vCPU / 2 GB RAM is enough for a personal
  forwarder. Ports 443 (TCP, for WebTransport) and 6363 (UDP+TCP,
  for native NDN faces) reachable.
- Docker Engine + the `compose` v2 plugin
  ([install instructions](https://docs.docker.com/engine/install/)).
- An ACME-friendly DNS provider. Cloudflare is the smoothest path
  out of the box; any other DNS provider with an `instant-acme`
  registered impl works.

## One-shot install

```bash
curl -fsSL https://raw.githubusercontent.com/named-data/ndn-rs/main/deploy/install.sh | bash
```

The installer asks four questions:

1. Your domain (FQDN).
2. Your email (for the Let's Encrypt account).
3. DNS provider name (`cloudflare`, `route53`, `manual`).
4. Your NDN namespace prefix — defaults to the reverse-DNS of your
   domain.

For Cloudflare it also asks for an API token (DNS:Edit on the zone)
and zone id. The installer writes `ndn-fwd.toml` and `.env` into
the deploy directory and runs `docker compose up -d`.

Re-running the installer is safe — it refreshes config from your
answers; existing volumes (PIB, ACME cache) are preserved.

## What's running

After the installer completes:

```text
$ docker compose ps
NAME                       STATUS    PORTS
ndn-fwd                    Up        host networking (UDP/TCP 6363, TCP 443, TCP 9696)
ndn-signaling-relay        Up        0.0.0.0:8888->8888/tcp
```

- **`ndn-fwd`** — the NDN forwarder. Hosts WebTransport at
  `https://<your-domain>/ndn` (no `?cert=` query string needed —
  the cert chains to a real CA). Hosts WebSocket at port 9696 and
  raw UDP/TCP NDN at 6363.
- **`ndn-signaling-relay`** — HTTP rendezvous for WebRTC peering.
  Browser tabs use this to bootstrap browser↔browser NDN sessions.
- **`watchtower`** *(opt-in, see Upgrades below)* — checks for new
  image tags hourly, restarts containers on update.

The first startup performs an ACME order via DNS-01 against your
DNS provider. Watch the logs:

```bash
docker compose logs -f ndn-fwd
```

The cert is cached on the `ndn-fwd-acme` volume; subsequent restarts
skip the order until ~30 days before expiry. Renewal happens
in-place; no operator action.

## Upgrades

ndn-rs ships three image tag aliases:

| Tag         | Updates                                         | Use when                            |
|-------------|-------------------------------------------------|-------------------------------------|
| `:vX.Y.Z`   | never (frozen)                                  | strict change-control environments  |
| `:vX-stable`| minor + patch (e.g. v0.1.3 → v0.1.4 → v0.2.0)   | **default for self-hosters**        |
| `:latest`   | every release                                   | tracking the bleeding edge          |

The compose file defaults to `:v0-stable`. A self-hoster who never
edits anything gets safe rolling updates on the major-zero stable
channel, which guarantees no schema-breaking config changes between
patches.

To turn auto-update on:

```bash
docker compose --profile watchtower up -d
```

Watchtower polls Docker Hub hourly, pulls any tag changes for the
labelled containers, and restarts them. It only acts on containers
labelled `com.centurylinklabs.watchtower.enable=true` (both ndn-rs
services in this compose file are).

To turn it off:

```bash
docker compose --profile watchtower stop watchtower
docker compose --profile watchtower rm watchtower
```

To pin a specific version, set the env in `.env`:

```bash
NDN_FWD_TAG=v0.1.3
NDN_RELAY_TAG=v0.1.3
```

…then `docker compose up -d` to roll forward.

## Backup and restore

The state worth preserving lives in three docker volumes:

- **`ndn-fwd-config`** — your toml, trust-anchor pem, signing identity.
- **`ndn-fwd-pib`** — the personal information base (issued certs,
  key chain).
- **`ndn-fwd-acme`** — the ACME cert cache. Excluding this from a
  restore means the first restart will re-issue, which trips
  Let's Encrypt's rate limiter.

```bash
./backup.sh > ndn-fwd-$(date +%F).tar.gz
```

That captures all three volumes. Cron-friendly:

```cron
0 3 * * * cd /opt/ndn-rs-deploy && ./backup.sh > /var/backups/ndn-fwd/$(date +\%F).tar.gz
```

To restore:

```bash
docker compose down
tar -xzf ndn-fwd-2026-05-10.tar.gz -C /var/lib/docker/volumes/
docker compose up -d
```

## Troubleshooting

**ACME order fails: "DNS challenge propagation timeout"**

Your DNS provider didn't propagate the TXT record fast enough.
Re-run `docker compose restart ndn-fwd` to retry; if it persists,
check the provider's API token has DNS:Edit on the zone. Cloudflare
tokens are scoped at creation; the installer's token must list the
exact zone id.

**Port 443 already in use**

Another service (nginx, Caddy, …) is bound to 443. Either stop it
or change `[listeners.webtransport].listen` in `ndn-fwd.toml` to
a different port — but note browsers can only reach WebTransport on
443 by default; using a non-443 port forces clients to dial
explicitly.

**No NDN peers reachable**

By default the forwarder doesn't auto-join the global NDN testbed.
Either configure NLSR neighbors in `[routing.nlsr]` (see
[NLSR setup](../guides/nlsr-setup.md)) or uncomment the testbed
multicast face in `ndn-fwd.toml`.

**Browser can't connect to WebTransport**

Three things to check:

1. The cert is real (not self-signed). Run
   `curl -v https://<your-domain>/ndn` — the TLS section should
   show "Server certificate: subject=CN=…, issuer=CN=R3,O=Let's
   Encrypt".
2. Your domain resolves to the VPS. `dig +short <your-domain>`
   should return the VPS's public IP.
3. The browser supports WebTransport. Recent Chromium (≥97) and
   Firefox (≥114) do; Safari is still partial. Open
   `chrome://webtransport-internals/` to confirm sessions are
   being attempted.

## What's not yet automated

- **Status page (`/status`)** — a small dashboard showing face
  count, peer count, ACME expiry. Drafted but not yet shipped;
  meanwhile, `docker compose logs ndn-fwd | grep -E 'ACME|face_up'`
  is the manual surface.
- **`migrate-config.sh`** — schema migrations on the
  `ndn-fwd.toml` file. Not yet needed (we're at v0.1; no
  cross-version schema breaks). Will land before any v0.2.x or
  v1.0.0 release that changes the toml shape.
- **NDNCERT CA** — the forwarder can run an NDNCERT CA at
  `/<namespace>/CA` (see `[demo_ca]` in the example toml), but the
  default config doesn't enable it; namespaces that need to issue
  user certs should add an NDNCERT block per the
  [NDNCERT setup guide](../guides/ndncert-setup.md).
