# WebTransport face

`ndn-fwd` ships a server-side WebTransport listener (issue #14).  Browsers
and other WT clients open a session, and the forwarder treats each session
as a face — one NDN packet per QUIC datagram, NDNLPv2-framed.

## TOML configuration

```toml
[listeners.webtransport]
enabled      = true
listen       = "0.0.0.0:443"
cert_source  = { type = "acme", directory_url = "https://acme-v02.api.letsencrypt.org/directory", email = "ops@example.com", domain = "router.example.com", dns_provider = "cloudflare", params = { api_token = "<token>", zone_id = "<zone>" }, cache_dir = "/var/lib/ndn-fwd/acme" }
```

`cert_source` accepts three shapes:

| `type`             | Use                                                                |
|--------------------|--------------------------------------------------------------------|
| `self_signed_dev`  | Loopback / development. `serverCertificateHashes` browser workflow. |
| `pem`              | `cert_pem`, `key_pem` paths. Bring your own CA.                    |
| `acme`             | RFC 8555 + DNS-01.  Requires a configured `dns_provider`.          |

## The localhost-cert caveat

Browsers refuse self-signed WT certs by default.  Two options for local
development:

1. **`serverCertificateHashes`** — generate a short-lived (≤14 days) cert,
   compute its SHA-256 digest, pass that digest to the browser via the
   `WebTransport` constructor's options bag.  This is the workflow yoursunny
   describes in the issue thread.
2. **Real cert from a public CA** — use `cert_source = { type = "acme", … }`
   with a domain you control.  Let's Encrypt rate limits apply (50/week per
   registered domain); the cert cache under `cache_dir` keeps you well
   below that.

## DNS-01 providers

`ndn-acme` ships with a Cloudflare implementation (`dns_provider =
"cloudflare"`).  Other providers implement the `DnsProvider` trait —
RFC 2136 `nsupdate`, Route 53, etc. — and are linked in by operators.

## Witnesses

- `testbed/tests/audit/i14_wt_loopback.sh` — loopback round-trip via
  `wtransport` self-signed identity.
- `testbed/tests/audit/acme_dns01.sh` — full ACME order against
  [Pebble](https://github.com/letsencrypt/pebble) running in Docker.

Browser-side interop (Playwright) lands in phase 3 of the WASM rollout.
