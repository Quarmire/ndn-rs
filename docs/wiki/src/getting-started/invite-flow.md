# Invite tokens — operator side

The forwarder's embedded NDNCERT CA can run in two modes:

- **Auto-approve (`NopChallenge`)** — every NEW request is approved.
  This is what `[demo_ca]` defaulted to before invite tokens
  landed. Only safe behind a trusted local face; the moment the
  CA is reachable from the open internet, anyone can mint a cert
  under your namespace.
- **Invite-token (`TokenChallenge`)** — every NEW request must
  present a one-shot pre-provisioned token. Tokens are minted
  out-of-band (you control supply), shared with users via a URL
  or QR code, and consumed on first use. This is the production
  shape for any CA reachable beyond loopback.

This page is the operator-side surface.

## Switching the demo CA to invite-token mode

In your `ndn-fwd.toml`:

```toml
[demo_ca]
enabled = true
prefix  = "/com/example/CA"
identity = "/com/example/CA"
# Pre-provisioned one-time tokens. An empty list (or omitting the
# field) keeps the CA in auto-approve mode.
tokens = [
    "8f3a7b2c91d04e6589a5e1d4c7f02a96",
    "4b1e8d3a92c75f068b1a4c9e7d63f102",
]
```

Restart `ndn-fwd`. The startup log will read:

```text
demo_ca  TokenChallenge — invite-token gated enrollment  count=2
```

Each token in the list is consumed on first successful enrollment;
once consumed, the CA rejects subsequent attempts to use it. Add
new tokens by editing the toml and restarting (live management
of the TokenStore via the `/localhost/nfd/...` socket is a
follow-on).

## Sharing an invite

Each token in `tokens` becomes a join URL of the form:

```text
https://<your-domain>/?join=<token>
```

The user clicks (or scans a QR pointing at) the URL. The
browser's `JoinClient` (in `dioxus-demo`'s `shared-engine`
bundle) pulls the token from the URL fragment, runs the
NDNCERT NEW + CHALLENGE round-trip, and on success persists
the issued cert to the per-origin IndexedDB so reloads
short-circuit.

Token shape: any bytes / string the operator chooses.
Recommended: 16-byte random (`openssl rand -hex 16` or
equivalent) — long enough to resist guessing, short enough to
fit in a QR code without padding. The CA does not interpret
the token; it just checks set membership.

## Generating tokens

Until a built-in `ndn-fwd-tokens` CLI lands, mint tokens
manually:

```bash
# 16 random bytes, hex-encoded
openssl rand -hex 16

# Or with /dev/urandom
head -c 16 /dev/urandom | xxd -p
```

Copy each token into `ndn-fwd.toml`'s `tokens = [...]` list and
restart. The matching join URL goes to the user.

## Revoking an invite

Tokens are consumed on use, so most "revocation" is automatic.
For an unsent or unclaimed token: remove it from `tokens` in
the toml and restart. The token is gone before the first claim
attempt.

For a *claimed* identity (revoking the cert, not the token):
that's a different flow — NDNCERT REVOKE, served by the same
CA. See [NDNCERT setup](ndncert-setup.md) for the cert-side
revocation surface.

## Security notes

- The token list is shared secret material. The toml is bind-
  mounted into the container at `/etc/ndn-fwd/config.toml:ro`;
  on a multi-user host treat the file as 0600. The compose file
  uses a docker volume so unprivileged container users can't
  read it.
- Tokens in the URL fragment are NOT sent to the server in HTTP
  request lines (browsers strip fragments before sending). The
  fragment goes only into the page's wasm module and from there
  via NDN to the CA.
- A leaked token can be claimed by anyone who has it; the CA
  has no way to authenticate the *human* on the other end of
  the URL. If a token leaks before its intended user claims it,
  remove it from the list.

## Follow-ups (not yet shipped)

- `ndn-fwd-tokens add` / `list` / `remove` CLI for live token
  management without restarts.
- QR-code generation built into the CLI (PNG to stdout / file).
- Out-of-band revocation channel (`/localhost/nfd/...` mgmt
  command).
