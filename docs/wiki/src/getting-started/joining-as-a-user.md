# Joining as a user

Someone gave you a link or a QR code. Here's what's actually
happening when you click it.

## The link

```text
https://ndn.example.com/?join=8f3a7b2c91d04e6589a5e1d4c7f02a96
```

The bit after `?join=` is your invite token — a one-shot pass
the host minted just for you. Click the link (or point your
phone's camera at the QR), and the host's web page does the
rest:

1. Loads the `JoinClient` wasm bundle (~200 KB; cached after
   the first visit).
2. Pulls the token out of the URL.
3. Runs the NDNCERT enrollment round-trip with the host's CA,
   submitting the token as the challenge response.
4. On success: persists your issued certificate to your
   browser's IndexedDB so future visits skip straight to step 5.
5. Shows you your identity (the cert name) and unlocks the
   producer / consumer UI.

End-to-end target: under 30 seconds on LTE. If it's slower,
the WebRTC handshake is the most likely culprit; the host
operator should check that ICE gathering is configured for
non-trickle so the SDP is bundled in a single round trip.

## What's persisted

Your identity is stored in your browser's IndexedDB as a **SafeBag**
— the same canonical NDN container `ndnsec export` produces. One
file (well, one IndexedDB row) carries:

- Your identity name (`/com/example/users/<random-id>`).
- Your signing key (16 bytes; never leaves your browser).
- The issued certificate (your proof to the network that the
  identity name is yours).

This data is **per-origin** — the host's domain is the key.
A different domain serving a different ndn-rs deployment gets
its own IndexedDB; cross-origin reads are impossible.

It's also **per-browser** — Chrome on your laptop and Chrome
on your phone are different stores. If you join from one
device, you don't automatically appear on the other; you
either re-join (each token is one-shot, so the operator gives
you a second one) or future device-pairing UX (not yet
shipped) bridges them via SVS.

## What if I close all the tabs

The SharedWorker that hosts the engine dies when its last
connected port closes (W3C rule). The next tab you open
re-spawns the worker; the worker pulls your identity back
from IndexedDB and you're connected again — no re-join, no
new token needed.

Both halves of your identity round-trip through IndexedDB: the
issued cert AND the encrypted signing key, bundled as a SafeBag.
Reload is a true zero-cost short-circuit — no NDNCERT round-trip,
the restored signer is the same one you started with.

The SafeBag wire format is the spec-canonical container the rest
of the NDN ecosystem speaks. In principle a future "Export
identity" button on the host's page will hand you the same bytes
`ndnsec export` would produce; you can carry that file to a
native machine and `ndnsec import` it to sign Data from the
command-line as the same identity. (Today the export button isn't
shipped — but the bytes are already in the right shape, so when
it lands the interop is free.)

> **Where the encryption key lives.** The SafeBag encrypts your
> private key with a passphrase. Today that passphrase lives in
> your browser's IndexedDB right next to the bag — meaning a
> hostile browser extension or an XSS bug at the host's origin
> could lift both. This is the honest truth about the current
> threat model and matches what every "in-browser key" service
> ships before WebAuthn integration. The wire shape is forward-
> compatible: a future version derives the passphrase from a
> WebAuthn passkey or asks you to type it; only the passphrase
> source changes, the SafeBag bytes stay the same.

## What if I clear my browser data

Same as never having joined. The operator can give you a fresh
invite token; the join flow is identical to the first time.

## Logging out

Hit the "forget identity" button on the page (or, equivalently,
clear the host's site data in your browser's settings). The
IndexedDB entries are dropped; subsequent visits show the
landing page. The host's CA can also revoke your cert
out-of-band (NDNCERT REVOKE).

## What the operator sees

From the operator's perspective, an enrollment looks like:

```text
demo_ca  NEW request  identity=/com/example/users/8f3a7b2c
demo_ca  CHALLENGE token  consumed=8f3a7b2c91d04e6589a5e1d4c7f02a96
demo_ca  cert issued  name=/com/example/users/8f3a7b2c/KEY/k1/CA/v=1
```

The operator gave out the token; you claimed it. The token is
now spent — no one else can use it. Your cert chains back to
the host's CA, which is itself the local trust anchor for the
session.

## Troubleshooting

**The page says "join failed: token already claimed"** — the
token has been used. Ask the operator for a fresh one. (Or,
if you think someone else claimed *your* token: tell the
operator immediately so they revoke that cert.)

**The page says "join failed: timeout"** — the browser couldn't
reach the host's WebTransport endpoint within the lifetime
window. Most often: a flaky network, or the host isn't
serving WebTransport on 443. Try again; if it persists, check
with the operator.

**The page says "no token in URL"** — you visited the host
without the `?join=...` fragment, and there's no cached
identity in your browser. Get a fresh invite link from the
operator.
