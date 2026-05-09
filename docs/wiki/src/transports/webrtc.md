# WebRTC Datachannel Face

The WebRTC face turns ndn-rs from "browser-as-client" into
"browser-as-peer". Two browser tabs (or browser ↔ native) exchange
NDN Interests and Data over a reliable, ordered SCTP datachannel
**with no NDN forwarder in the path**.

This is the load-bearing transport for serverless NDN
applications: every browser tab is a forwarding node, peer-to-peer
exchange happens directly, and the only infrastructure required
is a one-shot signaling rendezvous.

Crate: `ndn-face-webrtc`. Public API: [`WebRtcConnector`],
[`WebRtcFace`], [`RtcChannel`].

## How it fits

```
peer A ───── SCTP / DTLS / UDP ───── peer B
   │                                    │
   └── (one-time) signaling rendezvous ─┘
```

The signaling rendezvous is short-lived: peers swap an SDP offer +
answer pair (and any trickle-ICE candidates) once, the SCTP
datachannel comes up, and the rendezvous server is no longer
needed. Bytes flow peer-to-peer for the rest of the session.

## STUN, TURN, NAT

WebRTC needs at least one STUN server to discover its public-facing
address when peers are behind NAT. The default is two of Google's
public STUN endpoints; that is sufficient for the common cases
(home routers, mobile networks, most office Wi-Fi).

Symmetric NAT (corporate firewalls, some cellular carriers)
defeats STUN — direct UDP between peers is impossible and the
connection times out. The fix is a TURN relay, which forwards
encrypted UDP between the peers. TURN is **opt-in** because
operators must supply credentials:

```rust
use ndn_face_webrtc::{IceServers, TurnServer};

let servers = IceServers {
    stun: vec!["stun:stun.l.google.com:19302".into()],
    turn: vec![TurnServer {
        url: "turn:turn.example.com:3478".into(),
        username: "user".into(),
        credential: "secret".into(),
    }],
};
```

For testbed deployments behind a symmetric NAT, the repo's docker
compose ships a `coturn` service.

## Signaling

WebRTC peers must swap SDP descriptions and ICE candidates **out
of band** before the datachannel comes up. The transport for
those bytes is up to the application.

### Manual paste-into-Slack

The simplest possible signaling. Used for the integration test
and one-off demos. Zero infrastructure.

```rust
use ndn_face_webrtc::{IceServers, WebRtcConnector};
use ndn_face_webrtc::signaling::manual::{Bundle, encode_bundle, decode_bundle};

let connector = WebRtcConnector::new(IceServers::default())?;

// peer A
let (offer, pending) = connector.create_offer().await?;
let blob = encode_bundle(&Bundle { description: offer, candidates: vec![] })?;
println!("paste this to peer B: {blob}");

// peer A receives an answer blob over Slack
let answer_blob = read_from_slack();
let answer_bundle: Bundle = decode_bundle(&answer_blob)?;
let face = connector.finalize_with_answer(pending, answer_bundle.description).await?;
```

### HTTP relay (follow-up phase)

A tiny `axum` binary mediates one-shot rendezvous over HTTP POST
+ GET. The test harness uses it for browser↔native and
browser↔browser playwright runs.

### NDN-native signaling — deferred

The "obvious" fit would be `/<peer>/rtc-offer` over an NDN face.
This is a chicken-and-egg problem: NDN-native signaling requires
the peers to already share a discovery face, which is what
WebRTC is bootstrapping. A future phase can add this once we
have a clearer answer to "what does an existing face look like
when neither peer trusts any forwarder yet."

## Trust model

WebRTC encrypts the datachannel via DTLS with an ephemeral
self-signed cert per session. **DTLS is the link layer; NDN
signatures are the trust layer.** Every Data packet carries a
signature that chains to a configured trust anchor exactly the
same way it would on UDP or WebTransport. The DTLS fingerprint
is **not** bound to NDN identity — that complication is
unnecessary as long as ndn-rs is the one consuming both sides.

## Witness status

See `docs/notes/webrtc-design-2026-05-07.md` for the design
rationale and current witness status.

[`WebRtcConnector`]: https://docs.rs/ndn-face-webrtc/latest/ndn_face_webrtc/struct.WebRtcConnector.html
[`WebRtcFace`]: https://docs.rs/ndn-face-webrtc/latest/ndn_face_webrtc/struct.WebRtcFace.html
[`RtcChannel`]: https://docs.rs/ndn-face-webrtc/latest/ndn_face_webrtc/trait.RtcChannel.html
