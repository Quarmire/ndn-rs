//! Remote-signer custodian — the operator key lives on *another* device or
//! process (a phone, a second machine, a hardware token, a server), which
//! gates each signature (typically with biometric / a tap) and signs on the
//! dashboard's behalf. The key never touches this host, so it's the desktop
//! dashboard's real per-use second factor (where a local keychain can't be,
//! on an unsigned build).
//!
//! A phone "fob" is one instance — it's just a [`RemoteCustodian`] reporting
//! [`CustodianRef::Fob`]; a networked signer reports [`CustodianRef::Remote`].
//!
//! This module is the **dashboard side + the wire contract**: the
//! [`RemoteSignerTransport`] channel (concrete impls ride an NDN face —
//! WebRTC, BLE, Wi-Fi Aware — or a relay) and [`RemoteCustodian`], which
//! delegates [`Custodian::sign`] to the remote signer. The signer app
//! implements the matching responder against the same [`RemoteSignRequest`].
//!
//! Full design + protocol + security model:
//! `.claude/notes/remote-fob-design-2026-06-01.md`.

// `CustodianError` is intentionally large (it carries a `Name`); the type
// already opts out of `large_enum_variant`, so the codec's fallible helpers
// opt out of the matching `Result`-size lint for consistency.
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::custodian::KeyId;
use crate::custodian::custodian::{
    Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
};

/// A signing request sent to the remote signer.
///
/// `context` is the human-readable summary of *what* is being authorized
/// (e.g. the command name) — the remote device shows it so the operator
/// approves the real action, not a blind blob. This is the MITM defence: a
/// tampered `region` surfaces as a different `context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignRequest {
    /// Key name the dashboard expects the signer to sign with.
    pub key_name: Name,
    /// The exact bytes to sign (the command's signed region).
    pub region: Bytes,
    /// Human-readable summary shown on the remote device for approval.
    pub context: String,
}

/// The channel to the remote signer. Concrete impls ride an NDN face (WebRTC /
/// BLE / Wi-Fi Aware) or a relay; a loopback impl backs tests so the
/// delegation logic is testable without a real device or channel.
#[async_trait]
pub trait RemoteSignerTransport: Send + Sync {
    /// Send `req` to the remote signer and await the operator-approved
    /// signature. Errors when it's unreachable, denies, or times out.
    async fn request_signature(&self, req: &RemoteSignRequest) -> Result<Bytes, CustodianError>;

    /// Whether the remote signer is reachable right now.
    async fn is_reachable(&self) -> bool;
}

/// A [`Custodian`] whose key lives on a remote signer. `sign` delegates to it
/// over a [`RemoteSignerTransport`]; the remote device gates each signature.
/// The private key never touches this host. `kind` lets the caller say what
/// the signer is (a phone [`CustodianRef::Fob`], a networked
/// [`CustodianRef::Remote`], a [`CustodianRef::Tpm`], …).
pub struct RemoteCustodian {
    transport: Arc<dyn RemoteSignerTransport>,
    kind: CustodianRef,
}

impl RemoteCustodian {
    pub fn new(transport: Arc<dyn RemoteSignerTransport>, kind: CustodianRef) -> Self {
        Self { transport, kind }
    }
}

#[async_trait]
impl Custodian for RemoteCustodian {
    fn kind(&self) -> CustodianRef {
        self.kind.clone()
    }

    async fn is_available(&self) -> bool {
        self.transport.is_reachable().await
    }

    fn prompts_per_action(&self) -> bool {
        true
    }

    async fn unlock(&self, _ctx: UnlockContext) -> Result<(), CustodianError> {
        if self.transport.is_reachable().await {
            Ok(())
        } else {
            Err(CustodianError::Unavailable)
        }
    }

    async fn sign(
        &self,
        _key_id: &KeyId,
        name: &Name,
        content: &[u8],
    ) -> Result<Bytes, CustodianError> {
        let req = RemoteSignRequest {
            key_name: name.clone(),
            region: Bytes::copy_from_slice(content),
            context: format!("Authorize a signed command as {name}"),
        };
        self.transport.request_signature(&req).await
    }

    async fn unwrap_for(
        &self,
        _key_id: &KeyId,
        _wrapped: &WrappedKey,
    ) -> Result<UnwrappedKey, CustodianError> {
        // Content-key unwrap on a remote signer is a later phase (it would
        // unwrap after UV); signing is the v1 capability.
        Err(CustodianError::Unavailable)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Wire protocol — the contract the remote signer app implements.
//
// Carried as datachannel frames (a paired phone over a WebRTC datachannel, BLE,
// …) and encoded as NDN TLV (via `ndn-tlv`) with application-specific extension
// type codes. This is a **non-standard ndn-rs extension**, not an NDN
// community spec.
//
// Only the bytes-to-sign (`region`) and a correlation id cross the wire. The
// signer app renders *what it is signing* from `region` itself — it parses the
// embedded command name and shows that for approval — so a compromised
// dashboard cannot present a benign summary for malicious bytes. That parse is
// the real MITM defence; a human "context" string supplied by the dashboard
// would not be covered by the operator's signature, so it is advisory only and
// never transmitted.

/// Extension TLV type codes for the remote-signer protocol (non-standard).
mod tlv {
    pub const SIGN_REQUEST: u64 = 0x0640;
    pub const SIGN_RESPONSE: u64 = 0x0642;
    pub const REQ_ID: u64 = 0x0644;
    pub const REGION: u64 = 0x0646;
    pub const STATUS: u64 = 0x0648;
    pub const SIGNATURE: u64 = 0x064A;
    // Pairing handshake (the QR the phone scans).
    pub const PAIRING_OFFER: u64 = 0x0650;
    pub const DASHBOARD_PUBKEY: u64 = 0x0651;
    pub const TRANSPORT_HINT: u64 = 0x0652;
    pub const NONCE: u64 = 0x0653;
}

const STATUS_APPROVED: u8 = 1;
const STATUS_DENIED: u8 = 0;

fn wire_err(e: ndn_tlv::TlvError) -> CustodianError {
    CustodianError::SignFailed(format!("malformed remote-signer frame: {e:?}"))
}
fn missing(field: &str) -> CustodianError {
    CustodianError::SignFailed(format!("remote-signer frame missing {field}"))
}
fn decode_req_id(v: &[u8]) -> Result<u64, CustodianError> {
    let arr: [u8; 8] = v
        .try_into()
        .map_err(|_| CustodianError::SignFailed("ReqId must be 8 bytes".into()))?;
    Ok(u64::from_be_bytes(arr))
}

/// On-wire signing request the remote signer receives. `region` is the exact
/// bytes to sign; `req_id` correlates the reply on a shared channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireSignRequest {
    pub req_id: u64,
    pub region: Bytes,
}

impl WireSignRequest {
    /// Encode to a datachannel frame.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::SIGN_REQUEST, |w| {
            w.write_tlv(tlv::REQ_ID, &self.req_id.to_be_bytes());
            w.write_tlv(tlv::REGION, &self.region);
        });
        w.finish()
    }

    /// Decode a datachannel frame. Unknown inner elements are ignored
    /// (forward-compatible).
    pub fn decode(wire: &[u8]) -> Result<Self, CustodianError> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(wire));
        let (typ, body) = r.read_tlv().map_err(wire_err)?;
        if typ != tlv::SIGN_REQUEST {
            return Err(CustodianError::SignFailed(format!(
                "unexpected message type {typ:#x}, want SignRequest"
            )));
        }
        let (mut req_id, mut region) = (None, None);
        let mut br = TlvReader::new(body);
        while !br.is_empty() {
            let (t, v) = br.read_tlv().map_err(wire_err)?;
            match t {
                tlv::REQ_ID => req_id = Some(decode_req_id(&v)?),
                tlv::REGION => region = Some(v),
                _ => {}
            }
        }
        Ok(Self {
            req_id: req_id.ok_or_else(|| missing("ReqId"))?,
            region: region.ok_or_else(|| missing("Region"))?,
        })
    }
}

/// The remote signer's reply to a [`WireSignRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireSignResponse {
    /// Operator approved; carries the signature over the request's `region`.
    Approved { req_id: u64, signature: Bytes },
    /// Operator declined, or the request could not be satisfied.
    Denied { req_id: u64 },
}

impl WireSignResponse {
    pub fn req_id(&self) -> u64 {
        match self {
            Self::Approved { req_id, .. } | Self::Denied { req_id } => *req_id,
        }
    }

    /// Encode to a datachannel frame.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::SIGN_RESPONSE, |w| match self {
            Self::Approved { req_id, signature } => {
                w.write_tlv(tlv::REQ_ID, &req_id.to_be_bytes());
                w.write_tlv(tlv::STATUS, &[STATUS_APPROVED]);
                w.write_tlv(tlv::SIGNATURE, signature);
            }
            Self::Denied { req_id } => {
                w.write_tlv(tlv::REQ_ID, &req_id.to_be_bytes());
                w.write_tlv(tlv::STATUS, &[STATUS_DENIED]);
            }
        });
        w.finish()
    }

    /// Decode a datachannel frame.
    pub fn decode(wire: &[u8]) -> Result<Self, CustodianError> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(wire));
        let (typ, body) = r.read_tlv().map_err(wire_err)?;
        if typ != tlv::SIGN_RESPONSE {
            return Err(CustodianError::SignFailed(format!(
                "unexpected message type {typ:#x}, want SignResponse"
            )));
        }
        let (mut req_id, mut status, mut signature) = (None, None, None);
        let mut br = TlvReader::new(body);
        while !br.is_empty() {
            let (t, v) = br.read_tlv().map_err(wire_err)?;
            match t {
                tlv::REQ_ID => req_id = Some(decode_req_id(&v)?),
                tlv::STATUS => status = v.first().copied(),
                tlv::SIGNATURE => signature = Some(v),
                _ => {}
            }
        }
        let req_id = req_id.ok_or_else(|| missing("ReqId"))?;
        match status.ok_or_else(|| missing("Status"))? {
            STATUS_APPROVED => Ok(Self::Approved {
                req_id,
                signature: signature.ok_or_else(|| missing("Signature"))?,
            }),
            STATUS_DENIED => Ok(Self::Denied { req_id }),
            other => Err(CustodianError::SignFailed(format!(
                "bad status byte {other}"
            ))),
        }
    }
}

/// The pairing offer the dashboard renders as a QR/NFC payload; the signer app
/// scans it to learn where and how to connect back. TOFU — the operator
/// compares the `dashboard_pubkey` fingerprint out-of-band once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// The dashboard's public key, so the signer can bind its reply to this
    /// dashboard (and the operator can verify the fingerprint out-of-band).
    pub dashboard_pubkey: Bytes,
    /// How to reach the dashboard to pair — opaque to this crate; the WebRTC
    /// transport fills it with the relay URL + rendezvous session id.
    pub transport_hint: String,
    /// Single-use random nonce binding this pairing session.
    pub nonce: Bytes,
}

impl PairingOffer {
    /// Encode for a QR / NFC payload.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::PAIRING_OFFER, |w| {
            w.write_tlv(tlv::DASHBOARD_PUBKEY, &self.dashboard_pubkey);
            w.write_tlv(tlv::TRANSPORT_HINT, self.transport_hint.as_bytes());
            w.write_tlv(tlv::NONCE, &self.nonce);
        });
        w.finish()
    }

    /// Decode a scanned QR / NFC payload.
    pub fn decode(wire: &[u8]) -> Result<Self, CustodianError> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(wire));
        let (typ, body) = r.read_tlv().map_err(wire_err)?;
        if typ != tlv::PAIRING_OFFER {
            return Err(CustodianError::SignFailed(format!(
                "unexpected message type {typ:#x}, want PairingOffer"
            )));
        }
        let (mut pubkey, mut hint, mut nonce) = (None, None, None);
        let mut br = TlvReader::new(body);
        while !br.is_empty() {
            let (t, v) = br.read_tlv().map_err(wire_err)?;
            match t {
                tlv::DASHBOARD_PUBKEY => pubkey = Some(v),
                tlv::TRANSPORT_HINT => {
                    hint = Some(String::from_utf8(v.to_vec()).map_err(|_| {
                        CustodianError::SignFailed("TransportHint is not UTF-8".into())
                    })?)
                }
                tlv::NONCE => nonce = Some(v),
                _ => {}
            }
        }
        Ok(Self {
            dashboard_pubkey: pubkey.ok_or_else(|| missing("DashboardPubKey"))?,
            transport_hint: hint.ok_or_else(|| missing("TransportHint"))?,
            nonce: nonce.ok_or_else(|| missing("Nonce"))?,
        })
    }
}

/// A bidirectional byte channel to the remote signer (a WebRTC datachannel, a
/// BLE link, …). Mirrors `ndn_face_webrtc::RtcChannel`; concrete bindings live
/// in their own transport crates so this crate stays dependency-light and
/// wasm-safe.
#[async_trait]
pub trait SignerChannel: Send + Sync {
    /// Send one protocol frame.
    async fn send(&self, frame: Bytes) -> Result<(), CustodianError>;
    /// Await the next protocol frame.
    async fn recv(&self) -> Result<Bytes, CustodianError>;
    /// Whether the channel is currently usable.
    fn is_open(&self) -> bool;
}

/// A [`RemoteSignerTransport`] that frames the protocol over any
/// [`SignerChannel`]. Requests are single-flight (one outstanding signature at
/// a time): `Custodian::sign` is awaited sequentially per identity and the
/// remote's per-use approval serialises it anyway. The response `req_id` is
/// checked against the request to catch a desynchronised channel.
pub struct ChannelRemoteSigner<C: SignerChannel> {
    channel: C,
    next_req_id: AtomicU64,
}

impl<C: SignerChannel> ChannelRemoteSigner<C> {
    pub fn new(channel: C) -> Self {
        Self {
            channel,
            next_req_id: AtomicU64::new(1),
        }
    }
}

#[async_trait]
impl<C: SignerChannel + 'static> RemoteSignerTransport for ChannelRemoteSigner<C> {
    async fn request_signature(&self, req: &RemoteSignRequest) -> Result<Bytes, CustodianError> {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        let frame = WireSignRequest {
            req_id,
            region: req.region.clone(),
        }
        .encode();
        self.channel.send(frame).await?;
        let resp = WireSignResponse::decode(&self.channel.recv().await?)?;
        if resp.req_id() != req_id {
            return Err(CustodianError::SignFailed(format!(
                "response req_id {} != request {req_id} (channel desync)",
                resp.req_id()
            )));
        }
        match resp {
            WireSignResponse::Approved { signature, .. } => Ok(signature),
            WireSignResponse::Denied { .. } => Err(CustodianError::SignFailed(
                "remote signer denied the request".into(),
            )),
        }
    }

    async fn is_reachable(&self) -> bool {
        self.channel.is_open()
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Responder — the signer side (the phone/fob). The dashboard's
// `ChannelRemoteSigner` is the requester; this is the device that holds the key
// and gates each signature. Together they close the remote-signer loop.

/// The signer-side approval gate. The platform implements it with a biometric
/// prompt that renders *what* is being authorized — parsed from `region`
/// itself, never from a caller-supplied string — so a compromised requester
/// can't present benign text for malicious bytes. Returning `false` denies.
#[async_trait]
pub trait ApprovalGate: Send + Sync {
    /// Decide whether to authorize signing `region`. Implementations show the
    /// operator what `region` commits to and await their decision.
    async fn approve(&self, region: &[u8]) -> bool;
}

/// Serves [`WireSignRequest`]s from a paired requester over a
/// [`SignerChannel`]: decode → gate → sign → reply. This is the phone/fob side
/// of the protocol; `signer` is typically backed by an enclave key
/// ([`EnclaveCustodian`](crate::custodian::EnclaveCustodian) adapted through
/// [`CustodianSigner`](crate::custodian::CustodianSigner)), so the private key never
/// leaves secure hardware and every signature is biometric-gated by `gate`.
pub struct RemoteSignerResponder<C: SignerChannel> {
    channel: C,
    signer: Arc<dyn crate::Signer>,
    gate: Arc<dyn ApprovalGate>,
}

impl<C: SignerChannel> RemoteSignerResponder<C> {
    pub fn new(channel: C, signer: Arc<dyn crate::Signer>, gate: Arc<dyn ApprovalGate>) -> Self {
        Self {
            channel,
            signer,
            gate,
        }
    }

    /// Handle one request/response cycle. Returns the served `req_id`, or
    /// `None` when the channel has closed (so a `serve` loop can stop). A denied
    /// or failed signature still sends a `Denied` reply — the requester must
    /// always get a correlated response.
    pub async fn serve_one(&self) -> Result<Option<u64>, CustodianError> {
        let frame = match self.channel.recv().await {
            Ok(f) => f,
            // Channel closed / unreachable: nothing left to serve.
            Err(_) => return Ok(None),
        };
        let req = WireSignRequest::decode(&frame)?;

        let response = if self.gate.approve(&req.region).await {
            match self.signer.sign(&req.region).await {
                Ok(signature) => WireSignResponse::Approved {
                    req_id: req.req_id,
                    signature,
                },
                // Couldn't produce the signature (enclave error, etc.) — deny
                // rather than leave the requester hanging.
                Err(_) => WireSignResponse::Denied { req_id: req.req_id },
            }
        } else {
            WireSignResponse::Denied { req_id: req.req_id }
        };

        self.channel.send(response.encode()).await?;
        Ok(Some(req.req_id))
    }

    /// Serve requests until the channel closes.
    pub async fn serve(&self) -> Result<(), CustodianError> {
        while self.serve_one().await?.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::EcdsaSha256Verifier;
    use crate::{EcdsaP256Signer, Ed25519Signer, Ed25519Verifier, Signer, Verifier, VerifyOutcome};
    use tokio::sync::{Mutex, mpsc};

    /// A loopback remote signer: signs locally, standing in for the remote
    /// device so the delegation loop is testable without one.
    struct LoopbackSigner {
        signer: Ed25519Signer,
        reachable: bool,
    }

    #[async_trait]
    impl RemoteSignerTransport for LoopbackSigner {
        async fn request_signature(
            &self,
            req: &RemoteSignRequest,
        ) -> Result<Bytes, CustodianError> {
            self.signer
                .sign_sync(&req.region)
                .map_err(|e| CustodianError::SignFailed(e.to_string()))
        }
        async fn is_reachable(&self) -> bool {
            self.reachable
        }
    }

    #[tokio::test]
    async fn remote_custodian_delegates_signing_and_verifies() {
        let name: Name = "/op/alice/KEY/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[9u8; 32], name.clone());
        let pk = signer.public_key_bytes();

        let transport = Arc::new(LoopbackSigner {
            signer,
            reachable: true,
        });
        // A phone fob is one kind of remote signer.
        let custodian = RemoteCustodian::new(
            transport,
            CustodianRef::Fob {
                fob_id: "phone-1".into(),
            },
        );

        assert!(custodian.is_available().await);
        assert!(custodian.prompts_per_action());
        assert!(!custodian.kind().key_on_this_machine(), "key is off-host");

        // The dashboard delegates signing to the remote signer; the returned
        // signature verifies against the signer's public key.
        let region = b"to-be-signed command region";
        let sig = custodian
            .sign(&KeyId(name.clone()), &name, region)
            .await
            .expect("remote signs");
        assert!(matches!(
            Ed25519Verifier.verify_sync(region, &sig, &pk),
            VerifyOutcome::Valid
        ));
    }

    #[tokio::test]
    async fn unreachable_remote_is_unavailable() {
        let name: Name = "/op/bob/KEY/k1".parse().unwrap();
        let transport = Arc::new(LoopbackSigner {
            signer: Ed25519Signer::from_seed(&[1u8; 32], name.clone()),
            reachable: false,
        });
        let custodian = RemoteCustodian::new(
            transport,
            CustodianRef::Remote {
                reachable_via: name,
            },
        );
        assert!(!custodian.is_available().await);
        assert!(matches!(
            custodian.unlock(UnlockContext::default()).await,
            Err(CustodianError::Unavailable)
        ));
    }

    #[test]
    fn wire_request_round_trips() {
        let req = WireSignRequest {
            req_id: 0x1_0000_0001,
            region: Bytes::from_static(b"to-be-signed bytes"),
        };
        let decoded = WireSignRequest::decode(&req.encode()).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn wire_response_round_trips_both_outcomes() {
        let approved = WireSignResponse::Approved {
            req_id: 7,
            signature: Bytes::from_static(b"\xde\xad\xbe\xef"),
        };
        assert_eq!(
            WireSignResponse::decode(&approved.encode()).expect("decode approved"),
            approved
        );

        let denied = WireSignResponse::Denied { req_id: 9 };
        assert_eq!(
            WireSignResponse::decode(&denied.encode()).expect("decode denied"),
            denied
        );
    }

    #[test]
    fn decode_rejects_wrong_message_type() {
        // A response frame decoded as a request must be rejected, not silently
        // mis-parsed.
        let resp = WireSignResponse::Denied { req_id: 1 }.encode();
        assert!(WireSignRequest::decode(&resp).is_err());
    }

    #[test]
    fn pairing_offer_round_trips() {
        let offer = PairingOffer {
            dashboard_pubkey: Bytes::from_static(b"dashboard-spki-der"),
            transport_hint: "https://relay.example/ndn-fob#sess-42".into(),
            nonce: Bytes::from_static(b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        };
        let decoded = PairingOffer::decode(&offer.encode()).expect("decode offer");
        assert_eq!(decoded, offer);
    }

    /// An in-memory [`SignerChannel`] pair, standing in for the two ends of a
    /// real datachannel so the framing + delegation loop is testable.
    struct MpscChannel {
        tx: mpsc::UnboundedSender<Bytes>,
        rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    }

    #[async_trait]
    impl SignerChannel for MpscChannel {
        async fn send(&self, frame: Bytes) -> Result<(), CustodianError> {
            self.tx.send(frame).map_err(|_| CustodianError::Unavailable)
        }
        async fn recv(&self) -> Result<Bytes, CustodianError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(CustodianError::Unavailable)
        }
        fn is_open(&self) -> bool {
            !self.tx.is_closed()
        }
    }

    fn channel_pair() -> (MpscChannel, MpscChannel) {
        let (a_tx, b_rx) = mpsc::unbounded_channel();
        let (b_tx, a_rx) = mpsc::unbounded_channel();
        (
            MpscChannel {
                tx: a_tx,
                rx: Mutex::new(a_rx),
            },
            MpscChannel {
                tx: b_tx,
                rx: Mutex::new(b_rx),
            },
        )
    }

    #[tokio::test]
    async fn channel_remote_signer_delegates_over_a_channel() {
        let key: Name = "/op/phone/KEY/p1".parse().unwrap();
        let phone = EcdsaP256Signer::from_seed(&[8u8; 32], key.clone()).unwrap();
        let pk = phone.public_key().unwrap();

        let (dash_end, fob_end) = channel_pair();

        // Mock "phone": receive the request, sign its region, reply Approved.
        tokio::spawn(async move {
            let frame = fob_end.recv().await.expect("fob recv");
            let req = WireSignRequest::decode(&frame).expect("decode request");
            let sig = phone.sign_sync(&req.region).expect("phone signs");
            fob_end
                .send(
                    WireSignResponse::Approved {
                        req_id: req.req_id,
                        signature: sig,
                    }
                    .encode(),
                )
                .await
                .expect("fob send");
        });

        let transport = ChannelRemoteSigner::new(dash_end);
        let custodian = RemoteCustodian::new(
            Arc::new(transport),
            CustodianRef::Fob {
                fob_id: "phone-1".into(),
            },
        );

        let region = b"signed mgmt command region";
        let sig = custodian
            .sign(&KeyId(key.clone()), &key, region)
            .await
            .expect("remote signs over the channel");
        assert!(matches!(
            EcdsaSha256Verifier.verify(region, &sig, &pk).await,
            Ok(VerifyOutcome::Valid)
        ));
    }

    #[tokio::test]
    async fn channel_remote_signer_surfaces_denial() {
        let (dash_end, fob_end) = channel_pair();

        // Mock "phone" that declines every request.
        tokio::spawn(async move {
            let frame = fob_end.recv().await.expect("fob recv");
            let req = WireSignRequest::decode(&frame).expect("decode request");
            fob_end
                .send(WireSignResponse::Denied { req_id: req.req_id }.encode())
                .await
                .expect("fob send");
        });

        let transport = ChannelRemoteSigner::new(dash_end);
        let name: Name = "/op/phone/KEY/p1".parse().unwrap();
        let err = transport
            .request_signature(&RemoteSignRequest {
                key_name: name.clone(),
                region: Bytes::from_static(b"region"),
                context: "test".into(),
            })
            .await
            .expect_err("denial surfaces as an error");
        assert!(matches!(err, CustodianError::SignFailed(_)));
    }

    /// Phase-3 acceptance: a phone with an enclave key serves the desktop's
    /// remote-signer requests. Desktop (`ChannelRemoteSigner` → `RemoteCustodian`)
    /// delegates a signature; the phone (`RemoteSignerResponder` over an
    /// `EnclaveCustodian`-backed signer, gated by `ApprovalGate`) signs and
    /// replies; the desktop's signature verifies against the enclave key — and
    /// the private key never crosses the channel (only `region` and the sig do).
    #[tokio::test]
    async fn phone_enclave_responder_signs_for_desktop_under_approval() {
        use crate::custodian::{CustodianSigner, EnclaveBackend, EnclaveCustodian, KeyId};
        use ndn_packet::SignatureType;

        // Phone enclave key (software stand-in for the Secure Enclave / StrongBox).
        let key: Name = "/op/phone/KEY/enclave".parse().unwrap();
        let sw = EcdsaP256Signer::from_seed(&[4u8; 32], key.clone()).unwrap();
        let pk = sw.public_key().unwrap();

        struct SwEnclave {
            signer: EcdsaP256Signer,
            pk: Bytes,
        }
        #[async_trait]
        impl EnclaveBackend for SwEnclave {
            fn public_key(&self) -> Bytes {
                self.pk.clone()
            }
            async fn sign(&self, region: &[u8]) -> Result<Bytes, CustodianError> {
                self.signer
                    .sign_sync(region)
                    .map_err(|e| CustodianError::SignFailed(e.to_string()))
            }
            fn is_available(&self) -> bool {
                true
            }
        }

        let enclave = Arc::new(EnclaveCustodian::new(
            Arc::new(SwEnclave {
                signer: sw,
                pk: pk.clone(),
            }),
            "phone-1",
        ));
        let phone_signer: Arc<dyn Signer> = Arc::new(CustodianSigner::new(
            enclave,
            KeyId(key.clone()),
            SignatureType::SignatureSha256WithEcdsa,
            Some(pk.clone()),
        ));

        // The biometric prompt's "approve".
        struct ApproveAll;
        #[async_trait]
        impl ApprovalGate for ApproveAll {
            async fn approve(&self, _region: &[u8]) -> bool {
                true
            }
        }

        let (dash_end, fob_end) = channel_pair();
        let responder = RemoteSignerResponder::new(fob_end, phone_signer, Arc::new(ApproveAll));
        tokio::spawn(async move { responder.serve().await.ok() });

        // Desktop uses the phone as its remote signer.
        let custodian = RemoteCustodian::new(
            Arc::new(ChannelRemoteSigner::new(dash_end)),
            CustodianRef::Fob {
                fob_id: "phone-1".into(),
            },
        );
        let region = b"register /demo route under the operator key";
        let sig = custodian
            .sign(&KeyId(key.clone()), &key, region)
            .await
            .expect("phone signs for desktop");
        assert!(matches!(
            EcdsaSha256Verifier.verify(region, &sig, &pk).await,
            Ok(VerifyOutcome::Valid)
        ));
    }

    /// When the phone's operator declines the biometric prompt, the desktop's
    /// `sign` fails — a denial is never a silent success.
    #[tokio::test]
    async fn phone_denial_surfaces_to_desktop() {
        use crate::custodian::KeyId;

        struct DenyAll;
        #[async_trait]
        impl ApprovalGate for DenyAll {
            async fn approve(&self, _region: &[u8]) -> bool {
                false
            }
        }

        let key: Name = "/op/phone/KEY/enclave".parse().unwrap();
        let signer: Arc<dyn Signer> =
            Arc::new(EcdsaP256Signer::from_seed(&[6u8; 32], key.clone()).unwrap());

        let (dash_end, fob_end) = channel_pair();
        let responder = RemoteSignerResponder::new(fob_end, signer, Arc::new(DenyAll));
        tokio::spawn(async move { responder.serve().await.ok() });

        let custodian = RemoteCustodian::new(
            Arc::new(ChannelRemoteSigner::new(dash_end)),
            CustodianRef::Fob {
                fob_id: "phone-1".into(),
            },
        );
        let err = custodian
            .sign(&KeyId(key.clone()), &key, b"region")
            .await
            .expect_err("a declined biometric prompt fails the signature");
        assert!(matches!(err, CustodianError::SignFailed(_)));
    }
}
