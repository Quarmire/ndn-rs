//! Server-side WebTransport face.
//!
//! `WebTransportListener` accepts inbound WT sessions on `(host, port)` and
//! yields one [`WebTransportFace`] per session. Each NDN packet is wrapped in
//! NDNLPv2 and sent over QUIC datagrams; a packet larger than the negotiated
//! `max_datagram_size` is split into NDNLPv2 fragments (one per datagram) and
//! reassembled by the engine's decode stage. This matches NDNts'
//! `H3Transport` + `LpService` (datagram transport, fragment/reassemble at
//! `maxDatagramSize`) so the two interoperate. Datagrams are unreliable; a lost
//! fragment loses the packet, recovered the NDN way by re-expressing the
//! Interest. FaceUri scheme is `wts://host:port` (TLS mandatory at QUIC layer).

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{trace, warn};

use ndn_transport::{ClientTls, FaceError, FaceId, FaceKind, Transport};
use wtransport::{Endpoint, Identity, ServerConfig, endpoint::IncomingSession};

/// Conservative QUIC-datagram floor used when the connection cannot yet report
/// a negotiated `max_datagram_size` (≈ the QUIC minimum).
const WT_DATAGRAM_FLOOR: usize = 1200;

/// TLS configuration for the WT listener.
pub enum WtTlsConfig {
    /// Self-signed cert; only useful for loopback tests and the
    /// `serverCertificateHashes` browser workflow (cert validity capped at
    /// 14 days, see W3C WebTransport §3.2).
    SelfSigned { hostnames: Vec<String> },
    /// Externally provisioned PEM material (e.g. from ACME).
    Pem {
        cert_chain_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
    },
}

#[derive(Debug, Error)]
pub enum WtError {
    #[error("wtransport: {0}")]
    Wt(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// WebTransport listener accepting inbound HTTP/3 sessions.
pub struct WebTransportListener {
    endpoint: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    local_addr: std::net::SocketAddr,
    leaf_cert_sha256: Option<[u8; 32]>,
}

impl WebTransportListener {
    pub async fn bind(addr: std::net::SocketAddr, tls: WtTlsConfig) -> Result<Self, WtError> {
        let identity = match tls {
            WtTlsConfig::SelfSigned { hostnames } => Identity::self_signed(hostnames)
                .map_err(|e| WtError::Wt(format!("self_signed: {e}")))?,
            WtTlsConfig::Pem {
                cert_chain_pem,
                private_key_pem,
            } => {
                let certs = rustls_pemfile::certs(&mut cert_chain_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| WtError::Wt(format!("cert chain: {e}")))?;
                if certs.is_empty() {
                    return Err(WtError::Wt("cert chain: no certificates".into()));
                }
                let chain = wtransport::tls::CertificateChain::new(
                    certs
                        .into_iter()
                        .map(|d| wtransport::tls::Certificate::from_der(d.to_vec()))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| WtError::Wt(format!("cert chain: {e}")))?,
                );
                let key_der = rustls_pemfile::private_key(&mut private_key_pem.as_slice())
                    .map_err(|e| WtError::Wt(format!("private key: {e}")))?
                    .ok_or_else(|| WtError::Wt("private key: no key in PEM".into()))?;
                let key =
                    wtransport::tls::PrivateKey::from_der_pkcs8(key_der.secret_der().to_vec());
                Identity::new(chain, key)
            }
        };

        // SHA-256 of the leaf cert — a dialing peer pins this via
        // `ClientTls::CertHashes`, and browsers via `serverCertificateHashes`.
        let leaf_cert_sha256 = identity.certificate_chain().as_slice().first().map(|leaf| {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(leaf.der());
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        });

        let config = ServerConfig::builder()
            .with_bind_address(addr)
            .with_identity(identity)
            .build();

        let endpoint = Endpoint::server(config).map_err(|e| WtError::Wt(e.to_string()))?;
        let local_addr = endpoint.local_addr().map_err(WtError::Io)?;
        Ok(Self {
            endpoint,
            local_addr,
            leaf_cert_sha256,
        })
    }

    /// SHA-256 of the listener's leaf certificate, for dialers to pin via
    /// [`ClientTls::CertHashes`] or browsers via `serverCertificateHashes`.
    pub fn leaf_cert_sha256(&self) -> Option<[u8; 32]> {
        self.leaf_cert_sha256
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Accept one inbound WT session: QUIC accept, HTTP/3 CONNECT, session accept.
    pub async fn accept(&self, id: FaceId) -> Result<WebTransportFace, WtError> {
        let incoming: IncomingSession = self.endpoint.accept().await;
        let session_request = incoming
            .await
            .map_err(|e| WtError::Wt(format!("session request: {e}")))?;
        let connection = session_request
            .accept()
            .await
            .map_err(|e| WtError::Wt(format!("session accept: {e}")))?;
        let remote = connection.remote_address();
        Ok(WebTransportFace {
            id,
            remote_addr: remote.to_string(),
            local_addr: self.local_addr.to_string(),
            connection: Arc::new(connection),
            recv_lock: Mutex::new(()),
            frag_seq: AtomicU64::new(0),
        })
    }
}

/// One WebTransport face — one accepted WT session.
pub struct WebTransportFace {
    id: FaceId,
    remote_addr: String,
    local_addr: String,
    connection: Arc<wtransport::Connection>,
    // Serializes datagram receive so `recv_bytes` can take `&self`.
    recv_lock: Mutex<()>,
    // Monotonic NDNLPv2 fragmentation sequence base for oversized packets.
    frag_seq: AtomicU64,
}

impl WebTransportFace {
    /// Construct from an already-accepted wtransport `Connection`.
    pub fn from_connection(
        id: FaceId,
        connection: wtransport::Connection,
        local_addr: String,
    ) -> Self {
        let remote_addr = connection.remote_address().to_string();
        Self {
            id,
            remote_addr,
            local_addr,
            connection: Arc::new(connection),
            recv_lock: Mutex::new(()),
            frag_seq: AtomicU64::new(0),
        }
    }

    /// Dial a WebTransport peer at `url` (`https://host:port[/path]`) and wrap
    /// the session as an outbound face. This is the forwarder-to-forwarder
    /// counterpart to [`WebTransportListener`]; QUIC/HTTP3 traverses NAT and
    /// firewalls like HTTPS. TLS authenticates the link only — NDN trust is
    /// layered on top via signed Data.
    pub async fn connect(id: FaceId, url: &str, tls: ClientTls) -> Result<Self, WtError> {
        let builder = wtransport::ClientConfig::builder().with_bind_default();
        let client_config = match tls {
            ClientTls::CertHashes(hashes) => builder
                .with_server_certificate_hashes(
                    hashes.into_iter().map(wtransport::tls::Sha256Digest::new),
                )
                .build(),
            // wtransport validates against the OS trust store here; the QUIC
            // face uses the bundled webpki-roots. Both check trusted roots —
            // the difference is only the root source.
            ClientTls::WebPki => builder.with_native_certs().build(),
        };
        let endpoint =
            Endpoint::client(client_config).map_err(|e| WtError::Wt(format!("client: {e}")))?;
        let local_addr = endpoint
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        // The connection keeps its own driver alive, so the endpoint may drop.
        let connection = endpoint
            .connect(url)
            .await
            .map_err(|e| WtError::Wt(format!("connect {url}: {e}")))?;
        Ok(Self::from_connection(id, connection, local_addr))
    }

    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }
}

impl Transport for WebTransportFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::WebTransport
    }
    fn remote_uri(&self) -> Option<String> {
        Some(format!("wts://{}", self.remote_addr))
    }
    fn local_uri(&self) -> Option<String> {
        Some(format!("wts://{}", self.local_addr))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let _guard = self.recv_lock.lock().await;
        let dgram = self
            .connection
            .receive_datagram()
            .await
            .map_err(|e| FaceError::Io(std::io::Error::other(e)))?;
        let bytes = dgram.payload();
        trace!(target: "face.wt", face=%self.id, len=bytes.len(), "wt: recv datagram");
        Ok(bytes)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        // Fragment to the negotiated datagram size when oversized; the peer's
        // NDNLPv2 reassembler (ndn-rs decode stage or NDNts `LpService`) puts
        // the packet back together.
        let wire = ndn_packet::lp::encode_lp_packet(&pkt);
        let max_dg = self
            .connection
            .max_datagram_size()
            .unwrap_or(WT_DATAGRAM_FLOOR);
        let frames = if wire.len() > max_dg {
            let seq = self.frag_seq.fetch_add(1, Ordering::Relaxed);
            ndn_packet::fragment::fragment_packet(&wire, max_dg, seq)
        } else {
            vec![wire]
        };
        for frame in frames {
            let len = frame.len();
            trace!(target: "face.wt", face=%self.id, len, "wt: send datagram");
            if let Err(e) = self.connection.send_datagram(frame) {
                warn!(target: "face.wt", face=%self.id, error=%e, "wt: send failed");
                return Err(FaceError::Io(std::io::Error::other(e)));
            }
        }
        Ok(())
    }
}
