//! Client-side TLS trust policy shared by the TLS-bearing dial faces
//! (WebTransport, raw QUIC).
//!
//! This is the *dialer's* counterpart to a listener's cert source
//! (`ndn-acme::CertSource`): it says how to trust the peer's certificate. It is
//! deliberately dependency-free data — each face crate realizes it with its own
//! TLS stack (`wtransport` for WebTransport, `quinn`/`rustls` for QUIC) — so the
//! enum can be shared without dragging a crypto backend into `ndn-transport` or
//! the wasm build.

/// How a dialing face trusts the peer's TLS certificate.
///
/// TLS authenticates the *link* only; NDN data is authenticated separately by
/// signatures, so a backbone link can run pinned self-signed TLS and still rely
/// on NDN trust for content.
#[derive(Debug, Clone)]
pub enum ClientTls {
    /// Pin the peer's leaf certificate by its SHA-256 — the secure default for
    /// a self-signed peer (the dialing counterpart to a listener's
    /// `self_signed_dev` source / a browser's `serverCertificateHashes`). The
    /// hash is the listener's `leaf_sha256`; chain/hostname checks are skipped
    /// because the pin is itself the trust root.
    CertHashes(Vec<[u8; 32]>),
    /// Validate the peer's chain against the platform's WebPKI trust roots and
    /// the TLS server name — for a peer with a publicly-trusted (e.g.
    /// ACME-provisioned) certificate.
    WebPki,
}
