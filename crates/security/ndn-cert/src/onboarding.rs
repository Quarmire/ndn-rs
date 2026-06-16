//! Onboarding artefacts: the out-of-band [`BootstrapTicket`], TOFU-gated
//! [`adopt_with_tofu`], RDR naming for the published context, and the
//! privacy-preserving link-local [`AnchorAdvert`].
//!
//! A node does not "join a network" — it *adopts* an anchor-rooted
//! [`SignedTrustContext`]. The one irreducible bit a face cannot give for free is
//! **root authenticity**. A [`BootstrapTicket`] (a QR / deep-link fragment,
//! *not* an NDN wire packet) carries that bit: the namespace, the root
//! anchor's **fingerprint** (a public hash, not a secret), an optional
//! enrollment token, and a bootstrap face hint. Adoption is never automatic —
//! it is gated by a TOFU fingerprint match against the ticket, so a flooded
//! fake advert cannot poison a keyring. See
//! `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §3–§7, §16.

use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use ndn_packet::{Name, NameComponent};
use ndn_security::{Certificate, Keyring, SignedTrustContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CertError;

/// The RDR keyword component naming a published context: `/<ns>/32=trust-context`.
/// Canonical definition lives in `ndn-security` (the `SignedTrustContext`
/// owner); re-exported here so there is one source of truth.
pub const TRUST_CONTEXT_KEYWORD: &[u8] = ndn_security::trust_context::TRUST_CONTEXT_KEYWORD;
/// The RDR metadata keyword (`32=metadata`).
pub const METADATA_KEYWORD: &[u8] = b"metadata";

/// SHA-256 over an anchor's public key — the public fingerprint a ticket
/// commits to. (Public-key, not full-cert, so a re-issued anchor cert for the
/// same key keeps the same fingerprint.)
pub fn anchor_fingerprint(cert: &Certificate) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&cert.public_key);
    h.finalize().into()
}

/// The versioned RDR name of a published context:
/// `/<namespace>/32=trust-context/v=<version>`.
pub fn rdr_context_name(namespace: &Name, version: u64) -> Name {
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            TRUST_CONTEXT_KEYWORD,
        )))
        .append_version(version)
}

/// The RDR metadata name: `/<namespace>/32=trust-context/32=metadata`.
pub fn rdr_metadata_name(namespace: &Name) -> Name {
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            TRUST_CONTEXT_KEYWORD,
        )))
        .append_component(NameComponent::keyword(Bytes::from_static(METADATA_KEYWORD)))
}

/// The out-of-band bootstrap pointer carried by a QR / deep link.
///
/// Everything here is **public** trust material (the anchor is a public key) —
/// possessing a ticket lets you *verify* a namespace, not *produce* under it.
/// Only the optional `token` is a per-invite secret, and it is bounded by TTL +
/// scope + single-use (see [`crate::TokenStore`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapTicket {
    /// The context namespace, as an NDN URI (e.g. `/home/bob`).
    pub namespace: String,
    /// Lowercase-hex SHA-256 of the root anchor's public key (TOFU seed).
    pub anchor_fp_hex: String,
    /// Optional one-time enrollment token (only needed to *produce*).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token: Option<String>,
    /// Optional bootstrap face hint (a rendezvous/hub to dial first).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bootstrap_face: Option<String>,
}

impl BootstrapTicket {
    /// Build a ticket committing to `anchor`'s fingerprint under `namespace`.
    pub fn new(namespace: &Name, anchor: &Certificate) -> Self {
        Self {
            namespace: namespace.to_string(),
            anchor_fp_hex: hex_lower(&anchor_fingerprint(anchor)),
            token: None,
            bootstrap_face: None,
        }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn with_bootstrap_face(mut self, face: impl Into<String>) -> Self {
        self.bootstrap_face = Some(face.into());
        self
    }

    pub fn namespace_name(&self) -> Option<Name> {
        self.namespace.parse().ok()
    }

    /// The committed anchor fingerprint, if the hex is well-formed.
    pub fn fingerprint(&self) -> Option<[u8; 32]> {
        unhex_32(&self.anchor_fp_hex)
    }

    /// Encode as the value after `#bootstrap=` in a deep link: base64url(JSON).
    pub fn to_fragment(&self) -> String {
        let json = serde_json::to_vec(self).expect("BootstrapTicket serializes");
        format!(
            "bootstrap={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        )
    }

    /// A full deep link: `https://<domain>/#<fragment>`.
    pub fn to_url(&self, domain: &str) -> String {
        format!("https://{domain}/#{}", self.to_fragment())
    }

    /// Parse a ticket from a deep link or bare fragment. Accepts a full URL
    /// (`…#bootstrap=<b64>`), a `bootstrap=<b64>` fragment, the legacy
    /// `adopt=`/`join=` keys, or a bare `<b64>` payload.
    pub fn from_fragment(input: &str) -> Result<Self, CertError> {
        let frag = input.rsplit('#').next().unwrap_or(input);
        let b64 = frag
            .strip_prefix("bootstrap=")
            .or_else(|| frag.strip_prefix("adopt="))
            .or_else(|| frag.strip_prefix("join="))
            .unwrap_or(frag);
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64.trim())
            .map_err(|e| CertError::InvalidRequest(format!("bootstrap ticket base64: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CertError::InvalidRequest(format!("bootstrap ticket json: {e}")))
    }
}

/// Adopt `ctx` into `keyring` **only** if one of its anchors matches the
/// ticket's committed fingerprint (TOFU). This is the sole sanctioned path
/// from "received a context" to "trust a context": a context whose anchor was
/// not authenticated out-of-band (QR/NFC/pre-baked) never enters the keyring.
/// Returns `true` if adopted.
pub fn adopt_with_tofu(
    keyring: &Keyring,
    ctx: Arc<SignedTrustContext>,
    ticket: &BootstrapTicket,
) -> bool {
    let Some(expected) = ticket.fingerprint() else {
        return false;
    };
    // The ticket's namespace must also match the context it claims to root.
    if let Some(ns) = ticket.namespace_name()
        && ctx.namespace() != &ns
    {
        return false;
    }
    let matches = ctx
        .anchors()
        .iter()
        .any(|r| anchor_fingerprint(r.value()) == expected);
    if !matches {
        return false;
    }
    keyring.adopt(ctx)
}

/// Whether a node advertises its contexts on the link by default.
///
/// **Off by default** (N3 privacy): silent adopt/consume is the norm; only a
/// hub/rendezvous opts in. A passive listener of a non-advertising node sees
/// nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdvertConfig {
    pub enabled: bool,
}

/// A cold-discovery advertisement carried on the link-local
/// `/localhop/trust-context` prefix. It exposes **only** an opaque anchor
/// fingerprint — never the namespace in cleartext — so a passive listener
/// cannot learn which namespaces a node holds. Discovery-by-namespace is
/// pull-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorAdvert {
    pub fingerprint: [u8; 32],
}

impl AnchorAdvert {
    /// Build an advert from a context's first anchor. Returns `None` for an
    /// anchorless context.
    pub fn from_context(ctx: &SignedTrustContext) -> Option<Self> {
        ctx.anchors().iter().next().map(|r| Self {
            fingerprint: anchor_fingerprint(r.value()),
        })
    }

    /// The link-local advert prefix — no namespace, by design.
    pub fn advert_prefix() -> Name {
        "/localhop/trust-context".parse().expect("static name")
    }

    /// The opaque wire payload: just the 32-byte fingerprint.
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.fingerprint)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == 32).then(|| {
            let mut fp = [0u8; 32];
            fp.copy_from_slice(bytes);
            Self { fingerprint: fp }
        })
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn ticket_fragment_roundtrips() {
        let t = BootstrapTicket {
            namespace: "/home/bob".to_string(),
            anchor_fp_hex: hex_lower(&[0xABu8; 32]),
            token: Some("invite-123".into()),
            bootstrap_face: Some("udp://hub.local:6363".into()),
        };
        let frag = t.to_fragment();
        assert!(frag.starts_with("bootstrap="));
        let back = BootstrapTicket::from_fragment(&frag).unwrap();
        assert_eq!(back, t);
        // Also parse from a full URL.
        let url = t.to_url("join.example");
        assert_eq!(BootstrapTicket::from_fragment(&url).unwrap(), t);
    }

    #[test]
    fn advert_carries_no_namespace() {
        let advert = AnchorAdvert {
            fingerprint: [0x11u8; 32],
        };
        let wire = advert.encode();
        assert_eq!(wire.len(), 32);
        assert_eq!(AnchorAdvert::decode(&wire), Some(advert));
        // The advert prefix is link-local and namespace-free.
        assert_eq!(AnchorAdvert::advert_prefix(), n("/localhop/trust-context"));
        assert!(!AdvertConfig::default().enabled);
    }
}
