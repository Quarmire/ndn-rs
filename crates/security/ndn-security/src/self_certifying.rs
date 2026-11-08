//! Self-certifying namespaces: `/user/<0xA1: SHA-256(raw Ed25519 key)>`
//! (`docs/specs/trust-context.md` §4.5).
//!
//! Such a namespace is named by its **genesis root**: the Ed25519 key that
//! signs version 1 of its trust context. The name's last component, of
//! TLV-TYPE [`SELF_CERTIFYING`] directly after `/user`, is SHA-256 of that
//! key's 32 raw bytes (RFC 8032 encoding, no SubjectPublicKeyInfo wrapper).
//! So adopting it needs no expected fingerprint: a node fetches version 1,
//! checks it here ([`Genesis`]), and follows the continuity rule from it to
//! the newest version. Later versions may change the root (a recovery, a
//! root moved to a hardware token of another key type) without renaming the
//! namespace, because only version 1 is judged against the name.
//!
//! [`Keyring`](crate::Keyring) takes a self-certifying namespace it does not
//! hold only through [`Keyring::adopt_genesis`](crate::Keyring::adopt_genesis),
//! which needs a [`Genesis`]: a value only [`Genesis::open_received`] and
//! [`Genesis::open_stored`] make, after checking the signature.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name, NameComponent, SignatureType};
use sha2::{Digest, Sha256};

use crate::Certificate;
use crate::trust_context::{OpenContextError, SignedTrustContext};

/// TLV-TYPE of the self-certifying name component.
pub const SELF_CERTIFYING: u64 = ndn_packet::tlv_type::SELF_CERTIFYING;

/// The component a self-certifying namespace sits directly under: `/user`.
pub const PERSONAL_PREFIX: &[u8] = b"user";

/// `/user`, shared by every person: the prefix of every self-certifying
/// namespace, never itself one.
pub fn personal_prefix() -> Name {
    Name::root().append(PERSONAL_PREFIX)
}

/// SHA-256 of a raw 32-byte Ed25519 public key: the value of its
/// self-certifying component.
pub fn key_digest(public_key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(public_key).into()
}

/// The self-certifying namespace of the Ed25519 key `public_key`:
/// `/user/<0xA1: SHA-256(public_key)>`. The same bytes as ndf-rs's
/// `record::personal_root`.
pub fn self_certifying_name(public_key: &[u8; 32]) -> Name {
    personal_prefix().append_component(NameComponent::new(
        SELF_CERTIFYING,
        Bytes::copy_from_slice(&key_digest(public_key)),
    ))
}

/// Why a name with a self-certifying component is not a namespace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelfCertifyingNameError {
    /// A self-certifying component somewhere other than directly after
    /// `/user` as the last component, or not 32 bytes.
    #[error(
        "{namespace} carries a self-certifying component (type 0xA1) where none may be: one \
         names a person's namespace only as /user/<32 bytes: SHA-256 of an Ed25519 key>, \
         directly after /user and last; use that name, or a name without type 0xA1"
    )]
    Misplaced { namespace: String },
    /// A namespace under a person's self-certifying namespace: that person's
    /// names, never another root's.
    #[error(
        "{namespace} is under the self-certifying namespace {owner}: names under it are that \
         person's, judged by {owner}'s trust context; adopt {owner} itself"
    )]
    Under { namespace: String, owner: String },
}

/// Whether `namespace` is self-certifying: `Ok(Some(digest))` for
/// `/user/<0xA1: digest>` (32 bytes), `Ok(None)` for a name without any
/// self-certifying component, and refused for one anywhere else: under a
/// person's namespace ([`SelfCertifyingNameError::Under`]), or misplaced
/// ([`SelfCertifyingNameError::Misplaced`]). Name-only.
pub fn self_certifying_digest(
    namespace: &Name,
) -> Result<Option<[u8; 32]>, SelfCertifyingNameError> {
    let comps = namespace.components();
    let Some(at) = comps.iter().position(|c| c.typ == SELF_CERTIFYING) else {
        return Ok(None);
    };
    let placed = at == 1
        && comps[0].typ == ndn_packet::tlv_type::NAME_COMPONENT
        && comps[0].value.as_ref() == PERSONAL_PREFIX;
    let digest: Option<[u8; 32]> = comps[at].value.as_ref().try_into().ok();
    match digest {
        Some(digest) if placed && comps.len() == 2 => Ok(Some(digest)),
        Some(_) if placed && !comps[2..].iter().any(|c| c.typ == SELF_CERTIFYING) => {
            Err(SelfCertifyingNameError::Under {
                namespace: namespace.to_string(),
                owner: Name::from_components(comps[..2].iter().cloned()).to_string(),
            })
        }
        _ => Err(SelfCertifyingNameError::Misplaced {
            namespace: namespace.to_string(),
        }),
    }
}

/// Whether `name` lies in a person's self-certifying namespace: it starts
/// with `/user/<0xA1: 32 bytes>`. Such a name is judged only by that
/// namespace's own trust context, never by a context of a shorter prefix
/// (`/user` or `/`) — another root never vouches for a person's names
/// ([`crate::Keyring::context_for`]).
pub fn in_personal_namespace(name: &Name) -> bool {
    let comps = name.components();
    comps.len() >= 2
        && comps[0].typ == ndn_packet::tlv_type::NAME_COMPONENT
        && comps[0].value.as_ref() == PERSONAL_PREFIX
        && comps[1].typ == SELF_CERTIFYING
        && comps[1].value.len() == 32
}

/// Why a context Data is not the genesis of a self-certifying namespace.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error(transparent)]
    Name(#[from] SelfCertifyingNameError),
    #[error(
        "{namespace} is not self-certifying (/user/<0xA1: SHA-256 of an Ed25519 key>), so it \
         has no genesis to check; adopt it from an anchor link with its expected fingerprint"
    )]
    NotSelfCertifying { namespace: String },
    #[error("the genesis of a self-certifying namespace does not open: {0}")]
    Unauthentic(#[from] OpenContextError),
    #[error(
        "this is version {version} of {namespace}, not version 1: a self-certifying namespace \
         is checked against its name only at version 1 (its genesis); fetch \
         {namespace}/32=trust-context/v=1, then follow the versions after it"
    )]
    NotVersionOne { namespace: String, version: u64 },
    #[error(
        "version 1 of {namespace} is signed by {signer} with signature type {sig_type}, not \
         an Ed25519 key: a self-certifying name is SHA-256 of an Ed25519 key, and only that \
         key signs its genesis, so this is not {namespace}'s genesis (refused)"
    )]
    NotEd25519 {
        namespace: String,
        signer: String,
        sig_type: u64,
    },
    #[error(
        "version 1 of {namespace} is signed by {signer}, whose key does not hash to the name: a \
         forged genesis, or another namespace's — refused. Only the key {namespace} names \
         signs its genesis; check the name you were given"
    )]
    Mismatch { namespace: String, signer: String },
}

/// The checked version 1 of a self-certifying namespace: signed with
/// Ed25519 by one of its own anchors, whose raw public key hashes to the
/// name's last component.
#[derive(Debug)]
pub struct Genesis {
    context: Arc<SignedTrustContext>,
    data: Data,
    root: Certificate,
}

impl Genesis {
    /// Check a genesis received from elsewhere: [`SignedTrustContext::open_received`]
    /// (its signing anchor valid now), then the genesis rule.
    pub async fn open_received(data: &Data) -> Result<Self, GenesisError> {
        let (ctx, root) = SignedTrustContext::open_received(data).await?;
        Self::check(ctx, root, data)
    }

    /// Check a node's own stored copy of a genesis:
    /// [`SignedTrustContext::open_signed`], then the genesis rule.
    pub async fn open_stored(data: &Data) -> Result<Self, GenesisError> {
        let (ctx, root) = SignedTrustContext::open_signed(data).await?;
        Self::check(ctx, root, data)
    }

    fn check(
        ctx: SignedTrustContext,
        root: Certificate,
        data: &Data,
    ) -> Result<Self, GenesisError> {
        let namespace = ctx.namespace().to_string();
        let digest = self_certifying_digest(ctx.namespace())?.ok_or_else(|| {
            GenesisError::NotSelfCertifying {
                namespace: namespace.clone(),
            }
        })?;
        if ctx.version() != 1 {
            return Err(GenesisError::NotVersionOne {
                namespace,
                version: ctx.version(),
            });
        }
        // `open_signed` verified the signature under `root`'s key with this
        // signature type, so an Ed25519 type and a 32-byte key are the raw
        // Ed25519 key that signed.
        let sig_type = data.sig_info().map(|s| s.sig_type);
        let key: Option<&[u8; 32]> = root.public_key.as_ref().try_into().ok();
        let key = match (sig_type, key) {
            (Some(SignatureType::SignatureEd25519), Some(key)) => key,
            _ => {
                return Err(GenesisError::NotEd25519 {
                    namespace,
                    signer: root.name.to_string(),
                    sig_type: sig_type.map_or(0, |t| t.code()),
                });
            }
        };
        if key_digest(key) != digest {
            return Err(GenesisError::Mismatch {
                namespace,
                signer: root.name.to_string(),
            });
        }
        // The bytes exactly as given, decoded again (a `Data` is not `Clone`).
        let data = Data::decode(data.raw().clone())
            .map_err(|_| GenesisError::Unauthentic(OpenContextError::BadName(namespace.clone())))?;
        Ok(Self {
            context: Arc::new(ctx),
            data,
            root,
        })
    }

    /// The namespace it names.
    pub fn namespace(&self) -> &Name {
        self.context.namespace()
    }

    /// Version 1 of the namespace.
    pub fn context(&self) -> &Arc<SignedTrustContext> {
        &self.context
    }

    /// Its signed Data, as received or stored (what to keep and serve).
    pub fn data(&self) -> &Data {
        &self.data
    }

    /// The genesis root: the anchor that signed it, whose key the name hashes.
    pub fn root(&self) -> &Certificate {
        &self.root
    }
}
