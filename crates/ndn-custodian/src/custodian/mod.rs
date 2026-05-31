//! [`Custodian`] — the thing that holds private-key material for a surface.
//!
//! Four built-in implementations match the four surfaces a TrustContext can
//! attach to today: in-page wasm (browser tab), OS keyring (native desktop),
//! external fob (remote signer over a face), and a browser extension. The
//! extension impl is a Phase-1 stub; Phase 5 wires the Chrome MV3 backend.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;

use crate::KeyId;

pub mod browser_extension;
pub mod fob;
pub mod in_page;
pub mod os_keyring;

pub use browser_extension::BrowserExtensionCustodian;
pub use fob::FobCustodian;
pub use in_page::InPageCustodian;
#[cfg(not(target_arch = "wasm32"))]
pub use os_keyring::OsKeyringCustodian;

#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum CustodianError {
    #[error("custodian unavailable")]
    Unavailable,
    #[error("unlock failed: {0}")]
    UnlockFailed(String),
    #[error("no such key in this custodian: {0}")]
    UnknownKey(Name),
    #[error("sign failed: {0}")]
    SignFailed(String),
    #[error("unwrap failed: {0}")]
    UnwrapFailed(String),
}

/// Where a custodian's keys live. Surfaces use this both for routing
/// (`CustodianRegistry::get`) and for the dashboard's "security tier" badge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum CustodianRef {
    InPage,
    BrowserExtension,
    OsKeyring,
    Fob { fob_id: String },
    Remote { reachable_via: Name },
    Tpm { device_id: String },
}

/// Caller-provided unlock material. Custodians decide whether they need it.
/// `InPageCustodian` ignores it; `OsKeyringCustodian` may use the secret as
/// a passphrase; `FobCustodian` uses none — its unlock is the remote tap.
#[derive(Debug, Clone, Default)]
pub struct UnlockContext {
    pub passphrase: Option<String>,
}

/// Opaque wrapped-content-key blob (Phase 4 gives this its TLV codes).
#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub recipient: Name,
    pub algorithm: String,
    pub blob: Bytes,
}

/// Opaque unwrapped content key. Custodians never expose private signing
/// material this way — only content keys are revealed to callers.
#[derive(Debug, Clone)]
pub struct UnwrappedKey {
    pub blob: Bytes,
}

#[async_trait]
pub trait Custodian: Send + Sync {
    fn kind(&self) -> CustodianRef;

    /// Whether the custodian is reachable right now.
    async fn is_available(&self) -> bool;

    /// True if every `sign()` will prompt the user (fob touch, extension
    /// popup, etc.). Drives UI affordances.
    fn prompts_per_action(&self) -> bool;

    /// Idempotent — unlocking an already-unlocked custodian is a no-op.
    async fn unlock(&self, ctx: UnlockContext) -> Result<(), CustodianError>;

    async fn sign(
        &self,
        key_id: &KeyId,
        name: &Name,
        content: &[u8],
    ) -> Result<Bytes, CustodianError>;

    /// Decrypt a wrapped content-key for delegation (Phase 4 wires the engine
    /// side; Phase 1 implementations may return `Unavailable`).
    async fn unwrap_for(
        &self,
        key_id: &KeyId,
        wrapped: &WrappedKey,
    ) -> Result<UnwrappedKey, CustodianError>;
}

/// Lookup table from [`CustodianRef`] to a concrete custodian instance bound
/// to the local surface. Engines and the dashboard each hold one. Bindings
/// are explicit — there is no global default.
#[derive(Clone, Default)]
pub struct CustodianRegistry {
    table: HashMap<CustodianKey, Arc<dyn Custodian>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
enum CustodianKey {
    InPage,
    BrowserExtension,
    OsKeyring,
    Fob(String),
    Remote(Name),
    Tpm(String),
}

impl From<&CustodianRef> for CustodianKey {
    fn from(r: &CustodianRef) -> Self {
        match r {
            CustodianRef::InPage => Self::InPage,
            CustodianRef::BrowserExtension => Self::BrowserExtension,
            CustodianRef::OsKeyring => Self::OsKeyring,
            CustodianRef::Fob { fob_id } => Self::Fob(fob_id.clone()),
            CustodianRef::Remote { reachable_via } => Self::Remote(reachable_via.clone()),
            CustodianRef::Tpm { device_id } => Self::Tpm(device_id.clone()),
        }
    }
}

impl CustodianRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, custodian: Arc<dyn Custodian>) {
        self.table.insert((&custodian.kind()).into(), custodian);
    }

    pub fn get(&self, r: &CustodianRef) -> Option<Arc<dyn Custodian>> {
        self.table.get(&r.into()).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl std::fmt::Debug for CustodianRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodianRegistry")
            .field("entries", &self.table.len())
            .finish()
    }
}
