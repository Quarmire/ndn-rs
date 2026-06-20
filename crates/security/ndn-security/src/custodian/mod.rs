//! `ndn-custodian` — the [`Custodian`] trait and key-locator ([`KeyId`]).
//!
//! A custodian is the thing that holds private-key material for a surface, and
//! decides how a signature is produced (in-process, OS keyring, a remote
//! fob/phone, a browser extension). Four built-in implementations match the
//! four surfaces a `TrustContext` can attach to today.
//!
//! This was extracted from `ndn-identity` so wasm surfaces — the dashboard, the
//! future browser extension, mobile — can depend on the custodian primitives
//! without dragging in `ndn-identity`'s native CA/PIB graph (`rusqlite` /
//! `libsqlite3`). `ndn-identity` re-exports everything here, so existing
//! `ndn_identity::Custodian` / `ndn_identity::KeyId` paths keep working.

// The inner `custodian` module name mirrors the former `ndn-custodian` crate
// layout that `ndn-identity` re-exports; the repetition is intentional.
#[allow(clippy::module_inception)]
pub mod custodian;
mod key_id;
mod signer;

pub use key_id::KeyId;
pub use signer::CustodianSigner;

#[cfg(not(target_arch = "wasm32"))]
pub use custodian::OsKeyringCustodian;
pub use custodian::{
    ActionClass, ApprovalGate, BrowserExtensionCustodian, ChannelRemoteSigner, Custodian,
    CustodianError, CustodianRef, CustodianRegistry, Decision, EnclaveBackend, EnclaveCustodian,
    InPageCustodian, PairingOffer, RemoteCustodian, RemoteSignRequest, RemoteSignerResponder,
    RemoteSignerTransport, ScopedApprovalGate, ScopedGrant, ScopedSigningPolicy, SignerChannel,
    UnlockContext, UnwrappedKey, WireSignRequest, WireSignResponse, WrappedKey,
};
