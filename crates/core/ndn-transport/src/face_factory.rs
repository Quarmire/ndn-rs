//! `FaceFactory` — data-driven face construction.
//!
//! [`crate::Face`] / `Transport` are built by hand today: the engine takes an
//! already-constructed `impl Transport`. A connectivity resolver, by contrast,
//! holds **data** — a config row, a discovered-neighbor record, a management
//! command — that says *"kind = udp, remote = 192.0.2.1:6363"*. Turning that
//! record into a live face otherwise means a hand-written `match` over every
//! `FaceKind`, coupling the caller to every bearer crate.
//!
//! [`FaceFactory`] closes the gap: register one factory per [`FaceKind`], then
//! a resolver does `record.kind + record.params → add_face_of_kind` with no
//! per-kind code and no bearer-crate coupling. The constructor is object-safe
//! (returns a boxed future, mirroring [`ErasedTransport`]'s boxing) so a
//! registry can hold `Arc<dyn FaceFactory>` and dispatch by data alone.

use std::future::Future;
use std::pin::Pin;

use crate::face::{FaceError, FaceId, FaceKind};
use crate::transport::ErasedTransport;

/// Minimal, bearer-agnostic parameters a data record carries to construct a
/// face.
///
/// Deliberately tiny and free of any higher-layer (e.g. NDF) type: each factory
/// parses only its own kind's needs out of these two fields, so the record
/// stays serialisable and `ndn-transport` never grows a per-kind options enum.
///
/// - `remote` — the peer/endpoint locator as a string, interpreted per kind:
///   a `SocketAddr` for UDP/TCP, a device/path for L2/serial, `None` for a
///   bind-only / listen-only face.
/// - `opts` — a small set of `key → value` knobs (e.g. `local` bind address,
///   `mtu`). A string map (not a typed struct) keeps records uniform across
///   kinds; face creation is a rare, cold path, so the allocations are a
///   non-issue. Binary values can ride via any agreed encoding, but prefer
///   keeping this human-legible.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaceParams {
    pub remote: Option<String>,
    pub opts: Vec<(String, String)>,
}

impl FaceParams {
    /// A record with just a remote locator and no options.
    pub fn remote(remote: impl Into<String>) -> Self {
        Self {
            remote: Some(remote.into()),
            opts: Vec::new(),
        }
    }

    /// First option value for `key`, if present.
    pub fn opt(&self, key: &str) -> Option<&str> {
        self.opts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Builder-style: attach one `key → value` option.
    pub fn with_opt(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.opts.push((key.into(), value.into()));
        self
    }
}

/// Constructs a live `Transport` of one [`FaceKind`] from a [`FaceParams`]
/// record.
///
/// Object-safe: the [`create`](FaceFactory::create) constructor returns a boxed
/// future (mirroring [`ErasedTransport`]'s boxing) so the engine can hold
/// `Arc<dyn FaceFactory>` in a registry keyed by kind. The engine allocates the
/// [`FaceId`] and passes it in, so id ownership stays with the face table
/// (monotonic, never recycled) rather than leaking into each factory.
pub trait FaceFactory: Send + Sync {
    /// The single [`FaceKind`] this factory builds. A registry keys on this.
    fn kind(&self) -> FaceKind;

    /// Construct the face from `params`, returning a boxed, type-erased
    /// transport ready to be wired into the face table. Fails with a
    /// [`FaceError`] when `params` are malformed for this kind or the
    /// underlying bind/dial fails (bad-params conventionally surface as
    /// `FaceError::Io(ErrorKind::InvalidInput)`).
    fn create<'a>(
        &'a self,
        id: FaceId,
        params: &'a FaceParams,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn ErasedTransport>, FaceError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_remote_and_opts() {
        let p = FaceParams::remote("127.0.0.1:6363")
            .with_opt("local", "0.0.0.0:0")
            .with_opt("mtu", "1400");
        assert_eq!(p.remote.as_deref(), Some("127.0.0.1:6363"));
        assert_eq!(p.opt("local"), Some("0.0.0.0:0"));
        assert_eq!(p.opt("mtu"), Some("1400"));
        assert_eq!(p.opt("missing"), None);
    }

    #[test]
    fn params_default_is_empty() {
        let p = FaceParams::default();
        assert_eq!(p.remote, None);
        assert!(p.opts.is_empty());
        assert_eq!(p.opt("x"), None);
    }

    /// The trait is object-safe: it can be held as `Arc<dyn FaceFactory>`.
    #[test]
    fn face_factory_is_object_safe() {
        fn assert_obj_safe(_: &dyn FaceFactory) {}
        let _ = assert_obj_safe;
    }
}
