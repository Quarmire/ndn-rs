//! Serving by name what other devices of a namespace fetch from this one:
//! the trust-context versions it holds ([`PublishedContexts`], RDR) and its
//! own certificates ([`OwnCertificates`]).

mod certificates;
mod contexts;

pub use certificates::OwnCertificates;
pub use contexts::{
    ContextPublisher, METADATA_FRESHNESS, PublishedContexts, PublisherBypass,
    forget_cached_metadata, prepare,
};
