//! The data-layer contract: named, signed, versioned data that merges the
//! filesystem, the database and the network into one model.
//!
//! This crate is a **contract only**. It defines the model's types and the
//! seven verbs as the [`DataLayer`] trait; it implements none of them. The
//! normative text is `ndn-rs/docs/specs/data-layer.md`; the design is the
//! data-layer study (model revision 2, use cases, interface, plan).
//!
//! # The model in one paragraph
//!
//! Two kinds of thing exist: [`Version`]s, which never change, and
//! collections, which grow. A version is signed by one key — its
//! [`Writer`] — and is identified by `(writer, seq)` ([`VersionId`]); it names
//! its parents as a [`Frontier`]. A collection has a [`Rule`] (one key, log or
//! merge) and an owner-signed [`Members`] record saying who writes and who
//! reads. Everything else is a version that says something about other
//! versions: a [`Summary`] (what a collection holds, signed, nested by
//! digest), a [`Cut`] (removal or revocation: "up to here"), a [`Snapshot`]
//! (exact versions or a state), [`Custody`] (leases to keep data, never beyond
//! its [`Keep`]) and a [`Prune`] (drop one's own writes). A [`Seal`] says who
//! may read, over people, devices and groups — never apps. Content is typed
//! ([`TypeId`]) and writers keep fields they do not understand.
//!
//! # End to end
//!
//! The ends are the signing key and the reader. Caching, relaying and holding
//! are performance or protection only; whether data is correct, newest,
//! readable or still valid is decided by the reader. No verb's meaning depends
//! on a server or on a clock: dates ([`Timestamp`]) are display and retention
//! only, and [`Age`] is measured on the reader's own monotonic clock.
//!
//! # Who calls what
//!
//! | caller | verbs |
//! |---|---|
//! | lens or service code | [`get`](DataLayer::get), [`put`](DataLayer::put), [`watch`](DataLayer::watch), and [`snapshot`](DataLayer::snapshot) when several things change together |
//! | host, by policy defaults | [`hold`](DataLayer::hold), [`prune`](DataLayer::prune), [`share`](DataLayer::share); a lens calls `prune` or `share` only when the person makes that gesture |
//!
//! # Slices
//!
//! Each item says which slice of the plan gives it an implementation. Wire
//! formats (names, TLVs, signatures) are not defined here and are not defined
//! yet: each slice specifies the bytes it needs.
//!
//! | slice | fills |
//! |---|---|
//! | 1 | versions, members (owner only), merge rule, nested summaries, `get`, `put`, `watch` |
//! | 2 | members across prefixes, `share`, cuts on removal, log rule, `snapshot`, re-check on cut arrival |
//! | 3 | large payloads, custody leases with audits, `prune`, keep caps hold |
//! | 4 | signed blocks, one-key rule, retention by expiry |
//! | 5 | revocation as a cut, owner re-admission of honest work |
//! | 6 | named functions whose answers are sealed to their inputs' audience |
//! | 7 | the verbs over forwarder management and the mobile FFI |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod collection;
pub mod error;
pub mod layer;
pub mod statement;
pub mod version;

pub use collection::{Child, Cut, Members, Rule, Summary};
pub use error::{DataError, NextStep, Refusal};
pub use layer::{Age, Answer, Change, Changes, DataLayer, Got, Hold, PutOptions, Share, State};
pub use ndn_foundation_types::{Hash, Name};
pub use statement::{Custody, Lease, Prune, Snapshot};
pub use version::{
    Audience, Content, Frontier, Keep, Payload, Seal, Seq, Timestamp, TypeId, Version, VersionId,
    Writer,
};
