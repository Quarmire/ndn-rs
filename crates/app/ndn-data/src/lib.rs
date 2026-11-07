//! The data layer: named, signed, versioned data that merges the
//! filesystem, the database and the network into one model.
//!
//! This crate holds the **contract** — the model's types and the seven verbs
//! as the [`DataLayer`] trait — and its **reference implementation**,
//! [`Device`]: one device's layer over NDN, built on `ndn-app` (fetching and
//! serving), `ndn-sync` (State Vector Sync as the change notice, and the
//! `DataStore` entries are kept in) and `ndn-security` (the device key, the
//! validator). The normative text, wire format included, is
//! `ndn-rs/docs/specs/data-layer.md`; the design is the data-layer study
//! (model revision 2, use cases, interface, plan).
//!
//! # The model in one paragraph
//!
//! Two kinds of thing exist: [`Version`]s, which never change, and
//! collections, which grow. A version is signed by one key — its
//! [`Writer`] — and is identified by `(writer, seq)` ([`VersionId`]); it names
//! its parents as [`Parents`]: a [`Frontier`] bound to its tips' digests. A
//! collection has a [`Rule`] (one key, log or
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
//! Each item says which slice of the plan gives it an implementation; the
//! spec defines the bytes of what is implemented ([`wire`]).
//!
//! | slice | fills |
//! |---|---|
//! | 1 | versions, members records (owner-signed, writers of any prefix), the merge rule ([`merge`]), signed nested summaries, `get`, `put`, `watch`, `snapshot` of states and versions, `share` that adds |
//! | 2 | members of other namespaces reached through their own groups, `share` that removes (cuts) and changes the rule, re-check on cut arrival (`Withdrawn`), seals (epoch keys granted to the audience), the log rule, `prune` refusing others' writes |
//! | 3 | large payloads, custody leases with audits, `prune`, keep caps hold |
//! | 4 | signed blocks of small entries under a producer's delay, the one-key rule (a signed head with a freshness bound, rollback refused), retention by expiry (summaries listed by keep), range reads by seq and by time |
//! | 5 | revocation as a cut, owner re-admission of honest work |
//! | 6 | named functions whose answers are sealed to their inputs' audience |
//! | 7 | the verbs over forwarder management and the mobile FFI |
//!
//! [`Device`] answers a verb or option of a later slice with
//! [`DataError::Local`] saying which slice adds it.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod collection;
pub mod device;
pub mod error;
pub mod layer;
pub mod merge;
mod pieces;
mod rt;
mod seal;
pub mod statement;
mod tree;
pub mod version;
pub mod wire;

pub use collection::{Child, Cut, Epoch, Members, Parent, Resolve, Rule, Summary};
pub use device::{Clock, Config, CutBound, CutProposal, Device, Entropy, Released, Transport};
pub use error::{DataError, NextStep, Refusal};
pub use layer::{
    Age, Answer, BATCH_MAX, Change, Changes, DataLayer, Edit, Entries, Entry, Got, Hold,
    PutOptions, Share, State,
};
pub use merge::{
    Counting, MergeError, MergeRule, MergeRules, MergeState, Op, OpKind, Past, Value, Yrs,
};
pub use ndn_foundation_types::{Hash, Name};
pub use statement::{Audit, Breach, Custody, Lease, Prune, Snapshot};
pub use version::{
    Audience, BlockEntry, Content, Frontier, GROUP_MAX, Group, Keep, Parents, Payload, Seal, Seq,
    Timestamp, TypeId, Version, VersionId, Writer,
};
