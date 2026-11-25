//! The channel: ephemeral live data from one writer's device to the devices of a
//! space's readers and writers, set up by signed NDN (`<sender
//! device>/32=chan/<digest>`) and carried as frames (normative text:
//! `ndn-rs/docs/specs/channel.md`; design: SHAPES-CHANNEL.md).
//!
//! Stage 2 (the setup) and stage 3 (frames and batching) live here: the
//! session key ([`key`]) is shared by both, each stage adds its own modules.
//!
//! The setup and the frame layer are consumed by the verbs (`emit`, `get`) of stage 6: until then
//! the crate's own tests are their only caller, so the module allows `dead_code`.
#![allow(dead_code)]

pub(crate) mod aead;
#[cfg(test)]
mod alloc_probe;
pub(crate) mod answer;
mod api;
pub(crate) mod ask;
pub(crate) mod channels;
pub(crate) mod error;
pub(crate) mod frame;
pub(crate) mod hub;
pub(crate) mod key;
pub(crate) mod limits;
pub(crate) mod message;
pub(crate) mod ring;
pub(crate) mod sessions;
pub(crate) mod standing;
pub(crate) mod varint;
pub(crate) mod wire;

#[cfg(test)]
mod setup_tests;
