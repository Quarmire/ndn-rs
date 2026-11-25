//! The channel: ephemeral live data from one writer's device to the devices of a
//! space's readers and writers, set up by signed NDN (`<sender
//! device>/32=chan/<digest>`) and carried as frames (normative text:
//! `ndn-rs/docs/specs/channel.md`; design: SHAPES-CHANNEL.md).
//!
//! Stage 2 (the setup) and stage 3 (frames and batching) live here: the
//! session key ([`key`]) is shared by both, each stage adds its own modules.

pub(crate) mod aead;
#[cfg(test)]
mod alloc_probe;
pub(crate) mod answer;
mod api;
pub(crate) mod ask;
pub(crate) mod carrier;
pub(crate) mod channels;
pub(crate) mod control;
pub(crate) mod emit;
pub(crate) mod error;
pub(crate) mod fifo;
pub(crate) mod frame;
pub(crate) mod history;
pub(crate) mod hub;
pub(crate) mod items;
pub(crate) mod key;
pub(crate) mod latest;
pub(crate) mod limits;
pub(crate) mod message;
pub(crate) mod queues;
pub(crate) mod replay;
pub(crate) mod ring;
pub(crate) mod rx;
pub(crate) mod rx_hold;
pub(crate) mod rx_names;
pub(crate) mod sessions;
pub(crate) mod standing;
pub(crate) mod table;
pub(crate) mod tx;
pub(crate) mod varint;
pub(crate) mod verbs;
pub(crate) mod wire;

#[cfg(test)]
mod setup_tests;

#[cfg(test)]
mod rx_tests;

#[cfg(test)]
mod tx_tests;

#[cfg(test)]
pub(crate) mod carrier_kit;

#[cfg(test)]
mod stage3_tests;
