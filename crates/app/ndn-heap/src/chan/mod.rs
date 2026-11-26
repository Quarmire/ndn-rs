//! The channel: ephemeral live data from one writer's device to the devices of a
//! space's readers and writers, set up by signed NDN (`<sender
//! device>/32=chan/<digest>`) and carried as frames (normative text:
//! `ndn-rs/docs/specs/channel.md`; design: SHAPES-CHANNEL.md).
//!
//! Stage 2 (the setup) and stage 3 (frames and batching) live here: the
//! session key ([`key`]) is shared by both, each stage adds its own modules.

#[cfg(feature = "adversary")]
mod adversary;
pub(crate) mod aead;
#[cfg(test)]
mod alloc_probe;
pub(crate) mod answer;
mod api;
pub(crate) mod ask;
pub(crate) mod bar;
pub(crate) mod carrier;
pub(crate) mod channels;
pub(crate) mod checkpoint;
pub mod config;
pub(crate) mod control;
pub(crate) mod emit;
pub(crate) mod error;
pub mod evidence;
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
pub(crate) mod route;
pub(crate) mod rx;
pub(crate) mod rx_hold;
pub(crate) mod rx_names;
pub(crate) mod sessions;
pub(crate) mod standing;
pub(crate) mod table;
pub(crate) mod tx;
pub(crate) mod varint;
pub(crate) mod verbs;
pub(crate) mod verify;
pub(crate) mod wire;

/// The map of the per-message paths. A path, an id or a name is hashed on every message and
/// SipHash took a fifth of the sender's CPU; `foldhash` is seeded per map, as SipHash is, and the
/// keys are the device's own or were authenticated before they were inserted.
pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, foldhash::fast::RandomState>;

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

#[cfg(test)]
mod route_tests;

#[cfg(test)]
mod checkpoint_flow_tests;

#[cfg(test)]
mod checkpoint_verified_tests;

#[cfg(test)]
mod ask_stamp_tests;
