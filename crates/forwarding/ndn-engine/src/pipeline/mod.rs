//! Fixed-stage packet processing pipeline.
//!
//! Each stage receives a [`PacketContext`] by value and returns an [`Action`]
//! that drives dispatch (`Continue`, `Send`, `Satisfy`, `Drop`, `Nack`).

#![allow(missing_docs)]

pub mod action;
pub mod context;
pub mod stage;

pub use action::{Action, DropReason, ForwardingAction, NackReason};
pub use context::{DecodedPacket, PacketContext};
pub use ndn_transport::AnyMap;
pub use stage::PipelineStage;
