//! # `ndn_engine::pipeline` — Packet processing pipeline stages
//!
//! Defines the fixed-stage pipeline through which every NDN packet flows.
//! Each stage receives a [`PacketContext`] by value and returns an [`Action`]
//! that drives dispatch (`Continue`, `Send`, `Satisfy`, `Drop`, `Nack`).
//!
//! ## Key types
//!
//! - [`PipelineStage`] — trait implemented by each processing step
//! - [`PacketContext`] — per-packet state passed by value through the pipeline
//! - [`Action`] — enum controlling packet fate after each stage
//! - [`DecodedPacket`] — lazily-decoded Interest or Data
//! - `BoxedStage` — type-erased pipeline stage (`Box<dyn PipelineStage>`)

#![allow(missing_docs)]

pub mod action;
pub mod context;
pub mod stage;

pub use action::{Action, DropReason, ForwardingAction, NackReason};
pub use context::{DecodedPacket, PacketContext};
pub use ndn_transport::AnyMap;
pub use stage::PipelineStage;
