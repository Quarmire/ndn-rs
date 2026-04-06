//! # ndn-compute -- In-network computation
//!
//! Routes Interests to registered compute handlers and injects the resulting
//! Data packets back into the forwarder pipeline. This enables named-function
//! networking where computation is co-located with the router.
//!
//! ## Key types
//!
//! - [`ComputeFace`] -- virtual face bridging the pipeline to compute handlers
//! - [`ComputeRegistry`] -- maps name prefixes to handler instances
//! - [`ComputeHandler`] -- trait for user-defined compute functions

#![allow(missing_docs)]

pub mod compute_face;
pub mod registry;

pub use compute_face::ComputeFace;
pub use registry::{ComputeHandler, ComputeRegistry};
