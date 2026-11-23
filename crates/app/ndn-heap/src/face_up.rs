//! Announcing a group when a link comes up (spec §7).
//!
//! Under construction: the module lands behind its `wip-face-up` feature.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::Connection;
use ndn_foundation_types::Name;

use crate::rt::Instant;

#[cfg(test)]
#[path = "face_up_tests.rs"]
mod tests;
