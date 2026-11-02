//! Runtime glue: the same spawn/sleep/timeout `ndn-app` uses, and a monotonic
//! clock in the same domain as its timers (tokio's natively, so a paused or
//! virtual runtime measures ages in its own time; `performance.now()` on
//! wasm32).

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use tokio::time::Instant;
#[cfg(target_arch = "wasm32")]
pub(crate) use web_time::Instant;

pub(crate) use ndn_app::rt::{spawn, timeout};
