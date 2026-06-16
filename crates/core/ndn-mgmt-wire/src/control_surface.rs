//! Pluggable introspection/control surface for out-of-core subsystems.
//!
//! The cross-cutting **cold control plane** (rearchitecture note §5): a subsystem
//! that lives in its own crate/repo (routing, discovery, a custom strategy, an
//! extension face) implements [`ControlSurface`] to expose its capabilities,
//! current options, and runtime stats — and the mgmt server serves them
//! **generically** under `/localhost/nfd/ext/<name>/…` with **zero compile-time
//! knowledge** of the subsystem. The dashboard discovers loaded extensions and
//! their knobs the same way.
//!
//! Deliberately a self-describing **key→value** model rendered as `key=value\n`
//! text (consistent with the other status datasets), not a typed CRUD API — the
//! richly-typed verb surfaces (coding/rate-limit) keep their bespoke modules;
//! this is the *generic* introspection layer on top, so an unknown subsystem is
//! still inspectable. The trait is sans-io (sync, owned returns, object-safe) and
//! lives here in the no_std wire crate so a subsystem deps only this, never the
//! mgmt server.

use alloc::string::String;
use alloc::vec::Vec;

/// Self-describing capabilities + current option values of a subsystem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlInfo {
    /// Static capability descriptors (e.g. `("transport", "quic")`,
    /// `("supports-set", "true")`). Read-only facts about the subsystem.
    pub caps: Vec<(String, String)>,
    /// Current values of the runtime-settable options, by key. A key present
    /// here is what [`ControlSurface::set_option`] accepts.
    pub options: Vec<(String, String)>,
}

/// A runtime snapshot of a subsystem's counters / state, by key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlStats {
    pub entries: Vec<(String, String)>,
}

/// Render `key=value\n` lines (the dataset content wire form, matching the other
/// NFD status datasets this stack emits).
pub fn render_pairs(pairs: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in pairs {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// A subsystem's pluggable mgmt introspection/control surface. Registered with
/// the engine via `MgmtHandles::control_surfaces`; served generically at
/// `/localhost/nfd/ext/<name>/{caps,options,stats}`. Object-safe + sans-io.
pub trait ControlSurface: Send + Sync {
    /// Stable identifier — the `<name>` dataset component. Lowercase, no slashes
    /// (e.g. `"nlsr"`, `"monitor-wifi"`).
    fn name(&self) -> &str;

    /// Capabilities + current option values (backs `caps`/`options`).
    fn describe(&self) -> ControlInfo;

    /// Runtime counters / state snapshot (backs `stats`).
    fn stats(&self) -> ControlStats;

    /// Apply a runtime option update. Default is **read-only** — only subsystems
    /// with mutable knobs override it. `Err(reason)` rejects (unknown key, bad
    /// value, immutable).
    fn set_option(&self, key: &str, value: &str) -> Result<(), String> {
        let _ = (key, value);
        Err(String::from("read-only: this subsystem exposes no settable options"))
    }
}
