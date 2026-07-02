//! Cross-crate strategy registry.
//!
//! Each strategy crate registers a [`StrategyEntry`] via the
//! [`register_strategy!`](macro@crate::register_strategy) macro; `ndn-mgmt::strategy_set` resolves names
//! through [`create_by_name`].
//!
//! On native targets entries are collected at link time via
//! [`linkme::distributed_slice`] (zero-cost, fully automatic). `wasm32`
//! has no life-before-main and `linkme` is unsupported there, so the
//! macro instead defines a plain `static` and entries are pushed into a
//! runtime registry: in-crate built-ins are seeded lazily by
//! [`registered`], and external wasm strategy crates call `register`
//! explicitly during engine setup.

use std::sync::Arc;

use crate::erased::ErasedStrategy;

/// `name` is the NFD-style short identifier (matched against the last
/// component of `/localhost/nfd/strategy/<name>`). `version` pins a
/// behaviour revision. `build` is a fn-pointer because the entry lives
/// in a `static`.
pub struct StrategyEntry {
    pub name: &'static [u8],
    pub version: u64,
    pub build: fn() -> Arc<dyn ErasedStrategy>,
}

#[cfg(not(target_arch = "wasm32"))]
// linkme collects entries in a dedicated link section; the `unsafe_code`
// allow for the resulting `link_section` static is at the crate root (see
// lib.rs) so it covers both this declaration and the macro-generated elements
// without leaking into downstream expansions.
#[linkme::distributed_slice]
pub static STRATEGIES: [StrategyEntry] = [..];

#[cfg(not(target_arch = "wasm32"))]
pub fn registered() -> impl Iterator<Item = &'static StrategyEntry> {
    STRATEGIES.iter()
}

#[cfg(target_arch = "wasm32")]
static STRATEGIES: std::sync::LazyLock<std::sync::Mutex<Vec<&'static StrategyEntry>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Register a strategy entry into the wasm runtime registry. Idempotent
/// by `(name, version)`. Native targets collect entries at link time and
/// do not expose this. External wasm strategy crates call this with the
/// `static` defined by [`register_strategy!`](macro@crate::register_strategy) during engine setup.
#[cfg(target_arch = "wasm32")]
pub fn register(entry: &'static StrategyEntry) {
    let mut guard = STRATEGIES.lock().unwrap();
    if !guard
        .iter()
        .any(|e| e.name == entry.name && e.version == entry.version)
    {
        guard.push(entry);
    }
}

#[cfg(target_arch = "wasm32")]
fn ensure_builtins() {
    use std::sync::Once;
    static SEEDED: Once = Once::new();
    SEEDED.call_once(|| {
        register(&crate::best_route::BEST_ROUTE_REG);
        register(&crate::multicast::MULTICAST_REG);
    });
}

#[cfg(target_arch = "wasm32")]
pub fn registered() -> impl Iterator<Item = &'static StrategyEntry> {
    ensure_builtins();
    STRATEGIES.lock().unwrap().clone().into_iter()
}

pub fn create_by_name(short_name: &[u8]) -> Option<Arc<dyn ErasedStrategy>> {
    registered()
        .find(|e| e.name == short_name)
        .map(|e| (e.build)())
}

/// Look up a strategy matching the `<name>/v=<N>` NFD strategy-name shape.
pub fn create_by_name_version(short_name: &[u8], version: u64) -> Option<Arc<dyn ErasedStrategy>> {
    registered()
        .find(|e| e.name == short_name && e.version == version)
        .map(|e| (e.build)())
}

/// Register a strategy. Use at module scope. The `build` expression must
/// coerce to a plain `fn` pointer (no captures), since the entry lives in
/// a `static`.
///
/// On native targets the entry is collected at link time. On `wasm32` it
/// defines a `pub static`; in-crate built-ins are seeded automatically,
/// but external wasm strategy crates must additionally call
/// `registry::register` with the named
/// `static` during engine setup (wasm has no life-before-main).
///
/// ```rust,ignore
/// register_strategy!(
///     MY_STRATEGY,
///     b"my-strategy",
///     1,
///     || Arc::new(MyStrategy) as Arc<dyn ErasedStrategy>,
/// );
/// ```
#[macro_export]
macro_rules! register_strategy {
    ($static_ident:ident, $name:expr, $version:expr, $build:expr $(,)?) => {
        #[cfg(not(target_arch = "wasm32"))]
        // NOTE: no `#[allow(unsafe_code)]` here. The element-form
        // `distributed_slice` attribute does not emit a `link_section` static,
        // so it does not trip the `unsafe_code` lint — and an `allow` here
        // would be *incompatible* with a downstream crate that sets
        // `#![forbid(unsafe_code)]` (e.g. ndn-ext's ndn-strategy-cclf). The
        // one place that needs the allow is the slice *declaration* above.
        #[linkme::distributed_slice($crate::registry::STRATEGIES)]
        static $static_ident: $crate::registry::StrategyEntry = $crate::registry::StrategyEntry {
            name: $name,
            version: $version,
            build: $build,
        };

        #[cfg(target_arch = "wasm32")]
        pub static $static_ident: $crate::registry::StrategyEntry =
            $crate::registry::StrategyEntry {
                name: $name,
                version: $version,
                build: $build,
            };
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_registered() {
        let names: Vec<&[u8]> = registered().map(|e| e.name).collect();
        assert!(
            names.iter().any(|n| *n == b"best-route"),
            "best-route not in registry: {names:?}",
        );
        assert!(
            names.iter().any(|n| *n == b"multicast"),
            "multicast not in registry: {names:?}",
        );
    }

    #[test]
    fn create_by_name_returns_built_strategy() {
        let s = create_by_name(b"best-route").expect("best-route registered");
        assert_eq!(
            s.name().to_string(),
            "/localhost/nfd/strategy/best-route/v=5"
        );
    }

    #[test]
    fn create_by_name_unknown_returns_none() {
        assert!(create_by_name(b"no-such-strategy").is_none());
    }
}
