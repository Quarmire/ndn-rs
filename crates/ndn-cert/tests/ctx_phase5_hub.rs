//! Phase 5 witness: a clockless node enforces a monotonic context version and
//! single-use tokens with no wall-clock, and the hub init produces a coherent
//! anchor + context + ticket.
//!
//! Backs `testbed/tests/audit/ctx16_*.sh`. See §16 (N4).

use std::sync::Arc;

use dashmap::DashMap;
use ndn_cert::{BootstrapTicket, TokenStore, ValidityMode, adopt_with_tofu, init_hub};
use ndn_packet::Name;
use ndn_security::{SecurityManager, TrustContext, TrustSchema, Validator};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn validator() -> Validator {
    Validator::with_chain(
        TrustSchema::hierarchical(),
        Arc::new(ndn_security::CertCache::new()),
        Arc::new(DashMap::new()),
        None,
        5,
    )
}

/// CTX.16 (clockless degradation): with no wall-clock, a node still refuses an
/// older context version (monotonic, version-compare only) and rejects a
/// reused token (set membership only) — neither check consults a clock.
#[test]
fn ctx16_clockless_monotonic_version_and_single_use() {
    // A clockless node cannot lean on TTL…
    let mode = ValidityMode::detect(/* has_wall_clock = */ false);
    assert_eq!(mode, ValidityMode::Clockless);
    assert!(!mode.ttl_enforceable(), "clockless must not rely on TTL");

    // …so it relies on monotonic context version (no clock involved).
    let v = validator();
    let mk = |ver: u64| {
        let c = TrustContext::hierarchical(n("/home/bob")).with_version(ver);
        Arc::new(c)
    };
    assert!(v.adopt_context(mk(2)), "v2 adopted");
    assert!(!v.adopt_context(mk(1)), "older v1 refused with no clock");
    assert_eq!(v.keyring().version_of(&n("/home/bob")), Some(2));
    assert!(v.adopt_context(mk(3)), "newer v3 adopted");

    // …and single-use tokens (no TTL set ⇒ no clock dependence).
    let store = TokenStore::new();
    store.add("baked-invite"); // unbounded: no expiry, no scope
    assert!(store.consume("baked-invite"), "first use ok");
    assert!(!store.consume("baked-invite"), "reuse rejected, clock-free");
}

/// CTX.16 (hub coherence): `init_hub` yields an anchor/context/ticket that a
/// fresh node can adopt via TOFU end to end.
#[test]
fn ctx16_hub_init_roundtrips_through_tofu() {
    let mgr = SecurityManager::new();
    let hub = init_hub(&mgr, &n("/home/bob")).unwrap();

    // Publish + re-fetch the context bytes.
    let content = hub.published_content();
    let fetched = Arc::new(TrustContext::decode_content(&content, 1).unwrap());

    // A fresh node parses the ticket and adopts under TOFU.
    let frag = hub.ticket.to_fragment();
    let ticket = BootstrapTicket::from_fragment(&frag).unwrap();
    let v = validator();
    for r in fetched.anchors().iter() {
        v.cert_cache().insert(r.value().clone());
    }
    assert!(adopt_with_tofu(v.keyring(), fetched, &ticket));
    assert_eq!(v.keyring().version_of(&n("/home/bob")), Some(1));
}
