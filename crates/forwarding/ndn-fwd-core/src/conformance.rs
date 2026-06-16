//! Shared cross-impl conformance vectors.
//!
//! These pin the *behaviour* of the forwarding rules across the two table
//! implementations that cannot share a container: the native trie
//! (`ndn-store`) and the constrained linear table (`ndn-embedded`). Each side's
//! test harness drives the same vectors through its own FIB and asserts the
//! same result, so the trie and the linear scan cannot drift even though their
//! code differs.
//!
//! Vectors are `&'static str` names so either API — `Name::from_components` on
//! the native side, byte-slice components on the constrained side — can consume
//! them. `nexthop` is an opaque id the harness maps onto each impl's FaceId
//! type. The default route (empty prefix) is intentionally excluded so the
//! vectors don't depend on whether a given table supports it.

/// A route to install before running [`LPM_CASES`].
pub struct LpmRoute {
    /// Slash-delimited prefix, e.g. `"/ndn/edu"`.
    pub prefix: &'static str,
    /// Opaque nexthop id; the harness maps it to the impl's FaceId type.
    pub nexthop: u32,
}

/// A query and the nexthop the longest-prefix-match rule must select.
pub struct LpmCase {
    /// Slash-delimited queried name.
    pub name: &'static str,
    /// Expected nexthop id, or `None` when no prefix matches.
    pub expect: Option<u32>,
}

/// Routes installed into the FIB under test before [`LPM_CASES`].
pub const LPM_ROUTES: &[LpmRoute] = &[
    LpmRoute {
        prefix: "/ndn",
        nexthop: 1,
    },
    LpmRoute {
        prefix: "/ndn/edu",
        nexthop: 2,
    },
    LpmRoute {
        prefix: "/ndn/edu/ucla",
        nexthop: 3,
    },
];

/// Longest-prefix-match cases over [`LPM_ROUTES`].
pub const LPM_CASES: &[LpmCase] = &[
    // Most specific wins.
    LpmCase {
        name: "/ndn/edu/ucla/data",
        expect: Some(3),
    },
    // Falls back to the next-shorter prefix.
    LpmCase {
        name: "/ndn/edu/mit",
        expect: Some(2),
    },
    // Falls back to the shortest prefix.
    LpmCase {
        name: "/ndn/other",
        expect: Some(1),
    },
    // Exact match at the prefix's own length.
    LpmCase {
        name: "/ndn",
        expect: Some(1),
    },
    // No prefix matches → miss.
    LpmCase {
        name: "/com/example",
        expect: None,
    },
];

/// A freshness vector. `now`/`stored`/`period` share one unit (ms).
pub struct FreshForCase {
    pub now: u32,
    pub stored: u32,
    pub period: u32,
    pub fresh: bool,
}

/// An Interest forwarding-decision case. The cross-impl observable is
/// `expect_forward`: the sans-io [`crate::pipeline::decide_interest`] yields
/// `Forward` iff `expect_forward`, and the native engine forwards the Interest
/// to its nexthop iff `expect_forward`. Face-id convention for harnesses:
/// the Interest arrives on face 1; a non-split-horizon route points at face 2.
pub struct InterestDecisionCase {
    pub desc: &'static str,
    pub hop_limit: Option<u8>,
    pub duplicate_nonce: bool,
    /// Whether a FIB entry matches the Interest name.
    pub has_route: bool,
    /// Whether that route's only nexthop is the incoming face (split horizon).
    pub route_to_incoming: bool,
    pub expect_forward: bool,
}

/// Forwarding-decision cases driven through both the sans-io decision and the
/// native engine. (Duplicate-nonce loop detection is exercised separately by
/// the native harness, which must inject the same nonce twice.)
pub const INTEREST_DECISION_CASES: &[InterestDecisionCase] = &[
    InterestDecisionCase {
        desc: "routed, no hop limit -> forward",
        hop_limit: None,
        duplicate_nonce: false,
        has_route: true,
        route_to_incoming: false,
        expect_forward: true,
    },
    InterestDecisionCase {
        desc: "routed, hop limit 5 -> forward",
        hop_limit: Some(5),
        duplicate_nonce: false,
        has_route: true,
        route_to_incoming: false,
        expect_forward: true,
    },
    InterestDecisionCase {
        desc: "no route -> drop",
        hop_limit: Some(5),
        duplicate_nonce: false,
        has_route: false,
        route_to_incoming: false,
        expect_forward: false,
    },
    InterestDecisionCase {
        desc: "hop limit 0 -> drop",
        hop_limit: Some(0),
        duplicate_nonce: false,
        has_route: true,
        route_to_incoming: false,
        expect_forward: false,
    },
    InterestDecisionCase {
        desc: "split horizon (only nexthop is incoming) -> drop",
        hop_limit: None,
        duplicate_nonce: false,
        has_route: true,
        route_to_incoming: true,
        expect_forward: false,
    },
];

/// Relative-period freshness cases (see [`crate::freshness::fresh_for`]).
pub const FRESH_FOR_CASES: &[FreshForCase] = &[
    FreshForCase {
        now: 50,
        stored: 0,
        period: 100,
        fresh: true,
    },
    FreshForCase {
        now: 100,
        stored: 0,
        period: 100,
        fresh: false,
    },
    FreshForCase {
        now: 0,
        stored: 0,
        period: 0,
        fresh: false,
    },
    // Survives a u32 clock wrap: true age 10ms < 100ms.
    FreshForCase {
        now: 5,
        stored: u32::MAX - 4,
        period: 100,
        fresh: true,
    },
];
