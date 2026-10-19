//! Behaviour every `ContentStore` backend must share, run against each one
//! from its own test module.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Interest, Name};

use crate::{ContentStore, CsListedEntry, CsMeta};

/// Round 14 of `docs/nfd-divergence-findings.md`: a `LatestPublisher` prefix
/// holds many versions of which only the newest is fresh. A CanBePrefix +
/// MustBeFresh Interest for the prefix must be answered by that version however
/// many stale siblings surround it, and must miss once it too is stale. The
/// stores used to take the first (or an arbitrary) descendant and give up if
/// it was stale, so they answered ~1/N of the time.
pub(crate) async fn only_the_fresh_version_answers_latest<C: ContentStore>(cs: &C) {
    const N: u64 = 256;
    const S: u64 = 1_000_000_000;
    let now = 1_000 * S;
    let version = |v: u64| -> Arc<Name> { Arc::new(format!("/p/v={v}/seg=0").parse().unwrap()) };
    // One version a second, FreshnessPeriod 0.5 s: at `now` only v=N is fresh.
    // Inserted in a scrambled order so no insertion or name order hands it out.
    for i in 0..N {
        let v = (i * 37) % N + 1;
        let published = now - (N - v) * S;
        let meta = CsMeta {
            stale_at: published + S / 2,
            revocation_epoch: None,
        };
        cs.insert(Bytes::from(format!("v={v}")), version(v), meta)
            .await;
    }
    let interest = |fresh: bool| {
        let b = InterestBuilder::new(ndn_packet::name!("/p")).can_be_prefix();
        let b = if fresh { b.must_be_fresh() } else { b };
        Interest::decode(b.build()).unwrap()
    };

    let hit = cs.get(&interest(true), now).await;
    assert_eq!(
        hit.map(|e| e.name),
        Some(version(N)),
        "the one fresh version answers CanBePrefix+MustBeFresh"
    );
    assert!(
        cs.get(&interest(true), now + S / 2).await.is_none(),
        "once the newest version is stale too, the prefix misses"
    );
    assert_eq!(
        cs.get(&interest(false), now + S / 2).await.map(|e| e.name),
        Some(version(N)),
        "without MustBeFresh the answer is still the freshest, not an arbitrary one"
    );
}

/// `list` reports what is held at or under a prefix — never a sibling whose
/// first component merely starts with the same bytes — in canonical name
/// order, capped, with the uncapped total, each entry's wire size and its
/// freshness at the caller's time.
pub(crate) async fn lists_entries_under_a_prefix<C: ContentStore>(cs: &C) {
    const NOW: u64 = 1_000_000_000;
    let name = |uri: &str| -> Arc<Name> { Arc::new(uri.parse().unwrap()) };
    let meta = |stale_at: u64| CsMeta {
        stale_at,
        revocation_epoch: None,
    };
    // Inserted out of name order.
    for (uri, data, stale_at) in [
        ("/p/c/d", "dd", u64::MAX),
        ("/p/b", "bbb", u64::MAX),
        ("/q/x", "x", u64::MAX),
        ("/p/a", "a", 0),
        ("/pz", "z", u64::MAX),
    ] {
        cs.insert(Bytes::from(data), name(uri), meta(stale_at))
            .await;
    }
    let entry = |uri: &str, bytes: usize, fresh: bool| CsListedEntry {
        name: name(uri),
        bytes,
        fresh,
    };

    let capped = cs.list(&name("/p"), 2, NOW).await;
    assert_eq!(
        capped.total, 3,
        "every entry under /p counts, listed or not"
    );
    assert_eq!(
        capped.entries,
        vec![entry("/p/a", 1, false), entry("/p/b", 3, true)],
        "the first two in name order, stale judged at the caller's time"
    );

    let all = cs.list(&name("/p"), 10, NOW).await;
    assert_eq!(all.total, 3);
    assert_eq!(
        all.entries,
        vec![
            entry("/p/a", 1, false),
            entry("/p/b", 3, true),
            entry("/p/c/d", 2, true),
        ]
    );

    let exact = cs.list(&name("/p/c/d"), 10, NOW).await;
    assert_eq!(
        exact.entries,
        vec![entry("/p/c/d", 2, true)],
        "at the prefix"
    );

    let root = cs.list(&Name::root(), 0, NOW).await;
    assert_eq!(root.total, 5, "the root holds everything");
    assert!(root.entries.is_empty(), "a zero cap lists nothing");

    let none = cs.list(&name("/r"), 10, NOW).await;
    assert_eq!((none.total, none.entries.len()), (0, 0));
}
