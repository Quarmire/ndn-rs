//! Behaviour every `ContentStore` backend must share, run against each one
//! from its own test module.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Interest, Name};

use crate::{ContentStore, CsMeta};

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
        };
        cs.insert(Bytes::from(format!("v={v}")), version(v), meta)
            .await;
    }
    let interest = |fresh: bool| {
        let b = InterestBuilder::new("/p").can_be_prefix();
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
