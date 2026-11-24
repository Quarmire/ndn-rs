//! The namespace an introduction brings is judged by one rule on both sides
//! (`credentials::overlap`, spec §19.3, §19.4): the policy's refusals, the device's own
//! namespace, every namespace it trusts. Judged here against a device that holds one
//! other namespace.

use std::sync::Arc;

use ndn_foundation_types::Name;
use ndn_security::anchor_fingerprint;

use crate::credentials::overlap;
use crate::policy::IntroPolicy;
use crate::test_kit::{Device, Person, Setup, n};

/// The whole fingerprint of `person`'s anchor.
fn fingerprint(person: &Person) -> [u8; 32] {
    let anchors = person.ctx.anchors();
    anchor_fingerprint(anchors.iter().next().expect("an anchor").value())
}

/// `device` judges `ns`, whose anchor is `fp`, as the namespace of an introduction's other
/// party.
fn judged(device: &Device, ns: &str, fp: &[u8; 32]) -> Option<String> {
    let inner = device.invites.inner();
    overlap(&inner.node, &inner.policy, &n(ns), fp)
}

/// The root, a namespace the policy keeps out, the device's own namespace and every one
/// over or under it, a trusted namespace under another anchor, and one over or under a
/// trusted one are refused, each with its reason; the same namespace under the anchor
/// already held, and an unrelated one, are not.
#[tokio::test]
async fn overlap_refuses_root_own_over_under_other_anchor_and_allows_same_anchor() {
    // A device of /bob/team that trusts /carol/team.
    let bob = Person::new("/bob/team");
    let phone = Setup::new(&bob, "/bob/team/phone")
        .policy(IntroPolicy::new())
        .start()
        .await;
    let carol = Person::new("/carol/team");
    phone
        .validator
        .adopt_context(Arc::clone(&carol.ctx))
        .unwrap();
    let carols = fingerprint(&carol);
    let stranger = [0x42u8; 32];

    let root = overlap(
        &phone.invites.inner().node,
        &phone.invites.inner().policy,
        &Name::root(),
        &stranger,
    );
    assert!(root.is_some_and(|w| w.contains("root")), "the root");

    for (ns, says) in [
        ("/localhost", "reserved"),
        ("/org", "share"),
        ("/bob/team", "own namespace"),
        ("/bob/team/sub", "own namespace"),
        ("/bob", "own namespace"),
        ("/carol/team", "under another anchor"),
        ("/carol/team/sub", "lies under"),
        ("/carol", "lies over"),
    ] {
        let why = judged(&phone, ns, &stranger);
        assert!(
            why.as_ref().is_some_and(|w| w.contains(says)),
            "{ns} under a stranger's anchor: {why:?} does not say {says:?}"
        );
    }

    // Held already, by the anchor held: a party known, and welcome again.
    assert_eq!(judged(&phone, "/carol/team", &carols), None);
    // Under or over what is held it is refused whatever its anchor.
    assert!(judged(&phone, "/carol/team/sub", &carols).is_some());
    assert!(judged(&phone, "/carol", &carols).is_some());
    // Unrelated to everything held.
    assert_eq!(judged(&phone, "/dave", &stranger), None);
}
