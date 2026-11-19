//! Keys whose authority over Data has ended but which no version revokes
//! yet: the root issues their revocation with a cut ([`ending_keys`]).
//!
//! Data is judged without a clock (a key's certificate expiring does not end
//! what it signs), so a key's authority over Data ends only by a revocation.
//! Two kinds of keys must end even though nobody lost them:
//!
//! - **Lapsed**: a key of a role the trust context lists in
//!   `DataRequiresCut` (every role, in a context `ndn-fwd init` makes; an
//!   older one lists `guest` alone) whose newest certificate's
//!   NotAfter has passed. Until the revocation exists, every node refuses
//!   its Data once no certificate of it is valid by the node's clock (fails
//!   closed); the cut then re-admits what it wrote before NotAfter. A
//!   device that was offline across NotAfter cannot renew (the CA renews
//!   only a current certificate): it enrols again, and what it signed after
//!   NotAfter is outside the cut, so it stays refused until the owner
//!   re-admits exact packets (`ndn-fwd readmit`).
//! - **Replaced**: a key of a device identity the CA certified a newer key
//!   for (one key per device name): the old key's Data stays accepted until
//!   it is revoked.
//!
//! Each is ended by a revocation with a cut bounded at the moment it ended
//! ([`EndingKey::held_before`]: the NotAfter, or the replacement's first
//! NotBefore): the cut holds only entries the root's data layer first
//! verified before then. The list is derived from what the root device
//! holds (the CA's issued certificates and the held version), never stored,
//! so it cannot drift: a key leaves it once a version revokes it.

use ndn_packet::Name;
use ndn_security::{Certificate, SignedTrustContext};

use crate::context_update::key_name_of;

/// Why a key's authority over Data ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// Its role requires a cut for Data and its newest certificate's
    /// NotAfter (ms since the Unix epoch) has passed.
    Lapsed { not_after: u64 },
    /// The CA certified the key `by` for the same device identity, first
    /// valid from `enrolled` (ms since the Unix epoch).
    Replaced { by: Name, enrolled: u64 },
}

/// A key to revoke with a cut bounded at `held_before`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndingKey {
    pub key: Name,
    pub why: Ending,
    /// When its authority ended (ms since the Unix epoch): its cut may hold
    /// only entries first verified before then.
    pub held_before: u64,
}

const NS_PER_MS: u64 = 1_000_000;

/// Per key of `ctx`'s namespace that ending may list, from the certificates
/// `issued`: its first NotBefore and its last NotAfter, in ms. Never a key
/// `ctx` revokes, an anchor's key or a key under `<ns>/CA`.
fn key_spans(ctx: &SignedTrustContext, issued: &[Certificate]) -> Vec<(Name, u64, u64)> {
    let namespace = ctx.namespace();
    let ca = namespace.clone().append("CA");
    let mut keys: Vec<(Name, u64, u64)> = Vec::new();
    for cert in issued {
        let Some(key) = key_name_of(&cert.name) else {
            continue;
        };
        if !key.has_prefix(namespace)
            || key.has_prefix(&ca)
            || ctx.is_revoked(&key)
            || ctx.anchors().iter().any(|a| a.key().has_prefix(&key))
        {
            continue;
        }
        let (from, until) = (cert.valid_from / NS_PER_MS, cert.valid_until / NS_PER_MS);
        match keys.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, first, last)) => {
                *first = (*first).min(from);
                *last = (*last).max(until);
            }
            None => keys.push((key, from, until)),
        }
    }
    keys
}

/// The keys of `ctx`'s namespace, from the certificates `issued`, that are
/// lapsed at `now` (ms since the Unix epoch) and of a device role among
/// `roles` (role names), whatever `ctx` itself lists in `DataRequiresCut`:
/// the keys a context listing exactly `roles` would refuse the Data of.
/// Ordered by key name.
pub fn lapsed_for_roles(
    ctx: &SignedTrustContext,
    issued: &[Certificate],
    now: u64,
    roles: &[String],
) -> Vec<EndingKey> {
    let mut lapsed: Vec<EndingKey> = key_spans(ctx, issued)
        .into_iter()
        .filter(|(key, _, last)| {
            *last < now
                && ctx
                    .role_of(key)
                    .is_some_and(|role| roles.iter().any(|r| r.as_bytes() == role))
        })
        .map(|(key, _, last)| EndingKey {
            key,
            why: Ending::Lapsed { not_after: last },
            held_before: last,
        })
        .collect();
    lapsed.sort_by(|a, b| a.key.cmp(&b.key));
    lapsed
}

/// The keys of `ctx`'s namespace whose authority over Data ended by `now`
/// (ms since the Unix epoch) and that `ctx` does not revoke, from the
/// certificates `issued` (what the namespace CA issued): lapsed keys of a
/// role `ctx` lists in `DataRequiresCut`, and keys replaced by a newer key
/// of the same identity. A key both lapsed and replaced ends at the
/// earlier of the two. Never an anchor's key or a key under `<ns>/CA`; the
/// root device's own admin key is listed like any other once it lapses.
/// Ordered by key name.
pub fn ending_keys(ctx: &SignedTrustContext, issued: &[Certificate], now: u64) -> Vec<EndingKey> {
    let keys = key_spans(ctx, issued);
    let identity = |key: &Name| {
        let comps = key.components();
        Name::from_components(comps[..comps.len().saturating_sub(2)].iter().cloned())
    };
    let mut ending: Vec<EndingKey> = Vec::new();
    for (key, first, last) in &keys {
        let lapsed = (ctx.requires_cut_for(key) && *last < now)
            .then_some(Ending::Lapsed { not_after: *last });
        // The next key of the same identity the CA certified after this one.
        let replaced = keys
            .iter()
            .filter(|(other, from, _)| {
                other != key && identity(other) == identity(key) && from > first && *from <= now
            })
            .min_by_key(|(other, from, _)| (*from, other.clone()))
            .map(|(by, from, _)| Ending::Replaced {
                by: by.clone(),
                enrolled: *from,
            });
        let at = |e: &Ending| match e {
            Ending::Lapsed { not_after } => *not_after,
            Ending::Replaced { enrolled, .. } => *enrolled,
        };
        let why = match (lapsed, replaced) {
            (Some(l), Some(r)) => Some(if at(&r) < at(&l) { r } else { l }),
            (l, r) => l.or(r),
        };
        if let Some(why) = why {
            ending.push(EndingKey {
                key: key.clone(),
                held_before: at(&why),
                why,
            });
        }
    }
    ending.sort_by(|a, b| a.key.cmp(&b.key));
    ending
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ndn_security::KeyRole;

    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// A certificate of `key` valid from `from` until `until` (ms).
    fn cert(key: &str, from: u64, until: u64) -> Certificate {
        Certificate {
            name: Arc::new(n(&format!("{key}/NDNCERT/%01"))),
            public_key: bytes::Bytes::new(),
            valid_from: from * NS_PER_MS,
            valid_until: until * NS_PER_MS,
            issuer: Some(Arc::new(n("/home/bob/CA/KEY/ca"))),
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        }
    }

    /// `/home/bob` listing guest in DataRequiresCut, as `ndn-fwd init` makes.
    fn ctx() -> SignedTrustContext {
        SignedTrustContext::hierarchical(n("/home/bob")).with_data_requires_cut("guest")
    }

    #[test]
    fn a_lapsed_key_of_a_listed_role_ends_at_its_last_not_after() {
        let now = 1_000;
        let issued = [
            // Lapsed, renewed once: ends at the later NotAfter.
            cert("/home/bob/guest/ann/KEY/a", 100, 400),
            cert("/home/bob/guest/ann/KEY/a", 300, 600),
            // Still valid.
            cert("/home/bob/guest/eve/KEY/e", 100, 2_000),
            // A role not listed: its Data is judged without clocks.
            cert("/home/bob/member/tv/KEY/t", 100, 500),
            // Never the CA's keys.
            cert("/home/bob/CA/KEY/ca", 100, 500),
        ];
        let ending = ending_keys(&ctx(), &issued, now);
        assert_eq!(
            ending,
            [EndingKey {
                key: n("/home/bob/guest/ann/KEY/a"),
                why: Ending::Lapsed { not_after: 600 },
                held_before: 600,
            }]
        );
        // Without DataRequiresCut nothing lapses.
        let unlisted = SignedTrustContext::hierarchical(n("/home/bob"));
        assert!(ending_keys(&unlisted, &issued, now).is_empty());
        // A key the held version revokes is not listed again.
        let revoked = ctx().with_revocation(n("/home/bob/guest/ann/KEY/a"));
        assert!(ending_keys(&revoked, &issued, now).is_empty());
    }

    /// `/home/bob` listing every role, as a namespace the creation path makes
    /// now does.
    fn ctx_every_role() -> SignedTrustContext {
        ["admin", "member", "node", "guest"].into_iter().fold(
            SignedTrustContext::hierarchical(n("/home/bob")),
            |ctx, role| ctx.with_data_requires_cut(role),
        )
    }

    #[test]
    fn a_lapsed_key_of_any_role_ends_when_its_context_lists_every_role() {
        let now = 1_000;
        let issued = [
            cert("/home/bob/member/tv/KEY/t", 100, 500),
            cert("/home/bob/admin/desk/KEY/d", 100, 500),
            cert("/home/bob/node/vps/KEY/v", 100, 500),
            cert("/home/bob/guest/ann/KEY/a", 100, 500),
            // A device that renewed before it lapsed does not end.
            cert("/home/bob/member/phone/KEY/p", 100, 500),
            cert("/home/bob/member/phone/KEY/p", 400, 5_000),
            // Never the CA's keys.
            cert("/home/bob/CA/KEY/ca", 100, 500),
        ];
        let lapsed = |key: &str| EndingKey {
            key: n(key),
            why: Ending::Lapsed { not_after: 500 },
            held_before: 500,
        };
        let mut want = [
            lapsed("/home/bob/admin/desk/KEY/d"),
            lapsed("/home/bob/guest/ann/KEY/a"),
            lapsed("/home/bob/member/tv/KEY/t"),
            lapsed("/home/bob/node/vps/KEY/v"),
        ];
        want.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(ending_keys(&ctx_every_role(), &issued, now), want);
        // A context made before this rule lists guest alone: the member
        // key's lapse is not listed (and `ndn-fwd status` says so).
        let only_member = ending_keys(&ctx(), &issued, now);
        assert_eq!(only_member, [lapsed("/home/bob/guest/ann/KEY/a")]);
    }

    #[test]
    fn a_replaced_key_ends_when_the_next_key_of_its_device_was_enrolled() {
        let now = 1_000;
        let issued = [
            cert("/home/bob/member/phone/KEY/a", 100, 5_000),
            cert("/home/bob/member/phone/KEY/b", 300, 5_000),
            cert("/home/bob/member/phone/KEY/c", 700, 5_000),
            // A replacement not valid yet replaces nothing yet.
            cert("/home/bob/member/tv/KEY/a", 100, 5_000),
            cert("/home/bob/member/tv/KEY/b", 2_000, 5_000),
            // Keys of another device are no replacement.
            cert("/home/bob/member/laptop/KEY/a", 100, 5_000),
        ];
        let ending = ending_keys(&ctx(), &issued, now);
        assert_eq!(
            ending,
            [
                EndingKey {
                    key: n("/home/bob/member/phone/KEY/a"),
                    why: Ending::Replaced {
                        by: n("/home/bob/member/phone/KEY/b"),
                        enrolled: 300,
                    },
                    held_before: 300,
                },
                EndingKey {
                    key: n("/home/bob/member/phone/KEY/b"),
                    why: Ending::Replaced {
                        by: n("/home/bob/member/phone/KEY/c"),
                        enrolled: 700,
                    },
                    held_before: 700,
                },
            ]
        );
    }

    #[test]
    fn a_key_both_lapsed_and_replaced_ends_at_the_earlier() {
        let now = 1_000;
        let replaced_first = [
            cert("/home/bob/guest/ann/KEY/a", 100, 600),
            cert("/home/bob/guest/ann/KEY/b", 400, 5_000),
        ];
        let ending = ending_keys(&ctx(), &replaced_first, now);
        assert_eq!(ending.len(), 1);
        assert_eq!(ending[0].held_before, 400);
        assert!(matches!(ending[0].why, Ending::Replaced { .. }));

        let lapsed_first = [
            cert("/home/bob/guest/ann/KEY/a", 100, 300),
            cert("/home/bob/guest/ann/KEY/b", 400, 5_000),
        ];
        let ending = ending_keys(&ctx(), &lapsed_first, now);
        assert_eq!(ending.len(), 1);
        assert_eq!(ending[0].why, Ending::Lapsed { not_after: 300 });
    }

    /// Round-8 L-d: the root device's own admin key lapses like any other
    /// key of a listed role, and the owner ends it from the list (its Data is
    /// refused meanwhile). The CA's key, also a root-device key, is never
    /// listed.
    #[test]
    fn the_root_devices_own_lapsed_key_is_listed_to_end() {
        let desk = "/home/bob/admin/desk/KEY/device";
        let ctx = ctx_every_role()
            .with_key_role(KeyRole::ROOT_DEVICE, n(desk))
            .with_key_role(KeyRole::ROOT_DEVICE, n("/home/bob/CA/KEY/ca"));
        let issued = [
            cert(desk, 100, 500),
            cert("/home/bob/CA/KEY/ca", 100, 500),
            // Still valid: not listed.
            cert("/home/bob/admin/phone/KEY/p", 100, 5_000),
        ];
        assert_eq!(
            ending_keys(&ctx, &issued, 1_000),
            [EndingKey {
                key: n(desk),
                why: Ending::Lapsed { not_after: 500 },
                held_before: 500,
            }]
        );
    }

    /// Round-8 L-c: which keys a context listing exactly `roles` would
    /// refuse the Data of, whatever the held context lists: lapsed keys of
    /// those roles only (a replaced key is not refused, a valid one is not
    /// lapsed, the CA's key is never listed).
    #[test]
    fn lapsed_for_roles_lists_the_lapsed_keys_of_those_roles_only() {
        let issued = [
            cert("/home/bob/member/tv/KEY/t", 100, 500),
            cert("/home/bob/guest/ann/KEY/a", 100, 500),
            cert("/home/bob/node/vps/KEY/v", 100, 5_000),
            // Replaced, not lapsed: refused by nobody.
            cert("/home/bob/member/phone/KEY/a", 100, 5_000),
            cert("/home/bob/member/phone/KEY/b", 300, 5_000),
            cert("/home/bob/CA/KEY/ca", 100, 500),
        ];
        let roles = |r: &[&str]| r.iter().map(|r| r.to_string()).collect::<Vec<_>>();
        let held = ctx();
        assert_eq!(
            lapsed_for_roles(&held, &issued, 1_000, &roles(&["member", "node"])),
            [EndingKey {
                key: n("/home/bob/member/tv/KEY/t"),
                why: Ending::Lapsed { not_after: 500 },
                held_before: 500,
            }]
        );
        assert!(lapsed_for_roles(&held, &issued, 1_000, &[]).is_empty());
    }
}
