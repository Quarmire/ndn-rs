//! The built-in merge rule: the register, `/ndf/merge/newest/v=1`. A path
//! holds the bytes of its newest version, and an empty version is a removal.
//!
//! A version supersedes every version in its past (those its writer had
//! applied when it signed). The versions nothing supersedes are the heads;
//! the state is the head with the highest digest ([`winner`]), so every
//! device holding the same versions reads the same winner, and a head that
//! is later in no one's past never loses to an older one. The value is
//! `by ‖ bytes`: the writer's person (the 32-byte hash in its namespace
//! `/user/<0xA1 hash>`, else zeros) and what it wrote.
//!
//! Only heads are kept, so memory is bounded by the concurrent writes, not
//! by the history. A collection's [`Rule::Merge`](crate::Rule::Merge) names
//! this function exactly; a device holds the versions of a collection that
//! names another and reads them under no rule
//! ([`DataError::RuleUnknown`](crate::DataError::RuleUnknown)).

use std::sync::LazyLock;

use bytes::Bytes;
use ndn_foundation_types::Name;

use crate::layer::Value;
use crate::version::VersionId;

/// The register's name, as the members record of every collection spells it.
pub const NEWEST: &str = "/ndf/merge/newest/v=1";

static REGISTER: LazyLock<Newest> =
    LazyLock::new(|| Newest(NEWEST.parse().expect("the rule's name is an NDN name")));

/// The rule named exactly `function`, if this device knows it: the register.
pub(crate) fn rule(function: &Name) -> Option<&'static dyn MergeRule> {
    (*function == REGISTER.0).then_some(&*REGISTER as &dyn MergeRule)
}

/// The head `heads` read as: the one with the highest digest. Each head is
/// its version's digest and whatever the caller wants back of it.
pub fn winner<'a, T>(heads: impl IntoIterator<Item = (&'a [u8; 32], T)>) -> Option<T> {
    heads
        .into_iter()
        .max_by_key(|(digest, _)| *digest)
        .map(|(_, head)| head)
}

/// The versions an operation was made over: every version of the collection
/// at or below the version's parents joined with (its writer, seq − 1) that
/// applies at all. Every reader answers alike.
pub(crate) trait Past {
    /// Whether `id` lies inside it.
    fn contains(&self, id: &VersionId) -> bool;
}

/// One version's operation as the layer hands it to the rule.
pub(crate) struct Op<'a> {
    /// Its writer (one key) and seq.
    pub(crate) id: &'a VersionId,
    /// The implicit digest of its packet.
    pub(crate) digest: &'a [u8; 32],
    /// The versions it was made over.
    pub(crate) past: &'a dyn Past,
    /// The `MergeOp` octets.
    pub(crate) bytes: &'a [u8],
}

/// A named merge function.
pub(crate) trait MergeRule: Send + Sync {
    /// An empty state of a collection.
    fn start(&self) -> Box<dyn MergeState>;
}

/// One collection's state under a merge rule.
pub(crate) trait MergeState: Send {
    /// Apply an operation. The layer applies a version only after its
    /// writer's earlier ones and its parents. Whether a version counts is a
    /// function of the set of versions applied (each with its past), never
    /// of the order they arrived in.
    fn apply(&mut self, op: &Op<'_>);

    /// The merged value.
    fn value(&self) -> Value;
}

/// The register.
struct Newest(Name);

impl MergeRule for Newest {
    fn start(&self) -> Box<dyn MergeState> {
        Box::new(Heads(Vec::new()))
    }
}

/// A head: the version, its digest (the tie-break) and what it carries.
struct Head {
    id: VersionId,
    digest: [u8; 32],
    value: Bytes,
}

struct Heads(Vec<Head>);

/// The person who signed `id`: the hash in the namespace its key lies under,
/// else zeros.
fn person_of(id: &VersionId) -> [u8; 32] {
    ndn_security::self_certifying::personal_namespace_of(id.writer.key())
        .and_then(|person| person.components()[1].value[..].try_into().ok())
        .unwrap_or_default()
}

impl MergeState for Heads {
    fn apply(&mut self, op: &Op<'_>) {
        if self.0.iter().all(|h| h.id != *op.id) {
            self.0.retain(|h| !op.past.contains(&h.id));
            let mut value = person_of(op.id).to_vec();
            value.extend_from_slice(op.bytes);
            self.0.push(Head {
                id: op.id.clone(),
                digest: *op.digest,
                value: value.into(),
            });
        }
    }

    fn value(&self) -> Value {
        let heads = self.0.iter().map(|h| (&h.digest, &h.value));
        Value::Rule(winner(heads).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Seq, Writer};

    struct Over(Vec<VersionId>);

    impl Past for Over {
        fn contains(&self, id: &VersionId) -> bool {
            self.0.contains(id)
        }
    }

    /// A device of the person `person`: its key lies under
    /// `/user/<0xA1: person × 32>`.
    fn id(person: u8, seq: u64) -> VersionId {
        let hash = ndn_packet::NameComponent::new(
            ndn_security::self_certifying::SELF_CERTIFYING,
            Bytes::from(vec![person; 32]),
        );
        let key = Name::root()
            .append("user")
            .append_component(hash)
            .append("member")
            .append("d")
            .append("KEY")
            .append("1");
        VersionId {
            writer: Writer::new(key),
            seq: Seq(seq),
        }
    }

    /// `bytes` as a version `id` made over `past` and digested `digest`,
    /// applied to `state`.
    fn apply(
        state: &mut dyn MergeState,
        id: &VersionId,
        digest: u8,
        past: &[&VersionId],
        bytes: &[u8],
    ) {
        let past = Over(past.iter().map(|i| (*i).clone()).collect());
        state.apply(&Op {
            id,
            digest: &[digest; 32],
            past: &past,
            bytes,
        });
    }

    /// The person and the bytes the state reads.
    fn read(state: &dyn MergeState) -> (u8, Vec<u8>) {
        let value = state.value();
        let v = value.bytes().expect("a rule value");
        (
            v.first().copied().unwrap_or(0),
            v.get(32..).unwrap_or_default().to_vec(),
        )
    }

    fn fresh() -> Box<dyn MergeState> {
        rule(&NEWEST.parse().unwrap()).unwrap().start()
    }

    #[test]
    fn a_version_over_another_replaces_it_whatever_the_digests() {
        let (a1, a2) = (id(1, 1), id(1, 2));
        let mut s = fresh();
        assert_eq!(read(&*s), (0, vec![]), "nothing written reads as nothing");
        apply(&mut *s, &a1, 200, &[], b"old");
        apply(&mut *s, &a2, 1, &[&a1], b"new");
        assert_eq!(read(&*s), (1, b"new".to_vec()));
    }

    #[test]
    fn concurrent_versions_give_one_winner_in_any_order() {
        let (a, b) = (id(1, 1), id(2, 1));
        let (mut s, mut t) = (fresh(), fresh());
        apply(&mut *s, &a, 5, &[], b"from a");
        apply(&mut *s, &b, 9, &[], b"from b");
        apply(&mut *t, &b, 9, &[], b"from b");
        apply(&mut *t, &a, 5, &[], b"from a");
        assert_eq!(read(&*s), (2, b"from b".to_vec()));
        assert_eq!(read(&*s), read(&*t));
        // A version made over both settles it, whatever its digest.
        apply(&mut *s, &id(1, 2), 0, &[&a, &b], b"merged");
        assert_eq!(read(&*s), (1, b"merged".to_vec()));
    }

    #[test]
    fn an_empty_version_is_a_removal() {
        let (a1, a2) = (id(1, 1), id(1, 2));
        let mut s = fresh();
        apply(&mut *s, &a1, 1, &[], b"x");
        apply(&mut *s, &a2, 2, &[&a1], b"");
        assert_eq!(read(&*s), (1, vec![]));
        assert_eq!(s.value().bytes().map(|b| b.len()), Some(32));
    }

    #[test]
    fn a_version_applied_twice_counts_once() {
        let (a1, b1) = (id(1, 1), id(2, 1));
        let mut s = fresh();
        apply(&mut *s, &a1, 7, &[], b"a");
        apply(&mut *s, &b1, 3, &[], b"b");
        apply(&mut *s, &a1, 7, &[], b"a");
        assert_eq!(read(&*s), (1, b"a".to_vec()));
        apply(&mut *s, &id(2, 2), 0, &[&a1, &b1], b"c");
        assert_eq!(read(&*s), (2, b"c".to_vec()));
    }

    #[test]
    fn the_value_is_the_writers_person_then_the_bytes() {
        let mut s = fresh();
        apply(&mut *s, &id(9, 1), 1, &[], b"hello");
        let value = s.value();
        let v = value.bytes().unwrap();
        assert_eq!(&v[..32], &[9u8; 32][..]);
        assert_eq!(&v[32..], b"hello");
    }

    #[test]
    fn a_key_outside_a_person_namespace_is_by_zeros() {
        let outside = VersionId {
            writer: Writer::new("/alice/laptop/KEY/1".parse().unwrap()),
            seq: Seq(1),
        };
        let mut s = fresh();
        apply(&mut *s, &outside, 1, &[], b"x");
        assert_eq!(
            s.value().bytes().unwrap().as_ref(),
            &[&[0u8; 32][..], b"x"].concat()[..]
        );
    }

    #[test]
    fn the_winner_is_the_highest_digest() {
        let (lo, hi) = ([1u8; 32], [2u8; 32]);
        assert_eq!(winner([(&lo, "lo"), (&hi, "hi")]), Some("hi"));
        assert_eq!(winner([(&hi, "hi"), (&lo, "lo")]), Some("hi"));
        assert_eq!(winner(std::iter::empty::<(&[u8; 32], u8)>()), None);
    }

    #[test]
    fn only_the_register_is_a_rule() {
        assert!(rule(&"/merge/other/v=1".parse().unwrap()).is_none());
        assert!(rule(&NEWEST.parse().unwrap()).is_some());
    }
}
