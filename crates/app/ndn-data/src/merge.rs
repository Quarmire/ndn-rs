//! The built-in merge rule: the register, `/ndf/merge/newest/v=1`. A path
//! holds the bytes of its newest version, and an empty version is a removal.
//!
//! A version supersedes every version in its past (those its writer had
//! applied when it signed). The versions nothing supersedes are the heads;
//! the state is the head with the highest **signed digest** ([`winner`]):
//! the digest of what its key signed, which every copy of the packet shares
//! (an ECDSA signature value is malleable, so the digest of the whole
//! packet is not the same on every device). Every device holding the same
//! versions reads the same winner, and a head that is later in no one's
//! past never loses to an older one. The value is `by ‖ bytes`: the
//! writer's person (the 32-byte hash in its namespace `/user/<0xA1 hash>`,
//! else zeros) and what it wrote.
//!
//! Only heads are kept, so memory is bounded by the concurrent writes, not
//! by the history, and a head is only its id and digest: the winner's value
//! is the one copy of bytes the state holds, and a head that becomes the
//! winner later is read again from where the layer holds it (`Ops`). A
//! collection's [`Rule::Merge`](crate::Rule::Merge) names this function
//! exactly; a device holds the versions of a collection that names another
//! and reads them under no rule
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
/// its version's signed digest ([`crate::wire::signed_digest`]) and whatever
/// the caller wants back of it.
pub fn winner<'a, T>(heads: impl IntoIterator<Item = (&'a [u8; 32], T)>) -> Option<T> {
    heads
        .into_iter()
        .max_by_key(|(digest, _)| *digest)
        .map(|(_, head)| head)
}

/// Where the layer holds the operations of the versions applied.
pub(crate) trait Ops {
    /// The `MergeOp` octets of the applied version `id`, if they can be read
    /// now (an operation travelling in pieces is read from the store).
    fn op_of(&self, id: &VersionId) -> Option<Bytes>;
}

/// No version held: an own first version on an empty state.
pub(crate) struct NoOps;

impl Ops for NoOps {
    fn op_of(&self, _: &VersionId) -> Option<Bytes> {
        None
    }
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
    /// The digest of what its key signed ([`crate::wire::signed_digest`]):
    /// the same on every copy of the packet, whatever its signature value.
    pub(crate) signed: &'a [u8; 32],
    /// The versions it was made over.
    pub(crate) past: &'a dyn Past,
    /// The `MergeOp` octets.
    pub(crate) bytes: &'a Bytes,
    /// The operations of the versions applied before it.
    pub(crate) ops: &'a dyn Ops,
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

    /// The merged value; `Err(id)` when the winning version `id`'s
    /// operation cannot be read now.
    fn value(&self) -> Result<Value, VersionId>;
}

/// The register.
struct Newest(Name);

impl MergeRule for Newest {
    fn start(&self) -> Box<dyn MergeState> {
        Box::new(Heads::default())
    }
}

/// A head: the version and its signed digest (the tie-break).
struct Head {
    id: VersionId,
    signed: [u8; 32],
}

/// The heads, and the winner's value: the only operation bytes held.
#[derive(Default)]
struct Heads {
    heads: Vec<Head>,
    /// The winner, and its `by ‖ bytes` when it could be read.
    winner: Option<VersionId>,
    value: Option<Bytes>,
}

/// The person who signed `id`: the hash in the namespace its key lies under,
/// else zeros.
fn person_of(id: &VersionId) -> [u8; 32] {
    ndn_security::self_certifying::personal_namespace_of(id.writer.key())
        .and_then(|person| person.components()[1].value[..].try_into().ok())
        .unwrap_or_default()
}

impl MergeState for Heads {
    fn apply(&mut self, op: &Op<'_>) {
        if self.heads.iter().any(|h| h.id == *op.id) {
            return;
        }
        self.heads.retain(|h| !op.past.contains(&h.id));
        self.heads.push(Head {
            id: op.id.clone(),
            signed: *op.signed,
        });
        let top = winner(self.heads.iter().map(|h| (&h.signed, &h.id)))
            .expect("a head was just added")
            .clone();
        if self.winner.as_ref() == Some(&top) && self.value.is_some() {
            return;
        }
        let bytes = if top == *op.id {
            Some(op.bytes.clone())
        } else {
            op.ops.op_of(&top)
        };
        self.value = bytes.map(|bytes| {
            let mut value = person_of(&top).to_vec();
            value.extend_from_slice(&bytes);
            Bytes::from(value)
        });
        self.winner = Some(top);
    }

    fn value(&self) -> Result<Value, VersionId> {
        match (&self.winner, &self.value) {
            (None, _) => Ok(Value::Rule(Bytes::new())),
            (Some(_), Some(value)) => Ok(Value::Rule(value.clone())),
            (Some(id), None) => Err(id.clone()),
        }
    }
}

#[cfg(test)]
impl Heads {
    /// The octets of operations the state keeps: the winner's value, the
    /// only one it holds.
    fn held(&self) -> usize {
        self.value.as_ref().map_or(0, Bytes::len)
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

    thread_local! {
        /// The operations applied through [`apply`], where `Ops` reads them.
        static APPLIED: std::cell::RefCell<Vec<(VersionId, Bytes)>> = const {
            std::cell::RefCell::new(Vec::new())
        };
    }

    struct Applied;

    impl Ops for Applied {
        fn op_of(&self, id: &VersionId) -> Option<Bytes> {
            APPLIED.with(|a| {
                a.borrow()
                    .iter()
                    .find(|(v, _)| v == id)
                    .map(|(_, op)| op.clone())
            })
        }
    }

    /// `bytes` as a version `id` made over `past` and signed-digested
    /// `digest`, applied to `state`.
    fn apply(
        state: &mut dyn MergeState,
        id: &VersionId,
        digest: u8,
        past: &[&VersionId],
        bytes: &[u8],
    ) {
        let past = Over(past.iter().map(|i| (*i).clone()).collect());
        let bytes = Bytes::copy_from_slice(bytes);
        APPLIED.with(|a| a.borrow_mut().push((id.clone(), bytes.clone())));
        state.apply(&Op {
            id,
            signed: &[digest; 32],
            past: &past,
            bytes: &bytes,
            ops: &Applied,
        });
    }

    /// What the state reads: its value's bytes.
    fn value_of(state: &dyn MergeState) -> Bytes {
        state
            .value()
            .expect("the winner is readable")
            .bytes()
            .expect("a rule value")
            .clone()
    }

    /// The person and the bytes the state reads.
    fn read(state: &dyn MergeState) -> (u8, Vec<u8>) {
        let v = value_of(state);
        (
            v.first().copied().unwrap_or(0),
            v.get(32..).unwrap_or_default().to_vec(),
        )
    }

    fn fresh() -> Box<dyn MergeState> {
        APPLIED.with(|a| a.borrow_mut().clear());
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
        assert_eq!(value_of(&*s).len(), 32);
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
        let v = value_of(&*s);
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
        assert_eq!(value_of(&*s).as_ref(), &[&[0u8; 32][..], b"x"].concat()[..]);
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

    #[test]
    fn a_head_that_wins_once_the_winner_is_superseded_is_read_again() {
        let (a, b, c) = (id(1, 1), id(2, 1), id(3, 1));
        let mut s = fresh();
        apply(&mut *s, &a, 5, &[], b"from a");
        apply(&mut *s, &b, 9, &[], b"from b");
        assert_eq!(read(&*s), (2, b"from b".to_vec()));
        // `c` is made over `b` only: `a` stays a head and now wins (5 > 1),
        // though the state held nothing of it but its id.
        apply(&mut *s, &c, 1, &[&b], b"from c");
        assert_eq!(read(&*s), (1, b"from a".to_vec()));
    }

    /// What a state keeps of the values written is one value, not one per
    /// head: many concurrent writers of large values (every key a person's
    /// namespace issues may write) cost the memory of one.
    #[test]
    fn memory_does_not_grow_with_heads_times_value_size() {
        let mut heads = Heads::default();
        let big = Bytes::from(vec![7u8; 1 << 20]);
        for i in 0..8u8 {
            heads.apply(&Op {
                id: &id(i + 1, 1),
                signed: &[i + 1; 32],
                past: &Over(Vec::new()),
                bytes: &big,
                ops: &NoOps,
            });
        }
        assert!(
            heads.held() < 2 << 20,
            "8 heads of 1 MiB hold {} octets",
            heads.held()
        );
        assert_eq!(heads.heads.len(), 8);
    }
}
