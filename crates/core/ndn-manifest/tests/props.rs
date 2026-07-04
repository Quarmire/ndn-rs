//! R13 property tests: decode ∘ encode = byte identity, or reject — over
//! randomized documents (ndf-the-landing Act III: "property-test this").
//!
//! The strong form of the property is baked into `decode_document` itself
//! (it re-encodes and compares before returning), so the tests here assert:
//! every encodable model document decodes successfully — i.e. the encoder
//! only ever produces canonical bytes — and hashing is stable.

use ndn_manifest::canon::{decode_document, document_hash, encode_decoded, encode_document};
use ndn_manifest::model::*;
use ndn_manifest::Hash;
use proptest::prelude::*;

fn hash_strategy() -> impl Strategy<Value = Hash> {
    any::<[u8; 32]>()
}

fn label_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,9}"
}

fn primitive_strategy() -> impl Strategy<Value = PrimitiveKind> {
    prop::sample::select(vec![
        PrimitiveKind::Bytes,
        PrimitiveKind::Text,
        PrimitiveKind::Integer,
        PrimitiveKind::Decimal,
        PrimitiveKind::Boolean,
        PrimitiveKind::Hash,
        PrimitiveKind::Name,
    ])
}

fn decimal_strategy() -> impl Strategy<Value = Decimal> {
    (any::<i32>(), 0u32..10_000).prop_map(|(int, frac)| {
        let raw = format!("{int}.{frac}");
        Decimal::normalize(&raw).expect("digit strings normalize")
    })
}

/// Flat values only — what attributes may carry (knob #4).
fn flat_value_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..16).prop_map(Value::Bytes),
        "[ -~]{0,12}".prop_map(Value::Text),
        any::<u64>().prop_map(Value::Integer),
        decimal_strategy().prop_map(Value::Decimal),
        any::<bool>().prop_map(Value::Boolean),
        hash_strategy().prop_map(Value::Hash),
        "[a-z0-9/.-]{0,16}".prop_map(Value::Name),
        hash_strategy().prop_map(Value::TermRef),
    ]
}

fn value_strategy() -> impl Strategy<Value = Value> {
    flat_value_strategy().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::List),
            // Unique string keys sidestep authoring-side duplicate rejects;
            // the encoder re-sorts by canonical key bytes (R8).
            prop::collection::btree_map("[a-z]{1,6}", inner.clone(), 0..4).prop_map(|m| {
                Value::Map(m.into_iter().map(|(k, v)| (Value::Text(k), v)).collect())
            }),
            prop::collection::vec(inner, 0..4).prop_map(Value::Record),
        ]
    })
}

fn attr_strategy() -> impl Strategy<Value = Attribute> {
    (hash_strategy(), flat_value_strategy()).prop_map(|(key, value)| Attribute { key, value })
}

fn cardinality_strategy() -> impl Strategy<Value = Cardinality> {
    prop::sample::select(vec![
        Cardinality::One,
        Cardinality::Optional,
        Cardinality::Some,
        Cardinality::Many,
    ])
}

fn type_strategy() -> impl Strategy<Value = TypeExpr> {
    let leaf = prop_oneof![
        primitive_strategy().prop_map(TypeExpr::Primitive),
        hash_strategy().prop_map(TypeExpr::TermOf),
        Just(TypeExpr::Opaque),
    ];
    leaf.prop_recursive(2, 12, 3, |inner| {
        let key = prop_oneof![
            Just(TypeExpr::Primitive(PrimitiveKind::Text)),
            Just(TypeExpr::Primitive(PrimitiveKind::Integer)),
            Just(TypeExpr::Primitive(PrimitiveKind::Hash)),
            Just(TypeExpr::Primitive(PrimitiveKind::Name)),
            hash_strategy().prop_map(TypeExpr::TermOf),
        ];
        prop_oneof![
            inner.clone().prop_map(|t| TypeExpr::ListOf(Box::new(t))),
            (key, inner.clone()).prop_map(|(k, v)| TypeExpr::MapOf(Box::new(k), Box::new(v))),
            (hash_strategy(), inner.clone()).prop_map(|(h, t)| TypeExpr::Of(h, Box::new(t))),
            prop::collection::vec((label_strategy(), inner, cardinality_strategy()), 0..3).prop_map(
                |fs| {
                    TypeExpr::Record(
                        fs.into_iter()
                            .map(|(label, ty, cardinality)| Field {
                                label,
                                doc: None,
                                ty,
                                cardinality,
                                attrs: Vec::new(),
                            })
                            .collect(),
                    )
                }
            ),
        ]
    })
}

fn term_strategy() -> impl Strategy<Value = Term> {
    (
        label_strategy(),
        prop::option::of("[ -~]{0,20}"),
        prop::option::of(type_strategy()),
        prop::collection::vec(attr_strategy(), 0..2),
    )
        .prop_map(|(label, doc, ty, attrs)| Term { label, doc, ty, attrs })
}

fn subject_strategy() -> impl Strategy<Value = Subject> {
    prop_oneof![
        hash_strategy().prop_map(Subject::Hash),
        "[a-z0-9/.-]{1,20}".prop_map(Subject::Name),
    ]
}

fn edge_strategy() -> impl Strategy<Value = EdgeForm> {
    prop_oneof![
        (hash_strategy(), hash_strategy())
            .prop_map(|(narrower, broader)| EdgeForm::NarrowerThan { narrower, broader }),
        (hash_strategy(), hash_strategy()).prop_map(|(a, b)| EdgeForm::EquivalentTo { a, b }),
        (hash_strategy(), hash_strategy(), hash_strategy(), prop::collection::vec(attr_strategy(), 0..2))
            .prop_map(|(from, to, loss, attrs)| EdgeForm::MapsTo { from, to, loss, attrs }),
        (subject_strategy(), hash_strategy(), subject_strategy(), prop::collection::vec(attr_strategy(), 0..2))
            .prop_map(|(subject, kind, object, attrs)| EdgeForm::Edge { subject, kind, object, attrs }),
    ]
}

fn vocabulary_strategy() -> impl Strategy<Value = Document> {
    (
        label_strategy(),
        prop::option::of("[ -~]{0,20}"),
        prop::collection::vec(hash_strategy(), 0..3),
        prop::collection::vec(term_strategy(), 0..4),
        prop::collection::vec(edge_strategy(), 0..3),
        prop::option::of(hash_strategy()),
    )
        .prop_map(|(label, doc, imports, terms, edges, supersedes)| {
            Document::Vocabulary(Vocabulary { label, doc, imports, terms, edges, supersedes })
        })
}

fn manifest_strategy() -> impl Strategy<Value = Document> {
    (
        hash_strategy(),
        prop::option::of(label_strategy()),
        subject_strategy(),
        prop::collection::vec((hash_strategy(), value_strategy()), 0..4),
        prop::collection::vec(edge_strategy(), 0..2),
    )
        .prop_map(|(ty, label, describes, entries, edges)| {
            Document::Manifest(Manifest {
                ty,
                label,
                describes,
                entries: entries
                    .into_iter()
                    .map(|(field, value)| ManifestEntry { field, value })
                    .collect(),
                edges,
            })
        })
}

fn intent_strategy() -> impl Strategy<Value = Intent> {
    ("[a-z]{1,8}\\.[a-z]{1,8}", prop::collection::vec(attr_strategy(), 0..2))
        .prop_map(|(name, attrs)| Intent { name, attrs })
}

fn via_strategy() -> impl Strategy<Value = Via> {
    prop_oneof![
        hash_strategy().prop_map(Via::Wasm),
        "[a-z0-9:-]{1,16}".prop_map(Via::Native),
    ]
}

fn contract_strategy() -> impl Strategy<Value = Document> {
    // Opaque `impl Strategy` values cannot be cloned, so each use site
    // builds a fresh strategy instead.
    let clause = prop_oneof![
        (intent_strategy(), hash_strategy(), prop::option::of(via_strategy()), prop::collection::vec(attr_strategy(), 0..2))
            .prop_map(|(intent, target, via, attrs)| Clause::Express { intent, target, via, attrs }),
        (intent_strategy(), hash_strategy(), prop::option::of(via_strategy()), prop::collection::vec(attr_strategy(), 0..2))
            .prop_map(|(intent, target, via, attrs)| Clause::Approximate { intent, target, via, attrs }),
        intent_strategy().prop_map(|intent| Clause::Refuse { intent }),
    ];
    (
        label_strategy(),
        prop::option::of("[ -~]{0,20}"),
        prop::collection::vec(hash_strategy(), 0..2),
        prop::collection::vec(subject_strategy(), 0..2),
        prop::collection::vec(clause, 0..4),
    )
        .prop_map(|(label, doc, imports, binds, clauses)| {
            Document::Contract(Contract { label, doc, imports, binds, clauses })
        })
}

fn document_strategy() -> impl Strategy<Value = Document> {
    prop_oneof![vocabulary_strategy(), manifest_strategy(), contract_strategy()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// R13, positive direction: whatever the encoder emits, the decoder
    /// accepts — and (enforced inside `decode_document`) re-encodes to the
    /// identical bytes.
    #[test]
    fn encoder_output_is_canonical(doc in document_strategy()) {
        let bytes = encode_document(&doc).expect("model documents encode");
        let decoded = decode_document(&bytes).expect("canonical bytes decode (R13)");
        prop_assert!(!decoded.critical);
        prop_assert_eq!(encode_decoded(&decoded).expect("re-encode"), bytes.clone());
        // Hash stability: the document hash is a pure function of the bytes.
        prop_assert_eq!(document_hash(&bytes), document_hash(&bytes));
    }

    /// Single-byte corruption never panics: it either still decodes (rare —
    /// e.g. a flipped bit inside free-form text) or rejects with a typed
    /// reject. "Reject, not a tolerance" (R2) — and never a crash (W-19's
    /// spirit generalized).
    #[test]
    fn corruption_rejects_or_decodes_never_panics(
        doc in document_strategy(),
        idx in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let mut bytes = encode_document(&doc).expect("encode");
        if !bytes.is_empty() {
            let i = idx.index(bytes.len());
            bytes[i] ^= 1 << bit;
            let _ = decode_document(&bytes); // must not panic
        }
    }
}
