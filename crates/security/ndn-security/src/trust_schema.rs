use ndn_packet::{Name, NameComponent};
use std::collections::HashMap;
use std::sync::Arc;

use crate::lvs::{LvsError, LvsModel, UserFnRegistry};

/// Error returned when a pattern or rule string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternParseError {
    #[error("empty pattern string")]
    Empty,
    #[error("unclosed capture variable (missing '>')")]
    UnclosedCapture,
    #[error("MultiCapture ('**') must be the last component")]
    MultiCaptureNotLast,
    #[error("rule must have exactly one '=>' separator")]
    BadRuleSeparator,
}

/// A single component in a name pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternComponent {
    /// Must match this exact component.
    Literal(NameComponent),
    /// Binds one component to a named variable.
    Capture(Arc<str>),
    /// Binds one or more trailing components to a named variable.
    MultiCapture(Arc<str>),
}

/// A name pattern with named capture groups; used to express rules like
/// "Data under `/sensor/<node>/<type>` must be signed by
/// `/sensor/<node>/KEY/<id>`" where `<node>` must match in both patterns.
///
/// Text format: `/`-separated components; `/literal` is a literal,
/// `/<var>` captures one component, `/<**var>` captures all remaining
/// components (must be last).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamePattern(pub Vec<PatternComponent>);

impl NamePattern {
    /// Parse a pattern from text; see the type-level docs for the grammar.
    ///
    /// ```
    /// use ndn_security::trust_schema::NamePattern;
    /// let _ = NamePattern::parse("/sensor/<node>/KEY/<id>").unwrap();
    /// ```
    pub fn parse(s: &str) -> Result<Self, PatternParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(PatternParseError::Empty);
        }
        let s = s.strip_prefix('/').unwrap_or(s);
        if s.is_empty() {
            return Ok(Self(vec![]));
        }

        let mut components = Vec::new();
        let parts: Vec<&str> = s.split('/').collect();
        let last_idx = parts.len().saturating_sub(1);

        for (i, part) in parts.iter().enumerate() {
            if let Some(inner) = part.strip_prefix('<') {
                let var = inner
                    .strip_suffix('>')
                    .ok_or(PatternParseError::UnclosedCapture)?;
                if let Some(multi_var) = var.strip_prefix("**") {
                    if i != last_idx {
                        return Err(PatternParseError::MultiCaptureNotLast);
                    }
                    components.push(PatternComponent::MultiCapture(Arc::from(multi_var)));
                } else {
                    components.push(PatternComponent::Capture(Arc::from(var)));
                }
            } else {
                let comp = NameComponent::generic(bytes::Bytes::copy_from_slice(part.as_bytes()));
                components.push(PatternComponent::Literal(comp));
            }
        }

        Ok(Self(components))
    }

    /// Attempt to match `name` against this pattern, extending `bindings`.
    /// Returns `true` if the match succeeds.
    pub fn matches(&self, name: &Name, bindings: &mut HashMap<Arc<str>, NameComponent>) -> bool {
        let components = name.components();
        let mut name_idx = 0;

        for pat in &self.0 {
            match pat {
                PatternComponent::Literal(c) => {
                    if name_idx >= components.len() || &components[name_idx] != c {
                        return false;
                    }
                    name_idx += 1;
                }
                PatternComponent::Capture(var) => {
                    if name_idx >= components.len() {
                        return false;
                    }
                    let comp = components[name_idx].clone();
                    if let Some(existing) = bindings.get(var) {
                        if existing != &comp {
                            return false;
                        }
                    } else {
                        bindings.insert(Arc::clone(var), comp);
                    }
                    name_idx += 1;
                }
                PatternComponent::MultiCapture(_var) => {
                    name_idx = components.len();
                }
            }
        }
        name_idx == components.len()
    }
}

/// Data matching `data_pattern` must be signed by a key matching
/// `key_pattern`; captured variables must agree across both. Serialized
/// as `"<data_pattern> => <key_pattern>"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaRule {
    pub data_pattern: NamePattern,
    pub key_pattern: NamePattern,
}

impl SchemaRule {
    pub fn parse(s: &str) -> Result<Self, PatternParseError> {
        let parts: Vec<&str> = s.splitn(2, "=>").collect();
        if parts.len() != 2 {
            return Err(PatternParseError::BadRuleSeparator);
        }
        let data_pattern = NamePattern::parse(parts[0].trim())?;
        let key_pattern = NamePattern::parse(parts[1].trim())?;
        Ok(Self {
            data_pattern,
            key_pattern,
        })
    }

    pub fn check(&self, data_name: &Name, key_name: &Name) -> bool {
        let mut bindings = HashMap::new();
        self.data_pattern.matches(data_name, &mut bindings)
            && self.key_pattern.matches(key_name, &mut bindings)
    }
}

impl std::fmt::Display for NamePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("/");
        }
        for comp in &self.0 {
            f.write_str("/")?;
            match comp {
                PatternComponent::Literal(nc) => {
                    f.write_str(&String::from_utf8_lossy(&nc.value))?;
                }
                PatternComponent::Capture(var) => {
                    write!(f, "<{var}>")?;
                }
                PatternComponent::MultiCapture(var) => {
                    write!(f, "<**{var}>")?;
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for SchemaRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} => {}", self.data_pattern, self.key_pattern)
    }
}

/// Trust-schema rules plus an optional compiled LightVerSec model.
///
/// Two independent rule sources are OR'd: native [`SchemaRule`]s authored
/// in ndn-rs's text grammar, and an [`LvsModel`] imported via
/// [`TrustSchema::from_lvs_binary`] from the binary TLV format used by
/// python-ndn, NDNts, and ndnd. [`TrustSchema::allows`] returns `true` if
/// either source permits the `(data_name, key_name)` pair.
#[derive(Clone, Debug, Default)]
pub struct TrustSchema {
    rules: Vec<SchemaRule>,
    lvs: Option<Arc<LvsModel>>,
    /// User-function handlers ($eq/$regex/…) for the LVS model (G8). Empty unless loaded
    /// via [`from_lvs_binary_with_user_fns`](Self::from_lvs_binary_with_user_fns), so the
    /// default path keeps fail-closing user functions.
    user_fns: UserFnRegistry,
}

impl TrustSchema {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            lvs: None,
            user_fns: UserFnRegistry::new(),
        }
    }

    pub fn add_rule(&mut self, rule: SchemaRule) {
        self.rules.push(rule);
    }

    /// Construct from a compiled LightVerSec model in its TLV binary form
    /// (python-ndn, NDNts `@ndn/lvs`, ndnd). Format spec:
    /// <https://python-ndn.readthedocs.io/en/latest/src/lvs/binary-format.html>.
    ///
    /// Returns [`LvsError::UserFunctionsNotSupported`] when the schema
    /// uses `$eq`, `$regex`, or any other user function — loading such a
    /// schema would silently mis-enforce it. Use [`LvsModel::decode`]
    /// directly to inspect without loading.
    pub fn from_lvs_binary(wire: &[u8]) -> Result<Self, LvsError> {
        let model = LvsModel::decode(wire)?;
        if model.uses_user_functions() {
            return Err(LvsError::UserFunctionsNotSupported);
        }
        Ok(Self {
            rules: Vec::new(),
            lvs: Some(Arc::new(model)),
            user_fns: UserFnRegistry::new(),
        })
    }

    /// As [`from_lvs_binary`](Self::from_lvs_binary), but enforces a schema that uses
    /// user functions by dispatching them through `registry` (G8). Returns
    /// [`LvsError::UserFunctionsNotSupported`] only if the schema references a function
    /// the registry does **not** cover — so an unhandled `$fn` still fails safe at load
    /// rather than silently never-matching at check time.
    pub fn from_lvs_binary_with_user_fns(
        wire: &[u8],
        registry: UserFnRegistry,
    ) -> Result<Self, LvsError> {
        let model = LvsModel::decode(wire)?;
        if let Some(missing) = model.user_fn_ids().iter().find(|id| !registry.covers(id)) {
            tracing::warn!(target: "ndn_security::lvs", fn_id = %missing, "LVS schema uses an unregistered user function");
            return Err(LvsError::UserFunctionsNotSupported);
        }
        Ok(Self {
            rules: Vec::new(),
            lvs: Some(Arc::new(model)),
            user_fns: registry,
        })
    }

    pub fn lvs_model(&self) -> Option<&LvsModel> {
        self.lvs.as_deref()
    }

    /// Checks native rules first, then falls through to the LVS model (dispatching any
    /// user functions through this schema's registry).
    pub fn allows(&self, data_name: &Name, key_name: &Name) -> bool {
        if self.rules.iter().any(|r| r.check(data_name, key_name)) {
            return true;
        }
        if let Some(lvs) = self.lvs.as_deref() {
            return lvs.check_with(data_name, key_name, &self.user_fns);
        }
        false
    }

    /// Reusable, general schema-driven authorization gate; see [`SchemaGate`].
    pub fn gate(self: &Arc<Self>) -> SchemaGate {
        SchemaGate {
            schema: Arc::clone(self),
        }
    }

    /// Native rules only; not the rules inside an imported LVS model.
    pub fn rules(&self) -> &[SchemaRule] {
        &self.rules
    }

    /// Remove the rule at `index`. Panics if out of bounds.
    pub fn remove_rule(&mut self, index: usize) -> SchemaRule {
        self.rules.remove(index)
    }

    /// Reset to reject-all (also clears any imported LVS model).
    pub fn clear(&mut self) {
        self.rules.clear();
        self.lvs = None;
    }

    /// Accept any signed packet regardless of name relationship. Suits the
    /// `AcceptSigned` security profile and tests.
    pub fn accept_all() -> Self {
        let mut schema = Self::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        schema
    }

    /// Hierarchical trust: data and key must share a top component. Full
    /// hierarchy enforcement is the cert chain walk's job — the schema
    /// only fixes the top-level namespace.
    pub fn hierarchical() -> Self {
        let mut schema = Self::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![
                PatternComponent::Capture("org".into()),
                PatternComponent::MultiCapture("_data".into()),
            ]),
            key_pattern: NamePattern(vec![
                PatternComponent::Capture("org".into()),
                PatternComponent::MultiCapture("_key".into()),
            ]),
        });
        schema
    }
}

/// A general, schema-driven **authorization gate** over a [`TrustSchema`]:
/// answers "may `principal` perform `action`?" as `schema.allows(action,
/// principal)`. The reusable seam for subsystems that gate an operation on a
/// trust schema (LVS or native rules) — e.g. management-command authorization,
/// compute-invocation authorization — rather than each re-deriving an ad-hoc
/// check.
///
/// Where the gated operation *is* a real signed packet (e.g. NDNCERT
/// device-approval), prefer validating that packet through a
/// [`Validator`](crate::Validator) — it evaluates the schema over the real
/// `(packet_name, cert_name)` plus the certificate chain, the canonical path.
///
/// The same `(name, name)` evaluation is what NDN trust schemas use for
/// signature validation (python-ndn `Checker.check`, ndnd `LvsSchema.Check`),
/// where the pair is `(packet_name, cert_name)` from a real signed packet.
/// **For parity with schemas authored for validation, `principal` should be a
/// real key/certificate name** (e.g. `/a/KEY/v=1`). A gate that passes bare
/// identities is using a *different* convention and needs its schema written
/// accordingly — see [`SchemaGate::authorize`].
#[derive(Clone)]
pub struct SchemaGate {
    schema: Arc<TrustSchema>,
}

impl SchemaGate {
    pub fn new(schema: Arc<TrustSchema>) -> Self {
        Self { schema }
    }

    /// `true` iff the schema permits `principal` to sign/produce `action`.
    /// Canonically `principal` is a key/cert name (the signer), matching how
    /// trust schemas are evaluated during validation.
    pub fn authorize(&self, action: &Name, principal: &Name) -> bool {
        self.schema.allows(action, principal)
    }

    pub fn schema(&self) -> &Arc<TrustSchema> {
        &self.schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn comp(s: &'static str) -> NameComponent {
        NameComponent::generic(Bytes::from_static(s.as_bytes()))
    }
    fn name(components: &[&'static str]) -> Name {
        Name::from_components(components.iter().map(|s| comp(s)))
    }

    #[test]
    fn literal_matches_exact() {
        let pat = NamePattern(vec![PatternComponent::Literal(comp("sensor"))]);
        assert!(pat.matches(&name(&["sensor"]), &mut HashMap::new()));
    }

    #[test]
    fn literal_rejects_wrong_component() {
        let pat = NamePattern(vec![PatternComponent::Literal(comp("sensor"))]);
        assert!(!pat.matches(&name(&["actuator"]), &mut HashMap::new()));
    }

    #[test]
    fn literal_rejects_extra_components() {
        let pat = NamePattern(vec![PatternComponent::Literal(comp("a"))]);
        assert!(!pat.matches(&name(&["a", "b"]), &mut HashMap::new()));
    }

    #[test]
    fn capture_binds_variable() {
        let pat = NamePattern(vec![
            PatternComponent::Literal(comp("sensor")),
            PatternComponent::Capture(Arc::from("node")),
        ]);
        let mut bindings = HashMap::new();
        assert!(pat.matches(&name(&["sensor", "node1"]), &mut bindings));
        assert_eq!(bindings[&Arc::from("node")], comp("node1"));
    }

    #[test]
    fn capture_enforces_consistency() {
        let var: Arc<str> = Arc::from("node");
        let data_pat = NamePattern(vec![PatternComponent::Capture(Arc::clone(&var))]);
        let key_pat = NamePattern(vec![PatternComponent::Capture(Arc::clone(&var))]);
        let mut bindings = HashMap::new();
        assert!(data_pat.matches(&name(&["n1"]), &mut bindings));
        assert!(key_pat.matches(&name(&["n1"]), &mut bindings.clone()));
        assert!(!key_pat.matches(&name(&["n2"]), &mut bindings));
    }

    #[test]
    fn multi_capture_consumes_remaining() {
        let pat = NamePattern(vec![
            PatternComponent::Literal(comp("prefix")),
            PatternComponent::MultiCapture(Arc::from("rest")),
        ]);
        assert!(pat.matches(&name(&["prefix", "a", "b", "c"]), &mut HashMap::new()));
    }

    #[test]
    fn schema_rule_allows_matching_pair() {
        let rule = SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp("data"))]),
            key_pattern: NamePattern(vec![PatternComponent::Literal(comp("key"))]),
        };
        assert!(rule.check(&name(&["data"]), &name(&["key"])));
        assert!(!rule.check(&name(&["data"]), &name(&["wrong"])));
    }

    #[test]
    fn trust_schema_allows_via_any_rule() {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp("data"))]),
            key_pattern: NamePattern(vec![PatternComponent::Literal(comp("key"))]),
        });
        assert!(schema.allows(&name(&["data"]), &name(&["key"])));
        assert!(!schema.allows(&name(&["data"]), &name(&["wrong"])));
    }

    #[test]
    fn empty_schema_rejects_everything() {
        let schema = TrustSchema::new();
        assert!(!schema.allows(&name(&["a"]), &name(&["b"])));
    }

    #[test]
    fn accept_all_allows_any_pair() {
        let schema = TrustSchema::accept_all();
        assert!(schema.allows(&name(&["a", "b"]), &name(&["x", "y", "z"])));
        assert!(schema.allows(&name(&["data"]), &name(&["key"])));
    }

    #[test]
    fn pattern_parse_literal() {
        let p = NamePattern::parse("/sensor/temp").unwrap();
        assert_eq!(p.0.len(), 2);
        assert!(matches!(&p.0[0], PatternComponent::Literal(nc) if nc.value.as_ref() == b"sensor"));
        assert!(matches!(&p.0[1], PatternComponent::Literal(nc) if nc.value.as_ref() == b"temp"));
    }

    #[test]
    fn pattern_parse_captures() {
        let p = NamePattern::parse("/sensor/<node>/KEY/<id>").unwrap();
        assert_eq!(p.0.len(), 4);
        assert!(matches!(&p.0[0], PatternComponent::Literal(_)));
        assert!(matches!(&p.0[1], PatternComponent::Capture(v) if v.as_ref() == "node"));
        assert!(matches!(&p.0[2], PatternComponent::Literal(_)));
        assert!(matches!(&p.0[3], PatternComponent::Capture(v) if v.as_ref() == "id"));
    }

    #[test]
    fn pattern_parse_multi_capture_at_end() {
        let p = NamePattern::parse("/org/<**rest>").unwrap();
        assert_eq!(p.0.len(), 2);
        assert!(matches!(&p.0[1], PatternComponent::MultiCapture(v) if v.as_ref() == "rest"));
    }

    #[test]
    fn pattern_parse_multi_capture_not_last_errors() {
        assert!(matches!(
            NamePattern::parse("/org/<**rest>/extra"),
            Err(PatternParseError::MultiCaptureNotLast)
        ));
    }

    #[test]
    fn pattern_parse_unclosed_capture_errors() {
        assert!(matches!(
            NamePattern::parse("/sensor/<node"),
            Err(PatternParseError::UnclosedCapture)
        ));
    }

    #[test]
    fn pattern_roundtrip_text() {
        let s = "/sensor/<node>/KEY/<id>";
        let p = NamePattern::parse(s).unwrap();
        assert_eq!(p.to_string(), s);
    }

    #[test]
    fn pattern_roundtrip_multi() {
        let s = "/org/<**rest>";
        let p = NamePattern::parse(s).unwrap();
        assert_eq!(p.to_string(), s);
    }

    #[test]
    fn rule_parse_roundtrip() {
        let s = "/sensor/<node>/<type> => /sensor/<node>/KEY/<id>";
        let r = SchemaRule::parse(s).unwrap();
        assert_eq!(r.to_string(), s);
    }

    #[test]
    fn rule_parse_bad_separator_errors() {
        assert!(matches!(
            SchemaRule::parse("/a /b"),
            Err(PatternParseError::BadRuleSeparator)
        ));
    }

    #[test]
    fn schema_remove_rule() {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp("data"))]),
            key_pattern: NamePattern(vec![PatternComponent::Literal(comp("key"))]),
        });
        assert!(schema.allows(&name(&["data"]), &name(&["key"])));
        schema.remove_rule(0);
        assert!(!schema.allows(&name(&["data"]), &name(&["key"])));
    }

    #[test]
    fn schema_rules_returns_slice() {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp("d"))]),
            key_pattern: NamePattern(vec![PatternComponent::Literal(comp("k"))]),
        });
        assert_eq!(schema.rules().len(), 1);
    }

    /// Build a minimal LVS binary fixture equivalent to the native rule
    /// `"/app => /key"` — root has two ValueEdges, and the "app" node's
    /// SignConstraint points at the "key" node.
    /// Minimal LVS binary fixture equivalent to `/app => /key`.
    fn lvs_hierarchical_fixture() -> Vec<u8> {
        use crate::lvs::type_number as tn;
        use bytes::BytesMut;
        use ndn_tlv::TlvWriter;

        fn write_tlv(buf: &mut BytesMut, t: u64, v: &[u8]) {
            let mut w = TlvWriter::new();
            w.write_tlv(t, v);
            buf.extend_from_slice(&w.finish());
        }
        fn uint_tlv(buf: &mut BytesMut, t: u64, v: u64) {
            let be = if v <= u8::MAX as u64 {
                vec![v as u8]
            } else {
                (v as u32).to_be_bytes().to_vec()
            };
            write_tlv(buf, t, &be);
        }
        fn write_cv(buf: &mut BytesMut, bytes: &[u8]) {
            let mut nc = Vec::with_capacity(2 + bytes.len());
            nc.push(0x08);
            nc.push(bytes.len() as u8);
            nc.extend_from_slice(bytes);
            write_tlv(buf, tn::COMPONENT_VALUE, &nc);
        }

        let mut out = BytesMut::new();
        uint_tlv(&mut out, tn::VERSION, crate::lvs::LVS_VERSION);
        uint_tlv(&mut out, tn::NODE_ID, 0);
        uint_tlv(&mut out, tn::NAMED_PATTERN_NUM, 0);

        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 0);
            {
                let mut ve = BytesMut::new();
                uint_tlv(&mut ve, tn::NODE_ID, 1);
                write_cv(&mut ve, b"app");
                write_tlv(&mut node, tn::VALUE_EDGE, &ve);
            }
            {
                let mut ve = BytesMut::new();
                uint_tlv(&mut ve, tn::NODE_ID, 2);
                write_cv(&mut ve, b"key");
                write_tlv(&mut node, tn::VALUE_EDGE, &ve);
            }
            write_tlv(&mut out, tn::NODE, &node);
        }
        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 1);
            uint_tlv(&mut node, tn::PARENT_ID, 0);
            uint_tlv(&mut node, tn::KEY_NODE_ID, 2);
            write_tlv(&mut out, tn::NODE, &node);
        }
        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 2);
            uint_tlv(&mut node, tn::PARENT_ID, 0);
            write_tlv(&mut out, tn::NODE, &node);
        }
        out.to_vec()
    }

    #[test]
    fn trust_schema_from_lvs_binary_roundtrip() {
        let schema = TrustSchema::from_lvs_binary(&lvs_hierarchical_fixture()).expect("LVS import");
        assert!(schema.lvs_model().is_some());
        assert!(schema.allows(&name(&["app"]), &name(&["key"])));
        assert!(!schema.allows(&name(&["app"]), &name(&["wrong"])));
        assert!(!schema.allows(&name(&["stranger"]), &name(&["key"])));
    }

    #[test]
    fn trust_schema_mixes_native_rules_with_lvs_model() {
        let mut schema = TrustSchema::from_lvs_binary(&lvs_hierarchical_fixture()).unwrap();
        schema.add_rule(SchemaRule::parse("/native => /native/KEY").unwrap());

        assert!(schema.allows(&name(&["app"]), &name(&["key"])));
        assert!(schema.allows(&name(&["native"]), &name(&["native", "KEY"])));
        assert!(!schema.allows(&name(&["foo"]), &name(&["bar"])));
    }

    #[test]
    fn trust_schema_lvs_model_accessor_returns_parsed_model() {
        let schema = TrustSchema::from_lvs_binary(&lvs_hierarchical_fixture()).unwrap();
        let model = schema.lvs_model().expect("lvs model set");
        assert_eq!(model.nodes.len(), 3);
        assert!(!model.uses_user_functions());
    }

    #[test]
    fn trust_schema_from_lvs_binary_bad_version_errors() {
        use crate::lvs::LvsError;
        let mut bad = lvs_hierarchical_fixture();
        bad.clear();
        use crate::lvs::type_number as tn;
        use bytes::BytesMut;
        use ndn_tlv::TlvWriter;
        let mut out = BytesMut::new();
        {
            let mut w = TlvWriter::new();
            w.write_tlv(tn::VERSION, &0xDEADBEEFu32.to_be_bytes());
            out.extend_from_slice(&w.finish());
            let mut w = TlvWriter::new();
            w.write_tlv(tn::NODE_ID, &[0u8]);
            out.extend_from_slice(&w.finish());
            let mut w = TlvWriter::new();
            w.write_tlv(tn::NAMED_PATTERN_NUM, &[0u8]);
            out.extend_from_slice(&w.finish());
        }
        let err = TrustSchema::from_lvs_binary(&out).unwrap_err();
        assert!(matches!(err, LvsError::UnsupportedVersion { .. }));
    }

    #[test]
    fn hierarchical_requires_matching_first_component() {
        let schema = TrustSchema::hierarchical();
        assert!(schema.allows(&name(&["org", "data"]), &name(&["org", "KEY", "k1"])));
        assert!(!schema.allows(&name(&["orgA", "data"]), &name(&["orgB", "KEY", "k1"])));
        assert!(schema.allows(
            &name(&["org", "dept", "sensor", "temp"]),
            &name(&["org", "dept", "KEY", "k1"])
        ));
    }

    /// `from_lvs_binary` rejects schemas using user functions rather than
    /// loading them silently (fail-safe behaviour).
    #[test]
    fn c16_from_lvs_binary_rejects_user_functions() {
        use crate::lvs::{LVS_VERSION, LvsError, type_number as tn};
        use bytes::BytesMut;
        use ndn_tlv::TlvWriter;

        fn write_tlv(buf: &mut BytesMut, t: u64, v: &[u8]) {
            let mut w = TlvWriter::new();
            w.write_tlv(t, v);
            buf.extend_from_slice(&w.finish());
        }
        fn uint_tlv(buf: &mut BytesMut, t: u64, v: u64) {
            let be = if v <= u8::MAX as u64 {
                vec![v as u8]
            } else {
                (v as u32).to_be_bytes().to_vec()
            };
            write_tlv(buf, t, &be);
        }

        let mut out = BytesMut::new();
        uint_tlv(&mut out, tn::VERSION, LVS_VERSION);
        uint_tlv(&mut out, tn::NODE_ID, 0);
        uint_tlv(&mut out, tn::NAMED_PATTERN_NUM, 1);

        // Node 0: PatternEdge -> node 1, with a $regex user-fn constraint.
        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 0);
            let mut pe = BytesMut::new();
            uint_tlv(&mut pe, tn::NODE_ID, 1);
            uint_tlv(&mut pe, tn::PATTERN_TAG, 1);
            {
                let mut cons = BytesMut::new();
                let mut opt = BytesMut::new();
                let mut call = BytesMut::new();
                write_tlv(&mut call, tn::USER_FN_ID, b"$regex");
                {
                    let mut arg = BytesMut::new();
                    let mut nc = Vec::new();
                    nc.push(0x08u8);
                    nc.push(b"^[0-9]+$".len() as u8);
                    nc.extend_from_slice(b"^[0-9]+$");
                    write_tlv(&mut arg, tn::COMPONENT_VALUE, &nc);
                    write_tlv(&mut call, tn::FN_ARGS, &arg);
                }
                write_tlv(&mut opt, tn::USER_FN_CALL, &call);
                write_tlv(&mut cons, tn::CONS_OPTION, &opt);
                write_tlv(&mut pe, tn::CONSTRAINT, &cons);
            }
            write_tlv(&mut node, tn::PATTERN_EDGE, &pe);
            write_tlv(&mut out, tn::NODE, &node);
        }
        {
            let mut node = BytesMut::new();
            uint_tlv(&mut node, tn::NODE_ID, 1);
            uint_tlv(&mut node, tn::PARENT_ID, 0);
            write_tlv(&mut out, tn::NODE, &node);
        }

        let err = TrustSchema::from_lvs_binary(&out).expect_err("user-fn schema must be rejected");
        assert!(
            matches!(err, LvsError::UserFunctionsNotSupported),
            "expected UserFunctionsNotSupported, got {err:?}"
        );
    }
}
