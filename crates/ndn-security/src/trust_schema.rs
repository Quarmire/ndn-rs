use std::collections::HashMap;
use std::sync::Arc;
use ndn_packet::{Name, NameComponent};

/// A single component in a name pattern.
#[derive(Clone, Debug)]
pub enum PatternComponent {
    /// Must match this exact component.
    Literal(NameComponent),
    /// Binds one component to a named variable.
    Capture(Arc<str>),
    /// Binds one or more trailing components to a named variable.
    MultiCapture(Arc<str>),
}

/// A name pattern with named capture groups.
///
/// Used by the trust schema to express rules like:
/// "Data under `/sensor/<node>/<type>` must be signed by `/sensor/<node>/KEY/<id>`"
/// where `<node>` must match in both patterns.
#[derive(Clone, Debug)]
pub struct NamePattern(pub Vec<PatternComponent>);

impl NamePattern {
    /// Attempt to match `name` against this pattern, extending `bindings`.
    /// Returns `true` if the match succeeds.
    pub fn matches(
        &self,
        name: &Name,
        bindings: &mut HashMap<Arc<str>, NameComponent>,
    ) -> bool {
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
                            return false; // variable must be consistent
                        }
                    } else {
                        bindings.insert(Arc::clone(var), comp);
                    }
                    name_idx += 1;
                }
                PatternComponent::MultiCapture(_var) => {
                    // Greedily consume all remaining components.
                    name_idx = components.len();
                }
            }
        }
        name_idx == components.len()
    }
}

/// A single trust schema rule: Data matching `data_pattern` must be signed
/// by a key matching `key_pattern`, with captured variables consistent between
/// both patterns.
#[derive(Clone, Debug)]
pub struct SchemaRule {
    pub data_pattern: NamePattern,
    pub key_pattern:  NamePattern,
}

impl SchemaRule {
    /// Check whether `data_name` and `key_name` satisfy this rule.
    pub fn check(&self, data_name: &Name, key_name: &Name) -> bool {
        let mut bindings = HashMap::new();
        self.data_pattern.matches(data_name, &mut bindings)
            && self.key_pattern.matches(key_name, &mut bindings)
    }
}

/// A collection of trust schema rules.
#[derive(Clone, Debug, Default)]
pub struct TrustSchema {
    rules: Vec<SchemaRule>,
}

impl TrustSchema {
    pub fn new() -> Self { Self { rules: Vec::new() } }

    pub fn add_rule(&mut self, rule: SchemaRule) {
        self.rules.push(rule);
    }

    /// Returns `true` if at least one rule permits this (data_name, key_name) pair.
    pub fn allows(&self, data_name: &Name, key_name: &Name) -> bool {
        self.rules.iter().any(|r| r.check(data_name, key_name))
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
        let key_pat  = NamePattern(vec![PatternComponent::Capture(Arc::clone(&var))]);
        let mut bindings = HashMap::new();
        // Bind node = "n1" via data pattern
        assert!(data_pat.matches(&name(&["n1"]), &mut bindings));
        // Key pattern with same value succeeds
        assert!(key_pat.matches(&name(&["n1"]), &mut bindings.clone()));
        // Key pattern with different value fails
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
            key_pattern:  NamePattern(vec![PatternComponent::Literal(comp("key"))]),
        };
        assert!(rule.check(&name(&["data"]), &name(&["key"])));
        assert!(!rule.check(&name(&["data"]), &name(&["wrong"])));
    }

    #[test]
    fn trust_schema_allows_via_any_rule() {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp("data"))]),
            key_pattern:  NamePattern(vec![PatternComponent::Literal(comp("key"))]),
        });
        assert!(schema.allows(&name(&["data"]), &name(&["key"])));
        assert!(!schema.allows(&name(&["data"]), &name(&["wrong"])));
    }

    #[test]
    fn empty_schema_rejects_everything() {
        let schema = TrustSchema::new();
        assert!(!schema.allows(&name(&["a"]), &name(&["b"])));
    }
}
