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
