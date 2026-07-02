//! Native textual **LightVerSec compiler** (G8 part 2): LVS source → the binary
//! [`LvsModel`](crate::lvs::LvsModel), so a trust schema can be authored in-tree without
//! python-ndn / NDNts `@ndn/lvs`.
//!
//! ## Grammar (the deployable core)
//!
//! ```text
//! // line comment
//! #rule_id: /comp/comp/...  [ <= #signer_id, #signer_id ]
//! ```
//!
//! A component is a quoted **literal** (`"KEY"`) or a **pattern variable** (`_name`, or `_`
//! anonymous); an unquoted bareword is a **compile error** (it would silently change the
//! trust graph on a typo). `<=` lists the rules whose keys may sign data matching this
//! rule. Example:
//!
//! ```text
//! #root:  /"ndn"/"KEY"/_/_/_
//! #admin: /"ndn"/"admin"/_/"KEY"/_/_/_   <= #root
//! #doc:   /"ndn"/_site/"doc"/_name/"KEY"/_/_/_  <= #admin
//! ```
//!
//! Each rule lowers to a chain of nodes from the shared start: a literal is a value edge,
//! a variable a pattern edge. Signing relations become the data node's key-node
//! constraints. The result round-trips through [`LvsModel::decode`], so the evaluator and
//! the user-function dispatch seam (`$eq`, …) apply unchanged.
//!
//! **Deferred** (compile errors / not yet lowered): inline constraints (`& {...}` /
//! `$eq(...)` in source — the *runtime* supports user functions, the compiler doesn't emit
//! them yet), `#id` pattern references (inlining one rule's pattern into another), and
//! cross-pattern tag equality. These are additive; the core hierarchical schema compiles.

use bytes::BytesMut;
use ndn_tlv::TlvWriter;

use crate::lvs::{LVS_VERSION, LvsError, LvsModel, type_number as tn};

/// Why an LVS source failed to compile.
#[derive(Debug, thiserror::Error)]
pub enum LvsCompileError {
    #[error("line {line}: {msg}")]
    Syntax { line: usize, msg: String },
    #[error("rule '{rule}' signs with unknown rule '{signer}'")]
    UnknownSigner { rule: String, signer: String },
    #[error("duplicate rule '{0}'")]
    DuplicateRule(String),
    /// The emitted binary did not re-parse — an internal lowering bug.
    #[error("internal: emitted schema did not decode: {0}")]
    Lowering(#[from] LvsError),
}

/// One parsed component of a rule's name pattern.
enum Comp {
    Literal(Vec<u8>),
    /// A pattern variable; `Some(name)` is captured (a tag symbol), `None` is anonymous.
    Var(Option<String>),
}

struct Rule {
    id: String,
    pattern: Vec<Comp>,
    signers: Vec<String>,
}

/// Compile LVS `source` to the binary trust-schema model.
pub fn compile(source: &str) -> Result<LvsModel, LvsCompileError> {
    let rules = parse(source)?;
    let wire = lower(&rules)?;
    Ok(LvsModel::decode(&wire)?)
}

/// Compile LVS `source` to the binary TLV (the `@ndn/lvs`-compatible form consumed by
/// [`LvsModel::decode`] / `TrustSchema::from_lvs_binary`).
pub fn compile_to_binary(source: &str) -> Result<Vec<u8>, LvsCompileError> {
    let rules = parse(source)?;
    lower(&rules)
}

fn parse(source: &str) -> Result<Vec<Rule>, LvsCompileError> {
    let mut rules: Vec<Rule> = Vec::new();
    for (i, raw) in source.lines().enumerate() {
        let line = i + 1;
        // Strip `//` comments and surrounding whitespace; skip blanks.
        let text = raw.split("//").next().unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        let syntax = |msg: &str| LvsCompileError::Syntax {
            line,
            msg: msg.to_string(),
        };

        let id_rest = text
            .strip_prefix('#')
            .ok_or_else(|| syntax("rule must start with '#'"))?;
        let (id, rest) = id_rest
            .split_once(':')
            .ok_or_else(|| syntax("expected ':' after rule id"))?;
        let id = id.trim().to_string();
        if id.is_empty() {
            return Err(syntax("empty rule id"));
        }

        // Split off the optional `<= signers` tail.
        let (pattern_str, signers) = match rest.split_once("<=") {
            Some((p, s)) => {
                let signers = s
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(|t| t.strip_prefix('#').unwrap_or(t).to_string())
                    .collect();
                (p, signers)
            }
            None => (rest, Vec::new()),
        };

        let mut pattern = Vec::new();
        for seg in pattern_str
            .split('/')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            pattern.push(parse_comp(seg).ok_or_else(|| syntax("malformed component"))?);
        }
        if pattern.is_empty() {
            return Err(syntax("rule has no name components"));
        }
        if rules.iter().any(|r| r.id == id) {
            return Err(LvsCompileError::DuplicateRule(id));
        }
        rules.push(Rule {
            id,
            pattern,
            signers,
        });
    }
    Ok(rules)
}

fn parse_comp(seg: &str) -> Option<Comp> {
    if let Some(inner) = seg.strip_prefix('"') {
        let lit = inner.strip_suffix('"')?;
        return Some(Comp::Literal(lit.as_bytes().to_vec()));
    }
    if let Some(name) = seg.strip_prefix('_') {
        return Some(Comp::Var((!name.is_empty()).then(|| name.to_string())));
    }
    // Reject barewords: a literal must be quoted (`"KEY"`) and a variable underscore-led
    // (`_x`). Silently treating an unquoted token as a literal lets a typo change the trust
    // graph without error — unacceptable for a security schema.
    None
}

/// One node under construction, indexed by node id (== array position, as the decoder
/// requires).
#[derive(Default)]
struct NodeB {
    value_edges: Vec<(Vec<u8>, u64)>, // (literal bytes, dest id)
    pattern_edges: Vec<u64>,          // dest id (tag assigned at emit by position)
    pattern_tags: Vec<u64>,           // parallel to pattern_edges: the tag id
    key_nodes: Vec<u64>,              // sign constraints (signer terminal node ids)
}

fn lower(rules: &[Rule]) -> Result<Vec<u8>, LvsCompileError> {
    let mut nodes: Vec<NodeB> = vec![NodeB::default()]; // node 0 = start
    let mut terminal: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    let mut next_tag: u64 = 0;
    let mut tag_symbols: Vec<(u64, String)> = Vec::new(); // named pattern vars

    // Pass 1: one linear chain per rule from the shared start node.
    for rule in rules {
        let mut cur = 0u64;
        for comp in &rule.pattern {
            let dest = nodes.len() as u64;
            nodes.push(NodeB::default());
            match comp {
                Comp::Literal(v) => nodes[cur as usize].value_edges.push((v.clone(), dest)),
                Comp::Var(name) => {
                    nodes[cur as usize].pattern_edges.push(dest);
                    nodes[cur as usize].pattern_tags.push(next_tag);
                    if let Some(name) = name {
                        tag_symbols.push((next_tag, name.clone()));
                    }
                    next_tag += 1;
                }
            }
            cur = dest;
        }
        terminal.insert(rule.id.as_str(), cur);
    }

    // Pass 2: resolve signing relations to the signer rules' terminal nodes.
    for rule in rules {
        let data_node = terminal[rule.id.as_str()];
        for signer in &rule.signers {
            let key_node =
                *terminal
                    .get(signer.as_str())
                    .ok_or_else(|| LvsCompileError::UnknownSigner {
                        rule: rule.id.clone(),
                        signer: signer.clone(),
                    })?;
            nodes[data_node as usize].key_nodes.push(key_node);
        }
    }

    Ok(emit(&nodes, next_tag, &tag_symbols))
}

fn emit(nodes: &[NodeB], tag_count: u64, tag_symbols: &[(u64, String)]) -> Vec<u8> {
    let mut out = BytesMut::new();
    write_uint(&mut out, tn::VERSION, LVS_VERSION);
    write_uint(&mut out, tn::NODE_ID, 0); // start node
    write_uint(&mut out, tn::NAMED_PATTERN_NUM, tag_count);

    for (id, node) in nodes.iter().enumerate() {
        let mut nb = BytesMut::new();
        write_uint(&mut nb, tn::NODE_ID, id as u64);
        for (value, dest) in &node.value_edges {
            let mut ve = BytesMut::new();
            write_uint(&mut ve, tn::NODE_ID, *dest);
            write_component_value(&mut ve, value);
            write_tlv(&mut nb, tn::VALUE_EDGE, &ve);
        }
        for (dest, tag) in node.pattern_edges.iter().zip(&node.pattern_tags) {
            let mut pe = BytesMut::new();
            write_uint(&mut pe, tn::NODE_ID, *dest);
            write_uint(&mut pe, tn::PATTERN_TAG, *tag);
            write_tlv(&mut nb, tn::PATTERN_EDGE, &pe);
        }
        for key in &node.key_nodes {
            write_uint(&mut nb, tn::KEY_NODE_ID, *key);
        }
        write_tlv(&mut out, tn::NODE, &nb);
    }

    // Tag symbols give named pattern variables a readable identifier in the model.
    for (tag, ident) in tag_symbols {
        let mut ts = BytesMut::new();
        write_uint(&mut ts, tn::PATTERN_TAG, *tag);
        write_tlv(&mut ts, tn::IDENTIFIER, ident.as_bytes());
        write_tlv(&mut out, tn::TAG_SYMBOL, &ts);
    }
    out.to_vec()
}

fn write_tlv(buf: &mut BytesMut, typ: u64, value: &[u8]) {
    let mut w = TlvWriter::new();
    w.write_tlv(typ, value);
    buf.extend_from_slice(&w.finish());
}

fn write_uint(buf: &mut BytesMut, typ: u64, value: u64) {
    let be: Vec<u8> = if value <= u8::MAX as u64 {
        vec![value as u8]
    } else if value <= u16::MAX as u64 {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= u32::MAX as u64 {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };
    write_tlv(buf, typ, &be);
}

/// `COMPONENT_VALUE` wraps a full GenericNameComponent TLV (`0x08 len value`).
fn write_component_value(buf: &mut BytesMut, value: &[u8]) {
    let mut nc = Vec::with_capacity(2 + value.len());
    nc.push(0x08);
    nc.push(value.len() as u8);
    nc.extend_from_slice(value);
    write_tlv(buf, tn::COMPONENT_VALUE, &nc);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn compiles_a_hierarchical_schema_and_enforces_it() {
        // root signs admin; admin signs docs. Pattern vars are wildcards.
        let src = r#"
            // a small hierarchy
            #root:  /"site"/"KEY"/_keyid
            #admin: /"site"/"admin"/_/"KEY"/_keyid   <= #root
            #doc:   /"site"/_user/"doc"/_name        <= #admin
        "#;
        let model = compile(src).expect("compiles");

        // A doc is signed by an admin key.
        let doc = n("/site/alice/doc/readme");
        let admin_key = n("/site/admin/k7/KEY/x");
        assert!(model.check(&doc, &admin_key), "admin key may sign a doc");

        // An admin cert is signed by the root key.
        let root_key = n("/site/KEY/r1");
        assert!(
            model.check(&admin_key, &root_key),
            "root key may sign an admin cert"
        );

        // A doc may NOT be signed by the root key directly (no such signing edge).
        assert!(
            !model.check(&doc, &root_key),
            "root may not sign a doc directly"
        );
        // A name outside the schema is rejected.
        assert!(!model.check(&n("/other/thing"), &admin_key));
    }

    #[test]
    fn binary_is_decodable_and_unknown_signer_errors() {
        let bin = compile_to_binary(r#"#a: /"x"/_"#).expect("compiles");
        assert!(LvsModel::decode(&bin).is_ok(), "emits decodable binary");

        let err = compile(r#"#a: /"x" <= #ghost"#).unwrap_err();
        assert!(matches!(err, LvsCompileError::UnknownSigner { .. }));

        let dup = compile("#a: /\"x\"\n#a: /\"y\"").unwrap_err();
        assert!(matches!(dup, LvsCompileError::DuplicateRule(_)));

        let bad = compile("a: /\"x\"").unwrap_err();
        assert!(matches!(bad, LvsCompileError::Syntax { .. }));

        // A bareword component (unquoted, not `_`-led) is a compile error, not a literal.
        let bareword = compile("#a: /KEY/_").unwrap_err();
        assert!(
            matches!(bareword, LvsCompileError::Syntax { .. }),
            "bareword must error"
        );
    }

    #[test]
    fn walk_is_bounded_against_crafted_names() {
        // A schema with overlapping pattern edges + a long name must not blow up: the walk
        // budget caps it. (Compile a chain of unconstrained vars, then check a long name.)
        let src = "#a: /_/_/_/_/_/_/_/_";
        let model = compile(src).expect("compiles");
        let long: ndn_packet::Name = "/a/b/c/d/e/f/g/h/i/j/k/l".parse().unwrap();
        // Just must terminate quickly without panicking; result value is unimportant here.
        let _ = model.check(&long, &long);
    }
}
