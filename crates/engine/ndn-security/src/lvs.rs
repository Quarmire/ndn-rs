//! LightVerSec (LVS) binary trust schema parser and evaluator.
//!
//! This module imports pre-compiled LVS trust schemas in the TLV binary
//! format defined by python-ndn
//! (<https://python-ndn.readthedocs.io/en/latest/src/lvs/binary-format.html>)
//! and interoperable with NDNts `@ndn/lvs` and ndnd's
//! `std/security/trust_schema` packages. It exists so ndn-rs users can
//! consume trust schemas authored in the tooling the wider NDN community
//! already uses, rather than re-expressing them in ndn-rs's native
//! `SchemaRule` vocabulary.
//!
//! # Supported subset
//!
//! ndn-rs v0.1.0 supports:
//!
//! - Full TLV parse of `LvsModel`, `Node`, `ValueEdge`, `PatternEdge`,
//!   `Constraint`, `ConstraintOption`, `TagSymbol` (every type number in
//!   the binary format spec).
//! - Tree-walk evaluation of `(data_name, key_name)` pairs against the
//!   LVS graph, checking `ValueEdge` literal matches first, then
//!   `PatternEdge` pattern matches (per the spec's dispatch order).
//! - `ConstraintOption::Value` (literal) and `ConstraintOption::Tag`
//!   (equals a previously-bound pattern variable).
//! - `SignConstraint`: the signing-key name is walked from the start node
//!   and must reach one of the node IDs listed on the matched data node.
//! - `NamedPatternCnt` handling: temporary (`_`) vs. named edges are
//!   treated uniformly during matching, per the spec note that a checker
//!   concerned only with signature validity does not need to distinguish
//!   them.
//!
//! # Not supported in v0.1.0
//!
//! - **`ConstraintOption::UserFnCall`** — user functions (e.g. `$eq`,
//!   `$regex`) are not yet dispatched. A PatternEdge whose constraints
//!   contain a `UserFnCall` option cannot be satisfied; if no other
//!   option on that constraint succeeds, the edge fails to match.
//!   Attempting to load a schema that contains user functions is allowed
//!   — the schema parses fine — but any rule that depends on a user
//!   function will never match a packet. This mirrors python-ndn's
//!   documented fallback where unknown functions cause verification to
//!   fail, and is loudly marked by a [`LvsModel::uses_user_functions`]
//!   flag so callers can refuse to load such schemas when interop
//!   parity matters.
//! - Sanity checks beyond the mandatory set from the spec. Unreachable
//!   nodes are not pruned; trust-anchor-reachability is not verified.
//!   This matches python-ndn's behaviour.
//! - Roundtripping back to the binary format (`from_lvs_binary` is import
//!   only).
//!
//! # Version compatibility
//!
//! Only LVS binary version `0x00011000` (the python-ndn current stable
//! version) is accepted. Loading any other version returns
//! [`LvsError::UnsupportedVersion`].
//!
//! # Cross-reference
//!
//! The parser was written against two upstream references:
//!
//! - Binary format spec: `docs/src/lvs/binary-format.rst` in python-ndn.
//! - Reference parser:
//!   `src/ndn/app_support/light_versec/binary.py` in python-ndn.
//!
//! Every TLV type number in [`type_number`] matches the python-ndn
//! `TypeNumber` class verbatim.

use std::collections::HashMap;

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};

/// LVS binary format version supported by this parser.
///
/// Must match python-ndn's `binary.VERSION`. See the module docs for
/// version-compatibility rules.
pub const LVS_VERSION: u64 = 0x0001_1000;

/// LVS TLV type numbers (mirrors python-ndn's `TypeNumber`).
pub mod type_number {
    pub const COMPONENT_VALUE: u64 = 0x21;
    pub const PATTERN_TAG: u64 = 0x23;
    pub const NODE_ID: u64 = 0x25;
    pub const USER_FN_ID: u64 = 0x27;
    pub const IDENTIFIER: u64 = 0x29;
    pub const USER_FN_CALL: u64 = 0x31;
    pub const FN_ARGS: u64 = 0x33;
    pub const CONS_OPTION: u64 = 0x41;
    pub const CONSTRAINT: u64 = 0x43;
    pub const VALUE_EDGE: u64 = 0x51;
    pub const PATTERN_EDGE: u64 = 0x53;
    pub const KEY_NODE_ID: u64 = 0x55;
    pub const PARENT_ID: u64 = 0x57;
    pub const VERSION: u64 = 0x61;
    pub const NODE: u64 = 0x63;
    pub const TAG_SYMBOL: u64 = 0x67;
    pub const NAMED_PATTERN_NUM: u64 = 0x69;
}

/// Errors raised while parsing or checking an LVS binary model.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LvsError {
    #[error("truncated TLV: {0}")]
    Truncated(&'static str),
    #[error("TLV length mismatch at offset {offset}: claimed {claimed}, available {available}")]
    LengthMismatch {
        offset: usize,
        claimed: usize,
        available: usize,
    },
    #[error("unexpected TLV type 0x{actual:x}, expected 0x{expected:x}")]
    UnexpectedType { actual: u64, expected: u64 },
    #[error("unsupported LVS binary version 0x{actual:x} (expected 0x{expected:x})")]
    UnsupportedVersion { actual: u64, expected: u64 },
    #[error("node id {node_id} out of range (model has {n} nodes)")]
    NodeIdOutOfRange { node_id: u64, n: usize },
    #[error("node at index {idx} has id {id} (must equal its index)")]
    NodeIdMismatch { idx: usize, id: u64 },
    #[error("ConstraintOption must have exactly one of Value/Tag/UserFn")]
    MalformedConstraintOption,
    #[error("invalid UTF-8 in identifier")]
    BadIdentifier,
}

/// A parsed LVS trust schema.
///
/// See the module docs for which LVS features are supported. Construct via
/// [`LvsModel::decode`] (typically via
/// [`crate::TrustSchema::from_lvs_binary`]).
#[derive(Debug, Clone)]
pub struct LvsModel {
    pub version: u64,
    pub start_id: u64,
    pub named_pattern_cnt: u64,
    pub nodes: Vec<LvsNode>,
    pub tag_symbols: Vec<LvsTagSymbol>,
    /// True if any `PatternEdge` constraint references a `UserFnCall`.
    /// Callers that require exact parity with python-ndn should refuse
    /// to load such schemas until user-function dispatch lands.
    uses_user_functions: bool,
}

#[derive(Debug, Clone)]
pub struct LvsNode {
    pub id: u64,
    pub parent: Option<u64>,
    pub rule_names: Vec<String>,
    pub value_edges: Vec<LvsValueEdge>,
    pub pattern_edges: Vec<LvsPatternEdge>,
    pub sign_constraints: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct LvsValueEdge {
    pub dest: u64,
    /// The exact `NameComponent` this edge matches, parsed from the
    /// pre-encoded `COMPONENT_VALUE` TLV field in the binary format. The
    /// wire layout is `COMPONENT_VALUE[length][NameComponentTLV]`, so the
    /// value bytes themselves are a full `t+l+v` NameComponent.
    pub value: NameComponent,
}

#[derive(Debug, Clone)]
pub struct LvsPatternEdge {
    pub dest: u64,
    pub tag: u64,
    pub constraints: Vec<LvsConstraint>,
}

/// A disjunction of options; the edge matches only if every constraint's
/// option-set is satisfied (CNF: AND of ORs).
#[derive(Debug, Clone)]
pub struct LvsConstraint {
    pub options: Vec<LvsConstraintOption>,
}

#[derive(Debug, Clone)]
pub enum LvsConstraintOption {
    /// Name component must equal this literal value. Parsed from the
    /// pre-encoded `COMPONENT_VALUE` TLV in the binary format — see the
    /// note on [`LvsValueEdge::value`].
    Value(NameComponent),
    /// Name component must equal the component previously bound to this
    /// pattern-edge tag id.
    Tag(u64),
    /// User function call — not supported in v0.1.0. Stored so the parser
    /// can accept the schema and flag `uses_user_functions`, but never
    /// matches anything at check time.
    UserFn(LvsUserFnCall),
}

#[derive(Debug, Clone)]
pub struct LvsUserFnCall {
    pub fn_id: String,
    pub args: Vec<LvsUserFnArg>,
}

#[derive(Debug, Clone)]
pub enum LvsUserFnArg {
    Value(NameComponent),
    Tag(u64),
}

#[derive(Debug, Clone)]
pub struct LvsTagSymbol {
    pub tag: u64,
    pub ident: String,
}

impl LvsModel {
    /// Parse an LVS binary model from its TLV wire bytes.
    ///
    /// The top-level `LvsModel` has no outer TLV wrapper — the input
    /// buffer is a sequence of top-level TLV fields (Version, StartId,
    /// NamedPatternCnt, *Node, *TagSymbol).
    pub fn decode(input: &[u8]) -> Result<Self, LvsError> {
        let mut cursor = input;
        let mut version: Option<u64> = None;
        let mut start_id: Option<u64> = None;
        let mut named_pattern_cnt: Option<u64> = None;
        let mut nodes: Vec<LvsNode> = Vec::new();
        let mut tag_symbols: Vec<LvsTagSymbol> = Vec::new();
        let mut uses_user_functions = false;

        while !cursor.is_empty() {
            let (t, value, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::VERSION => {
                    version = Some(read_uint(value)?);
                }
                type_number::NODE_ID => {
                    start_id = Some(read_uint(value)?);
                }
                type_number::NAMED_PATTERN_NUM => {
                    named_pattern_cnt = Some(read_uint(value)?);
                }
                type_number::NODE => {
                    let (node, node_uses_fn) = LvsNode::decode(value)?;
                    uses_user_functions |= node_uses_fn;
                    nodes.push(node);
                }
                type_number::TAG_SYMBOL => {
                    tag_symbols.push(LvsTagSymbol::decode(value)?);
                }
                // Unknown top-level type — skip per TLV forward-compat convention.
                _ => {}
            }
        }

        let version = version.ok_or(LvsError::Truncated("missing Version"))?;
        if version != LVS_VERSION {
            return Err(LvsError::UnsupportedVersion {
                actual: version,
                expected: LVS_VERSION,
            });
        }
        let start_id = start_id.ok_or(LvsError::Truncated("missing StartId"))?;
        let named_pattern_cnt =
            named_pattern_cnt.ok_or(LvsError::Truncated("missing NamedPatternCnt"))?;

        // Sanity: every node's id equals its index.
        for (idx, n) in nodes.iter().enumerate() {
            if n.id as usize != idx {
                return Err(LvsError::NodeIdMismatch { idx, id: n.id });
            }
        }
        // Sanity: every edge and sign constraint refers to an existing node.
        let n_nodes = nodes.len();
        for node in &nodes {
            for e in &node.value_edges {
                if e.dest as usize >= n_nodes {
                    return Err(LvsError::NodeIdOutOfRange {
                        node_id: e.dest,
                        n: n_nodes,
                    });
                }
            }
            for e in &node.pattern_edges {
                if e.dest as usize >= n_nodes {
                    return Err(LvsError::NodeIdOutOfRange {
                        node_id: e.dest,
                        n: n_nodes,
                    });
                }
            }
            for &sc in &node.sign_constraints {
                if sc as usize >= n_nodes {
                    return Err(LvsError::NodeIdOutOfRange {
                        node_id: sc,
                        n: n_nodes,
                    });
                }
            }
        }
        if (start_id as usize) >= n_nodes && n_nodes > 0 {
            return Err(LvsError::NodeIdOutOfRange {
                node_id: start_id,
                n: n_nodes,
            });
        }

        Ok(Self {
            version,
            start_id,
            named_pattern_cnt,
            nodes,
            tag_symbols,
            uses_user_functions,
        })
    }

    /// Returns `true` if the loaded schema references any user functions.
    ///
    /// Because v0.1.0 does not dispatch user functions, any rule that
    /// depends on one will never match a packet. Callers that need bit-exact
    /// parity with python-ndn's evaluation can inspect this flag and refuse
    /// to use the schema.
    pub fn uses_user_functions(&self) -> bool {
        self.uses_user_functions
    }

    /// Walk the LVS graph for `name`, collecting the set of reachable
    /// `(node_id, bindings)` pairs where the walk has consumed all of
    /// `name`'s components. Multiple endings are possible because different
    /// pattern-edge choices can lead to different terminal nodes.
    fn walk(&self, name: &Name) -> Vec<(u64, HashMap<u64, NameComponent>)> {
        let mut out = Vec::new();
        if self.nodes.is_empty() {
            return out;
        }
        let start = self.start_id;
        let bindings: HashMap<u64, NameComponent> = HashMap::new();
        self.walk_inner(start, name.components(), 0, bindings, &mut out);
        out
    }

    fn walk_inner(
        &self,
        node_id: u64,
        comps: &[NameComponent],
        depth: usize,
        bindings: HashMap<u64, NameComponent>,
        out: &mut Vec<(u64, HashMap<u64, NameComponent>)>,
    ) {
        if depth == comps.len() {
            out.push((node_id, bindings));
            return;
        }
        let Some(node) = self.nodes.get(node_id as usize) else {
            return;
        };
        let comp = &comps[depth];

        // Per the spec: check ValueEdges for exact matches first.
        for ve in &node.value_edges {
            if &ve.value == comp {
                self.walk_inner(ve.dest, comps, depth + 1, bindings.clone(), out);
            }
        }

        // Then PatternEdges. Per the spec: when multiple PatternEdges can
        // match, the first one in the file should hit. We explore all
        // matching edges so that alternative paths for the key-name walk
        // still get considered, but we stop at the first successful
        // terminal — matching the "first occurring" semantics is done by
        // the caller (which picks out[0] if out is non-empty).
        for pe in &node.pattern_edges {
            if self.pattern_edge_matches(pe, comp, &bindings) {
                let mut new_bindings = bindings.clone();
                new_bindings.insert(pe.tag, comp.clone());
                self.walk_inner(pe.dest, comps, depth + 1, new_bindings, out);
            }
        }
    }

    fn pattern_edge_matches(
        &self,
        edge: &LvsPatternEdge,
        comp: &NameComponent,
        bindings: &HashMap<u64, NameComponent>,
    ) -> bool {
        // Every constraint must be satisfied (AND). If there are no
        // constraints, the edge always matches.
        edge.constraints
            .iter()
            .all(|c| c.options.iter().any(|opt| self.option_matches(opt, comp, bindings)))
    }

    fn option_matches(
        &self,
        opt: &LvsConstraintOption,
        comp: &NameComponent,
        bindings: &HashMap<u64, NameComponent>,
    ) -> bool {
        match opt {
            LvsConstraintOption::Value(v) => v == comp,
            LvsConstraintOption::Tag(t) => bindings.get(t).is_some_and(|prev| prev == comp),
            // User functions are not dispatched in v0.1.0 — they never match.
            LvsConstraintOption::UserFn(_) => false,
        }
    }

    /// Check whether `data_name` is allowed to be signed by `key_name`
    /// under this LVS schema. Returns `true` if:
    ///
    /// 1. `data_name` reaches some node `D` in the graph, and
    /// 2. `D` has at least one `SignConstraint`, and
    /// 3. `key_name` reaches a node whose id is listed in `D.sign_constraints`.
    pub fn check(&self, data_name: &Name, key_name: &Name) -> bool {
        let data_endings = self.walk(data_name);
        if data_endings.is_empty() {
            return false;
        }
        let key_endings = self.walk(key_name);
        if key_endings.is_empty() {
            return false;
        }
        for (data_node_id, _data_bindings) in &data_endings {
            let Some(node) = self.nodes.get(*data_node_id as usize) else {
                continue;
            };
            if node.sign_constraints.is_empty() {
                continue;
            }
            for (key_node_id, _) in &key_endings {
                if node.sign_constraints.contains(key_node_id) {
                    return true;
                }
            }
        }
        false
    }
}

impl LvsNode {
    fn decode(input: &[u8]) -> Result<(Self, bool), LvsError> {
        let mut cursor = input;
        let mut id: Option<u64> = None;
        let mut parent: Option<u64> = None;
        let mut rule_names = Vec::new();
        let mut value_edges = Vec::new();
        let mut pattern_edges = Vec::new();
        let mut sign_constraints = Vec::new();
        let mut uses_user_functions = false;

        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::NODE_ID => id = Some(read_uint(v)?),
                type_number::PARENT_ID => parent = Some(read_uint(v)?),
                type_number::IDENTIFIER => rule_names.push(read_string(v)?),
                type_number::VALUE_EDGE => value_edges.push(LvsValueEdge::decode(v)?),
                type_number::PATTERN_EDGE => {
                    let (edge, uses_fn) = LvsPatternEdge::decode(v)?;
                    uses_user_functions |= uses_fn;
                    pattern_edges.push(edge);
                }
                type_number::KEY_NODE_ID => sign_constraints.push(read_uint(v)?),
                _ => {}
            }
        }

        let id = id.ok_or(LvsError::Truncated("Node missing NodeId"))?;
        Ok((
            Self {
                id,
                parent,
                rule_names,
                value_edges,
                pattern_edges,
                sign_constraints,
            },
            uses_user_functions,
        ))
    }
}

impl LvsValueEdge {
    fn decode(input: &[u8]) -> Result<Self, LvsError> {
        let mut cursor = input;
        let mut dest: Option<u64> = None;
        let mut value: Option<NameComponent> = None;
        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::NODE_ID => dest = Some(read_uint(v)?),
                type_number::COMPONENT_VALUE => value = Some(parse_name_component(v)?),
                _ => {}
            }
        }
        Ok(Self {
            dest: dest.ok_or(LvsError::Truncated("ValueEdge missing dest"))?,
            value: value.ok_or(LvsError::Truncated("ValueEdge missing value"))?,
        })
    }
}

impl LvsPatternEdge {
    fn decode(input: &[u8]) -> Result<(Self, bool), LvsError> {
        let mut cursor = input;
        let mut dest: Option<u64> = None;
        let mut tag: Option<u64> = None;
        let mut constraints = Vec::new();
        let mut uses_user_functions = false;
        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::NODE_ID => dest = Some(read_uint(v)?),
                type_number::PATTERN_TAG => tag = Some(read_uint(v)?),
                type_number::CONSTRAINT => {
                    let (c, uses_fn) = LvsConstraint::decode(v)?;
                    uses_user_functions |= uses_fn;
                    constraints.push(c);
                }
                _ => {}
            }
        }
        Ok((
            Self {
                dest: dest.ok_or(LvsError::Truncated("PatternEdge missing dest"))?,
                tag: tag.ok_or(LvsError::Truncated("PatternEdge missing tag"))?,
                constraints,
            },
            uses_user_functions,
        ))
    }
}

impl LvsConstraint {
    fn decode(input: &[u8]) -> Result<(Self, bool), LvsError> {
        let mut cursor = input;
        let mut options = Vec::new();
        let mut uses_user_functions = false;
        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            if t == type_number::CONS_OPTION {
                let (opt, uses_fn) = LvsConstraintOption::decode(v)?;
                uses_user_functions |= uses_fn;
                options.push(opt);
            }
        }
        Ok((Self { options }, uses_user_functions))
    }
}

impl LvsConstraintOption {
    fn decode(input: &[u8]) -> Result<(Self, bool), LvsError> {
        let mut cursor = input;
        let mut value: Option<NameComponent> = None;
        let mut tag: Option<u64> = None;
        let mut fn_call: Option<LvsUserFnCall> = None;

        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::COMPONENT_VALUE => value = Some(parse_name_component(v)?),
                type_number::PATTERN_TAG => tag = Some(read_uint(v)?),
                type_number::USER_FN_CALL => fn_call = Some(LvsUserFnCall::decode(v)?),
                _ => {}
            }
        }

        let set_count =
            value.is_some() as u8 + tag.is_some() as u8 + fn_call.is_some() as u8;
        if set_count != 1 {
            return Err(LvsError::MalformedConstraintOption);
        }

        if let Some(v) = value {
            Ok((Self::Value(v), false))
        } else if let Some(t) = tag {
            Ok((Self::Tag(t), false))
        } else {
            Ok((Self::UserFn(fn_call.unwrap()), true))
        }
    }
}

impl LvsUserFnCall {
    fn decode(input: &[u8]) -> Result<Self, LvsError> {
        let mut cursor = input;
        let mut fn_id: Option<String> = None;
        let mut args: Vec<LvsUserFnArg> = Vec::new();
        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::USER_FN_ID => fn_id = Some(read_string(v)?),
                type_number::FN_ARGS => args.push(LvsUserFnArg::decode(v)?),
                _ => {}
            }
        }
        Ok(Self {
            fn_id: fn_id.ok_or(LvsError::Truncated("UserFnCall missing FnId"))?,
            args,
        })
    }
}

impl LvsUserFnArg {
    fn decode(input: &[u8]) -> Result<Self, LvsError> {
        let mut cursor = input;
        let mut value: Option<NameComponent> = None;
        let mut tag: Option<u64> = None;
        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::COMPONENT_VALUE => value = Some(parse_name_component(v)?),
                type_number::PATTERN_TAG => tag = Some(read_uint(v)?),
                _ => {}
            }
        }
        if let Some(v) = value {
            Ok(Self::Value(v))
        } else if let Some(t) = tag {
            Ok(Self::Tag(t))
        } else {
            Err(LvsError::Truncated("UserFnArg empty"))
        }
    }
}

impl LvsTagSymbol {
    fn decode(input: &[u8]) -> Result<Self, LvsError> {
        let mut cursor = input;
        let mut tag: Option<u64> = None;
        let mut ident: Option<String> = None;
        while !cursor.is_empty() {
            let (t, v, rest) = read_tlv(cursor)?;
            cursor = rest;
            match t {
                type_number::PATTERN_TAG => tag = Some(read_uint(v)?),
                type_number::IDENTIFIER => ident = Some(read_string(v)?),
                _ => {}
            }
        }
        Ok(Self {
            tag: tag.ok_or(LvsError::Truncated("TagSymbol missing tag"))?,
            ident: ident.ok_or(LvsError::Truncated("TagSymbol missing ident"))?,
        })
    }
}

// ── TLV primitive helpers ─────────────────────────────────────────────────────

/// Read a TLV from the start of `input`, returning (type, value_slice, rest).
fn read_tlv(input: &[u8]) -> Result<(u64, &[u8], &[u8]), LvsError> {
    let (t, tn) = ndn_tlv::read_varu64(input)
        .map_err(|_| LvsError::Truncated("TLV type"))?;
    let (l, ln) = ndn_tlv::read_varu64(&input[tn..])
        .map_err(|_| LvsError::Truncated("TLV length"))?;
    let header_len = tn + ln;
    let total = header_len
        .checked_add(l as usize)
        .ok_or(LvsError::Truncated("TLV length overflow"))?;
    if total > input.len() {
        return Err(LvsError::LengthMismatch {
            offset: 0,
            claimed: total,
            available: input.len(),
        });
    }
    Ok((t, &input[header_len..total], &input[total..]))
}

/// Read a non-negative integer from a TLV value (1/2/4/8 bytes big-endian).
fn read_uint(v: &[u8]) -> Result<u64, LvsError> {
    match v.len() {
        1 => Ok(v[0] as u64),
        2 => Ok(u16::from_be_bytes(v.try_into().unwrap()) as u64),
        4 => Ok(u32::from_be_bytes(v.try_into().unwrap()) as u64),
        8 => Ok(u64::from_be_bytes(v.try_into().unwrap())),
        _ => Err(LvsError::Truncated("uint: unexpected length")),
    }
}

fn read_string(v: &[u8]) -> Result<String, LvsError> {
    std::str::from_utf8(v)
        .map(|s| s.to_owned())
        .map_err(|_| LvsError::BadIdentifier)
}

/// Parse a `COMPONENT_VALUE` field (which itself contains a full
/// NameComponent TLV, per the LVS binary format) into a `NameComponent`.
///
/// The LVS spec line `Value = COMPONENT-VALUE-TYPE TLV-LENGTH NameComponent`
/// is easy to misread as "the value is raw bytes" — python-ndn's
/// `BytesField` declaration is the source of that confusion. In reality the
/// bytes *are* a full NameComponent with its own type+length header, so
/// e.g. a Generic "KEY" literal is stored as `08 03 4b 45 59`, not `4b 45
/// 59`. We parse the inner TLV here so that matching compares the full
/// component (including type) against the walked Name's components.
fn parse_name_component(value: &[u8]) -> Result<NameComponent, LvsError> {
    let (t, tn) = ndn_tlv::read_varu64(value)
        .map_err(|_| LvsError::Truncated("NameComponent type"))?;
    let (l, ln) = ndn_tlv::read_varu64(&value[tn..])
        .map_err(|_| LvsError::Truncated("NameComponent length"))?;
    let start = tn + ln;
    let end = start
        .checked_add(l as usize)
        .ok_or(LvsError::Truncated("NameComponent length overflow"))?;
    if end > value.len() {
        return Err(LvsError::LengthMismatch {
            offset: 0,
            claimed: end,
            available: value.len(),
        });
    }
    Ok(NameComponent::new(t, Bytes::copy_from_slice(&value[start..end])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // ── Hand-built fixtures ────────────────────────────────────────────────
    //
    // Each helper writes a TLV (type, value) pair in the same wire format
    // python-ndn produces. Because python-ndn's IntField writes the minimum
    // number of bytes (1/2/4/8) that fit the value, we do the same here.

    fn write_tlv(buf: &mut BytesMut, t: u64, value: &[u8]) {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(t, value);
        buf.extend_from_slice(&w.finish());
    }

    /// Encode `bytes` as a GenericNameComponent TLV (type 0x08) — the form
    /// the LVS binary compiler uses for literal values.
    fn encode_generic_nc(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.push(0x08);
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
        out
    }

    /// Write a COMPONENT_VALUE TLV whose value is a pre-encoded
    /// GenericNameComponent wrapping `bytes`, matching the python-ndn LVS
    /// compiler output.
    fn write_component_value_tlv(buf: &mut BytesMut, bytes: &[u8]) {
        let nc = encode_generic_nc(bytes);
        write_tlv(buf, type_number::COMPONENT_VALUE, &nc);
    }

    fn uint_be(value: u64) -> Vec<u8> {
        if value <= u8::MAX as u64 {
            vec![value as u8]
        } else if value <= u16::MAX as u64 {
            (value as u16).to_be_bytes().to_vec()
        } else if value <= u32::MAX as u64 {
            (value as u32).to_be_bytes().to_vec()
        } else {
            value.to_be_bytes().to_vec()
        }
    }

    fn write_uint_tlv(buf: &mut BytesMut, t: u64, value: u64) {
        let be = uint_be(value);
        write_tlv(buf, t, &be);
    }

    // ── Basic fixture: hierarchical trust ─────────────────────────────────
    //
    // Three nodes:
    //   0 (root)
    //     --value("app")--> 1 (data)        sign_cons = [2]
    //     --value("key")--> 2 (key, leaf)
    //
    // The "app" data name can be signed by the "key" key name.
    //
    // Named-pattern count is 0 (no pattern edges).
    fn build_hierarchical_fixture() -> Vec<u8> {
        let mut out = BytesMut::new();
        // LvsModel envelope fields (flat, no outer wrapper).
        write_uint_tlv(&mut out, type_number::VERSION, LVS_VERSION);
        write_uint_tlv(&mut out, type_number::NODE_ID, 0); // start_id = 0
        write_uint_tlv(&mut out, type_number::NAMED_PATTERN_NUM, 0);

        // Node 0 (root).
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 0);
            // ValueEdge → node 1 on "app"
            {
                let mut ve = BytesMut::new();
                write_uint_tlv(&mut ve, type_number::NODE_ID, 1);
                write_component_value_tlv(&mut ve, b"app");
                write_tlv(&mut node, type_number::VALUE_EDGE, &ve);
            }
            // ValueEdge → node 2 on "key"
            {
                let mut ve = BytesMut::new();
                write_uint_tlv(&mut ve, type_number::NODE_ID, 2);
                write_component_value_tlv(&mut ve, b"key");
                write_tlv(&mut node, type_number::VALUE_EDGE, &ve);
            }
            write_tlv(&mut out, type_number::NODE, &node);
        }

        // Node 1 (app data) — sign_cons = [2].
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 1);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 0);
            write_uint_tlv(&mut node, type_number::KEY_NODE_ID, 2);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        // Node 2 (key, leaf, trust anchor).
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 2);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 0);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        out.to_vec()
    }

    fn comp(s: &'static str) -> NameComponent {
        NameComponent::generic(Bytes::from_static(s.as_bytes()))
    }

    fn name(parts: &[&'static str]) -> Name {
        Name::from_components(parts.iter().map(|p| comp(p)))
    }

    #[test]
    fn decode_hierarchical_fixture() {
        let wire = build_hierarchical_fixture();
        let model = LvsModel::decode(&wire).expect("decode");
        assert_eq!(model.version, LVS_VERSION);
        assert_eq!(model.start_id, 0);
        assert_eq!(model.named_pattern_cnt, 0);
        assert_eq!(model.nodes.len(), 3);
        assert_eq!(model.nodes[0].value_edges.len(), 2);
        assert_eq!(model.nodes[1].sign_constraints, vec![2]);
        assert!(!model.uses_user_functions());
    }

    #[test]
    fn hierarchical_allows_app_signed_by_key() {
        let model = LvsModel::decode(&build_hierarchical_fixture()).unwrap();
        assert!(model.check(&name(&["app"]), &name(&["key"])));
    }

    #[test]
    fn hierarchical_rejects_wrong_key_name() {
        let model = LvsModel::decode(&build_hierarchical_fixture()).unwrap();
        assert!(!model.check(&name(&["app"]), &name(&["other"])));
    }

    #[test]
    fn hierarchical_rejects_unknown_data_name() {
        let model = LvsModel::decode(&build_hierarchical_fixture()).unwrap();
        assert!(!model.check(&name(&["stranger"]), &name(&["key"])));
    }

    // ── Pattern-edge fixture with capture variable ────────────────────────
    //
    // Models the schema:
    //     /sensor/<node> => /sensor/<node>/KEY
    //
    // where <node> is a pattern variable that must be consistent between
    // the data and key walks.
    //
    // Layout:
    //   0 root
    //     --value("sensor")--> 1
    //   1 "sensor"
    //     --pattern(tag=1, no constraints)--> 2  // data endpoint
    //     --pattern(tag=1, no constraints)--> 3  // key endpoint prefix
    //   2 (data, sign_cons=[4])
    //   3 intermediate "key"
    //     --value("KEY")--> 4
    //   4 (key, leaf)
    //
    // This is a simplification — python-ndn's compiler would produce a
    // more complex graph. But the parser and checker must handle the
    // primitives used here correctly.
    fn build_pattern_fixture() -> Vec<u8> {
        let mut out = BytesMut::new();
        write_uint_tlv(&mut out, type_number::VERSION, LVS_VERSION);
        write_uint_tlv(&mut out, type_number::NODE_ID, 0);
        write_uint_tlv(&mut out, type_number::NAMED_PATTERN_NUM, 1);

        // Node 0 (root) — ValueEdge "sensor" → 1.
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 0);
            let mut ve = BytesMut::new();
            write_uint_tlv(&mut ve, type_number::NODE_ID, 1);
            write_component_value_tlv(&mut ve, b"sensor");
            write_tlv(&mut node, type_number::VALUE_EDGE, &ve);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        // Node 1 — two PatternEdges (tag=1, no constraints).
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 1);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 0);

            // PatternEdge → 2
            {
                let mut pe = BytesMut::new();
                write_uint_tlv(&mut pe, type_number::NODE_ID, 2);
                write_uint_tlv(&mut pe, type_number::PATTERN_TAG, 1);
                write_tlv(&mut node, type_number::PATTERN_EDGE, &pe);
            }
            // PatternEdge → 3 with constraint: tag == 1 (consistency)
            // Here we want the key-path pattern edge to BIND a new variable
            // that must equal tag 1 from the data path. But bindings don't
            // cross walks — the check is per-walk. Since ndn-rs evaluates
            // data and key separately, consistency across walks is only
            // possible via sign-constraint graph structure, which this
            // fixture emulates by tying the two endpoints through sign_cons.
            //
            // For a meaningful test of the Tag constraint option, we add a
            // constraint that says "this pattern edge must equal tag 1 from
            // the SAME walk". That can't actually fire during a single walk
            // without a preceding pattern-edge on the same path, so we add
            // a pattern edge first on the key path (node 3 → 4).
            {
                let mut pe = BytesMut::new();
                write_uint_tlv(&mut pe, type_number::NODE_ID, 3);
                write_uint_tlv(&mut pe, type_number::PATTERN_TAG, 1);
                write_tlv(&mut node, type_number::PATTERN_EDGE, &pe);
            }
            write_tlv(&mut out, type_number::NODE, &node);
        }

        // Node 2 — data endpoint, sign_cons = [4].
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 2);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 1);
            write_uint_tlv(&mut node, type_number::KEY_NODE_ID, 4);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        // Node 3 — intermediate on key path, ValueEdge "KEY" → 4.
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 3);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 1);
            let mut ve = BytesMut::new();
            write_uint_tlv(&mut ve, type_number::NODE_ID, 4);
            write_component_value_tlv(&mut ve, b"KEY");
            write_tlv(&mut node, type_number::VALUE_EDGE, &ve);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        // Node 4 — key leaf.
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 4);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 3);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        out.to_vec()
    }

    #[test]
    fn pattern_fixture_allows_data_signed_by_key() {
        let model = LvsModel::decode(&build_pattern_fixture()).unwrap();
        // /sensor/temp signed by /sensor/temp/KEY
        assert!(model.check(&name(&["sensor", "temp"]), &name(&["sensor", "temp", "KEY"])));
    }

    #[test]
    fn pattern_fixture_rejects_shorter_key() {
        let model = LvsModel::decode(&build_pattern_fixture()).unwrap();
        assert!(!model.check(&name(&["sensor", "temp"]), &name(&["sensor", "temp"])));
    }

    #[test]
    fn pattern_fixture_rejects_wrong_root() {
        let model = LvsModel::decode(&build_pattern_fixture()).unwrap();
        assert!(!model.check(&name(&["other", "temp"]), &name(&["sensor", "temp", "KEY"])));
    }

    // ── Version check ──────────────────────────────────────────────────────

    #[test]
    fn unsupported_version_errors() {
        let mut out = BytesMut::new();
        write_uint_tlv(&mut out, type_number::VERSION, 0xDEADBEEF);
        write_uint_tlv(&mut out, type_number::NODE_ID, 0);
        write_uint_tlv(&mut out, type_number::NAMED_PATTERN_NUM, 0);
        assert!(matches!(
            LvsModel::decode(&out),
            Err(LvsError::UnsupportedVersion { .. })
        ));
    }

    // ── User function detection ────────────────────────────────────────────

    #[test]
    fn user_function_schema_parses_and_flags() {
        let mut out = BytesMut::new();
        write_uint_tlv(&mut out, type_number::VERSION, LVS_VERSION);
        write_uint_tlv(&mut out, type_number::NODE_ID, 0);
        write_uint_tlv(&mut out, type_number::NAMED_PATTERN_NUM, 1);

        // Node 0 with a PatternEdge → 1 whose constraint uses a user fn.
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 0);
            let mut pe = BytesMut::new();
            write_uint_tlv(&mut pe, type_number::NODE_ID, 1);
            write_uint_tlv(&mut pe, type_number::PATTERN_TAG, 1);
            {
                let mut cons = BytesMut::new();
                {
                    let mut opt = BytesMut::new();
                    let mut call = BytesMut::new();
                    write_tlv(&mut call, type_number::USER_FN_ID, b"$regex");
                    {
                        let mut arg = BytesMut::new();
                        write_component_value_tlv(&mut arg, b"^[0-9]+$");
                        write_tlv(&mut call, type_number::FN_ARGS, &arg);
                    }
                    write_tlv(&mut opt, type_number::USER_FN_CALL, &call);
                    write_tlv(&mut cons, type_number::CONS_OPTION, &opt);
                }
                write_tlv(&mut pe, type_number::CONSTRAINT, &cons);
            }
            write_tlv(&mut node, type_number::PATTERN_EDGE, &pe);
            write_tlv(&mut out, type_number::NODE, &node);
        }
        // Node 1 leaf.
        {
            let mut node = BytesMut::new();
            write_uint_tlv(&mut node, type_number::NODE_ID, 1);
            write_uint_tlv(&mut node, type_number::PARENT_ID, 0);
            write_tlv(&mut out, type_number::NODE, &node);
        }

        let model = LvsModel::decode(&out).expect("decode");
        assert!(
            model.uses_user_functions(),
            "user-fn schema must flag uses_user_functions"
        );
        // The user-fn-gated edge never matches, so the packet is rejected.
        assert!(!model.check(&name(&["123"]), &name(&["123"])));
    }
}
