//! ABE policy expression language.
//!
//! Grammar (canonical form):
//!   expr     := or_expr
//!   or_expr  := and_expr (OR and_expr)*
//!   and_expr := primary (AND primary)*
//!   primary  := attr | '(' expr ')'
//!   attr     := ['/path/components/']key':' value
//!
//! Single-authority: `role:doctor AND dept:cardiology`
//! Multi-authority:  `/hospital-A/role:doctor AND /licensing-board/cardiology:certified`
//!
//! Compiled to rabe's HumanPolicy: `"role:doctor" and "dept:cardiology"`
//! (attributes are double-quoted; AND/OR are lowercase).

use ndn_foundation_types::Name;

use crate::AbeError;

/// A parsed ABE policy expression.
// The `Attribute` leaf carries a `Name` (large) while the operator variants
// carry boxed children; the size disparity is inherent to the AST. This is a
// small, parse-time structure, never a hot path, so we keep the leaf inline
// rather than boxing it (which would change `PolicyExpr`'s public shape).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyExpr {
    /// A single attribute predicate.
    Attribute(AttributeRef),
    /// Both sub-expressions must be satisfied.
    And(Box<PolicyExpr>, Box<PolicyExpr>),
    /// Either sub-expression suffices.
    Or(Box<PolicyExpr>, Box<PolicyExpr>),
}

/// A single attribute reference within a policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttributeRef {
    /// `None` = single-authority. `Some(Name)` = multi-authority KGC prefix.
    pub authority: Option<Name>,
    /// Attribute key, e.g. `"role"`.
    pub key: String,
    /// Attribute value, e.g. `"doctor"`.
    pub value: String,
}

impl AttributeRef {
    /// The flat attribute string used in rabe's policy and keygen APIs.
    /// Format: `key:value` (authority prefix is stripped — it is the KGC's concern).
    pub fn flat(&self) -> String {
        format!("{}:{}", self.key, self.value)
    }
}

impl PolicyExpr {
    /// Parse a policy expression string.
    pub fn parse(source: &str) -> Result<Self, AbeError> {
        let tokens = tokenize(source).map_err(AbeError::PolicyParse)?;
        let mut pos = 0usize;
        let expr = parse_or(&tokens, &mut pos).map_err(AbeError::PolicyParse)?;
        if pos != tokens.len() {
            return Err(AbeError::PolicyParse(format!(
                "unexpected token at position {}: {:?}",
                pos,
                tokens.get(pos)
            )));
        }
        Ok(expr)
    }

    /// Canonical string representation (round-trips through `parse`).
    pub fn to_canonical(&self) -> String {
        match self {
            PolicyExpr::Attribute(a) => {
                if let Some(auth) = &a.authority {
                    format!("{}/{}:{}", auth, a.key, a.value)
                } else {
                    format!("{}:{}", a.key, a.value)
                }
            }
            PolicyExpr::And(l, r) => {
                format!("({} AND {})", l.to_canonical(), r.to_canonical())
            }
            PolicyExpr::Or(l, r) => {
                format!("({} OR {})", l.to_canonical(), r.to_canonical())
            }
        }
    }

    /// Format suitable for `rabe::schemes::bsw::encrypt` (HumanPolicy).
    ///
    /// Attributes are quoted: `"role:doctor"`. Operators are lowercase.
    /// Errors if any attribute carries an authority prefix (multi-authority
    /// policies must use AW11 via the multi-authority path).
    pub fn to_rabe_bsw(&self) -> Result<String, AbeError> {
        match self {
            PolicyExpr::Attribute(a) => {
                if a.authority.is_some() {
                    return Err(AbeError::MultiAuthorityNotSupported);
                }
                Ok(format!("\"{}\"", a.flat()))
            }
            PolicyExpr::And(l, r) => {
                Ok(format!("{} and {}", l.to_rabe_bsw()?, r.to_rabe_bsw()?))
            }
            PolicyExpr::Or(l, r) => {
                Ok(format!("({} or {})", l.to_rabe_bsw()?, r.to_rabe_bsw()?))
            }
        }
    }

    /// Format suitable for `rabe::schemes::aw11::encrypt` (HumanPolicy).
    ///
    /// AW11 uses uppercase attribute names internally; authority prefixes are
    /// stripped — the global key scope governs which authority owns each attr.
    pub fn to_rabe_aw11(&self) -> String {
        match self {
            PolicyExpr::Attribute(a) => {
                format!("\"{}\"", a.flat().to_uppercase())
            }
            PolicyExpr::And(l, r) => {
                format!("{} and {}", l.to_rabe_aw11(), r.to_rabe_aw11())
            }
            PolicyExpr::Or(l, r) => {
                format!("({} or {})", l.to_rabe_aw11(), r.to_rabe_aw11())
            }
        }
    }

    /// Distinct authority Names in the expression (sorted, deduplicated).
    /// Empty vec = single-authority.
    pub fn authorities(&self) -> Vec<Name> {
        let mut auths: Vec<Name> = Vec::new();
        self.collect_authorities(&mut auths);
        auths.sort_by_key(|n| n.to_string());
        auths.dedup_by_key(|n| n.to_string());
        auths
    }

    fn collect_authorities(&self, out: &mut Vec<Name>) {
        match self {
            PolicyExpr::Attribute(a) => {
                if let Some(auth) = &a.authority {
                    out.push(auth.clone());
                }
            }
            PolicyExpr::And(l, r) | PolicyExpr::Or(l, r) => {
                l.collect_authorities(out);
                r.collect_authorities(out);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Attr(String),   // raw attribute string, possibly with authority prefix
    And,
    Or,
    LParen,
    RParen,
}

fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = src.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => { chars.next(); }
            '(' => { chars.next(); tokens.push(Token::LParen); }
            ')' => { chars.next(); tokens.push(Token::RParen); }
            _ => {
                // Collect a word (attribute or keyword)
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '(' || c == ')' || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                match word.to_uppercase().as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR"  => tokens.push(Token::Or),
                    _ => tokens.push(Token::Attr(word)),
                }
            }
        }
    }
    Ok(tokens)
}

fn parse_or(tokens: &[Token], pos: &mut usize) -> Result<PolicyExpr, String> {
    let mut lhs = parse_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let rhs = parse_and(tokens, pos)?;
        lhs = PolicyExpr::Or(Box::new(lhs), Box::new(rhs));
    }
    Ok(lhs)
}

fn parse_and(tokens: &[Token], pos: &mut usize) -> Result<PolicyExpr, String> {
    let mut lhs = parse_primary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let rhs = parse_primary(tokens, pos)?;
        lhs = PolicyExpr::And(Box::new(lhs), Box::new(rhs));
    }
    Ok(lhs)
}

fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<PolicyExpr, String> {
    if *pos >= tokens.len() {
        return Err("unexpected end of input".to_string());
    }
    match &tokens[*pos] {
        Token::LParen => {
            *pos += 1;
            let inner = parse_or(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
                return Err("expected closing parenthesis".to_string());
            }
            *pos += 1;
            Ok(inner)
        }
        Token::Attr(raw) => {
            let attr = parse_attr_ref(raw)?;
            *pos += 1;
            Ok(PolicyExpr::Attribute(attr))
        }
        other => Err(format!("expected attribute or '(', found {:?}", other)),
    }
}

/// Parse a raw attribute token into an `AttributeRef`.
///
/// Formats accepted:
/// - `key:value`                      → single-authority
/// - `/prefix/key:value`              → authority = `/prefix`, key:value is last segment
fn parse_attr_ref(raw: &str) -> Result<AttributeRef, String> {
    if raw.starts_with('/') {
        // Multi-authority: find the last '/' that separates path from key:value
        let last_slash = raw.rfind('/').ok_or_else(|| format!("malformed attr: {raw}"))?;
        let authority_str = &raw[..last_slash];
        let kv = &raw[last_slash + 1..];
        let authority: Name = authority_str
            .parse()
            .map_err(|e| format!("invalid authority name '{authority_str}': {e}"))?;
        let (key, value) = split_kv(kv)?;
        Ok(AttributeRef { authority: Some(authority), key, value })
    } else {
        let (key, value) = split_kv(raw)?;
        Ok(AttributeRef { authority: None, key, value })
    }
}

fn split_kv(s: &str) -> Result<(String, String), String> {
    let colon = s.find(':').ok_or_else(|| format!("attribute missing ':' separator: {s}"))?;
    let key = s[..colon].to_string();
    let value = s[colon + 1..].to_string();
    if key.is_empty() {
        return Err(format!("attribute key is empty in: {s}"));
    }
    if value.is_empty() {
        return Err(format!("attribute value is empty in: {s}"));
    }
    Ok((key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parses_simple_attribute() {
        let expr = PolicyExpr::parse("role:doctor").unwrap();
        assert_eq!(
            expr,
            PolicyExpr::Attribute(AttributeRef {
                authority: None,
                key: "role".into(),
                value: "doctor".into(),
            })
        );
    }

    #[test]
    fn policy_parses_and() {
        let expr = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        assert_eq!(
            expr,
            PolicyExpr::And(
                Box::new(PolicyExpr::Attribute(AttributeRef { authority: None, key: "role".into(), value: "doctor".into() })),
                Box::new(PolicyExpr::Attribute(AttributeRef { authority: None, key: "dept".into(), value: "cardiology".into() })),
            )
        );
    }

    #[test]
    fn policy_parses_or() {
        let expr = PolicyExpr::parse("role:doctor OR role:chief").unwrap();
        assert!(matches!(expr, PolicyExpr::Or(_, _)));
    }

    #[test]
    fn policy_parses_grouping() {
        let expr = PolicyExpr::parse("(role:doctor AND dept:cardiology) OR role:chief").unwrap();
        match expr {
            PolicyExpr::Or(lhs, rhs) => {
                assert!(matches!(*lhs, PolicyExpr::And(_, _)));
                assert!(matches!(*rhs, PolicyExpr::Attribute(_)));
            }
            _ => panic!("expected Or at root"),
        }
    }

    #[test]
    fn policy_parses_multi_authority() {
        let expr = PolicyExpr::parse(
            "/hospital-A/role:doctor AND /licensing-board/cardiology:certified",
        ).unwrap();
        let auths = expr.authorities();
        assert_eq!(auths.len(), 2);
    }

    #[test]
    fn policy_round_trip_to_canonical() {
        let src = "role:doctor AND dept:cardiology";
        let expr = PolicyExpr::parse(src).unwrap();
        // canonical form wraps AND in parens
        let canonical = expr.to_canonical();
        let expr2 = PolicyExpr::parse(&canonical).unwrap();
        assert_eq!(expr, expr2);
    }

    #[test]
    fn policy_to_rabe_bsw_single_authority() {
        let expr = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let rabe = expr.to_rabe_bsw().unwrap();
        assert_eq!(rabe, r#""role:doctor" and "dept:cardiology""#);
    }

    #[test]
    fn policy_to_rabe_bsw_rejects_multi_auth() {
        let expr = PolicyExpr::parse(
            "/hospital-A/role:doctor AND /licensing-board/cardiology:certified",
        ).unwrap();
        assert!(matches!(expr.to_rabe_bsw(), Err(AbeError::MultiAuthorityNotSupported)));
    }
}
