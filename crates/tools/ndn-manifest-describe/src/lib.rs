//! ndn-manifest-describe — runtime support for `#[derive(Manifest)]`.
//!
//! The derive (`ndn-manifest-derive`) generates thin code that calls these
//! helpers, so the parts that carry *judgment* — the lossy `f64 → Decimal`
//! translation, the non-finite refusal, and the cardinality list-wrapping — are
//! ordinary, unit-tested Rust rather than macro output you can't step through.
//!
//! The house laws these encode (DERIVE.md, F55):
//!
//! - **Floats are a declared loss.** [`decimal`] rounds to a *declared*
//!   precision (round-half-even, then normalize). Non-finite input is
//!   `Err(NonFinite)` — never a silent zero, which "is a guess wearing a
//!   value's clothes" and poisons downstream aggregates.
//! - **Cardinality declares, list-ness encodes.** `One` is the bare value;
//!   `Optional`/`Vec`/`Some` encode as a list whose length the cardinality
//!   bounds — `None` is `[]`, never an absent slot or a presence flag.
//!
//! Tool tier: depends on `ndn-manifest`, never depended on by it (C7).
#![deny(missing_docs)]

use ndn_manifest::model::{Decimal, Value};

/// Why a value could not be described honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribeError {
    /// A float field held `NaN` or `±inf`: there is no canonical decimal for it,
    /// and mapping it to a number would be a guess. The producer must make the
    /// value finite, mark the field `#[field(nonfinite = absent)]` (optional
    /// fields only), or model real uncertainty as `measured { estimate, ± }`.
    NonFinite {
        /// The offending field's (kebab-case) label.
        field: &'static str,
    },
}

impl core::fmt::Display for DescribeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DescribeError::NonFinite { field } => {
                write!(f, "field `{field}` is non-finite (NaN/inf) — no honest decimal; never a guess")
            }
        }
    }
}

impl std::error::Error for DescribeError {}

/// `f64` → a canonical [`Value::Decimal`] at a **declared** precision.
///
/// Fixed `places` decimal places (Rust's float formatting rounds half-to-even),
/// then `Decimal::normalize` strips trailing zeros (`1.5000` → `1.5`). Two floats
/// differing below `places` collapse to one decimal — and that collapse *is* the
/// declared loss. Non-finite input is refused, not zeroed.
pub fn decimal(v: f64, places: u32, field: &'static str) -> Result<Value, DescribeError> {
    if !v.is_finite() {
        return Err(DescribeError::NonFinite { field });
    }
    Ok(Value::Decimal(finite_decimal(v, places)))
}

/// `f64` → `Some(Decimal)` when finite, `None` when not — the `nonfinite =
/// absent` opt-in for optional fields, where absence is honest and zero is not.
pub fn decimal_or_none(v: f64, places: u32) -> Option<Value> {
    v.is_finite().then(|| Value::Decimal(finite_decimal(v, places)))
}

fn finite_decimal(v: f64, places: u32) -> Decimal {
    let s = format!("{:.*}", places as usize, v);
    Decimal::normalize(&s).expect("fixed-point formatting of a finite f64 is always normalizable")
}

/// Wrap an optional value as the 0-or-1 list encoding (F55-A: `None` = `[]`,
/// `Some(v)` = `[v]`).
pub fn optional(v: Option<Value>) -> Value {
    Value::List(v.into_iter().collect())
}

/// Wrap a sequence as a list value (`Vec<T>` = `many`, or `#[field(some)]` = `some`).
pub fn list(vs: Vec<Value>) -> Value {
    Value::List(vs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_rounds_and_normalizes() {
        assert_eq!(decimal(1.5, 4, "x").unwrap(), Value::Decimal(Decimal::from_canonical("1.5").unwrap()));
        assert_eq!(decimal(11.18, 4, "x").unwrap(), Value::Decimal(Decimal::from_canonical("11.18").unwrap()));
        // round-half-even: 0.5 at 0 places → 0; 1.5 → 2.
        assert_eq!(decimal(0.5, 0, "x").unwrap(), Value::Decimal(Decimal::from_canonical("0").unwrap()));
        assert_eq!(decimal(2.5, 0, "x").unwrap(), Value::Decimal(Decimal::from_canonical("2").unwrap()));
    }

    #[test]
    fn non_finite_is_refused_not_zeroed() {
        assert_eq!(decimal(f64::NAN, 4, "stage"), Err(DescribeError::NonFinite { field: "stage" }));
        assert_eq!(decimal(f64::INFINITY, 4, "stage"), Err(DescribeError::NonFinite { field: "stage" }));
        // The opt-in absent path yields None (→ []), not a zero.
        assert_eq!(decimal_or_none(f64::NAN, 4), None);
        assert!(decimal_or_none(3.0, 4).is_some());
    }

    #[test]
    fn cardinality_list_wrapping() {
        assert_eq!(optional(None), Value::List(vec![]));
        assert_eq!(optional(Some(Value::Integer(1))), Value::List(vec![Value::Integer(1)]));
        assert_eq!(list(vec![Value::Integer(1), Value::Integer(2)]), Value::List(vec![Value::Integer(1), Value::Integer(2)]));
    }
}
