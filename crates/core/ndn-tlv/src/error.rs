/// Errors produced by TLV decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    UnexpectedEof,
    UnknownCriticalType(u64),
    InvalidLength {
        typ: u64,
        expected: usize,
        got: usize,
    },
    InvalidUtf8 {
        typ: u64,
    },
    MissingField(&'static str),
    DuplicateField(u64),
    NonMinimalVarNumber,
    /// TLV-TYPE outside the spec u32 range, or used the 9-byte VAR-NUMBER form
    /// (NDN Packet Format v0.3 §2.0: 9-byte form is LENGTH-only).
    TypeOutOfRange,
}

impl core::fmt::Display for TlvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlvError::UnexpectedEof => write!(f, "unexpected end of buffer"),
            TlvError::UnknownCriticalType(t) => {
                write!(f, "unknown critical TLV type {t:#x}")
            }
            TlvError::InvalidLength { typ, expected, got } => {
                write!(
                    f,
                    "TLV type {typ:#x}: expected length {expected}, got {got}"
                )
            }
            TlvError::InvalidUtf8 { typ } => {
                write!(f, "TLV type {typ:#x} contains invalid UTF-8")
            }
            TlvError::MissingField(name) => write!(f, "required field '{name}' missing"),
            TlvError::DuplicateField(t) => {
                write!(f, "TLV type {t:#x} appeared more than once")
            }
            TlvError::NonMinimalVarNumber => {
                write!(f, "VarNumber not in shortest encoding form")
            }
            TlvError::TypeOutOfRange => {
                write!(
                    f,
                    "TLV-TYPE exceeds spec u32 range (9-byte form is for LENGTH only)"
                )
            }
        }
    }
}

impl core::error::Error for TlvError {}
