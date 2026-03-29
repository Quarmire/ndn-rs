/// Errors produced by TLV decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    /// Packet was truncated before the expected end.
    UnexpectedEof,
    /// Unknown TLV type with the critical bit set (odd type number) — must drop.
    UnknownCriticalType(u64),
    /// A field had the wrong encoded length.
    InvalidLength { typ: u64, expected: usize, got: usize },
    /// A UTF-8 field contained invalid bytes.
    InvalidUtf8 { typ: u64 },
    /// A required field was absent.
    MissingField(&'static str),
    /// The same TLV type appeared more than once where only one is allowed.
    DuplicateField(u64),
    /// VarNumber is not in shortest encoding form.
    NonMinimalVarNumber,
}

impl core::fmt::Display for TlvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlvError::UnexpectedEof => write!(f, "unexpected end of buffer"),
            TlvError::UnknownCriticalType(t) => {
                write!(f, "unknown critical TLV type {t:#x}")
            }
            TlvError::InvalidLength { typ, expected, got } => {
                write!(f, "TLV type {typ:#x}: expected length {expected}, got {got}")
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
        }
    }
}

impl core::error::Error for TlvError {}
