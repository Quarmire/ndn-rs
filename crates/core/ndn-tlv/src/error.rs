//! Error type shared by the TLV reader, writer, and higher-level decoders.

/// Errors produced by TLV decoding.
///
/// Decoders in dependent crates (packet, LP, management) reuse these variants,
/// which is why the set covers structural framing (`UnexpectedEof`,
/// `NonMinimalVarNumber`, `TypeOutOfRange`) as well as schema-level faults
/// (`MissingField`, `DuplicateField`, `InvalidLength`) that this crate never
/// raises itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    /// The buffer ended mid-item: a VAR-NUMBER, or a value shorter than its
    /// declared TLV-LENGTH. Also raised when a length exceeds the bytes that
    /// remain, so an oversized length can never over-read (W-1).
    UnexpectedEof,
    /// An unrecognized TLV whose type is critical per the even/odd rule
    /// (NDN Packet Format v0.3 §2.2) and therefore may not be skipped. Carries
    /// the offending TLV-TYPE.
    UnknownCriticalType(u64),
    /// A fixed-width field carried a value length its type does not permit
    /// (e.g. a nonce that must be exactly 4 bytes). Raised by higher-level
    /// decoders, not by the low-level reader.
    InvalidLength {
        /// TLV-TYPE of the field that was mis-sized.
        typ: u64,
        /// Value length the type's schema requires.
        expected: usize,
        /// Value length actually present on the wire.
        got: usize,
    },
    /// A field defined as UTF-8 text held bytes that are not valid UTF-8.
    InvalidUtf8 {
        /// TLV-TYPE of the offending text field.
        typ: u64,
    },
    /// A field a decoder requires was absent from the element. Carries a static
    /// name for the field to aid diagnostics.
    MissingField(&'static str),
    /// A field that must appear at most once was seen twice. Carries the
    /// repeated TLV-TYPE.
    DuplicateField(u64),
    /// A VAR-NUMBER used a wider form than the minimum needed for its value
    /// (e.g. the 3-byte form for a value `< 253`). Non-minimal encodings are
    /// rejected so every element has one canonical wire form.
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
