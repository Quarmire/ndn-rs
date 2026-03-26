use bytes::Bytes;
use smallvec::SmallVec;

use crate::PacketError;
use crate::tlv_type;
use ndn_tlv::TlvReader;

/// A single NDN name component: a (type, value) pair.
///
/// The value is a zero-copy slice of the original packet buffer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NameComponent {
    pub typ:   u64,
    pub value: Bytes,
}

impl NameComponent {
    pub fn new(typ: u64, value: Bytes) -> Self {
        Self { typ, value }
    }

    pub fn generic(value: Bytes) -> Self {
        Self { typ: tlv_type::NAME_COMPONENT, value }
    }
}

/// An NDN name: an ordered sequence of name components.
///
/// Components are stored in a `SmallVec` with inline capacity for 8 elements,
/// covering typical 4–8 component names without heap allocation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    components: SmallVec<[NameComponent; 8]>,
}

impl Name {
    /// The root (empty) name `/`.
    pub fn root() -> Self {
        Self { components: SmallVec::new() }
    }

    pub fn from_components(components: impl IntoIterator<Item = NameComponent>) -> Self {
        Self { components: components.into_iter().collect() }
    }

    pub fn components(&self) -> &[NameComponent] {
        &self.components
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns `true` if `prefix` is a prefix of (or equal to) this name.
    pub fn has_prefix(&self, prefix: &Name) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        self.components.iter().zip(prefix.components.iter()).all(|(a, b)| a == b)
    }

    /// Decode a `Name` TLV from `reader`. The reader must be positioned at the
    /// start of the Name value (after the outer type+length have been consumed).
    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(value);
        let mut components = SmallVec::new();
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            components.push(NameComponent::new(typ, val));
        }
        Ok(Self { components })
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "/")?;
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            // Print printable ASCII; percent-encode everything else.
            for &b in c.value.iter() {
                if b.is_ascii_graphic() && b != b'/' && b != b'%' {
                    write!(f, "{}", b as char)?;
                } else {
                    write!(f, "%{b:02X}")?;
                }
            }
        }
        Ok(())
    }
}
