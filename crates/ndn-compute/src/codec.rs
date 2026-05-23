//! Framing for typed compute functions: arguments map to the name components
//! that follow the function prefix; results map to Data content bytes.
//!
//! The default framing is deliberately simple and TLV-native (no serde): scalar
//! arguments are ASCII-decimal or UTF-8 [`GenericNameComponent`]s, matching the
//! convention NDN already uses for segment / version numbers. Applications that
//! need richer encodings implement [`ComputeArgs`] / [`ComputeValue`] for their
//! own types.
//!
//! [`GenericNameComponent`]: ndn_packet::NameComponent::generic

use bytes::Bytes;
use ndn_packet::NameComponent;

use crate::registry::ComputeError;

/// A single typed argument, carried as exactly one name component.
pub trait ArgComponent: Sized {
    /// Encode this argument as one name component.
    fn to_component(&self) -> NameComponent;
    /// Decode this argument from one name component.
    fn from_component(c: &NameComponent) -> Result<Self, ComputeError>;
}

/// The full argument list of a function, mapped to the name components that
/// follow the function prefix (and precede any opaque nonce).
pub trait ComputeArgs: Sized {
    /// Encode the argument list as the trailing name components.
    fn to_components(&self) -> Vec<NameComponent>;
    /// Decode the argument list from the trailing name components.
    fn from_components(comps: &[NameComponent]) -> Result<Self, ComputeError>;
}

/// A value carried in Data content — a function result, or a single-blob input.
pub trait ComputeValue: Sized {
    /// Encode to Data content bytes.
    fn encode(&self) -> Bytes;
    /// Decode from Data content bytes.
    fn decode(bytes: &[u8]) -> Result<Self, ComputeError>;
}

fn parse_decimal<T: std::str::FromStr>(c: &NameComponent, what: &str) -> Result<T, ComputeError> {
    std::str::from_utf8(&c.value)
        .ok()
        .and_then(|s| s.parse::<T>().ok())
        .ok_or_else(|| ComputeError::BadArguments(format!("expected {what}")))
}

macro_rules! impl_decimal_arg {
    ($($t:ty),*) => {$(
        impl ArgComponent for $t {
            fn to_component(&self) -> NameComponent {
                NameComponent::generic(Bytes::from(self.to_string()))
            }
            fn from_component(c: &NameComponent) -> Result<Self, ComputeError> {
                parse_decimal::<$t>(c, stringify!($t))
            }
        }
        impl ComputeValue for $t {
            fn encode(&self) -> Bytes {
                Bytes::from(self.to_string())
            }
            fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|s| s.parse::<$t>().ok())
                    .ok_or_else(|| ComputeError::ComputeFailed(
                        concat!("result is not a ", stringify!($t)).into()))
            }
        }
    )*};
}

impl_decimal_arg!(i32, i64, u32, u64, usize);

impl ArgComponent for String {
    fn to_component(&self) -> NameComponent {
        NameComponent::generic(Bytes::from(self.clone().into_bytes()))
    }
    fn from_component(c: &NameComponent) -> Result<Self, ComputeError> {
        String::from_utf8(c.value.to_vec())
            .map_err(|_| ComputeError::BadArguments("argument is not UTF-8".into()))
    }
}

impl ComputeValue for String {
    fn encode(&self) -> Bytes {
        Bytes::from(self.clone().into_bytes())
    }
    fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| ComputeError::ComputeFailed("result is not UTF-8".into()))
    }
}

impl ComputeValue for Bytes {
    fn encode(&self) -> Bytes {
        self.clone()
    }
    fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        Ok(Bytes::copy_from_slice(bytes))
    }
}

impl ComputeValue for Vec<u8> {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self, ComputeError> {
        Ok(bytes.to_vec())
    }
}

/// A raw-bytes argument occupying one name component verbatim.
impl ArgComponent for Bytes {
    fn to_component(&self) -> NameComponent {
        NameComponent::generic(self.clone())
    }
    fn from_component(c: &NameComponent) -> Result<Self, ComputeError> {
        Ok(c.value.clone())
    }
}

/// No arguments.
impl ComputeArgs for () {
    fn to_components(&self) -> Vec<NameComponent> {
        Vec::new()
    }
    fn from_components(_comps: &[NameComponent]) -> Result<Self, ComputeError> {
        Ok(())
    }
}

/// A single argument occupies exactly one component.
impl<T: ArgComponent> ComputeArgs for T {
    fn to_components(&self) -> Vec<NameComponent> {
        vec![self.to_component()]
    }
    fn from_components(comps: &[NameComponent]) -> Result<Self, ComputeError> {
        match comps {
            [only] => T::from_component(only),
            _ => Err(ComputeError::BadArguments(format!(
                "expected 1 argument component, got {}",
                comps.len()
            ))),
        }
    }
}

impl<A: ArgComponent, B: ArgComponent> ComputeArgs for (A, B) {
    fn to_components(&self) -> Vec<NameComponent> {
        vec![self.0.to_component(), self.1.to_component()]
    }
    fn from_components(comps: &[NameComponent]) -> Result<Self, ComputeError> {
        match comps {
            [a, b] => Ok((A::from_component(a)?, B::from_component(b)?)),
            _ => Err(ComputeError::BadArguments(format!(
                "expected 2 argument components, got {}",
                comps.len()
            ))),
        }
    }
}

impl<A: ArgComponent, B: ArgComponent, C: ArgComponent> ComputeArgs for (A, B, C) {
    fn to_components(&self) -> Vec<NameComponent> {
        vec![
            self.0.to_component(),
            self.1.to_component(),
            self.2.to_component(),
        ]
    }
    fn from_components(comps: &[NameComponent]) -> Result<Self, ComputeError> {
        match comps {
            [a, b, c] => Ok((
                A::from_component(a)?,
                B::from_component(b)?,
                C::from_component(c)?,
            )),
            _ => Err(ComputeError::BadArguments(format!(
                "expected 3 argument components, got {}",
                comps.len()
            ))),
        }
    }
}
