use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use smallvec::SmallVec;

use ndn_packet::{Data, Interest, Nack, Name};
use ndn_store::PitToken;
use ndn_transport::FaceId;

/// The packet as it progresses through decode stages.
pub enum DecodedPacket {
    /// Not yet decoded — the raw bytes are still in `PacketContext::raw_bytes`.
    Raw,
    Interest(Box<Interest>),
    Data(Box<Data>),
    Nack(Box<Nack>),
}

/// Per-packet state passed by value through pipeline stages.
///
/// Passing by value (rather than `&mut`) makes ownership explicit:
/// a stage that short-circuits simply does not return the context,
/// so Rust's ownership system prevents use-after-hand-off at compile time.
pub struct PacketContext {
    /// Wire-format bytes of the original packet.
    pub raw_bytes: Bytes,
    /// Face the packet arrived on.
    pub face_id: FaceId,
    /// Decoded name — hoisted to top level because every stage needs it.
    /// `None` until `TlvDecodeStage` runs.
    pub name: Option<Arc<Name>>,
    /// Decoded packet — starts as `Raw`, transitions after TlvDecodeStage.
    pub packet: DecodedPacket,
    /// PIT token — written by PitCheckStage, `None` before that stage runs.
    pub pit_token: Option<PitToken>,
    /// Faces selected for forwarding by the strategy stage.
    pub out_faces: SmallVec<[FaceId; 4]>,
    /// Set to `true` by CsLookupStage on a cache hit.
    pub cs_hit: bool,
    /// Set to `true` by the security validation stage.
    pub verified: bool,
    /// Arrival time in nanoseconds since the Unix epoch (set by the face task).
    pub arrival: u64,
    /// Escape hatch for inter-stage communication not covered by explicit fields.
    /// Use sparingly; prefer explicit fields for anything the core pipeline touches.
    pub tags: AnyMap,
}

impl PacketContext {
    pub fn new(raw_bytes: Bytes, face_id: FaceId, arrival: u64) -> Self {
        Self {
            raw_bytes,
            face_id,
            name:      None,
            packet:    DecodedPacket::Raw,
            pit_token: None,
            out_faces: SmallVec::new(),
            cs_hit:    false,
            verified:  false,
            arrival,
            tags:      AnyMap::new(),
        }
    }
}

/// A type-erased map for optional inter-stage tags.
///
/// Implemented as a `HashMap<TypeId, Box<dyn Any + Send>>` so each type can
/// only appear once (like a typed slot), accessed with zero string overhead.
pub struct AnyMap(HashMap<TypeId, Box<dyn Any + Send>>);

impl AnyMap {
    pub fn new() -> Self { Self(HashMap::new()) }

    pub fn insert<T: Any + Send>(&mut self, val: T) {
        self.0.insert(TypeId::of::<T>(), Box::new(val));
    }

    pub fn get<T: Any + Send>(&self) -> Option<&T> {
        self.0.get(&TypeId::of::<T>())?.downcast_ref()
    }

    pub fn remove<T: Any + Send>(&mut self) -> Option<T> {
        self.0.remove(&TypeId::of::<T>())
            .and_then(|b| b.downcast().ok())
            .map(|b| *b)
    }
}

impl Default for AnyMap {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::FaceId;

    #[test]
    fn packet_context_new_defaults() {
        let raw = Bytes::from_static(b"\x05\x01\x00");
        let ctx = PacketContext::new(raw.clone(), FaceId(7), 12345);
        assert_eq!(ctx.raw_bytes, raw);
        assert_eq!(ctx.face_id, FaceId(7));
        assert_eq!(ctx.arrival, 12345);
        assert!(ctx.name.is_none());
        assert!(ctx.pit_token.is_none());
        assert!(ctx.out_faces.is_empty());
        assert!(!ctx.cs_hit);
        assert!(!ctx.verified);
        assert!(matches!(ctx.packet, DecodedPacket::Raw));
    }

    #[test]
    fn anymap_insert_get_roundtrip() {
        let mut m = AnyMap::new();
        m.insert(42u32);
        assert_eq!(m.get::<u32>(), Some(&42u32));
        assert!(m.get::<u64>().is_none()); // different type
    }

    #[test]
    fn anymap_insert_overwrite() {
        let mut m = AnyMap::new();
        m.insert(1u32);
        m.insert(2u32);
        assert_eq!(m.get::<u32>(), Some(&2u32));
    }

    #[test]
    fn anymap_remove_takes_value() {
        let mut m = AnyMap::new();
        m.insert(99u32);
        let v = m.remove::<u32>();
        assert_eq!(v, Some(99u32));
        assert!(m.get::<u32>().is_none());
    }

    #[test]
    fn anymap_different_types_coexist() {
        let mut m = AnyMap::new();
        m.insert(1u32);
        m.insert("hello");
        assert_eq!(m.get::<u32>(), Some(&1u32));
        assert_eq!(m.get::<&str>(), Some(&"hello"));
    }

    #[test]
    fn anymap_default_is_empty() {
        let m = AnyMap::default();
        assert!(m.get::<u32>().is_none());
    }
}
