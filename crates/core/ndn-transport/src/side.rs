//! The side path: frames that are **not NDN packets** and travel on a face.
//!
//! A *side frame* is marked by a first octet of [`SIDE_MARKER`] (`0x00`).
//! TLV-TYPE 0 is not assigned, so no Interest, Data, Nack or NDNLPv2 packet
//! starts with it (see `ndn_packet`'s decoders). A face carries side frames
//! with [`Face::send_side`](crate::Face::send_side), which reaches the
//! transport **without** the link service: no LP header, no fragmentation, no
//! reliability, no scope judge. The receiving link service returns a marked
//! frame unchanged, and the engine's face reader peels it before the NDN
//! pipeline.
//!
//! The transport layer knows nothing about what a side frame holds, and does
//! not delimit it: Ethernet pads a payload under 46 octets and a receiver sees
//! the padding, so a side frame on an Ethernet face must be self-delimiting or
//! at least 46 octets (the stage-3 channel codec is bound by this).

use crate::face::FaceError;

/// First octet of a side frame. Never the first octet of an NDN packet.
pub const SIDE_MARKER: u8 = 0x00;

/// Which carrier a side frame asks for.
///
/// A transport with one kind of delivery (a raw L2 or radio frame, a ring)
/// ignores the class; a transport with both (QUIC: datagram and stream)
/// routes on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SideClass {
    /// Unreliable, unordered, one frame per carrier packet.
    Datagram,
    /// Reliable and ordered, flow-controlled.
    Stream,
}

/// Why a side frame was not sent. Every refusal is final for that frame; the
/// face is unaffected unless the variant is [`Closed`](SideRefused::Closed).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SideRefused {
    /// The frame is longer than the carrier accepts. Side frames are never
    /// fragmented.
    #[error("side frame of {size} octets exceeds the carrier maximum of {max}")]
    TooLarge { size: usize, max: usize },
    /// The peer did not advertise channel capability.
    #[error("the peer did not advertise channel capability")]
    PeerLacksChannels,
    /// This face or link carries no side frames (a policy decided before any
    /// verdict on the frame).
    #[error("this face carries no side frames")]
    NotCarried,
    /// `forward_side` on a transport with no non-blocking path.
    #[error("this transport has no non-blocking side path")]
    Unsupported,
    /// `forward_side`: the bounded queue or send buffer has no room.
    #[error("side send buffer full")]
    Full,
    /// The face is closed.
    #[error("face closed")]
    Closed,
    /// An I/O error from the carrier.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<FaceError> for SideRefused {
    fn from(e: FaceError) -> Self {
        match e {
            FaceError::Closed => SideRefused::Closed,
            FaceError::Full => SideRefused::Full,
            FaceError::Io(e) => SideRefused::Io(e.to_string()),
            e @ FaceError::NoFactory(_) => SideRefused::Io(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_face_error_maps_to_its_side_refusal() {
        assert_eq!(SideRefused::from(FaceError::Closed), SideRefused::Closed);
        assert_eq!(SideRefused::from(FaceError::Full), SideRefused::Full);
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone");
        assert_eq!(
            SideRefused::from(FaceError::Io(io)),
            SideRefused::Io("gone".to_string())
        );
        assert!(matches!(
            SideRefused::from(FaceError::NoFactory(crate::FaceKind::Shm)),
            SideRefused::Io(_)
        ));
    }

    #[test]
    fn the_marker_is_the_unassigned_tlv_type_zero() {
        assert_eq!(SIDE_MARKER, 0x00);
    }

    /// The marker is TLV-TYPE 0, which no NDN decoder accepts: a side frame is
    /// never read as an Interest, a Data, a Nack or an LP packet, and the
    /// first octet of every real NDN packet is something else.
    #[test]
    fn ndn_decoding_rejects_tlv_type_zero_and_the_marker() {
        use bytes::Bytes;
        use ndn_packet::encode::{DataBuilder, encode_interest};
        use ndn_packet::lp::is_lp_packet;
        use ndn_packet::{Data, Interest, LpPacket, Nack, Name};

        let mut frames: Vec<Bytes> = vec![
            // Just the marker, and a well-formed TLV of type 0.
            Bytes::from_static(&[SIDE_MARKER]),
            Bytes::from_static(&[SIDE_MARKER, 0x00]),
            Bytes::from_static(&[SIDE_MARKER, 0x03, 1, 2, 3]),
            // A channel-frame-shaped record (marker, ver/class/kind, id, ...).
            Bytes::from([&[SIDE_MARKER, 0x20][..], &[0x11; 38]].concat()),
        ];
        // A real packet's body behind the marker is still not an NDN packet.
        let name: Name = "/a/b".parse().unwrap();
        let interest = encode_interest(&name, None);
        let data = DataBuilder::new(name, b"x").build();
        for pkt in [&interest, &data, &ndn_packet::encode_lp_packet(&interest)] {
            let mut v = vec![SIDE_MARKER];
            v.extend_from_slice(pkt);
            frames.push(Bytes::from(v));
        }

        for f in frames {
            assert!(Interest::decode(f.clone()).is_err(), "Interest: {f:02x?}");
            assert!(Data::decode(f.clone()).is_err(), "Data: {f:02x?}");
            assert!(Nack::decode(f.clone()).is_err(), "Nack: {f:02x?}");
            assert!(LpPacket::decode(f.clone()).is_err(), "LpPacket: {f:02x?}");
            assert!(!is_lp_packet(&f), "is_lp_packet: {f:02x?}");
        }

        // And no NDN packet starts with the marker.
        for first in [
            interest[0],
            data[0],
            ndn_packet::encode_lp_packet(&interest)[0],
        ] {
            assert_ne!(first, SIDE_MARKER);
        }
    }
}
