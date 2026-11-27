//! The limits of the channel frame codec (channel.md, Limits).
//!
//! Each constant is enforced where the codec is: the writer refuses to build
//! what a receiver would refuse, and a receiver refuses what the writer would
//! never build.

pub(crate) use ndn_transport::side_header::MIN_FRAME_LEN;
use ndn_transport::side_header::STREAM_FRAME_GRANT;

/// Octets of a sealed frame's header: marker, version/class/kind, channel id
/// (8), key epoch (1), `seq0` (8), `count` (1).
pub(crate) const HEADER_LEN: usize = 20;

/// Octets of the AEAD tag that ends a sealed frame.
pub(crate) const TAG_LEN: usize = 16;

/// The octets a sealed frame adds to its plaintext: 36.
pub(crate) const FRAME_OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// The most messages one `DATA` frame carries.
pub(crate) const MESSAGES_PER_FRAME: usize = 255;

/// The most octets a message's name may have (the Name TLV's value).
pub(crate) const NAME_MAX: usize = 255;

/// The most names (ids 1 to this) one channel carries.
pub(crate) const NAMES_PER_CHANNEL: u64 = 4_096;

/// Sequences are below this: 2^63. A channel that reaches it is re-keyed
/// before, never wrapped, because a (key, nonce) pair must not repeat.
pub(crate) const SEQUENCE_LIMIT: u64 = 1 << 63;

/// The largest message payload a session may allow: 16 MiB.
pub(crate) const MESSAGE_MAX: usize = 16 << 20;

/// The largest message payload when a session says nothing: what fits one
/// stream frame of [`STREAM_FRAME_DEFAULT`] (the grant of the faces,
/// [`STREAM_FRAME_GRANT`]) once the frame's and the message's headers are
/// taken off ([`MESSAGE_FRAME_SLACK`]): 1 MiB − 1 KiB. Derived, not a second
/// number, so a message at the limit is never refused by a face.
pub(crate) const MESSAGE_DEFAULT: usize = message_limit_for(STREAM_FRAME_DEFAULT);

/// The octets the longest message header takes: flags (1), original sequence
/// (8), name id (2: ids are at most 4,096), name length (2), name (255), stand
/// seconds (8), payload length (4: payloads are at most 16 MiB).
pub(crate) const MESSAGE_OVERHEAD_MAX: usize = 1 + 8 + 2 + 2 + NAME_MAX + 8 + 4;

/// Room a stream frame has beyond its message limit, so a message of the
/// largest allowed payload fits one frame with its header and the frame's:
/// at least [`FRAME_OVERHEAD`] + [`MESSAGE_OVERHEAD_MAX`].
pub(crate) const MESSAGE_FRAME_SLACK: usize = 1_024;

const _: () = assert!(MESSAGE_FRAME_SLACK >= FRAME_OVERHEAD + MESSAGE_OVERHEAD_MAX);

/// The largest stream frame a session may grant: 16 MiB of payload plus
/// [`MESSAGE_FRAME_SLACK`]. A frame is measured whole (header, body, tag).
pub(crate) const STREAM_FRAME_MAX: usize = MESSAGE_MAX + MESSAGE_FRAME_SLACK;

/// The stream frame limit when a session says nothing: the stream frame a
/// face grants by default, 1 MiB ([`STREAM_FRAME_GRANT`]).
pub(crate) const STREAM_FRAME_DEFAULT: usize = STREAM_FRAME_GRANT;

/// The message payload limit that fits a frame limit: a message must fit one
/// stream frame, so the payload is at most the frame's room less the longest
/// message header. At most [`MESSAGE_MAX`].
pub(crate) const fn message_limit_for(frame_limit: usize) -> usize {
    let room = frame_limit.saturating_sub(MESSAGE_FRAME_SLACK);
    if room > MESSAGE_MAX {
        MESSAGE_MAX
    } else {
        room
    }
}

/// The datagram frame limit: `min(max_datagram_size, S_FRAME_MAX)`, at most
/// [`STREAM_FRAME_MAX`]. The carrier tells the codec the first (it changes with the path), the
/// session the second. A limit below [`MIN_FRAME_LEN`] is returned as it is: no frame fits it
/// (a carrier whose datagrams are smaller carries no channel frames), and the writer refuses it.
pub(crate) const fn datagram_limit(max_datagram_size: usize, session_frame_max: usize) -> usize {
    let limit = if max_datagram_size < session_frame_max {
        max_datagram_size
    } else {
        session_frame_max
    };
    if limit > STREAM_FRAME_MAX {
        STREAM_FRAME_MAX
    } else {
        limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_of_the_largest_payload_fits_a_frame_of_the_default_and_the_maximum_limit() {
        assert_eq!(message_limit_for(STREAM_FRAME_DEFAULT), MESSAGE_DEFAULT);
        assert_eq!(message_limit_for(STREAM_FRAME_MAX), MESSAGE_MAX);
        assert_eq!(message_limit_for(STREAM_FRAME_MAX * 2), MESSAGE_MAX);
        assert_eq!(message_limit_for(10), 0);
    }

    #[test]
    fn the_datagram_limit_is_the_smaller_of_the_path_and_the_session() {
        assert_eq!(datagram_limit(1_200, 9_000), 1_200);
        assert_eq!(datagram_limit(65_000, 9_000), 9_000);
        assert_eq!(datagram_limit(usize::MAX, usize::MAX), STREAM_FRAME_MAX);
    }
}
