use bytes::{Bytes, BytesMut};

use ndn_packet::Name;

/// Default segment size: 8 KiB, well under any NDN MTU.
pub const NDN_DEFAULT_SEGMENT_SIZE: usize = 8192;

/// Segments a large payload into fixed-size chunks for NDN-style chunked transfer.
///
/// Each segment is identified by its zero-based index; the total segment count
/// is available via `segment_count()` for FinalBlockId encoding.
pub struct ChunkedProducer {
    prefix:   Name,
    segments: Vec<Bytes>,
}

impl ChunkedProducer {
    /// Segment `payload` into chunks of at most `segment_size` bytes.
    pub fn new(prefix: Name, payload: Bytes, segment_size: usize) -> Self {
        let seg_size = segment_size.max(1);
        let segments = payload
            .chunks(seg_size)
            .map(|c| Bytes::copy_from_slice(c))
            .collect();
        Self { prefix, segments }
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Return the payload for segment `index`, or `None` if out of range.
    pub fn segment(&self, index: usize) -> Option<&Bytes> {
        self.segments.get(index)
    }
}

/// Reassembles segments produced by `ChunkedProducer` into the original payload.
///
/// Segments may arrive out of order; `receive_segment` inserts each one by
/// index. `reassemble` returns `Some(Bytes)` once all segments are present.
pub struct ChunkedConsumer {
    prefix:        Name,
    segment_count: usize,
    received:      Vec<Option<Bytes>>,
}

impl ChunkedConsumer {
    /// Create a consumer expecting exactly `segment_count` segments.
    pub fn new(prefix: Name, segment_count: usize) -> Self {
        Self {
            prefix,
            segment_count,
            received: vec![None; segment_count],
        }
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Store the payload for `index`.  Out-of-range indices are silently dropped.
    pub fn receive_segment(&mut self, index: usize, payload: Bytes) {
        if index < self.segment_count {
            self.received[index] = Some(payload);
        }
    }

    /// Returns `true` when every segment has been received.
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(Option::is_some)
    }

    /// Concatenate all segments in order.  Returns `None` if incomplete.
    pub fn reassemble(&self) -> Option<Bytes> {
        if !self.is_complete() {
            return None;
        }
        let total: usize = self.received.iter()
            .filter_map(Option::as_ref)
            .map(Bytes::len)
            .sum();
        let mut out = BytesMut::with_capacity(total);
        for seg in &self.received {
            out.extend_from_slice(seg.as_ref().unwrap());
        }
        Some(out.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix() -> Name { Name::root() }

    #[test]
    fn producer_single_segment() {
        let payload = Bytes::from_static(b"hello");
        let p = ChunkedProducer::new(prefix(), payload.clone(), 8192);
        assert_eq!(p.segment_count(), 1);
        assert_eq!(p.segment(0).unwrap(), &payload);
    }

    #[test]
    fn producer_multiple_segments() {
        let payload = Bytes::from(vec![0u8; 100]);
        let p = ChunkedProducer::new(prefix(), payload, 30);
        // ceil(100 / 30) = 4
        assert_eq!(p.segment_count(), 4);
        assert_eq!(p.segment(0).unwrap().len(), 30);
        assert_eq!(p.segment(3).unwrap().len(), 10);
    }

    #[test]
    fn producer_out_of_range_returns_none() {
        let p = ChunkedProducer::new(prefix(), Bytes::from_static(b"x"), 8192);
        assert!(p.segment(1).is_none());
    }

    #[test]
    fn consumer_reassembles_in_order() {
        let payload = Bytes::from_static(b"hello world");
        let p = ChunkedProducer::new(prefix(), payload.clone(), 5);
        let mut c = ChunkedConsumer::new(prefix(), p.segment_count());
        for i in 0..p.segment_count() {
            c.receive_segment(i, p.segment(i).unwrap().clone());
        }
        assert!(c.is_complete());
        assert_eq!(c.reassemble().unwrap(), payload);
    }

    #[test]
    fn consumer_reassembles_out_of_order() {
        let payload = Bytes::from(b"abcde".repeat(2).to_vec());
        let p = ChunkedProducer::new(prefix(), payload.clone(), 5);
        let mut c = ChunkedConsumer::new(prefix(), p.segment_count());
        // receive segment 1 first
        c.receive_segment(1, p.segment(1).unwrap().clone());
        assert!(!c.is_complete());
        c.receive_segment(0, p.segment(0).unwrap().clone());
        assert!(c.is_complete());
        assert_eq!(c.reassemble().unwrap(), payload);
    }

    #[test]
    fn consumer_incomplete_reassemble_returns_none() {
        let mut c = ChunkedConsumer::new(prefix(), 3);
        c.receive_segment(0, Bytes::from_static(b"a"));
        assert!(!c.is_complete());
        assert!(c.reassemble().is_none());
    }

    #[test]
    fn consumer_ignores_out_of_range_segment() {
        let mut c = ChunkedConsumer::new(prefix(), 2);
        c.receive_segment(99, Bytes::from_static(b"x")); // out of range, no panic
        assert!(!c.is_complete());
    }
}
