/// Segments large payloads into NDN-MTU-sized Data packets and publishes them.
pub struct ChunkedProducer;

/// Reassembles segmented Data packets into the original payload.
pub struct ChunkedConsumer;
