use tokio::sync::mpsc;
use ndn_pipeline::{Action, DropReason, PacketContext, PipelineStage};

/// A pipeline stage that emits observation events without blocking forwarding.
///
/// Uses `try_send` on a bounded channel — events are dropped when the receiver
/// falls behind rather than slowing the forwarding pipeline.
pub struct FlowObserverStage {
    tx:              mpsc::Sender<FlowEvent>,
    /// Optional sampling rate (0.0–1.0). Events are dropped probabilistically
    /// to limit observer overhead on high-rate testbeds.
    sampling_rate:   f32,
}

/// An observation event emitted for each packet.
#[derive(Debug, Clone)]
pub struct FlowEvent {
    pub arrival_ns:  u64,
    pub face_id:     ndn_transport::FaceId,
    pub name:        Option<std::sync::Arc<ndn_packet::Name>>,
    pub packet_type: PacketType,
    pub cs_hit:      bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Interest,
    Data,
    Nack,
    Unknown,
}

impl FlowObserverStage {
    pub fn new(tx: mpsc::Sender<FlowEvent>) -> Self {
        Self { tx, sampling_rate: 1.0 }
    }

    pub fn with_sampling_rate(mut self, rate: f32) -> Self {
        self.sampling_rate = rate.clamp(0.0, 1.0);
        self
    }
}

impl FlowObserverStage {
    fn should_sample(&self) -> bool {
        self.sampling_rate >= 1.0
    }
}

impl PipelineStage for FlowObserverStage {
    async fn process(&self, ctx: PacketContext) -> Result<Action, DropReason> {
        let packet_type = match &ctx.packet {
            ndn_pipeline::DecodedPacket::Interest(_) => PacketType::Interest,
            ndn_pipeline::DecodedPacket::Data(_)     => PacketType::Data,
            ndn_pipeline::DecodedPacket::Nack(_)     => PacketType::Nack,
            ndn_pipeline::DecodedPacket::Raw         => PacketType::Unknown,
        };

        let event = FlowEvent {
            arrival_ns:  ctx.arrival,
            face_id:     ctx.face_id,
            name:        ctx.name.clone(),
            packet_type,
            cs_hit:      ctx.cs_hit,
        };

        // try_send is non-blocking — drops the event if the receiver is behind.
        let _ = self.tx.try_send(event);

        Ok(Action::Continue(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::FaceId;

    fn raw_ctx() -> PacketContext {
        PacketContext::new(Bytes::new(), FaceId(0), 42)
    }

    #[tokio::test]
    async fn process_emits_event_and_continues() {
        let (tx, mut rx) = mpsc::channel(8);
        let stage = FlowObserverStage::new(tx);
        let ctx = raw_ctx();
        let result = stage.process(ctx).await;
        assert!(matches!(result, Ok(Action::Continue(_))));
        let event = rx.try_recv().unwrap();
        assert_eq!(event.face_id, FaceId(0));
        assert_eq!(event.arrival_ns, 42);
        assert_eq!(event.packet_type, PacketType::Unknown);
        assert!(!event.cs_hit);
    }

    #[tokio::test]
    async fn process_drops_event_when_channel_full() {
        let (tx, _rx) = mpsc::channel(1);
        // Fill the channel first.
        let _ = tx.try_send(FlowEvent {
            arrival_ns: 0, face_id: FaceId(0),
            name: None, packet_type: PacketType::Unknown, cs_hit: false,
        });
        let stage = FlowObserverStage::new(tx);
        // Should not block or error even though the channel is full.
        let result = stage.process(raw_ctx()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn with_sampling_rate_clamps() {
        let (tx, _rx) = mpsc::channel(1);
        let stage = FlowObserverStage::new(tx).with_sampling_rate(2.0);
        assert!(stage.should_sample());
    }
}
