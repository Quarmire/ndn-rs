use ndn_transport::FaceId;

/// NDN face over Bluetooth Classic (RFCOMM).
///
/// On Linux, a paired RFCOMM channel appears as `/dev/rfcommN`.
/// This face should reuse [`StreamFace`](ndn_transport::StreamFace) with
/// COBS framing, identical to `SerialFace`.
///
/// Throughput up to ~3 Mbps; latency 20–40 ms.
///
/// TODO: implement using `StreamFace<ReadHalf<RfcommStream>, WriteHalf<RfcommStream>, CobsCodec>`
/// once a Tokio-compatible RFCOMM crate is available (e.g. `bluer` or `btleplug`).
pub struct BluetoothFace {
    id: FaceId,
}

impl BluetoothFace {
    pub fn new(id: FaceId) -> Self {
        Self { id }
    }
    pub fn id(&self) -> FaceId {
        self.id
    }
}
