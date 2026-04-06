//! `SimLink` — a configurable simulated link between two faces.
//!
//! Creates a bidirectional link with delay, loss, bandwidth, and jitter.

use std::time::Duration;

use ndn_transport::FaceId;

use crate::sim_face::SimFace;

/// Link properties for a simulated connection.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    /// Base one-way propagation delay.
    pub delay: Duration,
    /// Random jitter added to each packet's delay (uniform in `[0, jitter]`).
    pub jitter: Duration,
    /// Packet loss rate (0.0 = no loss, 1.0 = all packets dropped).
    pub loss_rate: f64,
    /// Link bandwidth in bits per second. `0` means unlimited.
    pub bandwidth_bps: u64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss_rate: 0.0,
            bandwidth_bps: 0,
        }
    }
}

impl LinkConfig {
    /// Lossless, zero-delay link (in-process direct connection).
    pub fn direct() -> Self {
        Self::default()
    }

    /// Typical LAN link: 1ms delay, no loss, 1 Gbps.
    pub fn lan() -> Self {
        Self {
            delay: Duration::from_millis(1),
            jitter: Duration::from_micros(100),
            loss_rate: 0.0,
            bandwidth_bps: 1_000_000_000,
        }
    }

    /// Typical WiFi link: 5ms delay, 1% loss, 54 Mbps.
    pub fn wifi() -> Self {
        Self {
            delay: Duration::from_millis(5),
            jitter: Duration::from_millis(2),
            loss_rate: 0.01,
            bandwidth_bps: 54_000_000,
        }
    }

    /// WAN link: 50ms delay, 0.1% loss, 100 Mbps.
    pub fn wan() -> Self {
        Self {
            delay: Duration::from_millis(50),
            jitter: Duration::from_millis(5),
            loss_rate: 0.001,
            bandwidth_bps: 100_000_000,
        }
    }

    /// Lossy wireless link: 10ms delay, 5% loss, 11 Mbps.
    pub fn lossy_wireless() -> Self {
        Self {
            delay: Duration::from_millis(10),
            jitter: Duration::from_millis(5),
            loss_rate: 0.05,
            bandwidth_bps: 11_000_000,
        }
    }
}

/// A simulated bidirectional link between two faces.
pub struct SimLink;

impl SimLink {
    /// Create a pair of connected `SimFace`s with the given link properties.
    ///
    /// Packets sent on `face_a` arrive at `face_b` (and vice versa) after
    /// the configured delay, subject to loss and bandwidth constraints.
    ///
    /// The same `LinkConfig` is applied in both directions. For asymmetric
    /// links, use [`pair_asymmetric`](Self::pair_asymmetric).
    ///
    /// ```rust,no_run
    /// # use ndn_sim::{SimLink, LinkConfig};
    /// # use ndn_transport::FaceId;
    /// let (face_a, face_b) = SimLink::pair(
    ///     FaceId(10), FaceId(11),
    ///     LinkConfig::wifi(),
    ///     128,  // channel buffer size
    /// );
    /// ```
    pub fn pair(
        id_a: FaceId,
        id_b: FaceId,
        config: LinkConfig,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        Self::pair_asymmetric(id_a, id_b, config.clone(), config, buffer)
    }

    /// Create a pair with different link properties per direction.
    ///
    /// `config_a_to_b` is applied when `face_a` sends to `face_b`;
    /// `config_b_to_a` is applied when `face_b` sends to `face_a`.
    pub fn pair_asymmetric(
        id_a: FaceId,
        id_b: FaceId,
        config_a_to_b: LinkConfig,
        config_b_to_a: LinkConfig,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(buffer);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(buffer);

        // face_a sends through config_a_to_b into rx_b (received by face_b)
        // face_b sends through config_b_to_a into rx_a (received by face_a)
        let face_a = SimFace::new(id_a, tx_b, rx_a, config_a_to_b);
        let face_b = SimFace::new(id_b, tx_a, rx_b, config_b_to_a);

        (face_a, face_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::Face;

    #[tokio::test]
    async fn direct_link_delivers_packet() {
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), LinkConfig::direct(), 16);

        let payload = bytes::Bytes::from_static(b"hello");
        face_a.send(payload.clone()).await.unwrap();

        let received = face_b.recv().await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn bidirectional_delivery() {
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), LinkConfig::direct(), 16);

        face_a
            .send(bytes::Bytes::from_static(b"ping"))
            .await
            .unwrap();
        face_b
            .send(bytes::Bytes::from_static(b"pong"))
            .await
            .unwrap();

        let at_b = face_b.recv().await.unwrap();
        let at_a = face_a.recv().await.unwrap();
        assert_eq!(at_b, &b"ping"[..]);
        assert_eq!(at_a, &b"pong"[..]);
    }

    #[tokio::test]
    async fn delayed_link() {
        let config = LinkConfig {
            delay: Duration::from_millis(50),
            ..Default::default()
        };
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), config, 16);

        let start = tokio::time::Instant::now();
        face_a.send(bytes::Bytes::from_static(b"hi")).await.unwrap();
        let _received = face_b.recv().await.unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(45),
            "expected ~50ms delay, got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn lossy_link_drops_some_packets() {
        let config = LinkConfig {
            loss_rate: 1.0, // drop everything
            ..Default::default()
        };
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), config, 16);

        for _ in 0..10 {
            face_a.send(bytes::Bytes::from_static(b"x")).await.unwrap();
        }

        // With 100% loss, nothing should arrive. Use a short timeout.
        let result = tokio::time::timeout(Duration::from_millis(100), face_b.recv()).await;
        assert!(result.is_err(), "expected timeout with 100% loss");
    }
}
