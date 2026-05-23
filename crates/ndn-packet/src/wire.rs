//! Wasm-safe wire helpers used on the forwarding hot path. Factored out of
//! [`encode`](crate::encode) so they compile on `wasm32-unknown-unknown`
//! without pulling in `ring`; signing paths remain gated on `std`.

use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{NackReason, lp::encode_lp_nack, tlv_type};

/// Wrap an Interest in an NDNLPv2 Nack with the given reason.
pub fn encode_nack(reason: NackReason, interest_wire: &[u8]) -> Bytes {
    encode_lp_nack(reason, interest_wire)
}

/// Per NFD Developer Guide §3.4 (outgoing-Interest pipeline), a forwarder MUST
/// add a Nonce to an Interest lacking one before forwarding.
pub fn ensure_nonce(interest_wire: &Bytes) -> Bytes {
    let mut reader = TlvReader::new(interest_wire.clone());
    let Ok((typ, value)) = reader.read_tlv() else {
        return interest_wire.clone();
    };
    if typ != tlv_type::INTEREST {
        return interest_wire.clone();
    }

    let mut inner = TlvReader::new(value.clone());
    while !inner.is_empty() {
        let Ok((t, _)) = inner.read_tlv() else { break };
        if t == tlv_type::NONCE {
            return interest_wire.clone();
        }
    }

    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        let mut inner = TlvReader::new(value);
        let mut name_written = false;
        while !inner.is_empty() {
            let Ok((t, v)) = inner.read_tlv() else { break };
            w.write_tlv(t, &v);
            if !name_written && t == tlv_type::NAME {
                w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
                name_written = true;
            }
        }
        if !name_written {
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
        }
    });
    w.finish()
}

fn next_nonce() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    #[cfg(not(target_arch = "wasm32"))]
    {
        (std::process::id() << 16).wrapping_add(seq)
    }
    #[cfg(target_arch = "wasm32")]
    {
        // No process id on wasm32-unknown-unknown; a per-instance counter is
        // sufficient for the duplicate-nonce loop-detection window.
        seq
    }
}
