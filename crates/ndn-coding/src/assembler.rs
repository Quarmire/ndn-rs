//! Consumer-side reassembly: feed received Data Content bodies in any order
//! and recover the original payload once the decoder reaches rank `K`.

use bytes::{BufMut, Bytes, BytesMut};

use crate::fec::Decoder;
use crate::metadata::{FecMetadata, split_metadata};
use crate::{CodingError, Result};

/// F1 reassembly; construct one per fetched object/generation.
#[derive(Default)]
pub struct CodedAssembler {
    state: Option<State>,
}

struct State {
    decoder: Decoder,
    k: u16,
    n: u16,
    generation_id: u64,
    padding_len: Option<u32>,
}

impl CodedAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_complete(&self) -> bool {
        self.state
            .as_ref()
            .map(|s| s.decoder.is_complete())
            .unwrap_or(false)
    }

    pub fn rank(&self) -> u16 {
        self.state.as_ref().map(|s| s.decoder.rank()).unwrap_or(0)
    }

    pub fn k(&self) -> Option<u16> {
        self.state.as_ref().map(|s| s.k)
    }

    pub fn n(&self) -> Option<u16> {
        self.state.as_ref().map(|s| s.n)
    }

    /// Absorb a segment's full `Content` (metadata prefix + row bytes).
    /// Returns `Ok(Some(payload))` once rank reaches `K`. Errors with
    /// `MalformedMetadata` if a later segment disagrees on
    /// `(generation_id, k, n)`.
    pub fn absorb_content(&mut self, content: &[u8]) -> Result<Option<Bytes>> {
        let (meta, payload) = split_metadata(content)?;
        self.ensure_state(&meta)?;
        let state = self
            .state
            .as_mut()
            .expect("ensure_state guarantees Some(state)");
        state.decoder.absorb(meta.index, payload)?;
        if state.decoder.is_complete() {
            Ok(Some(Self::recover_payload(state)?))
        } else {
            Ok(None)
        }
    }

    fn ensure_state(&mut self, meta: &FecMetadata) -> Result<()> {
        if let Some(state) = &self.state {
            if state.generation_id != meta.generation_id || state.k != meta.k || state.n != meta.n {
                return Err(CodingError::MalformedMetadata);
            }
        } else {
            self.state = Some(State {
                decoder: Decoder::new(meta.k, meta.n)?,
                k: meta.k,
                n: meta.n,
                generation_id: meta.generation_id,
                padding_len: meta.padding_len,
            });
        }
        Ok(())
    }

    fn recover_payload(state: &mut State) -> Result<Bytes> {
        let sources = state.decoder.recover()?;
        let total: usize = sources.iter().map(|s| s.len()).sum();
        let mut buf = BytesMut::with_capacity(total);
        for s in &sources {
            buf.put_slice(s);
        }
        let pad = state.padding_len.unwrap_or(0) as usize;
        if pad >= buf.len() {
            // Padding claims to cover everything; return an empty payload
            // rather than panicking.
            return Ok(Bytes::new());
        }
        buf.truncate(buf.len() - pad);
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FecPolicy, Field};
    use crate::segmenter::segment_payload;

    fn policy(k: u16, n: u16) -> FecPolicy {
        FecPolicy {
            k,
            n,
            field: Field::Gf8,
        }
    }

    #[test]
    fn round_trip_no_loss() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let plan = segment_payload(payload, &policy(4, 6), 1).unwrap();
        let mut asm = CodedAssembler::new();
        let mut recovered: Option<Bytes> = None;
        // K source segments alone are enough; parity never enters the decoder.
        for s in plan.iter().take(4) {
            recovered = asm.absorb_content(&s.content).unwrap();
            if recovered.is_some() {
                break;
            }
        }
        let recovered = recovered.expect("decoder completed");
        assert_eq!(recovered.as_ref(), payload);
    }

    #[test]
    fn round_trip_with_losses() {
        let payload: Vec<u8> = (0..512).map(|i| (i & 0xff) as u8).collect();
        let plan = segment_payload(&payload, &policy(8, 12), 1).unwrap();
        let mut asm = CodedAssembler::new();
        let lost = [1u16, 4, 6];
        let mut recovered: Option<Bytes> = None;
        for s in &plan {
            if lost.contains(&s.index) {
                continue;
            }
            recovered = asm.absorb_content(&s.content).unwrap();
            if recovered.is_some() {
                break;
            }
        }
        let recovered = recovered.expect("decoder completed");
        assert_eq!(recovered.as_ref(), payload.as_slice());
    }

    #[test]
    fn short_payload_with_padding() {
        let payload = b"abc";
        let plan = segment_payload(payload, &policy(4, 5), 1).unwrap();
        let mut asm = CodedAssembler::new();
        let mut recovered: Option<Bytes> = None;
        for s in plan.iter().take(4) {
            recovered = asm.absorb_content(&s.content).unwrap();
            if recovered.is_some() {
                break;
            }
        }
        assert_eq!(recovered.unwrap().as_ref(), payload);
    }

    #[test]
    fn rejects_metadata_disagreement() {
        let payload = vec![0xAAu8; 64];
        let plan_a = segment_payload(&payload, &policy(4, 6), 1).unwrap();
        let plan_b = segment_payload(&payload, &policy(4, 6), 2).unwrap();
        let mut asm = CodedAssembler::new();
        asm.absorb_content(&plan_a[0].content).unwrap();
        let err = asm.absorb_content(&plan_b[1].content);
        assert!(matches!(err, Err(CodingError::MalformedMetadata)));
    }
}
