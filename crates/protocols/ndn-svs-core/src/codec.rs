//! SVS v3 wire codec + the pure per-neighbour transition.
//!
//! Used by the ndn-dv one-hop Advertisement Broadcast (`ndnd/dv/SPEC.md` §4):
//! the outgoing state vector always contains only the router itself. Pure data
//! structure — codec + the `(boot, seq)` advance rule. No faces, no signing, no
//! locks, no std.
//!
//! SVS v3 wire format (`ndnd/std/ndn/svs/v3/definitions.go`):
//!
//! ```text
//! SvsData          (0xC9)
//!   StateVector    (0xCA)
//!     StateVectorEntry
//!       Name             (0x07)
//!       SeqNoEntries     (0xD2)
//!         SeqNoEntry
//!           BootstrapTime  (0xD4, NonNegativeInteger)
//!           SeqNo          (0xD6, NonNegativeInteger)
//! ```
//!
//! Receive rule mirrors ndnd's `advert_sync.go`: an entry is stale when
//! `local_boot >= in_boot && local_seq >= in_seq`; otherwise the local view
//! advances and the caller should fetch.

use alloc::vec::Vec;

use bytes::Bytes;
use ndn_packet::{Name, decode_nni, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};
use thiserror::Error;

use crate::tlv::encode_nni;

const T_SVS_DATA: u64 = 0xC9;
const T_STATE_VECTOR: u64 = 0xCA;
const T_SEQ_NO_ENTRIES: u64 = 0xD2;
const T_BOOTSTRAP_TIME: u64 = 0xD4;
const T_SEQ_NO: u64 = 0xD6;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SvsLocalError {
    #[error("malformed SVS v3 SvsData")]
    Malformed,
    #[error("expected SvsData (0xC9), got 0x{got:X}")]
    WrongOuterType { got: u64 },
    #[error("expected StateVector (0xCA), got 0x{got:X}")]
    WrongStateVectorType { got: u64 },
    #[error("StateVectorEntry missing required field: {0}")]
    MissingField(&'static str),
    /// `BootstrapTime` or `SeqNo` had a non-{1,2,4,8} octet width.
    #[error("NonNegativeInteger must be 1/2/4/8 octets")]
    InvalidNniWidth,
}

/// One row of an SVS v3 state vector. In the ndn-dv local variant the
/// outgoing vector has exactly one (self); incoming typically also
/// one (the peer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    pub name: Name,
    pub boot: u64,
    pub seq: u64,
}

/// A neighbour whose `(boot, seq)` just advanced past the local view;
/// caller fetches their Advertisement at `t=<boot>/v=<seq>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborAdvance {
    pub name: Name,
    pub boot: u64,
    pub seq: u64,
}

/// Read-only snapshot; liveness/TTL tracking lives in the caller's
/// higher-level neighbor table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborSnapshot {
    pub name: Name,
    pub boot: u64,
    pub seq: u64,
}

/// A single neighbour's most-recent advertised `(boot, seq)`, and the pure
/// advance rule over it.
///
/// This is the state the SVS v3 self-only variant keeps per peer. The rule is
/// executor-free: ndn-sync's `SvsLocal` holds a `HashMap<Name, NeighborSeqState>`
/// behind a std `RwLock` and delegates the decision here, so the "is this entry
/// newer?" logic lives once, in no_std.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighborSeqState {
    pub boot: u64,
    pub seq: u64,
}

impl NeighborSeqState {
    /// Apply an incoming entry to this neighbour's state. Returns the advance
    /// signal (and updates `self`) iff `(boot, seq)` is strictly newer than
    /// what was known; otherwise leaves `self` unchanged and returns `None`.
    ///
    /// "Strictly newer" = NOT stale, where stale is
    /// `self.boot >= entry.boot && self.seq >= entry.seq` (ndnd's
    /// `advert_sync.go` skip rule).
    pub fn apply(&mut self, entry: &StateEntry) -> Option<NeighborAdvance> {
        let stale = self.boot >= entry.boot && self.seq >= entry.seq;
        if stale {
            None
        } else {
            self.boot = entry.boot;
            self.seq = entry.seq;
            Some(NeighborAdvance {
                name: entry.name.clone(),
                boot: entry.boot,
                seq: entry.seq,
            })
        }
    }
}

/// `SvsData` (0xC9) wrapping one `StateVector` (0xCA). The local
/// variant always passes a one-element slice (self). `StateVectorEntry`
/// has no outer TLV — it's an inline `Name`+`SeqNoEntries` group.
pub fn encode_svs_data(entries: &[StateEntry]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(T_SVS_DATA, |svs| {
        svs.write_nested(T_STATE_VECTOR, |sv| {
            for entry in entries {
                sv.write_raw(&entry.name.encode_to_tlv());
                sv.write_nested(T_SEQ_NO_ENTRIES, |sne| {
                    sne.write_tlv(T_BOOTSTRAP_TIME, &encode_nni(entry.boot));
                    sne.write_tlv(T_SEQ_NO, &encode_nni(entry.seq));
                });
            }
        });
    });
    w.finish()
}

/// Accepts `(BootstrapTime, SeqNo)` in either order inside a
/// `SeqNoEntry` for forward-compat.
pub fn decode_svs_data(bytes: &Bytes) -> Result<Vec<StateEntry>, SvsLocalError> {
    let mut r = TlvReader::new(bytes.clone());
    let (typ, value) = r.read_tlv().map_err(|_| SvsLocalError::Malformed)?;
    if typ != T_SVS_DATA {
        return Err(SvsLocalError::WrongOuterType { got: typ });
    }
    let mut inner = TlvReader::new(value);
    let (sv_typ, sv_value) = inner.read_tlv().map_err(|_| SvsLocalError::Malformed)?;
    if sv_typ != T_STATE_VECTOR {
        return Err(SvsLocalError::WrongStateVectorType { got: sv_typ });
    }

    let mut entries = Vec::new();
    let mut sv = TlvReader::new(sv_value);

    while !sv.is_empty() {
        let (name_typ, name_value) = sv.read_tlv().map_err(|_| SvsLocalError::Malformed)?;
        if name_typ != tlv_type::NAME {
            continue;
        }
        let name = Name::decode(name_value).map_err(|_| SvsLocalError::Malformed)?;

        let (sne_typ, sne_value) = sv
            .read_tlv()
            .map_err(|_| SvsLocalError::MissingField("SeqNoEntries"))?;
        if sne_typ != T_SEQ_NO_ENTRIES {
            return Err(SvsLocalError::MissingField("SeqNoEntries"));
        }
        let (boot, seq) = decode_seq_no_entry(sne_value)?;

        entries.push(StateEntry { name, boot, seq });
    }

    Ok(entries)
}

/// If multiple `SeqNoEntry`s are present the last one wins (the local
/// variant only ever encodes one; matches ndnd).
fn decode_seq_no_entry(value: Bytes) -> Result<(u64, u64), SvsLocalError> {
    let mut r = TlvReader::new(value);
    let mut boot: Option<u64> = None;
    let mut seq: Option<u64> = None;
    while !r.is_empty() {
        let (typ, v) = r.read_tlv().map_err(|_| SvsLocalError::Malformed)?;
        match typ {
            T_BOOTSTRAP_TIME => {
                boot = Some(decode_nni(&v).map_err(|_| SvsLocalError::InvalidNniWidth)?);
            }
            T_SEQ_NO => {
                seq = Some(decode_nni(&v).map_err(|_| SvsLocalError::InvalidNniWidth)?);
            }
            _ => {}
        }
    }
    Ok((
        boot.ok_or(SvsLocalError::MissingField("BootstrapTime"))?,
        seq.ok_or(SvsLocalError::MissingField("SeqNo"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    /// Hand-computed against ndnd/std/ndn/svs/v3/definitions.go for
    /// entry `name=/a, boot=5, seq=99`.
    #[test]
    fn encode_svs_data_byte_level() {
        let entry = StateEntry {
            name: name("/a"),
            boot: 5,
            seq: 99,
        };
        let expected: &[u8] = &[
            0xC9, 0x0F, //                SvsData,           len 15
            0xCA, 0x0D, //                StateVector,       len 13
            0x07, 0x03, //                  Name,            len 3
            0x08, 0x01, 0x61, //              Component 'a'
            0xD2, 0x06, //                  SeqNoEntries,    len 6
            0xD4, 0x01, 0x05, //              BootstrapTime=5
            0xD6, 0x01, 0x63, //              SeqNo=99
        ];
        assert_eq!(&encode_svs_data(&[entry])[..], expected);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let entries = [
            StateEntry {
                name: name("/router/r1"),
                boot: 12345,
                seq: 2,
            },
            StateEntry {
                name: name("/peer"),
                boot: 7,
                seq: 42,
            },
        ];
        let decoded = decode_svs_data(&encode_svs_data(&entries)).unwrap();
        assert_eq!(decoded, entries.to_vec());
    }

    #[test]
    fn decode_rejects_wrong_outer_type() {
        let mut w = TlvWriter::new();
        w.write_tlv(0xAA, &[]);
        let err = decode_svs_data(&w.finish()).unwrap_err();
        assert_eq!(err, SvsLocalError::WrongOuterType { got: 0xAA });
    }

    #[test]
    fn decode_rejects_wrong_state_vector_type() {
        let mut w = TlvWriter::new();
        w.write_nested(T_SVS_DATA, |inner| {
            inner.write_tlv(0xAA, &[]);
        });
        let err = decode_svs_data(&w.finish()).unwrap_err();
        assert_eq!(err, SvsLocalError::WrongStateVectorType { got: 0xAA });
    }

    #[test]
    fn decode_rejects_missing_seq_no_entries() {
        let mut w = TlvWriter::new();
        w.write_nested(T_SVS_DATA, |svs| {
            svs.write_nested(T_STATE_VECTOR, |sv| {
                sv.write_raw(&name("/x").encode_to_tlv());
            });
        });
        let err = decode_svs_data(&w.finish()).unwrap_err();
        assert_eq!(err, SvsLocalError::MissingField("SeqNoEntries"));
    }

    #[test]
    fn decode_rejects_bad_nni_width() {
        let mut w = TlvWriter::new();
        w.write_nested(T_SVS_DATA, |svs| {
            svs.write_nested(T_STATE_VECTOR, |sv| {
                sv.write_raw(&name("/x").encode_to_tlv());
                sv.write_nested(T_SEQ_NO_ENTRIES, |sne| {
                    sne.write_tlv(T_BOOTSTRAP_TIME, &[0x01]);
                    sne.write_tlv(T_SEQ_NO, &[0x01, 0x02, 0x03]);
                });
            });
        });
        let err = decode_svs_data(&w.finish()).unwrap_err();
        assert_eq!(err, SvsLocalError::InvalidNniWidth);
    }

    #[test]
    fn neighbor_seq_state_advance_rule() {
        let mut st = NeighborSeqState::default();
        let adv = st
            .apply(&StateEntry {
                name: name("/peer"),
                boot: 200,
                seq: 1,
            })
            .expect("new neighbour advances");
        assert_eq!((adv.boot, adv.seq), (200, 1));
        assert_eq!(st, NeighborSeqState { boot: 200, seq: 1 });

        // Stale (same boot, lower seq): no advance, no mutation.
        assert!(
            st.apply(&StateEntry {
                name: name("/peer"),
                boot: 200,
                seq: 0,
            })
            .is_none()
        );
        assert_eq!(st, NeighborSeqState { boot: 200, seq: 1 });

        // Higher boot with lower seq is NOT stale — a restart advances.
        let adv = st
            .apply(&StateEntry {
                name: name("/peer"),
                boot: 300,
                seq: 0,
            })
            .expect("higher boot advances");
        assert_eq!((adv.boot, adv.seq), (300, 0));
    }
}
