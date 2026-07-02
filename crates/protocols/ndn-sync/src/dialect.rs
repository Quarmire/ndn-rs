//! SVS wire dialects (gap #10): one [`WireDialect`] selects the Sync
//! Interest name version and the state-vector codec, behind a single
//! `StateEntry`-based encode/decode interface so the rest of the crate
//! never branches on the format.
//!
//! * **V2** — ndn-svs (C++): flat `StateVectorEntry { Name, SeqNo }`
//!   under `StateVector` (201/202/204); Sync Interest name `<group>/v=2`.
//!   No boot timestamp, so a node that restarts without persistence
//!   relearns its own seq from peers (and historically could be hijacked
//!   — see the authoritative-for-self note in [`crate::svs_sync`]).
//! * **V3** — ndnd (Go): `SeqNoEntry { BootstrapTime, SeqNo }` under
//!   `SvsData`/`StateVector` (0xC9/0xCA/0xD2/0xD4/0xD6); Sync Interest
//!   name `<group>/v=3`. The boot timestamp disambiguates pre- and
//!   post-restart sequence spaces, so restart recovery is automatic.
//!
//! V3 is the better default for *new* deployments; V2 remains the default
//! here so existing groups (and ndn-svs interop) keep their wire. The V3
//! codec is [`crate::svs_local`]'s, reused verbatim — this module just
//! gives both a shared `StateEntry` vocabulary and the `v=N` name rule.

use bytes::{Bytes, BytesMut};

use ndn_packet::Name;

use crate::svs_local::{StateEntry, decode_svs_data, encode_svs_data};
use crate::tlv::{decode_nni, encode_nni, read_tlv, write_tlv};

// V2 (ndn-svs) TLV codes.
const TLV_STATE_VECTOR: u64 = 201;
const TLV_SV_ENTRY: u64 = 202;
const TLV_SV_SEQ_NO: u64 = 204;
const TLV_NDN_NAME: u64 = 7;

/// Which SVS wire format a group speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WireDialect {
    /// ndn-svs v2: flat `(name, seq)`, Sync Interest `<group>/v=2`.
    #[default]
    V2,
    /// ndnd v3: `(name, boot, seq)`, Sync Interest `<group>/v=3`.
    V3,
}

impl WireDialect {
    /// The VERSION component appended after the group prefix in the Sync
    /// Interest name (`appendVersion(2)` for V2, `(3)` for V3).
    pub fn sync_version(self) -> u64 {
        match self {
            WireDialect::V2 => 2,
            WireDialect::V3 => 3,
        }
    }

    /// Encode a state vector. For V2 the `boot` field of each entry is
    /// ignored (the v2 wire has no boot dimension).
    pub fn encode_state_vector(self, entries: &[StateEntry]) -> Bytes {
        match self {
            WireDialect::V2 => encode_v2(entries),
            WireDialect::V3 => encode_svs_data(entries),
        }
    }

    /// Decode a state vector into `StateEntry`s. V2 entries carry
    /// `boot = 0`.
    pub fn decode_state_vector(self, bytes: &Bytes) -> Option<Vec<StateEntry>> {
        let entries = match self {
            WireDialect::V2 => decode_v2(bytes),
            WireDialect::V3 => decode_svs_data(bytes).ok(),
        }?;
        // SY-1: reject an abusively large state vector up front, before it reaches
        // `merge`. (Frame caps already bound a single Interest, so this is
        // defence-in-depth.)
        if entries.len() > crate::svs::MAX_TRACKED_PRODUCERS {
            return None;
        }
        Some(entries)
    }
}

fn encode_name_tlv(name: &Name) -> Vec<u8> {
    let mut inner = BytesMut::new();
    for comp in name.components() {
        write_tlv(&mut inner, comp.typ, &comp.value);
    }
    let mut outer = BytesMut::new();
    write_tlv(&mut outer, TLV_NDN_NAME, &inner);
    outer.to_vec()
}

/// V2 `StateVector` (201) of `StateVectorEntry` (202) = `Name(7) SeqNo(204)`.
fn encode_v2(entries: &[StateEntry]) -> Bytes {
    let mut sv_inner = BytesMut::new();
    for e in entries {
        let name_bytes = encode_name_tlv(&e.name);
        let seq_bytes = encode_nni(e.seq);

        let mut entry_inner = BytesMut::new();
        entry_inner.extend_from_slice(&name_bytes);
        write_tlv(&mut entry_inner, TLV_SV_SEQ_NO, &seq_bytes);

        write_tlv(&mut sv_inner, TLV_SV_ENTRY, &entry_inner);
    }
    let mut buf = BytesMut::new();
    write_tlv(&mut buf, TLV_STATE_VECTOR, &sv_inner);
    buf.freeze()
}

fn decode_v2(bytes: &Bytes) -> Option<Vec<StateEntry>> {
    let (typ, mut body, _) = read_tlv(bytes)?;
    if typ != TLV_STATE_VECTOR {
        return None;
    }
    let mut entries = Vec::new();
    while !body.is_empty() {
        let (entry_typ, entry_body, rest) = read_tlv(body)?;
        body = rest;
        if entry_typ != TLV_SV_ENTRY {
            continue;
        }
        let (name_typ, name_val, after_name) = read_tlv(entry_body)?;
        if name_typ != TLV_NDN_NAME {
            continue;
        }
        let name = Name::decode(Bytes::copy_from_slice(name_val)).ok()?;
        let (seq_typ, seq_val, _) = read_tlv(after_name)?;
        if seq_typ != TLV_SV_SEQ_NO {
            continue;
        }
        entries.push(StateEntry {
            name,
            boot: 0,
            seq: decode_nni(seq_val),
        });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn versions() {
        assert_eq!(WireDialect::V2.sync_version(), 2);
        assert_eq!(WireDialect::V3.sync_version(), 3);
        assert_eq!(WireDialect::default(), WireDialect::V2);
    }

    #[test]
    fn v2_roundtrip_ignores_boot() {
        let entries = vec![
            StateEntry {
                name: n("/a"),
                boot: 999,
                seq: 5,
            },
            StateEntry {
                name: n("/b"),
                boot: 7,
                seq: 12,
            },
        ];
        let wire = WireDialect::V2.encode_state_vector(&entries);
        assert_eq!(wire[0], 0xC9, "V2 StateVector type 201");
        let decoded = WireDialect::V2.decode_state_vector(&wire).expect("decode");
        assert_eq!(decoded.len(), 2);
        // boot is not carried on the v2 wire → comes back 0.
        assert_eq!(
            decoded[0],
            StateEntry {
                name: n("/a"),
                boot: 0,
                seq: 5
            }
        );
        assert_eq!(
            decoded[1],
            StateEntry {
                name: n("/b"),
                boot: 0,
                seq: 12
            }
        );
    }

    #[test]
    fn v3_roundtrip_carries_boot() {
        let entries = vec![StateEntry {
            name: n("/r"),
            boot: 12345,
            seq: 9,
        }];
        let wire = WireDialect::V3.encode_state_vector(&entries);
        assert_eq!(wire[0], 0xC9, "V3 SvsData type 0xC9");
        let decoded = WireDialect::V3.decode_state_vector(&wire).expect("decode");
        assert_eq!(decoded, entries, "v3 preserves boot + seq");
    }

    #[test]
    fn dialects_are_not_cross_decodable() {
        // A V2 vector must not silently decode as V3 (different inner TLVs).
        let v2 = WireDialect::V2.encode_state_vector(&[StateEntry {
            name: n("/x"),
            boot: 0,
            seq: 1,
        }]);
        // Both share outer 0xC9, but the V3 decoder expects 0xCA/0xD2
        // inside; a V2 body (0xCA is StateVector in v3 but contents differ)
        // should fail to produce matching entries.
        let as_v3 = WireDialect::V3.decode_state_vector(&v2);
        assert!(
            as_v3.is_none()
                || as_v3.as_deref()
                    != Some(
                        &[StateEntry {
                            name: n("/x"),
                            boot: 0,
                            seq: 1
                        }][..]
                    ),
            "v2 bytes must not round-trip through the v3 decoder"
        );
    }
}
