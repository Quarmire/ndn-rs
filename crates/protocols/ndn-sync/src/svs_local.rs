//! SVS v3 local variant for one-hop Advertisement Broadcast (used by
//! ndn-dv per `~/Documents/Dev/ndnd/dv/SPEC.md` §4): the outgoing
//! state vector always contains only the router itself. Pure data
//! structure — codec + per-neighbour `(boot, seq)` tracking with
//! advance detection. No faces, no signing.
//!
//! SVS v3 wire format
//! (`~/Documents/Dev/ndnd/std/ndn/svs/v3/definitions.go`):
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
//! Receive rule mirrors ndnd's `advert_sync.go`: an entry is stale
//! when `local_boot >= in_boot && local_seq >= in_seq`; otherwise the
//! local view advances and the caller should fetch.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_packet::Name;

// Codec + wire types moved to the no_std `ndn_svs_core::codec`. They stay
// reachable as `crate::svs_local::*` (lib.rs re-exports several of them) so no
// import path changed. `SvsLocal` — the std-locked, `AtomicU64`-seq wrapper —
// stays here and delegates the codec and the per-neighbour advance rule to the
// core.
use ndn_svs_core::codec::NeighborSeqState;
pub use ndn_svs_core::codec::{
    NeighborAdvance, NeighborSnapshot, StateEntry, SvsLocalError, decode_svs_data, encode_svs_data,
};

/// Tracks this node's own `(boot, seq)` and each peer's most-recent
/// advertised `(boot, seq)`. Decoding an incoming Sync Interest's
/// state vector produces the neighbours whose advertisements should
/// be fetched.
pub struct SvsLocal {
    self_name: Name,
    boot: u64,
    seq: AtomicU64,
    neighbors: RwLock<HashMap<Name, NeighborSeqState>>,
}

impl SvsLocal {
    /// `boot` is the router's startup time in milliseconds since the
    /// Unix epoch (ndn-dv SPEC §2). Sequence starts at zero; advance
    /// via [`Self::advance_seq`].
    pub fn new(self_name: Name, boot: u64) -> Self {
        Self {
            self_name,
            boot,
            seq: AtomicU64::new(0),
            neighbors: RwLock::new(HashMap::new()),
        }
    }

    pub fn self_name(&self) -> &Name {
        &self.self_name
    }

    pub fn boot(&self) -> u64 {
        self.boot
    }

    pub fn current_seq(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Call when the locally-published advertisement changes.
    pub fn advance_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Self-only outgoing state vector per ndn-dv SPEC §4.
    pub fn encode_self_state_vector(&self) -> Bytes {
        let entry = StateEntry {
            name: self.self_name.clone(),
            boot: self.boot,
            seq: self.current_seq(),
        };
        encode_svs_data(&[entry])
    }

    /// Build the **full** outgoing state vector — self plus every
    /// tracked neighbour with their last-seen `(boot, seq)`. This is
    /// canonical SVS semantics, used by the ndn-dv Prefix Sync group
    /// (SPEC.md §4 *Prefix Sync*) and any other multi-peer SVS
    /// deployment.
    ///
    /// Output order is `[self, neighbour_1, neighbour_2, ...]` with
    /// neighbours sorted lexicographically by name for byte-stable
    /// output (NDN doesn't require ordering, but stable bytes make
    /// equality tests and diagnostics easier).
    pub fn encode_full_state_vector(&self) -> Bytes {
        let neighbors = self
            .neighbors
            .read()
            .expect("SvsLocal::neighbors RwLock poisoned");
        let mut entries = Vec::with_capacity(1 + neighbors.len());
        entries.push(StateEntry {
            name: self.self_name.clone(),
            boot: self.boot,
            seq: self.current_seq(),
        });
        let mut peer_entries: Vec<StateEntry> = neighbors
            .iter()
            .map(|(name, state)| StateEntry {
                name: name.clone(),
                boot: state.boot,
                seq: state.seq,
            })
            .collect();
        peer_entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries.extend(peer_entries);
        encode_svs_data(&entries)
    }

    /// Decode an incoming SVS v3 state vector and update neighbour
    /// state. Returns the entries that advanced past what the local
    /// view had — caller should fetch each.
    ///
    /// Entries whose `(boot, seq)` is not strictly newer than the
    /// local view are ignored (matches ndnd's
    /// `advert_sync.go` `onStateVector` skip rule).
    /// Entries referring to `self_name` are ignored.
    pub fn process_sync(&self, bytes: &Bytes) -> Result<Vec<NeighborAdvance>, SvsLocalError> {
        let entries = decode_svs_data(bytes)?;
        Ok(entries.iter().filter_map(|e| self.apply_entry(e)).collect())
    }

    /// Apply a single decoded state-vector entry to the local view,
    /// returning the advance signal if `(boot, seq)` is strictly newer
    /// than what was previously known for that neighbour. Entries
    /// naming this node are silently ignored.
    ///
    /// Useful when the caller has already decoded the state vector
    /// (e.g. to interleave face-tracking with seq-tracking).
    pub fn apply_entry(&self, entry: &StateEntry) -> Option<NeighborAdvance> {
        if entry.name == self.self_name {
            return None;
        }
        let mut neighbors = self
            .neighbors
            .write()
            .expect("SvsLocal::neighbors RwLock poisoned");
        // The advance rule (stale vs. strictly-newer) is the pure no_std
        // `NeighborSeqState::apply`; this wrapper only owns the lock.
        neighbors
            .entry(entry.name.clone())
            .or_default()
            .apply(entry)
    }

    pub fn neighbor(&self, name: &Name) -> Option<NeighborSnapshot> {
        let neighbors = self
            .neighbors
            .read()
            .expect("SvsLocal::neighbors RwLock poisoned");
        neighbors.get(name).map(|s| NeighborSnapshot {
            name: name.clone(),
            boot: s.boot,
            seq: s.seq,
        })
    }

    pub fn neighbors(&self) -> Vec<NeighborSnapshot> {
        let neighbors = self
            .neighbors
            .read()
            .expect("SvsLocal::neighbors RwLock poisoned");
        neighbors
            .iter()
            .map(|(n, s)| NeighborSnapshot {
                name: n.clone(),
                boot: s.boot,
                seq: s.seq,
            })
            .collect()
    }
}

// `encode_svs_data` / `decode_svs_data` (and the private `decode_seq_no_entry`)
// moved verbatim to the no_std `ndn_svs_core::codec` and are re-exported at the
// top of this module, so `crate::svs_local::{encode,decode}_svs_data` and the
// `lib.rs` re-exports resolve unchanged.

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    #[test]
    fn encode_self_state_vector_roundtrip() {
        let svs = SvsLocal::new(name("/router/r1"), 12345);
        svs.advance_seq();
        svs.advance_seq();
        let bytes = svs.encode_self_state_vector();
        let decoded = decode_svs_data(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, name("/router/r1"));
        assert_eq!(decoded[0].boot, 12345);
        assert_eq!(decoded[0].seq, 2);
    }

    #[test]
    fn encode_full_state_vector_with_no_neighbors() {
        let svs = SvsLocal::new(name("/r"), 100);
        svs.advance_seq();
        let self_only = svs.encode_self_state_vector();
        let full = svs.encode_full_state_vector();
        assert_eq!(&self_only[..], &full[..]);
    }

    #[test]
    fn encode_full_state_vector_includes_self_and_peers() {
        let svs = SvsLocal::new(name("/me"), 100);
        svs.advance_seq();
        let _ = svs
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/peer-b"),
                boot: 50,
                seq: 7,
            }]))
            .unwrap();
        let _ = svs
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/peer-a"),
                boot: 60,
                seq: 3,
            }]))
            .unwrap();

        let bytes = svs.encode_full_state_vector();
        let entries = decode_svs_data(&bytes).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, name("/me"));
        assert_eq!(entries[0].boot, 100);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[1].name, name("/peer-a"));
        assert_eq!(entries[1].boot, 60);
        assert_eq!(entries[1].seq, 3);
        assert_eq!(entries[2].name, name("/peer-b"));
        assert_eq!(entries[2].boot, 50);
        assert_eq!(entries[2].seq, 7);
    }

    #[test]
    fn encode_full_state_vector_byte_stable_across_insertion_order() {
        let svs_a = SvsLocal::new(name("/me"), 100);
        let _ = svs_a
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/x"),
                boot: 1,
                seq: 1,
            }]))
            .unwrap();
        let _ = svs_a
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/y"),
                boot: 2,
                seq: 2,
            }]))
            .unwrap();
        let svs_b = SvsLocal::new(name("/me"), 100);
        let _ = svs_b
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/y"),
                boot: 2,
                seq: 2,
            }]))
            .unwrap();
        let _ = svs_b
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/x"),
                boot: 1,
                seq: 1,
            }]))
            .unwrap();
        assert_eq!(
            &svs_a.encode_full_state_vector()[..],
            &svs_b.encode_full_state_vector()[..],
        );
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

    // The malformed-input decode tests (`decode_rejects_wrong_outer_type`,
    // `..._wrong_state_vector_type`, `..._missing_seq_no_entries`,
    // `..._bad_nni_width`) moved with the codec into `ndn_svs_core::codec`
    // (they reference that module's private `T_*` TLV constants). The
    // `encode_svs_data_byte_level` guard above is kept here too, exercising the
    // re-exported codec end-to-end from ndn-sync.

    #[test]
    fn advance_seq_increments() {
        let svs = SvsLocal::new(name("/r"), 100);
        assert_eq!(svs.current_seq(), 0);
        assert_eq!(svs.advance_seq(), 1);
        assert_eq!(svs.advance_seq(), 2);
        assert_eq!(svs.current_seq(), 2);
    }

    #[test]
    fn process_sync_records_new_neighbor() {
        let local = SvsLocal::new(name("/me"), 100);
        let peer = SvsLocal::new(name("/peer"), 200);
        peer.advance_seq();

        let advances = local
            .process_sync(&peer.encode_self_state_vector())
            .unwrap();
        assert_eq!(
            advances,
            vec![NeighborAdvance {
                name: name("/peer"),
                boot: 200,
                seq: 1,
            }]
        );
        assert_eq!(
            local.neighbor(&name("/peer")).map(|n| (n.boot, n.seq)),
            Some((200, 1)),
        );
    }

    #[test]
    fn process_sync_ignores_self() {
        let local = SvsLocal::new(name("/me"), 100);
        local.advance_seq();
        let advances = local
            .process_sync(&local.encode_self_state_vector())
            .unwrap();
        assert!(advances.is_empty());
        assert!(local.neighbor(&name("/me")).is_none());
    }

    #[test]
    fn process_sync_ignores_stale_entries() {
        let local = SvsLocal::new(name("/me"), 100);
        let peer = SvsLocal::new(name("/peer"), 200);
        peer.advance_seq();
        peer.advance_seq();
        let _ = local
            .process_sync(&peer.encode_self_state_vector())
            .unwrap();

        let stale = encode_svs_data(&[StateEntry {
            name: name("/peer"),
            boot: 200,
            seq: 1,
        }]);
        let advances = local.process_sync(&stale).unwrap();
        assert!(advances.is_empty(), "stale seq must not advance");
        assert_eq!(
            local.neighbor(&name("/peer")).map(|n| (n.boot, n.seq)),
            Some((200, 2)),
            "neighbor state must not regress",
        );
    }

    #[test]
    fn process_sync_accepts_new_boot() {
        let local = SvsLocal::new(name("/me"), 100);

        let _ = local
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/peer"),
                boot: 200,
                seq: 5,
            }]))
            .unwrap();
        assert_eq!(
            local.neighbor(&name("/peer")).map(|n| (n.boot, n.seq)),
            Some((200, 5)),
        );

        let advances = local
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/peer"),
                boot: 300,
                seq: 1,
            }]))
            .unwrap();
        assert_eq!(
            advances,
            vec![NeighborAdvance {
                name: name("/peer"),
                boot: 300,
                seq: 1,
            }],
        );
    }

    #[test]
    fn process_sync_idempotent_same_seq() {
        let local = SvsLocal::new(name("/me"), 100);
        let sv = encode_svs_data(&[StateEntry {
            name: name("/peer"),
            boot: 200,
            seq: 7,
        }]);
        let first = local.process_sync(&sv).unwrap();
        let second = local.process_sync(&sv).unwrap();
        assert_eq!(first.len(), 1);
        assert!(
            second.is_empty(),
            "identical (boot, seq) must not re-trigger",
        );
    }

    #[test]
    fn neighbors_snapshot_lists_all() {
        let local = SvsLocal::new(name("/me"), 100);
        let _ = local
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/a"),
                boot: 10,
                seq: 1,
            }]))
            .unwrap();
        let _ = local
            .process_sync(&encode_svs_data(&[StateEntry {
                name: name("/b"),
                boot: 20,
                seq: 2,
            }]))
            .unwrap();
        let mut snaps = local.neighbors();
        snaps.sort_by_key(|s| s.name.to_string());
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].name, name("/a"));
        assert_eq!(snaps[0].boot, 10);
        assert_eq!(snaps[0].seq, 1);
        assert_eq!(snaps[1].name, name("/b"));
        assert_eq!(snaps[1].boot, 20);
        assert_eq!(snaps[1].seq, 2);
    }

    // NNI width coverage now lives in the shared `crate::tlv` module
    // (`tlv::tests::nni_widths`), the single home for the codec.
}
