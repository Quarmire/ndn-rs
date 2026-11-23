//! Invariants of a payload in pieces: it round-trips, a piece is its own
//! proof, a sealed payload shows only its size, the pieces of a payload land
//! in one batch and only when all of them are held.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::ContentKey;
use ndn_sync::{DataStore, MemoryStore, StoreOp};
use proptest::prelude::*;

use super::*;
use crate::seal::{open_payload, seal_payload};
use crate::store::Stage;
use crate::test_kit::{Held, n};
use crate::wire::{CHUNK, FANOUT, PAYLOAD_MAX, log_name};

fn entry() -> Name {
    log_name(&n("/alice/phone"), &n("/alice/32=data/photos"), 3)
}

fn other_entry() -> Name {
    log_name(&n("/alice/phone"), &n("/alice/32=data/photos"), 4)
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 31 % 251) as u8).collect()
}

/// The pieces of a split, by name: what any holder would answer from.
fn holders(pieces: &Pieces) -> BTreeMap<Name, Bytes> {
    pieces
        .packets
        .iter()
        .map(|p| (p.name.clone(), p.wire.clone()))
        .collect()
}

/// Drive an assembler the way a fetcher does: ask for what the plan wants,
/// from `held`, until it is complete.
fn fetch(asm: &mut Assembler, held: &BTreeMap<Name, Bytes>, window: usize) {
    while !asm.is_complete() {
        let wanted = asm.next_wanted(window);
        assert!(!wanted.is_empty(), "an incomplete assembly always wants something");
        for name in wanted {
            let wire = held.get(&name).expect("a holder has every piece").clone();
            assert_eq!(asm.offer(wire), Ok(Offered::Accepted), "{name}");
        }
    }
}



#[test]
fn a_1_mib_payload_round_trips_through_pieces() {
    let e = entry();
    let payload = payload(1 << 20);
    let pieces = split(&e, &payload).unwrap();
    assert_eq!(pieces.size, 1 << 20);
    // 256 chunks under a root of two bottom nodes: 256 + 3 packets, leaves
    // first.
    assert_eq!(pieces.packets.len(), 256 + 3);
    assert!(
        pieces.packets[..256]
            .iter()
            .all(|p| matches!(parse_piece_name(&p.name).unwrap().kind, PieceKind::Chunk(_)))
    );

    let held = holders(&pieces);
    let mut asm = Assembler::new(e.clone(), pieces.blob()).unwrap();
    fetch(&mut asm, &held, 32);
    let ops = asm.take_ops().expect("complete");

    let store = MemoryStore::new();
    store.apply(ops);
    let joined = read(&store, &e, &pieces.blob()).unwrap();
    assert_eq!(joined, payload);
}

#[test]
fn a_payload_splits_into_pieces_its_manifest_lists_and_reassembles() {
    let v = entry();
    for size in [0usize, 1, 6145, 4096 * 128, 4096 * 128 + 1, 4096 * 300 + 7] {
        let payload = payload(size);
        let pieces = split(&v, &payload).unwrap();
        let shape = Shape::of(size as u64);
        assert_eq!(pieces.packets.len() as u64, shape.pieces(), "size {size}");
        let by_name = holders(&pieces);
        // Walk the tree from the root by digest and reassemble.
        let mut out = Vec::new();
        let mut stack = vec![(PieceKind::Manifest(0), pieces.root)];
        while let Some((kind, digest)) = stack.pop() {
            let wire = &by_name[&piece_name(&v, kind)];
            match open(&v, &shape, kind, wire, &digest).expect("verifies") {
                Opened::Node(listed) => {
                    let PieceKind::Manifest(k) = kind else { unreachable!() };
                    for (kid, d) in shape.children(k).unwrap().into_iter().zip(listed).rev() {
                        stack.push((kid, d));
                    }
                }
                Opened::Chunk(bytes) => out.extend_from_slice(&bytes),
            }
        }
        assert_eq!(out, payload, "size {size}");
        assert_eq!(
            join(&v, &pieces.blob(), |name| by_name.get(name).cloned()).unwrap(),
            payload,
            "size {size}"
        );
    }
}

#[test]
fn a_piece_from_a_stranger_verifies_by_digest_alone() {
    let e = entry();
    let pieces = split(&e, &payload(4096 * 3 + 10)).unwrap();
    let shape = Shape::of(pieces.size);
    let chunk0 = &pieces.packets[0];
    let root = pieces.packets.last().unwrap();

    // A copy that came by any road (no store, no assembler, no session) is
    // proven by the digest its parent lists.
    let copy = Bytes::copy_from_slice(&chunk0.wire);
    assert!(matches!(
        open(&e, &shape, PieceKind::Chunk(0), &copy, &chunk0.digest),
        Ok(Opened::Chunk(c)) if c.len() == CHUNK
    ));
    assert!(matches!(
        open(&e, &shape, PieceKind::Manifest(0), &root.wire, &pieces.root),
        Ok(Opened::Node(d)) if d.len() == 4
    ));

    // One flipped bit, anywhere, is another packet.
    for at in [0, chunk0.wire.len() / 2, chunk0.wire.len() - 1] {
        let mut bad = chunk0.wire.to_vec();
        bad[at] ^= 1;
        assert!(
            matches!(
                open(&e, &shape, PieceKind::Chunk(0), &Bytes::from(bad), &chunk0.digest),
                Err(PieceError::Wrong { .. })
            ),
            "bit flipped at {at}"
        );
    }
    // A genuine, well-formed piece of another slot or another entry is not
    // the piece asked for.
    assert!(matches!(
        open(&e, &shape, PieceKind::Chunk(1), &chunk0.wire, &chunk0.digest),
        Err(PieceError::Wrong { .. })
    ));
    let alien = split(&other_entry(), &payload(4096 * 3 + 10)).unwrap();
    assert!(matches!(
        open(&e, &shape, PieceKind::Chunk(0), &alien.packets[0].wire, &alien.packets[0].digest),
        Err(PieceError::Wrong { .. })
    ));
}

#[test]
fn a_sealed_payload_shows_only_its_size() {
    let e = entry();
    let key = ContentKey::generate();
    let secret_a = b"the quick brown fox / ".repeat(1000);
    let secret_b = b"JUMPS OVER THE LAZY / ".repeat(1000);
    assert_eq!(secret_a.len(), secret_b.len());

    // Encrypt whole, then cut: the chunks are slices of the ciphertext.
    let sealed_a = seal_payload(&key, &e, &secret_a);
    let sealed_b = seal_payload(&key, &e, &secret_b);
    let a = split(&e, &sealed_a).unwrap();
    let b = split(&e, &sealed_b).unwrap();

    // All a holder learns is the length: the same names, the same lengths,
    // the same tree.
    assert_eq!(a.size, b.size);
    assert_eq!(a.size as usize, sealed_a.len());
    assert!(a.size as usize > secret_a.len());
    let shape_of = |p: &Pieces| -> Vec<(Name, usize)> {
        p.packets.iter().map(|p| (p.name.clone(), p.wire.len())).collect()
    };
    assert_eq!(shape_of(&a), shape_of(&b));
    for p in &a.packets {
        assert!(
            !p.wire.windows(16).any(|w| secret_a.windows(16).any(|s| s == w)),
            "{} carries plaintext",
            p.name
        );
    }

    // The reader joins the sealed bytes whole, and opens them whole.
    let held = holders(&a);
    let joined = join(&e, &a.blob(), |name| held.get(name).cloned()).unwrap();
    assert_eq!(joined, sealed_a.to_vec());
    assert_eq!(open_payload(&key, &e, &joined).unwrap(), secret_a);
}

#[test]
fn pieces_are_written_in_one_batch() {
    let e = entry();
    let held = payload_held(&e);
    let pieces = split(&e, &payload(4096 * 200 + 1)).unwrap();
    let total = pieces.packets.len();

    // The writer side: every piece in one apply.
    let backing = Arc::new(Held::default());
    let stage = Stage::new(backing.clone());
    let ops = pieces.ops();
    assert_eq!(ops.len(), total);
    stage.apply(ops);
    assert_eq!(backing.batches(), 1);

    // The reader side: nothing is written while an assembly is incomplete;
    // all of it is, in one apply, when it completes.
    let backing = Arc::new(Held::default());
    let stage = Stage::new(backing.clone());
    let mut asm = Assembler::new(e.clone(), pieces.blob()).unwrap();
    while !asm.is_complete() {
        assert!(asm.take_ops().is_none(), "an incomplete assembly hands nothing over");
        for name in asm.next_wanted(8) {
            asm.offer(held[&name].clone()).unwrap();
        }
        assert_eq!(backing.batches(), 0);
    }
    let ops = asm.take_ops().expect("complete");
    assert_eq!(ops.len(), total);
    stage.apply(ops);
    assert_eq!(backing.batches(), 1);
    assert_eq!(
        read(&*backing, &e, &pieces.blob()).unwrap(),
        payload(4096 * 200 + 1)
    );
    assert!(asm.take_ops().is_none(), "the pieces are handed over once");
}

/// The pieces of the 200-chunk test payload, by name.
fn payload_held(e: &Name) -> BTreeMap<Name, Bytes> {
    holders(&split(e, &payload(4096 * 200 + 1)).unwrap())
}

#[test]
fn a_blob_head_is_unavailable_until_assembled() {
    let e = entry();
    let pieces = split(&e, &payload(4096 * 5)).unwrap();
    let blob = pieces.blob();
    let held = holders(&pieces);
    let store = MemoryStore::new();

    // Nothing held, then everything but one chunk: `Incomplete`, naming the
    // first piece it lacks, never a short value.
    assert!(matches!(read(&store, &e, &blob), Err(PieceError::Incomplete { .. })));
    let missing = piece_name(&e, PieceKind::Chunk(4));
    for (name, wire) in &held {
        if *name != missing {
            store.insert(name.clone(), wire.clone());
        }
    }
    assert_eq!(
        read(&store, &e, &blob),
        Err(PieceError::Incomplete { missing: missing.clone() })
    );

    // The assembler agrees: incomplete hands nothing over.
    let mut asm = Assembler::new(e.clone(), blob).unwrap();
    assert!(!asm.is_complete());
    assert!(asm.take_ops().is_none());

    store.insert(missing.clone(), held[&missing].clone());
    assert_eq!(read(&store, &e, &blob).unwrap(), payload(4096 * 5));
}

#[test]
fn a_manifest_shape_that_disagrees_with_the_declared_size_is_refused() {
    let e = entry();
    // The root of a 300-chunk tree under a claim of two chunks: the entry
    // says a size the tree it names cannot have.
    let big = split(&e, &payload(CHUNK * 300)).unwrap();
    let lying = ChunksBody { size: (CHUNK * 2) as u64, root: big.root };
    let mut asm = Assembler::new(e.clone(), lying).unwrap();
    let root = big.packets.last().unwrap().wire.clone();
    assert!(matches!(asm.offer(root), Err(PieceError::Shape { .. })));

    // The root of a one-chunk tree under a claim of 300 chunks.
    let small = split(&e, &payload(CHUNK)).unwrap();
    let lying = ChunksBody { size: (CHUNK * 300) as u64, root: small.root };
    let mut asm = Assembler::new(e.clone(), lying).unwrap();
    assert!(matches!(
        asm.offer(small.packets.last().unwrap().wire.clone()),
        Err(PieceError::Shape { .. })
    ));

    // A tree that lists a short chunk where the size wants a full one.
    let short = split(&e, &payload(CHUNK + 904)).unwrap();
    let lying = ChunksBody { size: (CHUNK * 2) as u64, root: short.root };
    let held = holders(&short);
    let mut asm = Assembler::new(e.clone(), lying).unwrap();
    asm.offer(held[&piece_name(&e, PieceKind::Manifest(0))].clone()).unwrap();
    asm.offer(held[&piece_name(&e, PieceKind::Chunk(0))].clone()).unwrap();
    assert!(matches!(
        asm.offer(held[&piece_name(&e, PieceKind::Chunk(1))].clone()),
        Err(PieceError::Shape { .. })
    ));
    assert!(!asm.is_complete());
}

#[test]
fn a_tampered_piece_is_refused_alone() {
    let e = entry();
    let pieces = split(&e, &payload(CHUNK * 4 + 3)).unwrap();
    let held = holders(&pieces);
    let mut asm = Assembler::new(e.clone(), pieces.blob()).unwrap();
    let root_name = piece_name(&e, PieceKind::Manifest(0));

    // A bad copy of the root changes nothing: the plan still wants it.
    let mut bad = held[&root_name].to_vec();
    let at = bad.len() - 1;
    bad[at] ^= 1;
    assert!(matches!(asm.offer(Bytes::from(bad)), Err(PieceError::Wrong { .. })));
    assert_eq!(asm.next_wanted(8), vec![root_name.clone()]);
    asm.offer(held[&root_name].clone()).unwrap();

    // A bad chunk is refused alone; the others, and a good copy of it,
    // are taken.
    let c2 = piece_name(&e, PieceKind::Chunk(2));
    let mut bad = held[&c2].to_vec();
    bad[40] ^= 0x80;
    assert!(matches!(asm.offer(Bytes::from(bad)), Err(PieceError::Wrong { .. })));
    for name in asm.next_wanted(8) {
        if name != c2 {
            assert_eq!(asm.offer(held[&name].clone()), Ok(Offered::Accepted));
        }
    }
    assert_eq!(asm.next_wanted(8), vec![c2.clone()]);
    assert!(asm.take_ops().is_none());
    assert_eq!(asm.offer(held[&c2].clone()), Ok(Offered::Accepted));
    assert!(asm.is_complete());

    // A piece of another entry, a duplicate, a name that is not a piece.
    let alien = split(&other_entry(), &payload(CHUNK)).unwrap();
    assert!(matches!(
        asm.offer(alien.packets[0].wire.clone()),
        Err(PieceError::Foreign { .. })
    ));
    assert_eq!(asm.offer(held[&c2].clone()), Ok(Offered::Duplicate));
}

#[test]
fn the_plan_asks_for_nodes_before_chunks_and_never_beyond_the_window() {
    let e = entry();
    let pieces = split(&e, &payload(CHUNK * 130)).unwrap();
    let held = holders(&pieces);
    let mut asm = Assembler::new(e.clone(), pieces.blob()).unwrap();

    // Only the root is known to be wanted: nothing else is listed yet.
    assert_eq!(asm.next_wanted(100), vec![piece_name(&e, PieceKind::Manifest(0))]);
    assert!(asm.next_wanted(0).is_empty());
    asm.offer(held[&piece_name(&e, PieceKind::Manifest(0))].clone()).unwrap();

    // Its two children (the bottom level) before any chunk, and then chunks
    // in order only once their node is held.
    let wanted = asm.next_wanted(100);
    assert_eq!(
        wanted,
        vec![
            piece_name(&e, PieceKind::Manifest(1)),
            piece_name(&e, PieceKind::Manifest(2)),
        ]
    );
    asm.offer(held[&wanted[0]].clone()).unwrap();
    let wanted = asm.next_wanted(5);
    assert_eq!(wanted.len(), 5);
    assert_eq!(wanted[0], piece_name(&e, PieceKind::Manifest(2)));
    assert_eq!(wanted[1], piece_name(&e, PieceKind::Chunk(0)));
    assert_eq!(wanted[4], piece_name(&e, PieceKind::Chunk(3)));
    assert_eq!(asm.next_wanted(usize::MAX).len(), 1 + FANOUT);
}

#[test]
fn the_pieces_a_holder_lacks_are_those_its_store_does_not_hold() {
    let e = entry();
    let pieces = split(&e, &payload(CHUNK * 3)).unwrap();
    let all: Vec<Name> = pieces.packets.iter().map(|p| p.name.clone()).collect();
    assert_eq!(pieces.wanted(|_| false), all);
    assert!(pieces.wanted(|_| true).is_empty());
    let held: BTreeSet<Name> = all[1..3].iter().cloned().collect();
    let lacking = pieces.wanted(|name| held.contains(name));
    assert_eq!(lacking, vec![all[0].clone(), all[3].clone()]);
}

#[test]
fn a_payload_over_payload_max_is_refused() {
    let e = entry();
    let big = vec![0u8; PAYLOAD_MAX as usize + 1];
    assert_eq!(
        split(&e, &big).map(|_| ()),
        Err(PieceError::Oversize { size: PAYLOAD_MAX + 1 })
    );
    let blob = ChunksBody { size: PAYLOAD_MAX + 1, root: [7; 32] };
    assert_eq!(
        Assembler::new(e.clone(), blob).map(|_| ()),
        Err(PieceError::Oversize { size: PAYLOAD_MAX + 1 })
    );
    assert!(matches!(
        join(&e, &blob, |_| None),
        Err(PieceError::Oversize { .. })
    ));
    // The most there is, is taken: only its pieces are missing.
    let blob = ChunksBody { size: PAYLOAD_MAX, root: [7; 32] };
    assert!(Assembler::new(e.clone(), blob).is_ok());
    assert!(matches!(
        join(&e, &blob, |_| None),
        Err(PieceError::Incomplete { .. })
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn assembly_order_does_not_matter(
        arrival in Just((0..(131 + 3)).collect::<Vec<usize>>()).prop_shuffle(),
    ) {
        let e = entry();
        let pieces = split(&e, &payload(CHUNK * 131 - 7)).unwrap();
        prop_assert_eq!(pieces.packets.len(), 134);
        let mut asm = Assembler::new(e.clone(), pieces.blob()).unwrap();

        // Pieces arrive in the drawn order; one whose parent is not held
        // yet is not lost, it is offered again when it can be proven.
        let mut waiting: Vec<&Piece> = arrival.iter().map(|&i| &pieces.packets[i]).collect();
        while !waiting.is_empty() {
            let before = waiting.len();
            let mut next = Vec::new();
            for p in waiting {
                let listed = asm.next_wanted(usize::MAX).contains(&p.name);
                match asm.offer(p.wire.clone()) {
                    Ok(Offered::Accepted) => prop_assert!(listed),
                    Ok(Offered::NotYet) => {
                        prop_assert!(!listed);
                        next.push(p);
                    }
                    other => prop_assert!(false, "{} gave {:?}", p.name, other),
                }
            }
            waiting = next;
            prop_assert!(waiting.len() < before, "every round makes progress");
        }
        prop_assert!(asm.is_complete());

        let mut ops = asm.take_ops().expect("complete");
        let mut want = pieces.ops();
        let key = |op: &StoreOp| match op {
            StoreOp::Insert(name, _) | StoreOp::Remove(name) => name.clone(),
        };
        ops.sort_by_key(key);
        want.sort_by_key(key);
        prop_assert_eq!(ops, want);
    }
}
