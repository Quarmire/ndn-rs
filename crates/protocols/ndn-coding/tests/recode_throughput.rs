//! RTT-vs-no-recode throughput benchmark (structural, deterministic).
//!
//! Counts the number of **fetch rounds** (≈ RTTs) to recover a K-of-N
//! generation over a Bernoulli(`p`) loss channel, two ways:
//!
//! - **recode**: a recoder mints innovative combinations on demand (real
//!   `GenerationBuffer` + `recode_combine`); the consumer needs *any* K
//!   delivered innovative packets, so each round it re-requests only the
//!   remaining rank deficit.
//! - **no-recode (ARQ)**: plain systematic segments; the consumer needs each
//!   of the K *specific* source segments.
//!
//! Two regimes, and the result is deliberately honest about both:
//!
//! 1. **Unicast, parallel retry** (Scenario A): each round re-requests *all*
//!    still-missing units. Here recoding and ARQ are ~equal — both fill each
//!    missing unit independently w.p. (1−p) per round, so coding buys no RTT
//!    advantage. This matches the F1 doctrine: "on a single clean path FEC is
//!    pure overhead." Reported, not asserted.
//! 2. **Multicast, M receivers** (Scenario B): the metric is *source
//!    transmissions* (airtime). ARQ must (re)send each receiver's *specific*
//!    missing segments — different receivers lose different segments, so the
//!    source's workload grows. Recoding broadcasts *fungible* innovative
//!    combinations that help any receiver, so one stream serves all. This is
//!    where coding wins, and it is asserted.
//!
//! Structural simulation (the gain is in RTT/airtime structure, not per-op
//! ns), driving the real coding logic under a seeded loss channel.
//! Gated by `f2-recode`. Run with `--nocapture` to see the tables.

#![cfg(feature = "f2-recode")]

use std::collections::HashSet;

use bytes::Bytes;

use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodedPacket, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy,
    SourceCommitment, recode_combine, row_hash,
};

/// Tiny seedable LCG → deterministic, no `rand` dependency.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    /// Bernoulli: `true` (a loss) with probability `p` (in parts-per-1000).
    fn lost(&mut self, p_permille: u64) -> bool {
        (self.next_u64() >> 11) % 1000 < p_permille
    }
    fn nonzero_byte(&mut self) -> u8 {
        let b = (self.next_u64() >> 24) as u8;
        if b == 0 { 1 } else { b }
    }
}

fn descriptor(k: u16, symbol_size: u32, sources: &[Vec<u8>]) -> GenerationDescriptor {
    GenerationDescriptor {
        generation_id: 1,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: "/bench/gen".parse().unwrap(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    }
}

const MAX_ROUNDS: u32 = 10_000;

/// Rounds for the recode scheme: each round re-requests the rank deficit; a
/// request is delivered w.p. (1−p) and (while rank < K) is innovative.
fn recode_rounds(k: u16, sources: &[Vec<u8>], p_permille: u64, rng: &mut Lcg) -> u32 {
    // Recoder holds the K source packets (full rank).
    let held: Vec<CodedPacket> = sources
        .iter()
        .enumerate()
        .map(|(i, row)| CodedPacket {
            vector: CodingVector::unit(k, i as u16),
            payload: Bytes::from(row.clone()),
        })
        .collect();
    let mut consumer = GenerationBuffer::new(descriptor(k, sources[0].len() as u32, sources));
    let mut rounds = 0;
    while !consumer.is_decodable() && rounds < MAX_ROUNDS {
        rounds += 1;
        let deficit = k as usize - consumer.rank();
        for _ in 0..deficit {
            // Mint a fresh random combination (real coding).
            let coeffs: Vec<u8> = (0..held.len()).map(|_| rng.nonzero_byte()).collect();
            let combo = recode_combine(&held, &coeffs).unwrap();
            if rng.lost(p_permille) {
                continue; // lost on the channel
            }
            let meta = CodedMetadata {
                generation_id: 1,
                k,
                field: Field::Gf8,
                vector: combo.vector,
            };
            let _ = consumer.absorb(&meta, combo.payload);
        }
    }
    rounds
}

/// Rounds for ARQ: each round re-requests every missing *specific* segment;
/// each is delivered w.p. (1−p). Done when all K are received.
fn arq_rounds(k: u16, p_permille: u64, rng: &mut Lcg) -> u32 {
    let mut received: HashSet<u16> = HashSet::new();
    let mut rounds = 0;
    while received.len() < k as usize && rounds < MAX_ROUNDS {
        rounds += 1;
        for seg in 0..k {
            if !received.contains(&seg) && !rng.lost(p_permille) {
                received.insert(seg);
            }
        }
    }
    rounds
}

/// Scenario B — multicast source transmissions to serve `m` receivers.
/// recode: broadcast fresh combinations; each receiver absorbs delivered
/// innovative ones; stop when all `m` are decodable.
fn recode_tx_multicast(
    k: u16,
    sources: &[Vec<u8>],
    m: usize,
    p_permille: u64,
    rng: &mut Lcg,
) -> u32 {
    let held: Vec<CodedPacket> = sources
        .iter()
        .enumerate()
        .map(|(i, row)| CodedPacket {
            vector: CodingVector::unit(k, i as u16),
            payload: Bytes::from(row.clone()),
        })
        .collect();
    let mut receivers: Vec<GenerationBuffer> = (0..m)
        .map(|_| GenerationBuffer::new(descriptor(k, sources[0].len() as u32, sources)))
        .collect();
    let mut tx = 0;
    while receivers.iter().any(|r| !r.is_decodable()) && tx < MAX_ROUNDS {
        let coeffs: Vec<u8> = (0..held.len()).map(|_| rng.nonzero_byte()).collect();
        let combo = recode_combine(&held, &coeffs).unwrap();
        tx += 1; // one source broadcast
        for r in receivers.iter_mut() {
            if r.is_decodable() || rng.lost(p_permille) {
                continue;
            }
            let meta = CodedMetadata {
                generation_id: 1,
                k,
                field: Field::Gf8,
                vector: combo.vector.clone(),
            };
            let _ = r.absorb(&meta, combo.payload.clone());
        }
    }
    tx
}

/// ARQ multicast: the source (re)broadcasts each *specific* segment that some
/// receiver still needs, until every receiver has every segment.
fn arq_tx_multicast(k: u16, m: usize, p_permille: u64, rng: &mut Lcg) -> u32 {
    let mut have: Vec<HashSet<u16>> = vec![HashSet::new(); m];
    let mut tx = 0;
    loop {
        let mut progressed_or_pending = false;
        for seg in 0..k {
            // Does any receiver still need this segment?
            if have.iter().all(|h| h.contains(&seg)) {
                continue;
            }
            progressed_or_pending = true;
            tx += 1; // one source broadcast of `seg`
            for h in have.iter_mut() {
                if !h.contains(&seg) && !rng.lost(p_permille) {
                    h.insert(seg);
                }
            }
        }
        if !progressed_or_pending || tx >= MAX_ROUNDS {
            break;
        }
    }
    tx
}

#[test]
fn rtt_vs_no_recode_tables() {
    let k: u16 = 16;
    let symbol_size = 64usize;
    let sources: Vec<Vec<u8>> = (0..k)
        .map(|s| {
            (0..symbol_size)
                .map(|j| ((s as usize * 31 + j) & 0xff) as u8)
                .collect()
        })
        .collect();
    let trials = 200u32;

    // ---- Scenario A: unicast fetch-rounds (honest "no win on a clean path").
    eprintln!("\nScenario A — unicast fetch-rounds (K={k}, {trials} trials)");
    eprintln!("  loss%   recode    ARQ");
    eprintln!("  -----   ------   -----");
    for &p in &[0u64, 100, 200, 300, 400, 500] {
        let mut rng = Lcg(0xA11CE ^ p.wrapping_mul(2654435761));
        let (mut rs, mut as_) = (0u64, 0u64);
        for _ in 0..trials {
            rs += recode_rounds(k, &sources, p, &mut rng) as u64;
            as_ += arq_rounds(k, p, &mut rng) as u64;
        }
        let (rec, arq) = (rs as f64 / trials as f64, as_ as f64 / trials as f64);
        eprintln!("  {:>4}    {:>6.2}   {:>5.2}", p / 10, rec, arq);
        if p == 0 {
            assert_eq!(arq, 1.0);
            assert!(rec < 1.1, "recode ≈ one round, no loss (got {rec:.3})");
        }
        // Parallel-retry unicast: comparable within a small factor (no win).
        if p >= 300 {
            assert!(
                rec <= arq * 1.3,
                "unicast recode ~ ARQ (rec {rec:.2}, arq {arq:.2})"
            );
        }
    }

    // ---- Scenario B: multicast source transmissions (the coding win).
    let m = 16usize;
    eprintln!(
        "\nScenario B — multicast source transmissions, M={m} receivers (K={k}, {trials} trials)"
    );
    eprintln!("  loss%   recode    ARQ   ARQ/recode");
    eprintln!("  -----   ------   -----  ----------");
    let mut checked = false;
    for &p in &[0u64, 100, 200, 300, 400, 500] {
        let mut rng = Lcg(0xB0B ^ p.wrapping_mul(40503));
        let (mut rs, mut as_) = (0u64, 0u64);
        for _ in 0..trials {
            rs += recode_tx_multicast(k, &sources, m, p, &mut rng) as u64;
            as_ += arq_tx_multicast(k, m, p, &mut rng) as u64;
        }
        let (rec, arq) = (rs as f64 / trials as f64, as_ as f64 / trials as f64);
        eprintln!(
            "  {:>4}    {:>6.1}   {:>5.1}   {:>5.2}x",
            p / 10,
            rec,
            arq,
            arq / rec.max(0.01)
        );
        if p >= 200 {
            assert!(
                rec < arq,
                "at {}% loss, multicast recode ({rec:.1}) should beat ARQ ({arq:.1})",
                p / 10
            );
            checked = true;
        }
    }
    assert!(checked);
}
