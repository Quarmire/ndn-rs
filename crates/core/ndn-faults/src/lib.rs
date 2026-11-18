//! A **fault profile** for one direction of a link: every packet crossing it is dropped,
//! duplicated, forged, delayed, reordered or (a Data) held back, each by a seeded draw. The
//! semantics are exactly those of ndf's element-link fault layer (`NDF_LINK_FAULTS`), so a
//! scenario run under a profile meets the same network a faulty ndf run meets:
//!
//! - `drop=P`: each packet is dropped with probability `P` (0–1);
//! - `dup=P`: it is delivered twice;
//! - `forge=P`: a Data has one byte of its signature value flipped (its verifier must refuse it);
//! - `delay=MS`: it is held a uniform 0..=`MS` ms, so packets also overtake each other;
//! - `reorder=P`: it is held a further `max(MS, 50)` ms, behind those after it;
//! - `blocks=MS`: a Data (as opposed to an Interest, a Nack or an LP control frame) is held a
//!   further 0..=`MS` ms;
//! - `seed=N`: the seed of the random draws.
//!
//! A Data is a frame carrying a whole Data packet, bare or as an NDNLPv2 packet's fragment; a
//! fragment of a larger Data is not one (as in ndf, it is neither forged nor held as a block).
//!
//! The draws are a xorshift64 sequence per link direction, seeded from the profile's seed and
//! the direction's two ends ([`Faults::stream`]), so a direction's fate sequence depends on
//! nothing but the seed, the link and the packets that crossed it before: a scenario replays
//! identically whatever ran before it in the process.
//!
//! This crate is the one definition of the profile. The simulator (`ndn-sim`, which re-exports
//! it, and the data-layer conformance `--faulty` profile) and ndn-link's test-only fault layer
//! (cargo feature `fault-injection`) draw from it, so a profile and a seed give the same fates
//! on a simulated link and on a real one. **For tests only**: nothing here belongs in a
//! production build, and its one runtime dependency is `bytes`.

use std::fmt;
use std::ops::Range;
use std::time::Duration;

use bytes::Bytes;

/// The fault profile ndf's scenario runner calls faulty, and every conformance case must pass
/// under: `drop=0.2,dup=0.1,forge=0.05,delay=400,reorder=0.1,blocks=1500`.
pub const FAULTY: &str = "drop=0.2,dup=0.1,forge=0.05,delay=400,reorder=0.1,blocks=1500";

/// The least a reordered packet is held beyond its delay, whatever `delay` says.
const REORDER_FLOOR_MS: u64 = 50;

/// A fault profile: what becomes of the packets crossing one link direction. The default is no
/// faults at all (seed 0).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Faults {
    /// Each packet is dropped with this probability.
    pub drop: f64,
    /// Each packet delivered is delivered twice with this probability.
    pub dup: f64,
    /// Each Data delivered has a byte of its signature value flipped with this probability.
    pub forge: f64,
    /// Each packet is held a uniform `0..=delay_ms` ms.
    pub delay_ms: u64,
    /// Each packet is held a further `max(delay_ms, 50)` ms with this probability.
    pub reorder: f64,
    /// Each Data is held a further uniform `0..=blocks_ms` ms.
    pub blocks_ms: u64,
    /// The seed of the draws.
    pub seed: u64,
}

/// What becomes of one packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fate {
    /// How many copies are delivered (0: dropped).
    pub copies: u8,
    /// Each copy is held this long beyond the link's own latency.
    pub delay: Duration,
    /// The packet as delivered: the frame itself, or a forged copy of it.
    pub frame: Bytes,
}

impl Faults {
    /// The profile `spec` names: comma-separated `key=value` pairs (see the module docs); an
    /// empty spec is no faults. A probability outside 0–1 is clamped into it.
    ///
    /// # Errors
    ///
    /// A pair that is not `key=value`, an unknown key, or a value that is not a number, each
    /// naming the pair and what the spec accepts.
    pub fn parse(spec: &str) -> Result<Faults, String> {
        let mut f = Faults::default();
        for pair in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let Some((key, value)) = pair.split_once('=') else {
                return Err(format!(
                    "fault {pair:?} is not key=value; write e.g. drop=0.2 (keys: drop, dup, \
                     forge, delay, reorder, blocks, seed)"
                ));
            };
            let chance = || {
                value
                    .parse::<f64>()
                    .ok()
                    .filter(|p| !p.is_nan())
                    .map(|p| p.clamp(0.0, 1.0))
                    .ok_or_else(|| format!("fault {pair:?}: {key} takes a probability, 0 to 1"))
            };
            let whole = |what: &str| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("fault {pair:?}: {key} takes {what}"))
            };
            match key {
                "drop" => f.drop = chance()?,
                "dup" => f.dup = chance()?,
                "forge" => f.forge = chance()?,
                "reorder" => f.reorder = chance()?,
                "delay" => f.delay_ms = whole("whole milliseconds")?,
                "blocks" => f.blocks_ms = whole("whole milliseconds")?,
                "seed" => f.seed = whole("a whole number")?,
                _ => {
                    return Err(format!(
                        "unknown fault {key:?} in {pair:?}; the keys are drop, dup, forge, \
                         delay, reorder, blocks and seed"
                    ));
                }
            }
        }
        Ok(f)
    }

    /// The profile with its seed replaced by `seed`.
    pub fn with_seed(mut self, seed: u64) -> Faults {
        self.seed = seed;
        self
    }

    /// Whether the profile does anything to a packet.
    pub fn is_none(&self) -> bool {
        self.drop == 0.0
            && self.dup == 0.0
            && self.forge == 0.0
            && self.delay_ms == 0
            && self.reorder == 0.0
            && self.blocks_ms == 0
    }

    /// The draws of the link direction `from` → `to` (any stable identities of its two ends,
    /// e.g. node ids) under this profile: seeded from the profile's seed and the direction, so
    /// every direction draws its own sequence and the same direction the same one every run.
    pub fn stream(&self, from: u64, to: u64) -> FaultStream {
        let link = mix(mix(from).wrapping_add(to));
        FaultStream {
            faults: *self,
            state: mix(self.seed ^ link) | 1,
        }
    }
}

impl fmt::Display for Faults {
    /// The spec [`parse`](Faults::parse) reads back to this profile, every key written.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "drop={},dup={},forge={},delay={},reorder={},blocks={},seed={}",
            self.drop, self.dup, self.forge, self.delay_ms, self.reorder, self.blocks_ms, self.seed
        )
    }
}

/// The live draws of one link direction under a [`Faults`] profile.
#[derive(Clone, Debug)]
pub struct FaultStream {
    faults: Faults,
    state: u64,
}

impl FaultStream {
    /// The profile drawn from.
    pub fn faults(&self) -> &Faults {
        &self.faults
    }

    /// The next of the xorshift64 sequence.
    fn next(&mut self) -> u64 {
        let x = &mut self.state;
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x
    }

    fn chance(&mut self, p: f64) -> bool {
        p > 0.0 && (self.next() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }

    fn upto(&mut self, ms: u64) -> Duration {
        Duration::from_millis(if ms == 0 { 0 } else { self.next() % (ms + 1) })
    }

    /// What becomes of `frame`, crossing the link now. Draws in ndf's order: the drop, the
    /// delay, the reorder, a Data's block hold, the duplicate, a Data's forgery.
    pub fn fate(&mut self, frame: Bytes) -> Fate {
        let f = self.faults;
        if self.chance(f.drop) {
            return Fate {
                copies: 0,
                delay: Duration::ZERO,
                frame,
            };
        }
        let data = data_in(&frame);
        let mut delay = self.upto(f.delay_ms);
        if self.chance(f.reorder) {
            delay += Duration::from_millis(f.delay_ms.max(REORDER_FLOOR_MS));
        }
        if data.is_some() {
            delay += self.upto(f.blocks_ms);
        }
        let copies = if self.chance(f.dup) { 2 } else { 1 };
        let forge_at = match data {
            Some(_) if self.chance(f.forge) => Some(self.next()),
            _ => None,
        };
        let frame = match forge_at.and_then(|at| forged(&frame, at)) {
            Some(forged) => forged,
            None => frame,
        };
        Fate {
            copies,
            delay,
            frame,
        }
    }
}

/// SplitMix64 finalizer: spreads a seed and adjacent node ids into well-separated states.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ---------------------------------------------------------------------------------------------
// Reading frames: just enough TLV to find a Data and its signature value.

const LP_PACKET: u64 = 0x64;
const LP_FRAGMENT: u64 = 0x50;
const DATA: u64 = 0x06;
const SIGNATURE_VALUE: u64 = 0x17;

/// An NDN variable-length number at `at`: its value and where what follows begins.
fn var(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(at)?;
    let (len, start) = match first {
        0..=252 => return Some((u64::from(first), at + 1)),
        253 => (2, at + 1),
        254 => (4, at + 1),
        255 => (8, at + 1),
    };
    let raw = bytes.get(start..start + len)?;
    Some((
        raw.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)),
        start + len,
    ))
}

/// The TLV at `at` within `bytes`: its type and its value's range.
fn tlv(bytes: &[u8], at: usize) -> Option<(u64, Range<usize>)> {
    let (typ, at) = var(bytes, at)?;
    let (len, at) = var(bytes, at)?;
    let end = at.checked_add(usize::try_from(len).ok()?)?;
    (end <= bytes.len()).then_some((typ, at..end))
}

/// The children of the TLV value `range`, each a type and value range.
fn children(bytes: &[u8], range: Range<usize>) -> impl Iterator<Item = (u64, Range<usize>)> + '_ {
    let mut at = range.start;
    std::iter::from_fn(move || {
        if at >= range.end {
            return None;
        }
        let (typ, value) = tlv(&bytes[..range.end], at)?;
        at = value.end;
        Some((typ, value))
    })
}

/// The value range of the whole Data in `frame` (a bare Data, or one an NDNLPv2 packet carries
/// as its fragment), if it holds one.
fn data_in(frame: &[u8]) -> Option<Range<usize>> {
    let (typ, value) = tlv(frame, 0)?;
    match typ {
        DATA => Some(value),
        LP_PACKET => {
            let (_, fragment) = children(frame, value).find(|(t, _)| *t == LP_FRAGMENT)?;
            let (typ, inner) = tlv(&frame[..fragment.end], fragment.start)?;
            (typ == DATA).then_some(inner)
        }
        _ => None,
    }
}

/// Whether `frame` carries a whole Data packet, bare or as an NDNLPv2 packet's fragment: the
/// frames a profile forges and holds as blocks (a fragment of a larger Data is not one).
pub fn carries_data(frame: &[u8]) -> bool {
    data_in(frame).is_some()
}

/// `frame` with one byte of its Data's signature value flipped (the `at`th, modulo its length);
/// `None` when it holds no Data or the Data no signature value.
fn forged(frame: &Bytes, at: u64) -> Option<Bytes> {
    let data = data_in(frame)?;
    let (_, sig) = children(frame, data).find(|(t, v)| *t == SIGNATURE_VALUE && !v.is_empty())?;
    let mut out = frame.to_vec();
    let i = sig.start + (at % sig.len() as u64) as usize;
    out[i] ^= 0x5a;
    Some(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};

    fn data() -> Bytes {
        DataBuilder::new("/a/b".parse::<Name>().unwrap(), b"content").build()
    }

    fn interest() -> Bytes {
        InterestBuilder::new("/a/b".parse::<Name>().unwrap()).build()
    }

    /// `n` fates of `frame` through `spec`'s stream on the direction 1 → 2.
    fn fates(spec: &str, frame: &Bytes, n: usize) -> Vec<Fate> {
        let mut s = Faults::parse(spec).unwrap().stream(1, 2);
        (0..n).map(|_| s.fate(frame.clone())).collect()
    }

    #[test]
    fn parses_ndf_specs_and_refuses_others_saying_why() {
        let f = Faults::parse(FAULTY).unwrap();
        assert_eq!(
            f,
            Faults {
                drop: 0.2,
                dup: 0.1,
                forge: 0.05,
                delay_ms: 400,
                reorder: 0.1,
                blocks_ms: 1500,
                seed: 0,
            }
        );
        assert_eq!(
            Faults::parse(&f.with_seed(9).to_string()),
            Ok(f.with_seed(9))
        );
        assert!(Faults::parse("").unwrap().is_none());
        assert_eq!(Faults::parse("drop=7").unwrap().drop, 1.0, "clamped");
        for bad in [
            "drop", "drop=x", "what=1", "delay=-1", "seed=1.5", "drop=NaN",
        ] {
            let e = Faults::parse(bad).unwrap_err();
            assert!(e.contains(bad.split('=').next().unwrap()), "{bad}: {e}");
        }
    }

    #[test]
    fn drop_loses_its_share_of_packets() {
        assert!(fates("drop=1", &data(), 50).iter().all(|f| f.copies == 0));
        assert!(fates("drop=0", &data(), 50).iter().all(|f| f.copies == 1));
        let lost = fates("drop=0.2,seed=3", &interest(), 10_000)
            .iter()
            .filter(|f| f.copies == 0)
            .count();
        assert!((1_700..2_300).contains(&lost), "{lost} of 10000 at 0.2");
    }

    #[test]
    fn dup_delivers_twice() {
        assert!(
            fates("dup=1", &interest(), 50)
                .iter()
                .all(|f| f.copies == 2)
        );
        let twice = fates("dup=0.1,seed=4", &data(), 10_000)
            .iter()
            .filter(|f| f.copies == 2)
            .count();
        assert!((800..1_200).contains(&twice), "{twice} of 10000 at 0.1");
    }

    #[test]
    fn forge_flips_one_signature_byte_of_a_data_only() {
        let d = data();
        for f in fates("forge=1", &d, 20) {
            assert_eq!(f.frame.len(), d.len());
            let changed: Vec<usize> = (0..d.len()).filter(|&i| d[i] != f.frame[i]).collect();
            assert_eq!(changed.len(), 1, "one byte changed");
            let (_, sig) = children(&d, data_in(&d).unwrap())
                .find(|(t, _)| *t == SIGNATURE_VALUE)
                .unwrap();
            assert!(
                sig.contains(&changed[0]),
                "the changed byte is the signature's"
            );
        }
        let i = interest();
        assert!(fates("forge=1", &i, 20).iter().all(|f| f.frame == i));
        // A Data an NDNLPv2 packet carries is forged inside it.
        let lp = ndn_packet::lp::encode_lp_packet(&d);
        let f = &fates("forge=1", &lp, 1)[0];
        assert_eq!(f.frame.len(), lp.len());
        assert_eq!((0..lp.len()).filter(|&k| lp[k] != f.frame[k]).count(), 1);
    }

    #[test]
    fn delay_holds_uniformly_up_to_its_bound() {
        let held: Vec<Duration> = fates("delay=400,seed=5", &interest(), 2_000)
            .iter()
            .map(|f| f.delay)
            .collect();
        assert!(held.iter().all(|d| *d <= Duration::from_millis(400)));
        assert!(held.iter().any(|d| *d < Duration::from_millis(40)));
        assert!(held.iter().any(|d| *d > Duration::from_millis(360)));
    }

    #[test]
    fn reorder_holds_a_further_delay_at_least_fifty_ms() {
        assert!(
            fates("reorder=1", &interest(), 20)
                .iter()
                .all(|f| f.delay == Duration::from_millis(50))
        );
        for f in fates("reorder=1,delay=400", &interest(), 200) {
            assert!(f.delay >= Duration::from_millis(400) && f.delay <= Duration::from_millis(800));
        }
    }

    #[test]
    fn blocks_hold_a_data_only() {
        assert!(
            fates("blocks=1500", &interest(), 50)
                .iter()
                .all(|f| f.delay.is_zero())
        );
        let held: Vec<Duration> = fates("blocks=1500,seed=6", &data(), 500)
            .iter()
            .map(|f| f.delay)
            .collect();
        assert!(held.iter().all(|d| *d <= Duration::from_millis(1500)));
        assert!(held.iter().any(|d| *d > Duration::from_millis(1000)));
    }

    #[test]
    fn a_seed_and_a_direction_fix_the_draws() {
        let d = data();
        let run = |spec: &str, from, to| {
            let mut s = Faults::parse(spec).unwrap().stream(from, to);
            (0..200).map(|_| s.fate(d.clone())).collect::<Vec<_>>()
        };
        assert_eq!(run(FAULTY, 1, 2), run(FAULTY, 1, 2), "replays");
        assert_ne!(
            run(FAULTY, 1, 2),
            run(FAULTY, 2, 1),
            "each direction its own"
        );
        assert_ne!(
            run(FAULTY, 1, 2),
            run(&format!("{FAULTY},seed=1"), 1, 2),
            "each seed its own"
        );
    }

    /// The first fates of [`FAULTY`] at seed 3 on the direction 1 → 2 over one Data, written
    /// down so a change of the draw sequence (which every recorded `--faulty` run and every
    /// ndn-link fault test depends on) fails here, not in a far-off run.
    #[test]
    fn the_draw_sequence_is_pinned() {
        let d = data();
        let mut s = Faults::parse(FAULTY).unwrap().with_seed(3).stream(1, 2);
        let got: Vec<(u8, u128, bool)> = (0..12)
            .map(|_| {
                let f = s.fate(d.clone());
                (f.copies, f.delay.as_millis(), f.frame != d)
            })
            .collect();
        assert_eq!(got, PINNED.to_vec(), "{got:?}");
    }

    /// (copies, delay in ms, forged) of the first twelve fates: see `the_draw_sequence_is_pinned`.
    const PINNED: [(u8, u128, bool); 12] = [
        (1, 1418, false),
        (0, 0, false),
        (1, 406, false),
        (1, 1401, false),
        (0, 0, false),
        (1, 540, true),
        (2, 593, false),
        (0, 0, false),
        (1, 1509, true),
        (0, 0, false),
        (1, 1406, false),
        (1, 1563, false),
    ];

    #[test]
    fn carries_data_sees_a_whole_data_only() {
        let d = data();
        assert!(carries_data(&d));
        assert!(carries_data(&ndn_packet::lp::encode_lp_packet(&d)));
        assert!(!carries_data(&interest()));
        assert!(!carries_data(&[]));
    }
}
