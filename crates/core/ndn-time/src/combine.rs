//! The Marzullo combiner — robustness, **not** admission.
//!
//! Given a set of intervals from different sources, Marzullo's algorithm finds
//! the smallest interval consistent with the *largest number of sources*,
//! discarding a minority of "false tickers" whose intervals don't overlap the
//! agreeing majority. It is what NTP uses to reject a lying or broken peer.
//!
//! **This is a robustness mechanism, not an admission mechanism.** It assumes a
//! *bounded fraction* of bad inputs. A Sybil adversary who mints a fabricated
//! *majority* defeats it — Marzullo over a manufactured majority simply launders
//! the attacker's chosen value. Admission (which keys may speak for time, and
//! the threat-diversity a high-stakes fix requires) happens **upstream** in
//! [`crate::provenance::admits`]; only already-admitted intervals should be
//! passed here.

use crate::interval::TimeInterval;
use crate::provenance::MAX_MEASUREMENTS;

#[derive(Clone, Copy)]
struct Edge {
    pos: i64,
    // -1 = an interval begins here, +1 = an interval ends here.
    kind: i8,
}

/// The result of a Marzullo combine: the agreed interval and how many of the
/// input sources support it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Combined {
    /// The smallest interval consistent with the most sources.
    pub interval: TimeInterval,
    /// How many input intervals contain [`Self::interval`] — the size of the
    /// agreeing majority. A caller may reject a result whose support is too
    /// small a fraction of the inputs (a quorum check).
    pub support: usize,
}

/// Combine `intervals` into the smallest interval supported by the most sources.
///
/// Returns `None` for an empty input. At most [`MAX_MEASUREMENTS`] intervals are
/// considered (the combiner is over the number of time *sources*, which is
/// small); extra inputs are ignored, which can only *lower* the reported
/// support, never fabricate agreement.
pub fn marzullo(intervals: &[TimeInterval]) -> Option<Combined> {
    let n = intervals.len().min(MAX_MEASUREMENTS);
    if n == 0 {
        return None;
    }

    // Build endpoint edges into a fixed scratch array (no allocation).
    let mut edges = [Edge { pos: 0, kind: 0 }; MAX_MEASUREMENTS * 2];
    let mut m = 0;
    for iv in intervals.iter().take(n) {
        edges[m] = Edge {
            pos: iv.lo(),
            kind: -1,
        };
        edges[m + 1] = Edge {
            pos: iv.hi(),
            kind: 1,
        };
        m += 2;
    }
    let edges = &mut edges[..m];

    // Insertion sort by (pos asc, kind asc) — `kind` -1 (begin) sorts before +1
    // (end) at the same position, so closed intervals that touch at a point
    // still count as overlapping there. n is small; insertion sort is fine and
    // keeps us allocation-free.
    let mut i = 1;
    while i < edges.len() {
        let e = edges[i];
        let mut j = i;
        while j > 0 && (edges[j - 1].pos, edges[j - 1].kind) > (e.pos, e.kind) {
            edges[j] = edges[j - 1];
            j -= 1;
        }
        edges[j] = e;
        i += 1;
    }

    // Sweep: a begin (-1) raises the running count, an end (+1) lowers it. Track
    // the widest-support region [pos_i, pos_{i+1}].
    let mut best_support: usize = 0;
    let mut best_lo: i64 = intervals[0].lo();
    let mut best_hi: i64 = intervals[0].hi();
    let mut cnt: i64 = 0;
    let mut k = 0;
    while k < edges.len() {
        cnt -= edges[k].kind as i64;
        if cnt > best_support as i64 && k + 1 < edges.len() {
            best_support = cnt as usize;
            best_lo = edges[k].pos;
            best_hi = edges[k + 1].pos;
        }
        k += 1;
    }

    let radius = (best_hi.wrapping_sub(best_lo) as u64) / 2;
    let center = best_lo.saturating_add_unsigned(radius);
    Some(Combined {
        interval: TimeInterval::new(center, radius),
        support: best_support,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iv(center: i64, radius: u64) -> TimeInterval {
        TimeInterval::new(center, radius)
    }

    #[test]
    fn empty_is_none() {
        assert!(marzullo(&[]).is_none());
    }

    #[test]
    fn single_source_returns_itself() {
        let c = marzullo(&[iv(100, 10)]).unwrap();
        assert_eq!(c.support, 1);
        assert!(c.interval.contains(100));
    }

    #[test]
    fn agreeing_majority_tightens() {
        // Three overlapping around 100, one liar far away.
        let sources = [iv(100, 20), iv(105, 20), iv(95, 20), iv(1_000, 5)];
        let c = marzullo(&sources).unwrap();
        assert_eq!(c.support, 3, "the three agree; the liar is dropped");
        // Agreed region is the common overlap [85..115]-ish, well away from 1000.
        assert!(c.interval.center_ns > 80 && c.interval.center_ns < 120);
    }

    #[test]
    fn false_ticker_is_excluded_from_the_result() {
        let sources = [iv(0, 10), iv(0, 10), iv(500, 10)];
        let c = marzullo(&sources).unwrap();
        assert_eq!(c.support, 2);
        assert!(!c.interval.contains(500));
    }

    #[test]
    fn touching_intervals_count_as_overlap() {
        // [90,110] and [110,130] touch at 110.
        let c = marzullo(&[iv(100, 10), iv(120, 10)]).unwrap();
        assert_eq!(c.support, 2);
        assert!(c.interval.contains(110));
    }

    // Documents the design boundary: a fabricated majority defeats Marzullo.
    // This is WHY admission must happen upstream (provenance::admits), and the
    // test exists so the property is not silently regressed into.
    #[test]
    fn a_fabricated_majority_wins_marzullo_hence_admission_is_upstream() {
        // One honest source at 100; three attacker intervals agreeing on 9000.
        let sources = [iv(100, 5), iv(9_000, 5), iv(9_000, 5), iv(9_000, 5)];
        let c = marzullo(&sources).unwrap();
        assert_eq!(c.support, 3);
        assert!(
            c.interval.contains(9_000),
            "Marzullo trusts the majority — so the majority must be authenticated first"
        );
    }
}
