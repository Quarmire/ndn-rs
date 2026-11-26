//! The receiver's replay window (docs/specs/channel.md, The receiver): 4,096 frame sequences per
//! channel, a bitmap beside the highest `seq0` seen.
//!
//! Frames are keyed by `seq0`: two frames of one channel never share one (every frame takes at
//! least one sequence and `seq0` rises for the life of the channel), so a repeated `seq0` is a
//! repeated frame. The window is **checked before the AEAD and marked after it**: a flood of
//! copies of a genuine frame costs a comparison each, and a forged frame that names a genuine
//! `seq0` cannot burn it, because a sequence is marked seen only once a frame of that sequence
//! authenticated.
//!
//! No clock is read.

/// How many frame sequences the window remembers.
pub(crate) const REPLAY_WINDOW: u64 = 4_096;

/// The most a frame's `seq0` may be above the highest the window has marked (or above the
/// session's `S_SEQ`, before it has marked any): 2^24 sequences. A key holder can seal a frame
/// of any `seq0` below 2^63, and the window's `highest` follows the highest it ever marked, so
/// one such frame would make every genuine frame after it [`Replay::TooOld`]; the bound turns
/// that into a wedge of at most this many sequences. Large enough that a sender at its fastest
/// (about 2 million messages a second) does not pass it during the ask and install of a
/// session (seconds), and that a receiver cut off for a few seconds does not either.
pub(crate) const SEQ_JUMP_MAX: u64 = 1 << 24;

const WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// What the window says of a `seq0` that is about to be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Replay {
    /// Not seen: open it.
    Fresh,
    /// Seen: a copy. Drop it.
    Replayed,
    /// Below the window: it may or may not have been seen, and the window cannot say. Drop it.
    TooOld,
}

/// The last [`REPLAY_WINDOW`] frame sequences of one channel.
#[derive(Clone, Debug)]
pub(crate) struct ReplayWindow {
    /// The highest `seq0` marked; `None` before the first.
    highest: Option<u64>,
    /// Bit `seq0 % 4096` is set when that sequence was marked and is inside the window.
    bits: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window: every `seq0` is [`Replay::Fresh`].
    pub(crate) const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; WORDS],
        }
    }

    /// The highest `seq0` marked, if any.
    #[cfg(test)]
    pub(crate) fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Whether `seq0` is further above what this window has seen than a genuine frame can be:
    /// more than [`SEQ_JUMP_MAX`] above the higher of `highest` and `floor` (the session's
    /// `S_SEQ`). Marks nothing.
    pub(crate) fn beyond(&self, floor: u64, seq0: u64) -> bool {
        let reference = self.highest.map_or(floor, |highest| highest.max(floor));
        seq0 > reference.saturating_add(SEQ_JUMP_MAX)
    }

    /// What the window says of `seq0`. Marks nothing: call [`Self::mark`] once the frame
    /// authenticated.
    pub(crate) fn check(&self, seq0: u64) -> Replay {
        let Some(highest) = self.highest else {
            return Replay::Fresh;
        };
        if seq0 > highest {
            return Replay::Fresh;
        }
        if highest - seq0 >= REPLAY_WINDOW {
            return Replay::TooOld;
        }
        if self.bit(seq0) {
            Replay::Replayed
        } else {
            Replay::Fresh
        }
    }

    /// Record that a frame of `seq0` authenticated. Returns what [`Self::check`] would have said
    /// before the call, so a caller that raced another frame of the same `seq0` (both passed the
    /// check, both opened) delivers only the first.
    pub(crate) fn mark(&mut self, seq0: u64) -> Replay {
        let before = self.check(seq0);
        if before != Replay::Fresh {
            return before;
        }
        match self.highest {
            Some(highest) if seq0 <= highest => {}
            Some(highest) => {
                let advance = seq0 - highest;
                if advance >= REPLAY_WINDOW {
                    self.bits = [0; WORDS];
                } else {
                    // The sequences that leave the window on the way to `seq0` share their bits
                    // with the ones that enter it: clear each as it is passed.
                    for s in highest + 1..=seq0 {
                        self.clear(s);
                    }
                }
                self.highest = Some(seq0);
            }
            None => self.highest = Some(seq0),
        }
        self.set(seq0);
        Replay::Fresh
    }

    fn bit(&self, seq: u64) -> bool {
        let at = (seq % REPLAY_WINDOW) as usize;
        self.bits[at / 64] >> (at % 64) & 1 == 1
    }

    fn set(&mut self, seq: u64) {
        let at = (seq % REPLAY_WINDOW) as usize;
        self.bits[at / 64] |= 1 << (at % 64);
    }

    fn clear(&mut self, seq: u64) {
        let at = (seq % REPLAY_WINDOW) as usize;
        self.bits[at / 64] &= !(1 << (at % 64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_new_window_calls_every_sequence_fresh() {
        let w = ReplayWindow::new();
        for seq in [0, 1, 4_095, 4_096, 1 << 40, (1 << 63) - 1] {
            assert_eq!(w.check(seq), Replay::Fresh, "seq {seq}");
        }
    }

    #[test]
    fn a_marked_sequence_is_a_repeat_and_a_check_marks_nothing() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check(7), Replay::Fresh);
        assert_eq!(w.check(7), Replay::Fresh, "check does not mark");
        assert_eq!(w.mark(7), Replay::Fresh);
        assert_eq!(w.check(7), Replay::Replayed);
        assert_eq!(
            w.mark(7),
            Replay::Replayed,
            "a second mark says it was seen"
        );
    }

    #[test]
    fn the_window_is_4096_sequences_wide_and_the_boundary_is_exact() {
        let mut w = ReplayWindow::new();
        let top = 10_000;
        w.mark(top);
        // The oldest sequence still inside is top - 4095.
        assert_eq!(w.check(top - 4_095), Replay::Fresh);
        assert_eq!(w.check(top - 4_096), Replay::TooOld);
        // Marking inside the window works down to its edge.
        assert_eq!(w.mark(top - 4_095), Replay::Fresh);
        assert_eq!(w.check(top - 4_095), Replay::Replayed);
        assert_eq!(
            w.mark(top - 4_096),
            Replay::TooOld,
            "below the window is never marked"
        );
        assert_eq!(w.check(top - 4_096), Replay::TooOld);
    }

    #[test]
    fn advancing_slides_the_window_and_forgets_what_left_it() {
        let mut w = ReplayWindow::new();
        w.mark(100);
        w.mark(101);
        // Jump so that 100 falls out and 101 stays in.
        let jump = 100 + REPLAY_WINDOW;
        w.mark(jump);
        assert_eq!(w.check(100), Replay::TooOld);
        assert_eq!(w.check(101), Replay::Replayed);
        // The bit that 100 used is reused by `jump`: a different sequence, unmarked, is fresh.
        assert_eq!(w.check(jump - 1), Replay::Fresh);
        assert_eq!(w.check(jump), Replay::Replayed);
    }

    #[test]
    fn a_jump_of_a_whole_window_or_more_clears_everything() {
        let mut w = ReplayWindow::new();
        for s in 0..64 {
            w.mark(s);
        }
        w.mark(1 << 50);
        for s in 0..64 {
            assert_eq!(w.check(s), Replay::TooOld);
        }
        assert_eq!(w.check((1 << 50) - 1), Replay::Fresh);
        assert_eq!(w.check(1 << 50), Replay::Replayed);
    }

    #[test]
    fn an_older_sequence_inside_the_window_is_fresh_once() {
        let mut w = ReplayWindow::new();
        w.mark(50);
        assert_eq!(w.mark(48), Replay::Fresh);
        assert_eq!(w.mark(48), Replay::Replayed);
        assert_eq!(w.check(49), Replay::Fresh);
        assert_eq!(w.highest(), Some(50));
    }

    proptest! {
        /// Against a model: a set of marked sequences and the highest.
        #[test]
        fn the_window_agrees_with_a_set_model(
            ops in prop::collection::vec((0u64..9_000, any::<bool>()), 1..400)
        ) {
            let mut w = ReplayWindow::new();
            let mut seen = std::collections::BTreeSet::new();
            let mut highest: Option<u64> = None;
            for (seq, mark) in ops {
                let expect = match highest {
                    None => Replay::Fresh,
                    Some(h) if seq > h => Replay::Fresh,
                    Some(h) if h - seq >= REPLAY_WINDOW => Replay::TooOld,
                    Some(_) if seen.contains(&seq) => Replay::Replayed,
                    Some(_) => Replay::Fresh,
                };
                prop_assert_eq!(w.check(seq), expect, "seq {} highest {:?}", seq, highest);
                if mark {
                    prop_assert_eq!(w.mark(seq), expect);
                    if expect == Replay::Fresh {
                        seen.insert(seq);
                        highest = Some(highest.map_or(seq, |h| h.max(seq)));
                    }
                }
            }
        }
    }

    #[test]
    fn a_seq0_is_beyond_when_it_is_over_the_jump_bound_above_the_higher_of_highest_and_the_floor() {
        let mut w = ReplayWindow::new();
        // Nothing marked: measured from the floor (the session's `S_SEQ`).
        assert!(!w.beyond(100, 100 + SEQ_JUMP_MAX));
        assert!(w.beyond(100, 100 + SEQ_JUMP_MAX + 1));
        assert!(
            !w.beyond(100, 5),
            "a frame below the floor is not beyond anything"
        );
        // Marked: measured from the highest when that is above the floor.
        w.mark(1_000);
        assert!(!w.beyond(100, 1_000 + SEQ_JUMP_MAX));
        assert!(w.beyond(100, 1_000 + SEQ_JUMP_MAX + 1));
        // And from the floor when the sender's last answer is above it.
        assert!(!w.beyond(5_000, 5_000 + SEQ_JUMP_MAX));
        assert!(w.beyond(5_000, 5_000 + SEQ_JUMP_MAX + 1));
        // The window itself is not moved by asking.
        assert_eq!(w.highest(), Some(1_000));
        assert!(!w.beyond(u64::MAX, u64::MAX), "no overflow at the top");
    }
}
