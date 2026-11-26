//! What tunes a node's channels (docs/specs/channel.md, Checkpoints): the checkpoint period, and
//! the detection window it states.

use std::time::Duration;

/// The checkpoint period a channel has unless the host sets one.
pub const CHECKPOINT_DEFAULT: Duration = Duration::from_millis(20);

/// The shortest checkpoint period: a sender signs at most 1,000 times a second.
pub const CHECKPOINT_MIN: Duration = Duration::from_millis(1);

/// The longest checkpoint period.
pub const CHECKPOINT_MAX: Duration = Duration::from_secs(2);

/// The verification queueing `ε` of the detection window: what a receiver adds between a
/// checkpoint reaching it and the evidence being recorded (it verifies one signature, 41 µs).
pub const VERIFY_EPSILON: Duration = Duration::from_millis(1);

/// What tunes a node's channels, as [`crate::Config::channel`].
///
/// # The detection window
///
/// A frame a key holder forged is delivered, as the sender's, to a receiver that trusts frames as
/// they arrive ([`crate::Trust::Prompt`]). The next checkpoint that covers it exposes it, with
/// evidence ([`crate::NodeHandle::channel_evidence`]), a [`crate::GetNotice::Retracted`] and an
/// [`crate::Alert::ChannelForgery`]. The stated window is
/// `W = P + d + ε`: the checkpoint period `P` ([`Self::checkpoint`], 20 ms by default), the
/// one-way delay `d` of the stream to the receiver, and `ε` ([`VERIFY_EPSILON`], 1 ms) of
/// verification. At the default and a 1 ms path, 22 ms: [`Self::detection_window`] computes it.
/// Inside the window an emission is authenticated as "a holder of the channel key's"; after a
/// covering checkpoint, as the sender's. [`crate::Trust::Verified`] closes the window by holding
/// delivery until the checkpoint has verified.
///
/// The period is a liveness bound, never a correctness one: a checkpoint that is late or lost
/// leaves frames unchecked (and held, under `Verified`), and never makes a frame look forged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelConfig {
    /// The checkpoint period of the channels this node sends on: a checkpoint is signed at most
    /// this often, and only while frames were sent since the last one (plus one empty checkpoint
    /// every 5 s while idle). Default [`CHECKPOINT_DEFAULT`] (20 ms); a value outside
    /// [`CHECKPOINT_MIN`] to [`CHECKPOINT_MAX`] (1 ms to 2 s) is taken as the nearest bound. It
    /// is carried in each session (`S_CKPT_MS`), which is how a receiver learns it.
    pub checkpoint: Duration,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        ChannelConfig {
            checkpoint: CHECKPOINT_DEFAULT,
        }
    }
}

impl ChannelConfig {
    /// The checkpoint period in force: [`Self::checkpoint`] within 1 ms to 2 s.
    pub fn period(&self) -> Duration {
        self.checkpoint.clamp(CHECKPOINT_MIN, CHECKPOINT_MAX)
    }

    /// The stated window `P + d + ε` for a stream whose one-way delay is `delay`.
    pub fn detection_window(&self, delay: Duration) -> Duration {
        self.period() + delay + VERIFY_EPSILON
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The period in force is the one set, held to 1 ms to 2 s: a zero would make the sender sign
    /// without pause, a very long one would make every verified receiver wait for nothing.
    #[test]
    fn the_period_is_clamped_to_one_millisecond_to_two_seconds() {
        let at = |d: Duration| ChannelConfig { checkpoint: d }.period();
        assert_eq!(ChannelConfig::default().period(), Duration::from_millis(20));
        assert_eq!(at(Duration::ZERO), CHECKPOINT_MIN);
        assert_eq!(at(Duration::from_micros(999)), Duration::from_millis(1));
        assert_eq!(at(Duration::from_millis(1)), Duration::from_millis(1));
        assert_eq!(at(Duration::from_millis(37)), Duration::from_millis(37));
        assert_eq!(at(Duration::from_secs(2)), Duration::from_secs(2));
        assert_eq!(at(Duration::from_millis(2_001)), Duration::from_secs(2));
        assert_eq!(at(Duration::MAX), CHECKPOINT_MAX);
        assert_eq!(CHECKPOINT_MIN, Duration::from_millis(1));
        assert_eq!(CHECKPOINT_MAX, Duration::from_millis(2_000));
    }

    /// The stated window is `W = P + d + epsilon`: 22 ms at the default period and a 1 ms path, and
    /// it follows the clamped period.
    #[test]
    fn the_detection_window_is_the_period_plus_the_delay_plus_one_millisecond() {
        let config = ChannelConfig::default();
        assert_eq!(
            config.detection_window(Duration::from_millis(1)),
            Duration::from_millis(22)
        );
        assert_eq!(VERIFY_EPSILON, Duration::from_millis(1));
        let slow = ChannelConfig {
            checkpoint: Duration::from_secs(60),
        };
        assert_eq!(
            slow.detection_window(Duration::ZERO),
            Duration::from_millis(2_001),
            "the period in force (2 s), not the one asked for"
        );
    }
}
