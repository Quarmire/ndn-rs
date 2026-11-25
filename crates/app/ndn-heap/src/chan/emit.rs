//! `Heap::emit`, and what the setup asks of the sender's frame layer (docs/specs/channel.md, The
//! verbs).
//!
//! `emit` passes the writer gate (this device's key stands as a **writer** of the space by the
//! entries held now), makes sure the channel of the emission's mode exists so asks can be answered,
//! and hands the message to that channel's [`TxChannel`]. The gate is passed again only when the
//! trust generation or the space's fold version moved, so the steady state of `emit` reads two
//! atomics and takes no log lock.

use std::sync::{Arc, Weak};

use bytes::Bytes;
use ndn_foundation_types::Name;

use super::answer::FRAME_MAX;
use super::channels::{Admitted, Cap, SendKey};
use super::standing::{Who, gate};
use super::tx::{KeySource, Refused, Terms, TxChannel};
use super::verbs::{EmitError, EmitOptions};
use super::wire::{ChanAsk, ChannelMode};
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::rt::Instant;
use crate::space::Heap;

/// Where a channel's key comes from: the node's table.
struct NodeKeys {
    node: Weak<NodeInner>,
    space: Name,
    mode: ChannelMode,
}

impl KeySource for NodeKeys {
    fn current(&self) -> Option<SendKey> {
        self.node
            .upgrade()?
            .chan
            .channels
            .current(&self.space, self.mode)
    }

    fn exhausted(&self) {
        if let Some(node) = self.node.upgrade() {
            node.chan.channels.close(&self.space, self.mode);
        }
    }
}

impl NodeInner {
    /// The sender of the channel `key` names, made if there is none yet.
    pub(crate) fn chan_tx_for(
        &self,
        space: &Name,
        mode: ChannelMode,
        key: &SendKey,
        fold_version: Arc<std::sync::atomic::AtomicU64>,
    ) -> Arc<TxChannel> {
        let tx = &self.chan.tx;
        tx.get_or_make(space, mode, key.id, || {
            TxChannel::new(
                mode,
                key,
                Arc::new(NodeKeys {
                    node: Arc::downgrade(&self.arc()),
                    space: space.clone(),
                    mode,
                }),
                Arc::clone(&self.tasks),
                Arc::clone(&tx.carrier),
                Arc::clone(&tx.stats),
                fold_version,
            )
        })
    }

    /// A receiver was judged in (`ChanAsk` `ask`, admitted as `admitted`): what the session says of
    /// this sender, and the frames that follow the session on the stream are queued (the channel's
    /// `welcome`).
    pub(crate) fn chan_tx_welcome(&self, ask: &ChanAsk, admitted: &Admitted) -> Terms {
        let fallback = || Terms {
            table: Vec::new(),
            window: (ask.mode == ChannelMode::Window).then_some(super::answer::WINDOW),
            frame_max: FRAME_MAX,
            seq: admitted.seq,
        };
        let Some(key) = self.chan.channels.current(&ask.space, ask.mode) else {
            return fallback();
        };
        let Some(held) = self.space_of(&ask.space) else {
            return fallback();
        };
        let version = held.log.lock().fold.version();
        let tx = self.chan_tx_for(&ask.space, ask.mode, &key, version);
        tx.welcome(admitted.fresh, ask.since, Instant::now())
    }
}

impl Heap {
    /// Send `bytes` to the receivers of this space's live channel of `opts.mode`, as the emission
    /// of `path` (relative to the space): ephemeral, never an entry (docs/specs/channel.md).
    ///
    /// `Latest` (the default) keeps the newest message per path: a newer emission replaces an
    /// older one that was not sent yet, and the call never waits. `Reliable` sends every message in
    /// order on the carrier's stream and waits for queue room when the queue is full
    /// ([`Congestion::Block`](crate::Congestion::Block)) or drops the oldest queued message
    /// ([`Congestion::Drop`](crate::Congestion::Drop)); a drop is a gap the receivers see.
    /// `Window` is `Reliable` plus a window the sender keeps for receivers that join later. With
    /// `opts.stand` the last emission of the path also stands for a receiver that joins within
    /// that lifetime. **A sender with no receiver sends nothing and returns at once** (a standing
    /// value and a window are still kept).
    ///
    /// # Errors
    ///
    /// Each [`EmitError`] says why and, by [`EmitError::next`], what to do: `NotWriter` (ask the
    /// owner), `NotReady` (retry), `TooLarge` (send less), `Congested` (retry), `NoStream`
    /// (`Latest`, or put), `FixRequest` (`Latest` with `Block`), `SequenceExhausted` (emit again),
    /// `Local` (fix this device).
    pub async fn emit(
        &self,
        path: &Name,
        bytes: Bytes,
        opts: EmitOptions,
    ) -> Result<(), EmitError> {
        TxChannel::validate(&opts)?;
        let mode = opts.mode.channel();
        let now = Instant::now();
        for _ in 0..2 {
            let channel = self.sender(mode, now)?;
            match channel.emit(path, &bytes, &opts, now).await {
                Ok(()) => return Ok(()),
                Err(Refused::Error(e)) => return Err(e),
                // The channel ended (a re-judging, its sequence): the next one is made.
                Err(Refused::Gone) => {}
            }
        }
        Err(EmitError::NotReady {
            space: self.inner.name.clone(),
            why: "the channel ended while this emission was made".into(),
        })
    }

    /// The sender of the channel of `mode`, after the writer gate.
    fn sender(&self, mode: ChannelMode, now: Instant) -> Result<Arc<TxChannel>, EmitError> {
        let space = &self.inner.name;
        let node = &self.node;
        let generation = node.judge.generation();
        if let Some(held) = node.chan.tx.get(space, mode)
            && held.gate_valid(generation)
            && !held
                .live()
                .closed
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(held);
        }
        let log = self.inner.log.lock();
        let version = log.fold.version();
        let judged_at = (
            generation,
            version.load(std::sync::atomic::Ordering::SeqCst),
        );
        gate(&log, &node.judge, Who::Writer, "live data").map_err(|e| match e {
            HeapError::NotReady { why, .. } => EmitError::NotReady {
                space: space.clone(),
                why,
            },
            HeapError::NotAllowed { why, .. } => EmitError::NotWriter {
                space: space.clone(),
                why,
            },
            other => EmitError::Local {
                reason: other.to_string(),
            },
        })?;
        let audience = if log.sealed() {
            match log.fold.in_force() {
                Some(epoch) => Some(epoch),
                None => {
                    return Err(EmitError::NotReady {
                        space: space.clone(),
                        why: "this sealed space holds no epoch in force yet".into(),
                    });
                }
            }
        } else {
            None
        };
        let key = node
            .chan
            .channels
            .open(space, mode, audience, judged_at, now)
            .map_err(|_cap: Cap| EmitError::TooLarge {
                what: "channels of this device",
                size: super::channels::CHANNELS_PER_SENDER + 1,
                max: super::channels::CHANNELS_PER_SENDER,
            })?;
        drop(log);
        let channel = node.chan_tx_for(space, mode, &key, version);
        channel.set_gate(judged_at.0, judged_at.1);
        Ok(channel)
    }
}
