//! The network half of a heap node: sync groups, the notice, direct fetch,
//! catch-up, serving and the grant pull (spec §7).
//!
//! Everything this half needs of the node it asks through [`Host`], a narrow
//! trait the node implements over its spaces; nothing in `sync`, `fetch` or
//! `serve` reaches a [`Log`](crate::log::Log) or the store itself. The node
//! validates and admits what arrives (`Host::take`: the judge, then
//! `Log::admit` under the space's lock, the flush ticket, watchers, re-check);
//! this half asks for what the log says is missing (`Host::missing`), and
//! answers what the log says it may serve.
//!
//! Under construction: the module lands behind its `wip-sync` feature.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_sync::{StoreOp, SvsConfig};

use crate::log::{Blob, Outcome, Want};
use crate::register::EntryId;
use crate::seal::GrantRefusal;
use crate::trust::{Judged, Waiting};
use crate::wire::EpochId;

/// The `tracing` target of the timeline events (level `trace`): the few
/// seams a put crosses on its way to another device's watch, each named by
/// its message so a recorder can lay one put's journey out in time:
/// `put_returns`, `flush_begin`, `flush_end` (the node), `announce`,
/// `sync_update`, `fetch_out`, `fetch_in`, `fetch_miss`, `verify_begin`,
/// `verify_end` (this half) and `watch_send` (the node). Disabled, each
/// costs the callsite check and nothing else; none changes what a node does.
pub(crate) const TIMELINE: &str = "ndn_heap::timeline";

/// What the network half is tuned by; the node derives it from its `Config`.
#[derive(Clone, Debug)]
pub(crate) struct NetConfig {
    /// The SVS group configuration every group starts from (`local_seq`,
    /// `max_producers` and `vouch` are set per group).
    pub svs: SvsConfig,
    /// How long one Interest lives (default 2 s).
    pub lifetime: Duration,
    /// The most entries of one device asked for at once (default 32).
    pub window: usize,
    /// The most asks of every kind in flight at once on the node (default
    /// 256).
    pub in_flight: usize,
    /// How long a restarting device waits for the first group vector before
    /// it fetches its own entries from its peers (default 1 s).
    pub settle: Duration,
    /// `Config.reserve_block`: own entries are fetched back at most four
    /// blocks above the head.
    pub reserve_block: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            svs: SvsConfig::default(),
            lifetime: Duration::from_secs(2),
            window: 32,
            in_flight: 256,
            settle: Duration::from_secs(1),
            reserve_block: 1024,
        }
    }
}

/// What the node made of a packet it was handed to take.
#[derive(Debug)]
pub(crate) enum Taken {
    /// The judge decided and the log took it (or refused it, or knew it).
    /// `blobs` are the entries whose pieces are now to be fetched.
    Decided {
        /// What the log did, or the refusal the judge gave: a refused
        /// packet is not held, and what it was fetched for stays wanted.
        outcome: Outcome,
        /// Entries that carry a value in pieces and were applied.
        blobs: Vec<Blob>,
    },
    /// The judgement waits for something that is not here yet (a context
    /// to adopt, a certificate): the packet is not held, and is fetched
    /// again later.
    Pending(Waiting),
}

/// Everything the network half needs of the node, and nothing else. `space`
/// is always a space name (`<O>/32=data/…`) the node has open; for a space it
/// does not hold, each method answers with nothing (no wants, no packet, no
/// vouching).
///
/// Methods are synchronous unless they validate, which may fetch
/// certificates. None holds a lock across an `.await`.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait Host: Send + Sync + 'static {
    /// This device.
    fn device(&self) -> &Name;

    // -- admission --------------------------------------------------------------

    /// Take a packet fetched as an entry of `space`: decode it, judge it
    /// (`Judge::validate`), admit it (`Log::admit`) under the space's lock
    /// with everything that follows (flush ticket, publication routing,
    /// watchers, re-check of what it changed). Nothing is applied for a
    /// packet that does not verify.
    async fn take(&self, space: &Name, wire: Bytes) -> Taken;

    // -- what the log wants and knows --------------------------------------------

    /// Everything wanted of `space`: `Log::missing`. It shrinks only by
    /// holding, so a replayed notice never ends an ask.
    fn missing(&self, space: &Name) -> Vec<Want>;

    /// The highest seq heard of `device` in `space` (`Log::high`).
    fn high(&self, space: &Name, device: &Name) -> u64;

    /// This device's own head in `space` (`Log::head`).
    fn head(&self, space: &Name) -> u64;

    /// A notice or vector named `device` at `seen` in `space`
    /// (`Log::note_counter`): it raises what is wanted and nothing else. For
    /// this device's own name above its head the node raises
    /// `Alert::UnbackedCounter`; the head moves only when a verified entry
    /// is taken (D17).
    fn note_counter(&self, space: &Name, device: &Name, seen: u64);

    /// Whether an admitted entry of `device` is held in `space`: what keeps
    /// a device among the devices heard whatever a Sync Interest names.
    fn vouched(&self, space: &Name, device: &Name) -> bool;

    /// How `device` stands as a source for another device's packets
    /// (`Heard::relays`): `None` when it is not vouched for or has ended,
    /// `Some(true)` when its entries were held first.
    fn standing(&self, space: &Name, device: &Name) -> Option<bool>;

    // -- serving ----------------------------------------------------------------

    /// The packet of the entry `<device>/32=log/<space>/seq=<seq>` as this
    /// device may serve it: its own entry at or below its head and not held
    /// back (a structural entry not yet durable), or another device's entry
    /// only if it is held and admitted. `None` otherwise.
    fn served(&self, space: &Name, device: &Name, seq: u64) -> Option<Bytes>;

    /// The piece `piece` (a name under that entry's) of an entry
    /// [`Self::served`] would serve, from the store.
    fn served_piece(&self, space: &Name, device: &Name, seq: u64, piece: &Name) -> Option<Bytes>;

    /// This device's seal key packet when `name` is its name
    /// (`<device>/32=seal/<public key>`).
    fn seal_key_packet(&self, name: &Name) -> Option<Bytes>;

    // -- values in pieces -------------------------------------------------------

    /// The entries of `space` that carry a value in pieces and whose pieces
    /// are not all held: what is fetched at open and asked again while owed.
    fn blobs(&self, space: &Name) -> Vec<Blob>;

    /// All the pieces of entry `id` arrived and proved: write them as one
    /// batch and make the value readable.
    fn assembled(&self, space: &Name, id: &EntryId, ops: Vec<StoreOp>);

    // -- grants, reader side ----------------------------------------------------

    /// The epochs of `space` whose key is owed: a held owner-signed Epoch
    /// entry names it, this device may hold it, it does not, and an entry
    /// waits for it or it is the epoch in force.
    fn owed_keys(&self, space: &Name) -> Vec<EpochId>;

    /// The public half of this device's recipient key: the seal key its
    /// grant asks name.
    fn seal_public(&self) -> [u8; 32];

    /// Judge a packet signed by a device key that is not an entry (a seal
    /// key packet, a grant) for `space`, valid only if the key is
    /// `device`'s (`Judge::validate_device_packet`).
    async fn validate_device_packet(&self, space: &Name, data: &Data, device: &Name) -> Judged;

    /// A grant arrived: unwrap `content` (wrapped under the grant's `name`)
    /// with the recipient key and hold the key for `epoch` if it matches the
    /// check of a held owner-signed Epoch entry (`Log::key_arrived`), which
    /// opens what it unlocks. Whether the key was taken.
    fn key_arrived(&self, space: &Name, epoch: &EpochId, name: &Name, content: Bytes) -> bool;

    // -- grants, granter side ---------------------------------------------------

    /// Whether the key of `epoch` of `space` may be granted to a device
    /// `asker`: all four conditions of `seal::may_grant` for the asker's
    /// person, and an epoch this device made only once its entry is durable.
    fn may_grant(&self, space: &Name, epoch: &EpochId, asker: &Name) -> Result<(), GrantRefusal>;

    /// The grant packet named `name`, wrapping the key of `epoch` to the seal
    /// key `to` of device `asker` and signed by this device: decided again
    /// as [`Self::may_grant`]. `None` when it is refused now or cannot be
    /// signed.
    fn grant_packet(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        to: &[u8; 32],
        name: &Name,
    ) -> Option<Bytes>;
}
