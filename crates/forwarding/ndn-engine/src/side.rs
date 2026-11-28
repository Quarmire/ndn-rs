//! [`SideTable`]: the forwarder's generic fan-out table for side frames.
//!
//! A *side frame* (first octet [`SIDE_MARKER`](ndn_transport::SIDE_MARKER), see
//! [`ndn_transport::side`]) is not an NDN packet. The face reader peels it
//! before the NDN pipeline and hands it to [`SideTable::on_frame`], which routes
//! it on the 10 octets of its [`SideHeader`]: the id it carries finds a route, a
//! route has **one source face** and any number of **sink faces**, and the frame
//! goes to every sink, once per face, as a reference-counted clone of the same
//! bytes. The table is a lighter cousin of the PIT and holds nothing but opaque
//! 64-bit ids, [`FaceId`]s, times and counters: it never sees a name, a key, a
//! space, a person or a mode, decrypts and verifies nothing, and reads only the keep-alive
//! `UP` and the token of a `QUERY` or an `ANSWER` (the breadcrumb table, below).
//!
//! # How a route comes to be
//!
//! The interface is an NDNLPv2 header on a Data ([`ndn_packet::lp::SideRoute`],
//! TLV 0x0370: id and TTL). In the Data pipeline, after the PIT matched and after
//! validation, for each in-record face `f` other than the arrival face `a` the
//! engine calls [`SideTable::install_live`]`(id, a, f, ttl)` and sends the Data to
//! `f` with the header again, so the next forwarder does the same. A Data that
//! matched no PIT entry installs nothing, nor does one from a face the Interest
//! was not sent out of ([`SideRefusal::NotAsked`]), nor between faces that cannot
//! carry channel frames or are gone ([`SideRefusal::NotCarried`],
//! [`SideRefusal::FaceGone`]); a refusal is counted, logged with its reason, and
//! that face gets the Data **without** the header (bare TLV on a bare-TLV face; the
//! receiver then sees no frames and reports `NoPath`).
//!
//! # Rules the table keeps
//!
//! - A frame of an id from any face but the route's source is dropped
//!   (`wrong_source`); a face that is not a sink of the route cannot refresh or
//!   remove anything with `UP`.
//! - **Never blocks.** A sink is handed the frame with
//!   [`Face::forward_side_from`](ndn_transport::Face::forward_side_from), which
//!   must not wait. A sink that cannot take it costs that sink the frame and is
//!   counted `sink_full`: relays are lossy under congestion, visibly.
//! - `UP` `Keep` refreshes that sink's expiry (its TTL after the Keep) and forwards one Keep to
//!   the route's source while the sink is within its burst
//!   ([`keep_forward_burst`](SideLimits::keep_forward_burst): a sink's first Keeps go at once,
//!   so the source learns the route to each receiver is up, and a relay's one link toward the
//!   source carries the first Keep of every receiver behind it), then at most one per
//!   [`keep_forward_min`](SideLimits::keep_forward_min): at most one frame per 5 s per sink per
//!   hop keeps a path alive. `Unsub`
//!   removes that face's sink; when none is left the route is removed and the
//!   `Unsub` is forwarded to the source.
//! - **Breadcrumbs (the side PIT).** A `QUERY` ([`ndn_transport::side_header::QueryPrefix`])
//!   from a *live sink* of a route leaves `(route id, token) -> (ingress face, expiry)` and goes
//!   up to the route's source as a datagram, with the sink as ingress; the `ANSWER`
//!   ([`AnswerPrefix`]) from the source *removes* the breadcrumb and goes to that one face only.
//!   Bounds [`pit_total`](SideLimits::pit_total), [`pit_per_face`](SideLimits::pit_per_face),
//!   [`pit_per_route`](SideLimits::pit_per_route) with a share held for each live sink of the
//!   route ([`pit_route_reserve`](SideLimits::pit_route_reserve): no sink takes what the others
//!   are owed), a per-face [`query_rate`](SideLimits::query_rate), a per-route rate up to the
//!   source ([`route_query_rate`](SideLimits::route_query_rate)) and the source face's own
//!   [`SideRate`] (`quota`); a ttl of 100 ms to
//!   [`pit_ttl_max`](SideLimits::pit_ttl_max). Every refusal drops the frame and counts it
//!   (`pit_dup`, `pit_full`, `unmatched`, `late`, ...): no Nack frame is built. A barred sink's
//!   `QUERY` passes, a barred source's `ANSWER` is dropped. docs/specs/channel.md §14.13.
//! - Bounds ([`SideLimits`]): routes, routes per source face, sinks per route,
//!   routes per sink face. A refusal names which ([`SideRefusal`]).
//! - Time is the engine's **monotonic** clock (nanoseconds since the table was made,
//!   [`SideTable::new`]), read through the table's clock, never the wall clock: a step
//!   of the host's time must not lapse every sink or lift every bar. `sweep(now)`,
//!   `bar(face, now)` and `quarantine_for(face, now, length)` take it explicitly so a
//!   caller or a test can supply it.
//! - A face that goes down takes its routes with it
//!   ([`remove_face`](SideTable::remove_face), called at every site where the
//!   engine drops a face; [`drop_gone_faces`](SideTable::drop_gone_faces) in the
//!   1 s sweep catches any other).
//! - **Quarantine.** A barred face has the frames it **sends** dropped
//!   (`quarantined`) and no route installed from it; the NDN traffic over it is not
//!   the table's and goes on. Its `UP` records (`Keep`, `Unsub`) are its own sinks'
//!   management and still count (a route to a barred face is not cut by the bar; it
//!   lapses only if the face stops sending `Keep`s). [`bar`](SideTable::bar) is 60 s,
//!   doubling for each repeat on the same face up to 1 h, back to 60 s after an hour
//!   clean; a call while a bar is live changes nothing. An explicit length is capped
//!   at 1 h.
//! - **Rate.** [`SideRate`] is a bytes-per-second token bucket on what the table
//!   hands one sink face; over it a frame is dropped and counted `quota`.
//!   Default off on the Ethernet kinds, 1 MB/s on the radio kinds
//!   ([`FaceKind::Wfb`], `WifiAware`, `WifiDirect`), per face via
//!   [`set_rate`](SideTable::set_rate) and per kind in [`SideConfig`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use ndn_runtime::Runtime;
use ndn_transport::side_header::{AnswerPrefix, QueryPrefix, SideHeader, SideKind, UpOp, UpRecord};
use ndn_transport::{FaceId, FaceKind, FaceTable, SideClass, SideRefused};

/// The clock a [`SideTable`] reads: monotonic nanoseconds ([`SideTable::new`] builds it from the
/// engine runtime's `Now::now`, not the wall clock).
pub type SideClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A route's id: the 8 octets after the marker and the kind of every frame, and
/// the id in a Data's `SideRoute` header. Opaque to the forwarder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SideId(pub u64);

/// The bounds of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideLimits {
    /// Routes in the table (default 4,096).
    pub routes: usize,
    /// Routes one source face may feed (default 256).
    pub per_source_face: usize,
    /// Sink faces on one route (default 64).
    pub sinks_per_route: usize,
    /// Routes one face may be a sink of (default 1,024).
    pub per_sink_face: usize,
    /// The TTL of a sink installed with a TTL of zero (default 30 s).
    pub ttl_default: Duration,
    /// The longest TTL a header may ask for (default 300 s); longer is clamped.
    pub ttl_max: Duration,
    /// The least time between two `Keep`s one sink passes to its route's source, once the
    /// sink's burst ([`keep_forward_burst`](Self::keep_forward_burst)) is used (default 5 s).
    pub keep_forward_min: Duration,
    /// How many `Keep`s one sink may pass to the source in quick succession (default 8). A
    /// receiver's first `Keep` must reach the sender, which waits for it before it sends its
    /// stream frames; behind a relay, the receivers of one channel share the sender's hop as
    /// one sink, so the second receiver's first `Keep` is no sink's first at that hop. The
    /// burst lets one `Keep` per receiver through at once up to this many; the rate over a
    /// longer time is still one per [`keep_forward_min`](Self::keep_forward_min).
    pub keep_forward_burst: u32,
    /// Breadcrumbs the table holds, for `QUERY` frames in flight (default 16,384).
    pub pit_total: usize,
    /// Breadcrumbs one ingress face may hold (default 256).
    pub pit_per_face: usize,
    /// Breadcrumbs one route may hold (default 1,024).
    pub pit_per_route: usize,
    /// The breadcrumbs of a route held for each of its **live sinks** (default 8): a sink with
    /// fewer than this many on the route is always admitted (while the route is under
    /// [`pit_per_route`](Self::pit_per_route)), and a sink at or over it is admitted only while
    /// the route's room, less what every *other* live sink has not yet used of its share, is
    /// left. So one sink, or a few, cannot take the whole route: each other sink keeps this many
    /// queries in flight whatever they do. `pit_route_reserve × sinks_per_route` should not
    /// exceed `pit_per_route` (8 × 64 = 512 of 1,024 by default); 0 reserves nothing.
    pub pit_route_reserve: usize,
    /// `QUERY` frames per second one sink face may send, the rate at which its allowance refills
    /// (default 512). 0 refuses every `QUERY`.
    pub query_rate: u32,
    /// `QUERY` frames one sink face may send in quick succession (default 128).
    pub query_burst: u32,
    /// `QUERY` frames per second **all** the sinks of one route may send up to its source
    /// together (default 2,048, four faces' worth), a generic cell rate like
    /// [`query_rate`](Self::query_rate): `N` sinks at their own rate would otherwise put `N`
    /// times that into the source's queue. Counted `rate_refused`. 0 refuses every `QUERY`.
    pub route_query_rate: u32,
    /// `QUERY` frames the sinks of one route may send up in quick succession (default 512).
    pub route_query_burst: u32,
    /// The longest a breadcrumb lives (default 10 s); a `QUERY` asking for more is clamped. Not
    /// [`ttl_max`](Self::ttl_max), which bounds a *sink's* TTL.
    pub pit_ttl_max: Duration,
}

impl Default for SideLimits {
    fn default() -> Self {
        Self {
            routes: 4096,
            per_source_face: 256,
            sinks_per_route: 64,
            per_sink_face: 1024,
            ttl_default: Duration::from_secs(30),
            ttl_max: Duration::from_secs(300),
            keep_forward_min: Duration::from_secs(5),
            keep_forward_burst: 8,
            pit_total: 16_384,
            pit_per_face: 256,
            pit_per_route: 1024,
            pit_route_reserve: 8,
            query_rate: 512,
            query_burst: 128,
            route_query_rate: 2048,
            route_query_burst: 512,
            pit_ttl_max: Duration::from_secs(10),
        }
    }
}

/// A per-face limit on the octets a sink face is handed per second (a token
/// bucket with one second's burst). A frame that finds the bucket empty is
/// dropped and counted `quota`; any size of frame passes while the bucket holds
/// something, so a large frame is not refused for ever at a low rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideRate {
    /// Octets per second.
    pub bytes_per_sec: u64,
}

impl SideRate {
    /// 1 MB/s: the default on the radio kinds.
    pub const RADIO_DEFAULT: SideRate = SideRate {
        bytes_per_sec: 1_000_000,
    };
}

/// What the engine builds a [`SideTable`] from (`EngineConfig::side`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideConfig {
    /// The bounds.
    pub limits: SideLimits,
    /// The rate of a radio face ([`FaceKind::Wfb`], `WifiAware`, `WifiDirect`);
    /// `None` is off. Default 1 MB/s.
    pub radio_rate: Option<SideRate>,
    /// The rate of an Ethernet face (`Ethernet`, `EtherMulticast`); `None` is
    /// off. Default off.
    pub ethernet_rate: Option<SideRate>,
}

impl Default for SideConfig {
    fn default() -> Self {
        Self {
            limits: SideLimits::default(),
            radio_rate: Some(SideRate::RADIO_DEFAULT),
            ethernet_rate: None,
        }
    }
}

impl SideConfig {
    /// The rate a face of `kind` starts with.
    pub fn rate_for(&self, kind: FaceKind) -> Option<SideRate> {
        match kind {
            FaceKind::Wfb | FaceKind::WifiAware | FaceKind::WifiDirect => self.radio_rate,
            FaceKind::Ethernet | FaceKind::EtherMulticast => self.ethernet_rate,
            _ => None,
        }
    }
}

/// Why [`SideTable::install`] refused. Each says what to look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SideRefusal {
    /// The table holds its most routes.
    #[error(
        "this forwarder's channel route table is full: end a channel, or raise the route limit (`routes`) in its side configuration"
    )]
    TableFull,
    /// The upstream face already feeds its most routes.
    #[error(
        "too many channel routes already come from this upstream face: end one, or raise `per_source_face`"
    )]
    SourceFull,
    /// The route already fans out to its most faces.
    #[error(
        "this channel route already fans out to the most faces it may: raise `sinks_per_route`, or put the receivers behind a relay"
    )]
    SinkCap,
    /// The receiver's face is already a sink of its most routes.
    #[error(
        "too many channel routes already go to this receiver face: end one, or raise `per_sink_face`"
    )]
    SinkFaceFull,
    /// The route exists with another source.
    #[error(
        "a channel route with this id already comes from another face: the id is in use or the path changed; wait for the old route to lapse"
    )]
    SourceMismatch,
    /// The receiver's face is the face the Data arrived on.
    #[error("the receiver's face is the face the Data arrived on: a route cannot loop back")]
    SinkIsSource,
    /// The upstream face is barred.
    #[error(
        "the upstream face is quarantined for channel frames it forged: wait for the bar to end, or lift it with the `side/quarantine` command"
    )]
    Quarantined,
    /// A face of the route is not on this forwarder.
    #[error("a face of the route is no longer on this forwarder")]
    FaceGone,
    /// A face of the route cannot carry channel frames (a stream socket such as TCP, a bare
    /// IPC socket, a face with no datagram carrier): a route over it could never carry a frame
    /// or a `Keep`.
    #[error(
        "a face of the route cannot carry channel frames (a stream or IPC socket has no datagram carrier for them): the receiver is reached over a link that does, or a relay"
    )]
    NotCarried,
    /// The Data did not come from a face this forwarder sent the Interest out of.
    #[error(
        "the Data did not come from a face its Interest was sent out of: a route is installed only from the face that answered the request"
    )]
    NotAsked,
}

impl SideRefusal {
    /// A short stable name, for logs and management output.
    pub const fn label(self) -> &'static str {
        match self {
            SideRefusal::TableFull => "table_full",
            SideRefusal::SourceFull => "source_full",
            SideRefusal::SinkCap => "sink_cap",
            SideRefusal::SinkFaceFull => "sink_face_full",
            SideRefusal::SourceMismatch => "source_mismatch",
            SideRefusal::SinkIsSource => "sink_is_source",
            SideRefusal::Quarantined => "quarantined",
            SideRefusal::FaceGone => "face_gone",
            SideRefusal::NotCarried => "not_carried",
            SideRefusal::NotAsked => "not_asked",
        }
    }

    const COUNT: usize = 10;

    const fn index(self) -> usize {
        self as usize
    }
}

/// Why a frame was dropped before any sink saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideDrop {
    /// Not a valid routing header or `UP` record.
    Malformed,
    /// From a barred face.
    Quarantined,
    /// No route has the id.
    Unrouted,
    /// A frame of the id from a face that is not the route's source, or an
    /// `UP` from a face that is not a sink of it.
    WrongSource,
    /// A `QUERY` from a face over its [`query_rate`](SideLimits::query_rate).
    QueryRate,
    /// A `QUERY` whose (route, token) already has a breadcrumb.
    PitDup,
    /// A `QUERY` with the table already at [`pit_total`](SideLimits::pit_total).
    PitFull,
    /// A `QUERY` from a face already at [`pit_per_face`](SideLimits::pit_per_face).
    PitFaceFull,
    /// A `QUERY` on a route already at [`pit_per_route`](SideLimits::pit_per_route).
    PitRouteFull,
    /// An `ANSWER` with no breadcrumb for its (route, token), or whose face is gone.
    Unmatched,
    /// An `ANSWER` whose breadcrumb had expired.
    Late,
    /// The face the frame had to go to could not take it (full, gone or refusing).
    SinkFull,
    /// An `ANSWER` for a face whose [`SideRate`] had no room.
    Quota,
}

/// What [`SideTable::on_frame`] did with a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideOutcome {
    /// Dropped before any sink.
    Dropped(SideDrop),
    /// Fanned out: `sinks` live sinks, `delivered` took it, `dropped` did not
    /// (full, over rate, not carrying the class, gone).
    Routed {
        sinks: usize,
        delivered: usize,
        dropped: usize,
    },
    /// An `UP` `Keep`: the sink was refreshed; `forwarded` says whether one was
    /// passed to the route's source.
    Kept { forwarded: bool },
    /// An `UP` `Unsub`: the face's sink was removed; the route went with it if
    /// it was the last (`route_removed`), and only then is the `Unsub` passed
    /// to the source (`forwarded`).
    Unsubscribed {
        route_removed: bool,
        forwarded: bool,
    },
    /// A `QUERY`: a breadcrumb was left and the route's source was handed the frame.
    Queried,
    /// An `ANSWER`: its breadcrumb was consumed and the face that asked was handed the frame.
    Answered,
}

/// One sink of a route, for [`RouteInfo`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkInfo {
    pub face: FaceId,
    /// Time left until the sink lapses without a `Keep` (zero when overdue).
    pub expires_in: Duration,
}

/// One route, read-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    /// The route id.
    pub id: u64,
    /// The one face frames of this id may arrive from.
    pub source: FaceId,
    pub sinks: Vec<SinkInfo>,
    /// Frames and octets routed on it since it was made.
    pub frames: u64,
    pub bytes: u64,
    /// Time since it was made.
    pub age: Duration,
}

/// A snapshot of the table's counters: gauges (`routes`, `sinks`) and totals
/// since start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SideStats {
    pub routes: u64,
    pub sinks: u64,
    /// Frames offered to [`SideTable::on_frame`] and their octets.
    pub frames_in: u64,
    pub bytes_in: u64,
    /// Frames (and octets) handed to sinks: one per sink that took one.
    pub frames_out: u64,
    pub bytes_out: u64,
    /// Drops, by reason.
    pub unrouted: u64,
    pub wrong_source: u64,
    pub malformed: u64,
    /// A sink does not carry the frame's class.
    pub class_unsupported: u64,
    /// A sink over its [`SideRate`].
    pub quota: u64,
    pub quarantined: u64,
    /// A sink's queue or send buffer had no room (also a sink face that was
    /// gone from the face table).
    pub sink_full: u64,
    /// Frames a sender that hands them over itself ([`SideTable::send_local`]) was told `Full`
    /// for, because no live sink had room: not lost, the sender keeps them and offers them
    /// again, so not in `sink_full`.
    pub held_back: u64,
    /// A sink refused for another reason (too large for it, closed, I/O).
    pub sink_error: u64,
    /// `UP` records accepted from a sink, and `Keep`s passed on, `Unsub`s.
    pub keeps: u64,
    pub keeps_forwarded: u64,
    pub unsubs: u64,
    /// Sinks that lapsed for want of a `Keep`.
    pub sinks_lapsed: u64,
    /// Installs refused, by reason.
    pub refused_table_full: u64,
    pub refused_source_full: u64,
    pub refused_sink_cap: u64,
    pub refused_sink_face_full: u64,
    pub refused_source_mismatch: u64,
    pub refused_sink_is_source: u64,
    pub refused_quarantined: u64,
    pub refused_face_gone: u64,
    pub refused_not_carried: u64,
    pub refused_not_asked: u64,
    /// Breadcrumbs held now (a gauge), and the `QUERY`s passed up and `ANSWER`s passed down.
    pub breadcrumbs: u64,
    pub queries: u64,
    pub answers: u64,
    /// `QUERY`s over a face's rate, and the other refusals of the breadcrumb table: a duplicate
    /// (route, token), each bound, an `ANSWER` with no breadcrumb (`unmatched`) or an expired one
    /// (`late`).
    pub query_rate_refused: u64,
    pub pit_dup: u64,
    pub pit_full: u64,
    pub pit_face_full: u64,
    pub pit_route_full: u64,
    pub unmatched: u64,
    pub late: u64,
}

#[derive(Default)]
struct Counters {
    frames_in: AtomicU64,
    bytes_in: AtomicU64,
    frames_out: AtomicU64,
    bytes_out: AtomicU64,
    unrouted: AtomicU64,
    wrong_source: AtomicU64,
    malformed: AtomicU64,
    class_unsupported: AtomicU64,
    quota: AtomicU64,
    quarantined: AtomicU64,
    sink_full: AtomicU64,
    held_back: AtomicU64,
    sink_error: AtomicU64,
    keeps: AtomicU64,
    keeps_forwarded: AtomicU64,
    unsubs: AtomicU64,
    sinks_lapsed: AtomicU64,
    refused: [AtomicU64; SideRefusal::COUNT],
    queries: AtomicU64,
    answers: AtomicU64,
    query_rate_refused: AtomicU64,
    pit_dup: AtomicU64,
    pit_full: AtomicU64,
    pit_face_full: AtomicU64,
    pit_route_full: AtomicU64,
    unmatched: AtomicU64,
    late: AtomicU64,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// The first bar of a face, doubling per repeat.
const BAR_BASE: Duration = Duration::from_secs(60);
/// The longest bar.
const BAR_MAX: Duration = Duration::from_secs(3600);
/// A face that stays unbarred this long after a bar ended starts again at
/// [`BAR_BASE`].
const BAR_CLEAN: Duration = Duration::from_secs(3600);

/// Where a table's own clock starts, so that 0 can mean "never" in the stamps it keeps.
pub const CLOCK_ORIGIN: u64 = 1_000_000_000;

fn ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Per-face state: the rate bucket and the bar history. Shared with the sinks
/// that name the face, so the hot path takes no lookup for the rate.
struct FaceEntry {
    rate_on: AtomicBool,
    bucket: Mutex<Option<Bucket>>,
    /// The face is barred until this time (ns); 0: never was.
    barred_until: AtomicU64,
    strikes: Mutex<Strikes>,
    /// The last time a side frame was handed to this face (ns).
    last_sent: AtomicU64,
    /// The theoretical arrival time (ns) of this face's `QUERY` allowance: the face may send a
    /// `QUERY` while it is within the burst of it (the generic cell rate algorithm).
    query_tat: AtomicU64,
}

struct Bucket {
    rate: u64,
    tokens: i64,
    last: u64,
}

#[derive(Default)]
struct Strikes {
    count: u32,
    /// When the last bar ended.
    last_end: u64,
}

impl FaceEntry {
    fn new() -> Self {
        Self {
            rate_on: AtomicBool::new(false),
            bucket: Mutex::new(None),
            barred_until: AtomicU64::new(0),
            last_sent: AtomicU64::new(0),
            query_tat: AtomicU64::new(0),
            strikes: Mutex::new(Strikes::default()),
        }
    }

    fn set_rate(&self, rate: Option<SideRate>, now: u64) {
        let mut bucket = self.bucket.lock().unwrap();
        *bucket = rate.map(|r| Bucket {
            rate: r.bytes_per_sec,
            tokens: i64::try_from(r.bytes_per_sec).unwrap_or(i64::MAX),
            last: now,
        });
        self.rate_on.store(rate.is_some(), Ordering::Relaxed);
    }

    /// Whether a frame of `len` octets may go to the face now; charges it.
    fn admit(&self, now: u64, len: usize) -> bool {
        let mut bucket = self.bucket.lock().unwrap();
        let Some(b) = bucket.as_mut() else {
            return true;
        };
        let elapsed = now.saturating_sub(b.last);
        b.last = now;
        let add = (u128::from(elapsed) * u128::from(b.rate) / 1_000_000_000) as i64;
        let burst = i64::try_from(b.rate).unwrap_or(i64::MAX);
        b.tokens = b.tokens.saturating_add(add).min(burst);
        if b.tokens > 0 {
            b.tokens = b
                .tokens
                .saturating_sub(i64::try_from(len).unwrap_or(i64::MAX));
            true
        } else {
            false
        }
    }

    /// Whether this face may send a `QUERY` now, at `rate` a second with `burst` in quick
    /// succession; charges it. A rate of 0 refuses every `QUERY`.
    fn admit_query(&self, now: u64, rate: u32, burst: u32) -> bool {
        cell_admit(&self.query_tat, now, rate, burst)
    }
}

struct Sink {
    face: FaceId,
    entry: Arc<FaceEntry>,
    ttl_ns: AtomicU64,
    /// Lapses at this time (ns).
    expires: AtomicU64,
    /// Until when the `Keep`s this sink passed to the route's source are paid for (ns): each
    /// one adds `keep_forward_min`, and one is passed while what is owed is within the burst
    /// (`keep_forward_burst`). 0 before the first.
    kept: AtomicU64,
}

impl Sink {
    fn refresh(&self, now: u64) {
        self.expires.store(
            now.saturating_add(self.ttl_ns.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }
}

struct Route {
    source: FaceId,
    sinks: ArcSwap<Vec<Arc<Sink>>>,
    frames: AtomicU64,
    bytes: AtomicU64,
    created: u64,
    /// The source face's state, stamped when an `UP` record goes to it.
    source_entry: Arc<FaceEntry>,
    /// The theoretical arrival time (ns) of the route's `QUERY` allowance, all its sinks together
    /// ([`SideLimits::route_query_rate`]).
    query_tat: AtomicU64,
}

#[derive(Default)]
struct Quota {
    per_source: HashMap<FaceId, usize>,
    per_sink: HashMap<FaceId, usize>,
    routes: usize,
    sinks: usize,
}

impl Quota {
    fn dec(map: &mut HashMap<FaceId, usize>, face: FaceId) {
        if let Some(n) = map.get_mut(&face) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&face);
            }
        }
    }
}

/// What a frame's routing header says it is, for [`SideTable::on_frame`].
enum Parsed {
    /// `DATA`, `CHECKPOINT` or `CONTROL`: fanned out from the route's source.
    Fan,
    /// An `UP` record and its operation.
    Up(UpOp),
    /// A `QUERY` and the prefix a relay reads.
    Query(QueryPrefix),
    /// An `ANSWER` and the prefix a relay reads.
    Answer(AnswerPrefix),
}

/// One breadcrumb: the face a `QUERY` came over, and when it lapses (ns).
#[derive(Clone, Copy)]
struct Crumb {
    face: FaceId,
    expires: u64,
}

/// The breadcrumbs of the queries in flight, keyed by (route id, token), with the counts the
/// bounds read. Every change is made under one lock, so the counts and the map never disagree.
#[derive(Default)]
struct Pit {
    crumbs: HashMap<(u64, u64), Crumb>,
    per_face: HashMap<FaceId, usize>,
    per_route: HashMap<u64, usize>,
    /// What each sink face holds on each route: the share the route keeps for it
    /// ([`SideLimits::pit_route_reserve`]) is read from here.
    per_route_face: HashMap<(u64, FaceId), usize>,
}

impl Pit {
    fn insert(&mut self, key: (u64, u64), crumb: Crumb) {
        *self.per_face.entry(crumb.face).or_insert(0) += 1;
        *self.per_route.entry(key.0).or_insert(0) += 1;
        *self.per_route_face.entry((key.0, crumb.face)).or_insert(0) += 1;
        self.crumbs.insert(key, crumb);
    }

    fn remove(&mut self, key: (u64, u64)) -> Option<Crumb> {
        let crumb = self.crumbs.remove(&key)?;
        Quota::dec(&mut self.per_face, crumb.face);
        Quota::dec_key(&mut self.per_route, key.0);
        Quota::dec_route_face(&mut self.per_route_face, (key.0, crumb.face));
        Some(crumb)
    }

    /// Keep the breadcrumbs `keep` accepts; returns how many were removed.
    fn retain(&mut self, mut keep: impl FnMut(&(u64, u64), &Crumb) -> bool) -> usize {
        let Pit {
            crumbs,
            per_face,
            per_route,
            per_route_face,
        } = self;
        let before = crumbs.len();
        crumbs.retain(|key, crumb| {
            let kept = keep(key, crumb);
            if !kept {
                Quota::dec(per_face, crumb.face);
                Quota::dec_key(per_route, key.0);
                Quota::dec_route_face(per_route_face, (key.0, crumb.face));
            }
            kept
        });
        before - crumbs.len()
    }

    /// Whether `from`, a live sink of `route` (`sinks` are its sinks), may leave one more
    /// breadcrumb there. The route's bound is never passed. Under its share
    /// ([`SideLimits::pit_route_reserve`]) a sink is admitted; at or over it, only while the room
    /// left in the route, less what every other live sink has not used of its own share, is not
    /// spent: so no sink, and no few sinks, can take what the others are owed.
    fn route_has_room(
        &self,
        route: u64,
        from: FaceId,
        sinks: &[Arc<Sink>],
        now: u64,
        limits: &SideLimits,
    ) -> bool {
        let held = self.per_route.get(&route).copied().unwrap_or(0);
        if held >= limits.pit_per_route {
            return false;
        }
        let share = |face: FaceId| {
            self.per_route_face
                .get(&(route, face))
                .copied()
                .unwrap_or(0)
        };
        if share(from) < limits.pit_route_reserve {
            return true;
        }
        let owed: usize = sinks
            .iter()
            .filter(|s| s.face != from && s.expires.load(Ordering::Relaxed) > now)
            .map(|s| limits.pit_route_reserve.saturating_sub(share(s.face)))
            .sum();
        held.saturating_add(owed) < limits.pit_per_route
    }
}

impl Quota {
    fn dec_key(map: &mut HashMap<u64, usize>, key: u64) {
        if let Some(n) = map.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&key);
            }
        }
    }

    fn dec_route_face(map: &mut HashMap<(u64, FaceId), usize>, key: (u64, FaceId)) {
        if let Some(n) = map.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&key);
            }
        }
    }
}

/// The generic cell rate algorithm on the theoretical arrival time `tat` (ns): one cell is
/// admitted while `tat` is within `burst` cells of `now`, and each admitted cell moves it on by
/// `1 / rate` seconds. A rate of 0 admits nothing.
fn cell_admit(tat: &AtomicU64, now: u64, rate: u32, burst: u32) -> bool {
    if rate == 0 {
        return false;
    }
    let interval = (1_000_000_000 / u64::from(rate)).max(1);
    let tolerance = interval.saturating_mul(u64::from(burst.max(1)) - 1);
    tat.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |tat| {
        (tat.saturating_sub(now) <= tolerance).then(|| tat.max(now).saturating_add(interval))
    })
    .is_ok()
}

/// The forwarder's fan-out table for side frames; see the [module](self).
pub struct SideTable {
    config: SideConfig,
    clock: SideClock,
    routes: DashMap<u64, Arc<Route>>,
    /// Every change to routes, sinks and their per-face counts is made under
    /// this lock, so the counts and the table never disagree; the data path
    /// reads without it.
    quota: Mutex<Quota>,
    faces: DashMap<FaceId, Arc<FaceEntry>>,
    /// The latest time any face is barred until: the data path skips the bar
    /// lookup while it is in the past.
    latest_bar_end: AtomicU64,
    /// The breadcrumbs of the `QUERY` frames in flight. Taken after, never before, `quota`.
    pit: Mutex<Pit>,
    counters: Counters,
}

impl SideTable {
    /// A table on the engine's monotonic clock ([`Now::now`](ndn_runtime::Now::now)): its time
    /// is the nanoseconds since the table was made, offset by [`CLOCK_ORIGIN`] so that 0 stays
    /// "never". Not the wall clock: a step of the host's clock (NTP, a VM that resumed) must
    /// neither lapse every sink nor lift every bar.
    pub fn new(config: SideConfig, runtime: Arc<dyn Runtime>) -> Self {
        let start = runtime.now();
        Self::with_clock(
            config,
            Arc::new(move || {
                CLOCK_ORIGIN.saturating_add(ns(runtime.now().saturating_duration_since(start)))
            }),
        )
    }

    /// A table on `clock` (nanoseconds).
    pub fn with_clock(config: SideConfig, clock: SideClock) -> Self {
        Self {
            config,
            clock,
            routes: DashMap::new(),
            quota: Mutex::new(Quota::default()),
            faces: DashMap::new(),
            latest_bar_end: AtomicU64::new(0),
            pit: Mutex::new(Pit::default()),
            counters: Counters::default(),
        }
    }

    /// The table's bounds.
    pub fn limits(&self) -> SideLimits {
        self.config.limits
    }

    /// The TTL a sink installed with `ttl` gets: zero is
    /// [`ttl_default`](SideLimits::ttl_default), anything longer than
    /// [`ttl_max`](SideLimits::ttl_max) is clamped to it.
    pub fn clamp_ttl(&self, ttl: Duration) -> Duration {
        if ttl.is_zero() {
            self.config.limits.ttl_default
        } else {
            ttl.min(self.config.limits.ttl_max)
        }
    }

    /// The table's clock now (ns): what to pass to [`bar`](Self::bar),
    /// [`sweep`](Self::sweep) and [`quarantine_for`](Self::quarantine_for) in a caller
    /// that has no clock of its own.
    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    fn entry(&self, face: FaceId) -> Arc<FaceEntry> {
        if let Some(e) = self.faces.get(&face) {
            return Arc::clone(&e);
        }
        Arc::clone(
            &self
                .faces
                .entry(face)
                .or_insert_with(|| Arc::new(FaceEntry::new())),
        )
    }

    /// Give a face that was just added the rate its kind starts with
    /// ([`SideConfig::rate_for`]).
    pub fn configure_face(&self, face: FaceId, kind: FaceKind) {
        self.set_rate(face, self.config.rate_for(kind));
    }

    /// Set (or, with `None`, clear) the rate limit of sink face `face`.
    pub fn set_rate(&self, face: FaceId, rate: Option<SideRate>) {
        if rate.is_none() && !self.faces.contains_key(&face) {
            return;
        }
        self.entry(face).set_rate(rate, self.now());
    }

    // ---- install ----

    /// Add `sink` to route `id`, creating the route with `source` if it does
    /// not exist; refresh the sink's expiry if it is already one. `ttl` is
    /// clamped to [`SideLimits::ttl_max`]; zero means
    /// [`SideLimits::ttl_default`]. Refused, with the table unchanged, when the
    /// route exists with another source, a bound would be exceeded, the sink is
    /// the source, or the source is barred.
    pub fn install(
        &self,
        id: SideId,
        source: FaceId,
        sink: FaceId,
        ttl: Duration,
    ) -> Result<(), SideRefusal> {
        let result = self.install_inner(id, source, sink, ttl, None);
        if let Err(refusal) = result {
            self.note_refusal(refusal);
        }
        result
    }

    /// [`install`](Self::install) for the forwarder's own data path: `faces` is the engine's
    /// face table, and the route is installed only between two faces that are on it and that
    /// can carry channel frames ([`SideRefusal::FaceGone`], [`SideRefusal::NotCarried`]).
    /// Liveness is read under the table's lock, and the teardown of a face leaves the face table
    /// *before* [`remove_face`](Self::remove_face) takes that lock: an install either sees the
    /// face gone, or its sink is removed by the teardown that follows. No route is left to a
    /// face that went while the install was in flight.
    pub fn install_live(
        &self,
        id: SideId,
        source: FaceId,
        sink: FaceId,
        ttl: Duration,
        faces: &FaceTable,
    ) -> Result<(), SideRefusal> {
        let result = self.install_inner(id, source, sink, ttl, Some(faces));
        if let Err(refusal) = result {
            self.note_refusal(refusal);
        }
        result
    }

    fn check_faces(faces: &FaceTable, source: FaceId, sink: FaceId) -> Result<(), SideRefusal> {
        for face in [source, sink] {
            let Some(f) = faces.get(face) else {
                return Err(SideRefusal::FaceGone);
            };
            if f.side_frame_max() == 0 || !f.side_carries(SideClass::Datagram) {
                return Err(SideRefusal::NotCarried);
            }
        }
        Ok(())
    }

    /// Count an install refusal the caller decided (a face the table cannot
    /// see is gone).
    pub fn note_refusal(&self, refusal: SideRefusal) {
        bump(&self.counters.refused[refusal.index()]);
    }

    fn install_inner(
        &self,
        id: SideId,
        source: FaceId,
        sink: FaceId,
        ttl: Duration,
        live: Option<&FaceTable>,
    ) -> Result<(), SideRefusal> {
        let limits = &self.config.limits;
        if source == sink {
            return Err(SideRefusal::SinkIsSource);
        }
        let now = self.now();
        if self.is_quarantined(source, now) {
            return Err(SideRefusal::Quarantined);
        }
        let ttl = self.clamp_ttl(ttl);
        let ttl_ns = ns(ttl);

        let mut q = self.quota.lock().unwrap();
        if let Some(faces) = live {
            Self::check_faces(faces, source, sink)?;
        }
        let sink_entry = self.entry(sink);
        let new_sink = || {
            Arc::new(Sink {
                face: sink,
                entry: Arc::clone(&sink_entry),
                ttl_ns: AtomicU64::new(ttl_ns),
                expires: AtomicU64::new(now.saturating_add(ttl_ns)),
                kept: AtomicU64::new(0),
            })
        };
        let existing = self.routes.get(&id.0).map(|r| Arc::clone(&r));
        match existing {
            Some(route) => {
                if route.source != source {
                    return Err(SideRefusal::SourceMismatch);
                }
                let sinks = route.sinks.load_full();
                if let Some(s) = sinks.iter().find(|s| s.face == sink) {
                    s.ttl_ns.store(ttl_ns, Ordering::Relaxed);
                    s.refresh(now);
                    return Ok(());
                }
                if sinks.len() >= limits.sinks_per_route {
                    return Err(SideRefusal::SinkCap);
                }
                if q.per_sink.get(&sink).copied().unwrap_or(0) >= limits.per_sink_face {
                    return Err(SideRefusal::SinkFaceFull);
                }
                let mut v = Vec::with_capacity(sinks.len() + 1);
                v.extend(sinks.iter().cloned());
                v.push(new_sink());
                route.sinks.store(Arc::new(v));
                *q.per_sink.entry(sink).or_insert(0) += 1;
                q.sinks += 1;
            }
            None => {
                if q.routes >= limits.routes {
                    return Err(SideRefusal::TableFull);
                }
                if q.per_source.get(&source).copied().unwrap_or(0) >= limits.per_source_face {
                    return Err(SideRefusal::SourceFull);
                }
                if q.per_sink.get(&sink).copied().unwrap_or(0) >= limits.per_sink_face {
                    return Err(SideRefusal::SinkFaceFull);
                }
                self.routes.insert(
                    id.0,
                    Arc::new(Route {
                        source,
                        sinks: ArcSwap::from_pointee(vec![new_sink()]),
                        frames: AtomicU64::new(0),
                        bytes: AtomicU64::new(0),
                        created: now,
                        source_entry: self.entry(source),
                        query_tat: AtomicU64::new(0),
                    }),
                );
                *q.per_source.entry(source).or_insert(0) += 1;
                *q.per_sink.entry(sink).or_insert(0) += 1;
                q.routes += 1;
                q.sinks += 1;
            }
        }
        Ok(())
    }

    // ---- the data path ----

    /// Route one frame that arrived on `from`; `faces` is the engine's face
    /// table. **Never blocks.** `from` is the face the frame came over: the
    /// reader's face, or the app face of a locally originated frame.
    pub fn on_frame(&self, from: FaceId, frame: Bytes, faces: &FaceTable) -> SideOutcome {
        let c = &self.counters;
        bump(&c.frames_in);
        c.bytes_in.fetch_add(frame.len() as u64, Ordering::Relaxed);
        let Ok(header) = SideHeader::parse(&frame) else {
            return self.dropped(SideDrop::Malformed);
        };
        let parsed = match header.kind() {
            SideKind::Up => UpRecord::parse(&frame).map(|r| Parsed::Up(r.op)),
            SideKind::Query => QueryPrefix::parse(&frame).map(Parsed::Query),
            SideKind::Answer => AnswerPrefix::parse(&frame).map(Parsed::Answer),
            _ => Ok(Parsed::Fan),
        };
        let Ok(parsed) = parsed else {
            return self.dropped(SideDrop::Malformed);
        };
        let now = self.now();
        // A bar is on what a face SENDS as a source. Its `UP` records are its own sinks'
        // management (`Keep`, `Unsub`): they pass, bounded as ever, and name no route they
        // are not a sink of (`WrongSource`). Dropping them would let the sinks the face holds
        // lapse within the TTL and end the senders' routes to it: the bar would cut the link
        // in both directions. A `QUERY` is likewise a sink's own request, not a frame it
        // sources, and passes; an `ANSWER` is sourced, and is dropped.
        if !matches!(parsed, Parsed::Up(_) | Parsed::Query(_)) && self.is_quarantined(from, now) {
            return self.dropped(SideDrop::Quarantined);
        }
        let Some(route) = self.routes.get(&header.id()).map(|r| Arc::clone(&r)) else {
            return self.dropped(SideDrop::Unrouted);
        };
        match parsed {
            Parsed::Up(op) => self.on_up(header.id(), &route, op, from, frame, faces, now),
            Parsed::Query(query) => self.on_query(&route, query, from, frame, faces, now),
            Parsed::Answer(answer) => self.on_answer(&route, answer, from, frame, faces, now),
            Parsed::Fan => {
                if route.source != from {
                    return self.dropped(SideDrop::WrongSource);
                }
                route.frames.fetch_add(1, Ordering::Relaxed);
                route.bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                self.fan_out(&route, frame, header.class(), from, faces, now)
            }
        }
    }

    /// Route a frame the application of the face `from` hands over itself, and say so when the
    /// frame would be lost to a full sink: **`Err(Full)` with nothing counted but `held_back`**
    /// when `frame` is a data-class frame (`DATA`, `CHECKPOINT`, `CONTROL`, of either class) of
    /// a route whose source is `from`, the route has live sinks, and none of them has room for
    /// this frame now ([`Face::side_room_for`](ndn_transport::Face::side_room_for)). The frame
    /// is the sender's again, to keep and offer when there is room ([`SideTable::room`]);
    /// `on_frame` would have dropped it for each full sink and the sender would never have known.
    /// A stream frame is held back like a datagram: a `Reliable` or `Window` message that the
    /// first hop dropped would be a gap its own sender caused, with the sender told nothing.
    /// Any other frame (an `UP`, a `QUERY`, an `ANSWER`, one for no route, from a barred face,
    /// from a face that is not the route's source) is `on_frame`'s, with its counts, and is `Ok`.
    /// A sink that has room in the hint and refuses all the same (another sender filled it
    /// between the look and the send) costs that sink the frame, counted `sink_full`, as on any
    /// hop. **Never blocks.**
    pub fn send_local(
        &self,
        from: FaceId,
        frame: Bytes,
        faces: &FaceTable,
    ) -> Result<SideOutcome, SideRefused> {
        if let Ok(header) = SideHeader::parse(&frame)
            && !matches!(
                header.kind(),
                SideKind::Up | SideKind::Query | SideKind::Answer
            )
            && let Some(route) = self.routes.get(&header.id()).map(|r| Arc::clone(&r))
            && route.source == from
            && !self.is_quarantined(from, self.now())
            && !self.has_room(&route, &frame, header.class(), faces, self.now())
        {
            bump(&self.counters.held_back);
            return Err(SideRefused::Full);
        }
        Ok(self.on_frame(from, frame, faces))
    }

    /// Whether `frame`, a frame of its route, would find room at a sink now: at least one live
    /// sink has it for this frame
    /// ([`Face::side_room_for`](ndn_transport::Face::side_room_for): a face whose queues the frame
    /// does not all go through, a radio that picks phys by frame, answers for the queues of this
    /// frame), or the route has no live sink (there is nothing to wait for: the frame goes
    /// nowhere, as `on_frame` would have it), or `frame` is no side frame or of no route. A hint,
    /// as the faces' answer is: room is not reserved. What a sender that `send_local` told `Full`
    /// for this frame waits on.
    pub fn room(&self, frame: &Bytes, faces: &FaceTable) -> bool {
        let Ok(header) = SideHeader::parse(frame) else {
            return true;
        };
        let Some(route) = self.routes.get(&header.id()).map(|r| Arc::clone(&r)) else {
            return true;
        };
        self.has_room(&route, frame, header.class(), faces, self.now())
    }

    fn has_room(
        &self,
        route: &Route,
        frame: &Bytes,
        class: SideClass,
        faces: &FaceTable,
        now: u64,
    ) -> bool {
        let sinks = route.sinks.load();
        let mut live = false;
        for sink in sinks.iter() {
            if sink.expires.load(Ordering::Relaxed) <= now {
                continue;
            }
            live = true;
            if faces
                .get(sink.face)
                .is_some_and(|f| f.side_room_for(frame, class))
            {
                return true;
            }
        }
        !live
    }

    /// A `QUERY` from `from`, which must be a live sink of `route`: leave a breadcrumb for its
    /// token and hand the frame to the route's source as a datagram, with `from` as its ingress
    /// (the way an `UP` goes up). The refusals, cheapest first: not a sink, over the face's
    /// rate, a token already in flight, then each bound; each drops the frame and counts.
    #[allow(clippy::too_many_arguments)]
    fn on_query(
        &self,
        route: &Arc<Route>,
        query: QueryPrefix,
        from: FaceId,
        frame: Bytes,
        faces: &FaceTable,
        now: u64,
    ) -> SideOutcome {
        let limits = &self.config.limits;
        let sinks = route.sinks.load();
        let Some(sink) = sinks
            .iter()
            .find(|s| s.face == from && s.expires.load(Ordering::Relaxed) > now)
        else {
            return self.dropped(SideDrop::WrongSource);
        };
        if !sink
            .entry
            .admit_query(now, limits.query_rate, limits.query_burst)
        {
            return self.dropped(SideDrop::QueryRate);
        }
        let ttl = Duration::from_millis(u64::from(query.ttl_ticks.clamp(1, 100)) * 100)
            .min(limits.pit_ttl_max);
        let crumb = Crumb {
            face: from,
            expires: now.saturating_add(ns(ttl)),
        };
        let key = (query.id, query.token);
        {
            let mut pit = self.pit.lock().unwrap();
            // A breadcrumb that lapsed and was not swept yet is absent, not a duplicate.
            if pit.crumbs.get(&key).is_some_and(|c| c.expires <= now) {
                pit.remove(key);
            }
            if pit.crumbs.contains_key(&key) {
                drop(pit);
                return self.dropped(SideDrop::PitDup);
            }
            let refused = if pit.crumbs.len() >= limits.pit_total {
                Some(SideDrop::PitFull)
            } else if pit.per_face.get(&from).copied().unwrap_or(0) >= limits.pit_per_face {
                Some(SideDrop::PitFaceFull)
            } else if !pit.route_has_room(key.0, from, &sinks, now, limits) {
                Some(SideDrop::PitRouteFull)
            } else {
                None
            };
            if let Some(why) = refused {
                drop(pit);
                return self.dropped(why);
            }
            pit.insert(key, crumb);
        }
        // The breadcrumb is in before the frame goes: an answer may come back before this
        // returns. A forward that fails takes it out again, if it is still ours.
        let len = frame.len() as u64;
        // What goes up is paid for before it goes: the sinks of the route together, and the
        // source face's own rate (as every frame handed to a face is).
        if !cell_admit(
            &route.query_tat,
            now,
            limits.route_query_rate,
            limits.route_query_burst,
        ) {
            self.unwind(key, crumb);
            return self.dropped(SideDrop::QueryRate);
        }
        let source_entry = &route.source_entry;
        if source_entry.rate_on.load(Ordering::Relaxed) && !source_entry.admit(now, frame.len()) {
            self.unwind(key, crumb);
            return self.dropped(SideDrop::Quota);
        }
        let Some(source) = faces.get(route.source) else {
            self.unwind(key, crumb);
            return self.dropped(SideDrop::SinkFull);
        };
        match source.forward_side_from(frame, SideClass::Datagram, from) {
            Ok(()) => {
                let c = &self.counters;
                bump(&c.queries);
                bump(&c.frames_out);
                c.bytes_out.fetch_add(len, Ordering::Relaxed);
                route.frames.fetch_add(1, Ordering::Relaxed);
                route.bytes.fetch_add(len, Ordering::Relaxed);
                route.source_entry.last_sent.store(now, Ordering::Relaxed);
                SideOutcome::Queried
            }
            Err(refused) => {
                self.unwind(key, crumb);
                self.refused_by_sink(&refused);
                SideOutcome::Dropped(SideDrop::SinkFull)
            }
        }
    }

    /// Take back the breadcrumb of a `QUERY` that could not be forwarded, unless an answer or a
    /// sweep already took it or another query holds the token now.
    fn unwind(&self, key: (u64, u64), crumb: Crumb) {
        let mut pit = self.pit.lock().unwrap();
        if pit
            .crumbs
            .get(&key)
            .is_some_and(|c| c.face == crumb.face && c.expires == crumb.expires)
        {
            pit.remove(key);
        }
    }

    /// An `ANSWER` from `from`, which must be `route`'s source: consume the breadcrumb of its
    /// token and hand the frame, on the class it came on, to the one face that asked. The
    /// breadcrumb goes at the first lookup whatever follows, so a token answers once.
    #[allow(clippy::too_many_arguments)]
    fn on_answer(
        &self,
        route: &Arc<Route>,
        answer: AnswerPrefix,
        from: FaceId,
        frame: Bytes,
        faces: &FaceTable,
        now: u64,
    ) -> SideOutcome {
        if route.source != from {
            return self.dropped(SideDrop::WrongSource);
        }
        let crumb = self.pit.lock().unwrap().remove((answer.id, answer.token));
        let Some(crumb) = crumb else {
            return self.dropped(SideDrop::Unmatched);
        };
        if crumb.expires <= now {
            return self.dropped(SideDrop::Late);
        }
        let Some(face) = faces.get(crumb.face) else {
            return self.dropped(SideDrop::Unmatched);
        };
        let len = frame.len();
        let entry = self.faces.get(&crumb.face).map(|e| Arc::clone(&e));
        if let Some(e) = &entry
            && e.rate_on.load(Ordering::Relaxed)
            && !e.admit(now, len)
        {
            return self.dropped(SideDrop::Quota);
        }
        match face.forward_side_from(frame, answer.class, from) {
            Ok(()) => {
                let c = &self.counters;
                bump(&c.answers);
                bump(&c.frames_out);
                c.bytes_out.fetch_add(len as u64, Ordering::Relaxed);
                route.frames.fetch_add(1, Ordering::Relaxed);
                route.bytes.fetch_add(len as u64, Ordering::Relaxed);
                if let Some(e) = entry {
                    e.last_sent.store(now, Ordering::Relaxed);
                }
                SideOutcome::Answered
            }
            Err(refused) => {
                self.refused_by_sink(&refused);
                SideOutcome::Dropped(SideDrop::SinkFull)
            }
        }
    }

    fn dropped(&self, why: SideDrop) -> SideOutcome {
        let c = &self.counters;
        bump(match why {
            SideDrop::Malformed => &c.malformed,
            SideDrop::Quarantined => &c.quarantined,
            SideDrop::Unrouted => &c.unrouted,
            SideDrop::WrongSource => &c.wrong_source,
            SideDrop::Quota => &c.quota,
            SideDrop::QueryRate => &c.query_rate_refused,
            SideDrop::PitDup => &c.pit_dup,
            SideDrop::PitFull => &c.pit_full,
            SideDrop::PitFaceFull => &c.pit_face_full,
            SideDrop::PitRouteFull => &c.pit_route_full,
            SideDrop::Unmatched => &c.unmatched,
            SideDrop::Late => &c.late,
            SideDrop::SinkFull => &c.sink_full,
        });
        SideOutcome::Dropped(why)
    }

    fn fan_out(
        &self,
        route: &Route,
        frame: Bytes,
        class: SideClass,
        from: FaceId,
        faces: &FaceTable,
        now: u64,
    ) -> SideOutcome {
        let c = &self.counters;
        let sinks = route.sinks.load();
        let (mut live, mut delivered) = (0, 0);
        for sink in sinks.iter() {
            if sink.expires.load(Ordering::Relaxed) <= now {
                continue; // lapsed; the sweep removes it
            }
            live += 1;
            if sink.entry.rate_on.load(Ordering::Relaxed) && !sink.entry.admit(now, frame.len()) {
                bump(&c.quota);
                continue;
            }
            let Some(face) = faces.get(sink.face) else {
                bump(&c.sink_full);
                continue;
            };
            match face.forward_side_from(frame.clone(), class, from) {
                Ok(()) => {
                    delivered += 1;
                    bump(&c.frames_out);
                    sink.entry.last_sent.store(now, Ordering::Relaxed);
                    c.bytes_out.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
                Err(refused) => self.refused_by_sink(&refused),
            }
        }
        SideOutcome::Routed {
            sinks: live,
            delivered,
            dropped: live - delivered,
        }
    }

    fn refused_by_sink(&self, refused: &SideRefused) {
        let c = &self.counters;
        bump(match refused {
            SideRefused::Full => &c.sink_full,
            SideRefused::Unsupported | SideRefused::PeerLacksChannels | SideRefused::NotCarried => {
                &c.class_unsupported
            }
            _ => &c.sink_error,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn on_up(
        &self,
        id: u64,
        route: &Arc<Route>,
        op: UpOp,
        from: FaceId,
        frame: Bytes,
        faces: &FaceTable,
        now: u64,
    ) -> SideOutcome {
        let sinks = route.sinks.load();
        let Some(sink) = sinks.iter().find(|s| s.face == from) else {
            return self.dropped(SideDrop::WrongSource);
        };
        match op {
            UpOp::Keep => {
                bump(&self.counters.keeps);
                sink.refresh(now);
                // A sink passes `keep_forward_burst` Keeps in quick succession and then one per
                // `keep_forward_min` (the generic cell rate algorithm over `kept`).
                let limits = &self.config.limits;
                let every = ns(limits.keep_forward_min);
                let allowance =
                    every.saturating_mul(u64::from(limits.keep_forward_burst.max(1)) - 1);
                let owed_until = sink.kept.load(Ordering::Relaxed);
                let due = owed_until.saturating_sub(now) <= allowance;
                let forwarded = due && self.up_to_source(route, frame, from, faces);
                if forwarded {
                    sink.kept
                        .store(owed_until.max(now).saturating_add(every), Ordering::Relaxed);
                    bump(&self.counters.keeps_forwarded);
                }
                SideOutcome::Kept { forwarded }
            }
            UpOp::Unsub => {
                bump(&self.counters.unsubs);
                let route_removed = {
                    let mut q = self.quota.lock().unwrap();
                    self.retain_sinks(&mut q, id, route, |s| s.face != from).1
                };
                let forwarded = route_removed && self.up_to_source(route, frame, from, faces);
                SideOutcome::Unsubscribed {
                    route_removed,
                    forwarded,
                }
            }
        }
    }

    /// Pass an `UP` record to the route's source, as a datagram, telling it
    /// which face it came over.
    fn up_to_source(&self, route: &Route, frame: Bytes, from: FaceId, faces: &FaceTable) -> bool {
        let Some(source) = faces.get(route.source) else {
            return false;
        };
        match source.forward_side_from(frame, SideClass::Datagram, from) {
            Ok(()) => {
                route
                    .source_entry
                    .last_sent
                    .store(self.now(), Ordering::Relaxed);
                true
            }
            Err(refused) => {
                self.refused_by_sink(&refused);
                false
            }
        }
    }

    // ---- removal ----

    /// Remove the sinks of `route` that fail `keep`; the route goes with its
    /// last sink. Returns the number of sinks removed and whether the route
    /// was removed. The caller holds the quota lock.
    fn retain_sinks(
        &self,
        q: &mut Quota,
        id: u64,
        route: &Arc<Route>,
        keep: impl Fn(&Sink) -> bool,
    ) -> (usize, bool) {
        let current = route.sinks.load_full();
        let kept: Vec<Arc<Sink>> = current.iter().filter(|s| keep(s)).cloned().collect();
        let removed = current.len() - kept.len();
        if removed == 0 {
            return (0, false);
        }
        for s in current.iter().filter(|s| !keep(s)) {
            Quota::dec(&mut q.per_sink, s.face);
        }
        q.sinks -= removed;
        if kept.is_empty() {
            let gone = self
                .routes
                .remove_if(&id, |_, r| Arc::ptr_eq(r, route))
                .is_some();
            if gone {
                Quota::dec(&mut q.per_source, route.source);
                q.routes -= 1;
            }
            (removed, gone)
        } else {
            route.sinks.store(Arc::new(kept));
            (removed, false)
        }
    }

    /// Remove `route` and every sink of it. The caller holds the quota lock.
    fn remove_route(&self, q: &mut Quota, id: u64, route: &Arc<Route>) {
        self.retain_sinks(q, id, route, |_| false);
    }

    fn snapshot(&self) -> Vec<(u64, Arc<Route>)> {
        self.routes
            .iter()
            .map(|r| (*r.key(), Arc::clone(r.value())))
            .collect()
    }

    /// Drop every route `face` is the source of and every sink on `face`; a
    /// route left without sinks goes. Call when a face goes down, **after** it has
    /// left the face table (see [`install_live`](Self::install_live)). Keeps the
    /// face's bar history (a barred link that is dialed again at the same id
    /// is still barred) and drops its rate.
    pub fn remove_face(&self, face: FaceId) {
        let mut sourceless = HashSet::new();
        {
            let mut q = self.quota.lock().unwrap();
            for (id, route) in self.snapshot() {
                if route.source == face {
                    sourceless.insert(id);
                    self.remove_route(&mut q, id, &route);
                } else {
                    self.retain_sinks(&mut q, id, &route, |s| s.face != face);
                }
            }
        }
        // Its breadcrumbs go with it, and those of the routes it was the source of: no answer
        // can come down a route that has no source.
        self.pit
            .lock()
            .unwrap()
            .retain(|key, c| c.face != face && !sourceless.contains(&key.0));
        if let Some(e) = self.faces.get(&face) {
            e.set_rate(None, 0);
        }
    }

    /// Drop the sinks that lapsed (no `Keep` within their TTL) as of `now`
    /// (ns), and the routes left without any; also forget bar history that is
    /// an hour old. Returns the number of sinks removed. The engine calls it
    /// every second.
    pub fn sweep(&self, now: u64) -> usize {
        let mut removed = 0;
        {
            let mut q = self.quota.lock().unwrap();
            for (id, route) in self.snapshot() {
                removed += self
                    .retain_sinks(&mut q, id, &route, |s| {
                        s.expires.load(Ordering::Relaxed) > now
                    })
                    .0;
            }
        }
        self.counters
            .sinks_lapsed
            .fetch_add(removed as u64, Ordering::Relaxed);
        let clean = ns(BAR_CLEAN);
        self.faces.retain(|_, e| {
            let strikes = e.strikes.lock().unwrap();
            let recent = strikes.count > 0 && now < strikes.last_end.saturating_add(clean);
            e.rate_on.load(Ordering::Relaxed)
                || e.barred_until.load(Ordering::Relaxed) > now
                || recent
                || Arc::strong_count(e) > 1
        });
        self.pit.lock().unwrap().retain(|_, c| c.expires > now);
        removed
    }

    /// Drop the routes and sinks whose face is no longer in `faces`: the 1 s
    /// sweep's catch for any face that left without a `remove_face`.
    pub fn drop_gone_faces(&self, faces: &FaceTable) {
        let mut sourceless = HashSet::new();
        {
            let mut q = self.quota.lock().unwrap();
            for (id, route) in self.snapshot() {
                if faces.get(route.source).is_none() {
                    sourceless.insert(id);
                    self.remove_route(&mut q, id, &route);
                } else {
                    self.retain_sinks(&mut q, id, &route, |s| faces.get(s.face).is_some());
                }
            }
        }
        self.pit
            .lock()
            .unwrap()
            .retain(|key, c| !sourceless.contains(&key.0) && faces.get(c.face).is_some());
    }

    // ---- quarantine ----

    /// Whether `face` is barred at `now` (ns).
    pub fn is_quarantined(&self, face: FaceId, now: u64) -> bool {
        self.latest_bar_end.load(Ordering::Relaxed) > now
            && self
                .faces
                .get(&face)
                .is_some_and(|e| e.barred_until.load(Ordering::Relaxed) > now)
    }

    /// Bar `face` for `length` from `now` (ns): frames it sends are dropped (`quarantined`) and
    /// no route is installed from it; its `UP` records (its own sinks' `Keep`s and `Unsub`s)
    /// still count. A `length` over the longest bar (1 h) is that: no value makes a bar that
    /// never ends. An existing longer bar is kept. NDN traffic over the face is not affected.
    /// Returns the length applied.
    pub fn quarantine_for(&self, face: FaceId, now: u64, length: Duration) -> Duration {
        let length = length.min(BAR_MAX);
        self.bar_until(&self.entry(face), now.saturating_add(ns(length)));
        length
    }

    fn bar_until(&self, entry: &FaceEntry, until: u64) {
        entry.barred_until.fetch_max(until, Ordering::Relaxed);
        self.latest_bar_end.fetch_max(until, Ordering::Relaxed);
    }

    /// End `face`'s bar now. Its history stays, so the next [`bar`](Self::bar)
    /// still doubles.
    pub fn lift(&self, face: FaceId) {
        if let Some(e) = self.faces.get(&face) {
            e.barred_until.store(0, Ordering::Relaxed);
        }
    }

    /// Bar `face` for the next length of its history: 60 s, doubling for each
    /// repeat on the same face up to 1 h, and back to 60 s once the face has
    /// been clean for an hour since its last bar ended. Returns the length
    /// applied. While a bar is live a call changes nothing, not even the history (one
    /// incident that is reported twice, as a checkpoint lags the frames, is one bar, not two
    /// doublings), and returns what is left of the live bar.
    pub fn bar(&self, face: FaceId, now: u64) -> Duration {
        let entry = self.entry(face);
        let mut strikes = entry.strikes.lock().unwrap();
        let live_until = entry.barred_until.load(Ordering::Relaxed);
        if live_until > now {
            return Duration::from_nanos(live_until - now);
        }
        if strikes.count > 0 && now >= strikes.last_end.saturating_add(ns(BAR_CLEAN)) {
            strikes.count = 0;
        }
        let doubled = BAR_BASE
            .checked_mul(1u32 << strikes.count.min(16))
            .unwrap_or(BAR_MAX);
        let length = doubled.min(BAR_MAX);
        strikes.count = strikes.count.saturating_add(1);
        strikes.last_end = strikes.last_end.max(now.saturating_add(ns(length)));
        self.bar_until(&entry, now.saturating_add(ns(length)));
        length
    }

    // ---- read ----

    /// Live sinks of route `id`; a sender with none sends nothing.
    pub fn sinks(&self, id: SideId) -> usize {
        self.routes.get(&id.0).map_or(0, |r| r.sinks.load().len())
    }

    /// The largest datagram frame route `id`'s sinks take **now**: the smallest
    /// [`side_frame_max`](ndn_transport::Face::side_frame_max) over the sink faces that carry
    /// datagrams, each read live (a link's follows its path MTU search). `None`: the route has
    /// no such sink (or no route), so the table knows no limit. It names the first hop only:
    /// what a relay's own sinks take is that relay's table's to say. A sender asks it for each
    /// frame it builds, so a frame is never built over what a sink takes at that moment; a
    /// limit that falls after, a frame already built is refused by the link (counted
    /// `sink_error`) and lost like any datagram, never cut. A lapsed sink still counts until the
    /// sweep removes it, which only makes the answer smaller.
    pub fn datagram_limit(&self, id: SideId, faces: &FaceTable) -> Option<usize> {
        let route = self.routes.get(&id.0)?;
        let sinks = route.sinks.load();
        let mut limit: Option<usize> = None;
        for sink in sinks.iter() {
            let Some(face) = faces.get(sink.face) else {
                continue;
            };
            if !face.side_carries(SideClass::Datagram) {
                continue;
            }
            let max = face.side_frame_max();
            limit = Some(limit.map_or(max, |l| l.min(max)));
        }
        limit
    }

    /// How long ago a side frame last went out over `face` (to it as a sink, or an `UP` record
    /// to it as a source), in ns on the table's clock; `None` if never. The idle reaper counts
    /// it as the face's activity, as it does an NDN packet: frames the face *receives* are
    /// stamped by the reader.
    pub fn idle_ns(&self, face: FaceId) -> Option<u64> {
        let last = self.faces.get(&face)?.last_sent.load(Ordering::Relaxed);
        (last != 0).then(|| self.now().saturating_sub(last))
    }

    /// Routes that have `face` as their source or as a sink.
    pub fn routes_to(&self, face: FaceId) -> usize {
        let q = self.quota.lock().unwrap();
        q.per_source.get(&face).copied().unwrap_or(0) + q.per_sink.get(&face).copied().unwrap_or(0)
    }

    /// Every route, ordered by id. Read-only.
    pub fn list(&self) -> Vec<RouteInfo> {
        let now = self.now();
        let mut out: Vec<RouteInfo> = self
            .snapshot()
            .into_iter()
            .map(|(id, route)| RouteInfo {
                id,
                source: route.source,
                sinks: route
                    .sinks
                    .load()
                    .iter()
                    .map(|s| SinkInfo {
                        face: s.face,
                        expires_in: Duration::from_nanos(
                            s.expires.load(Ordering::Relaxed).saturating_sub(now),
                        ),
                    })
                    .collect(),
                frames: route.frames.load(Ordering::Relaxed),
                bytes: route.bytes.load(Ordering::Relaxed),
                age: Duration::from_nanos(now.saturating_sub(route.created)),
            })
            .collect();
        out.sort_by_key(|r| r.id);
        out
    }

    /// The faces currently barred, with when each bar ends (ns).
    pub fn quarantined(&self) -> Vec<(FaceId, u64)> {
        let now = self.now();
        let mut out: Vec<(FaceId, u64)> = self
            .faces
            .iter()
            .filter_map(|e| {
                let until = e.barred_until.load(Ordering::Relaxed);
                (until > now).then_some((*e.key(), until))
            })
            .collect();
        out.sort_by_key(|(f, _)| f.0);
        out
    }

    /// The counters.
    pub fn stats(&self) -> SideStats {
        let (routes, sinks) = {
            let q = self.quota.lock().unwrap();
            (q.routes as u64, q.sinks as u64)
        };
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let refused = |r: SideRefusal| get(&c.refused[r.index()]);
        SideStats {
            routes,
            sinks,
            frames_in: get(&c.frames_in),
            bytes_in: get(&c.bytes_in),
            frames_out: get(&c.frames_out),
            bytes_out: get(&c.bytes_out),
            unrouted: get(&c.unrouted),
            wrong_source: get(&c.wrong_source),
            malformed: get(&c.malformed),
            class_unsupported: get(&c.class_unsupported),
            quota: get(&c.quota),
            quarantined: get(&c.quarantined),
            sink_full: get(&c.sink_full),
            held_back: get(&c.held_back),
            sink_error: get(&c.sink_error),
            keeps: get(&c.keeps),
            keeps_forwarded: get(&c.keeps_forwarded),
            unsubs: get(&c.unsubs),
            sinks_lapsed: get(&c.sinks_lapsed),
            refused_table_full: refused(SideRefusal::TableFull),
            refused_source_full: refused(SideRefusal::SourceFull),
            refused_sink_cap: refused(SideRefusal::SinkCap),
            refused_sink_face_full: refused(SideRefusal::SinkFaceFull),
            refused_source_mismatch: refused(SideRefusal::SourceMismatch),
            refused_sink_is_source: refused(SideRefusal::SinkIsSource),
            refused_quarantined: refused(SideRefusal::Quarantined),
            refused_face_gone: refused(SideRefusal::FaceGone),
            refused_not_carried: refused(SideRefusal::NotCarried),
            refused_not_asked: refused(SideRefusal::NotAsked),
            breadcrumbs: self.pit.lock().unwrap().crumbs.len() as u64,
            queries: get(&c.queries),
            answers: get(&c.answers),
            query_rate_refused: get(&c.query_rate_refused),
            pit_dup: get(&c.pit_dup),
            pit_full: get(&c.pit_full),
            pit_face_full: get(&c.pit_face_full),
            pit_route_full: get(&c.pit_route_full),
            unmatched: get(&c.unmatched),
            late: get(&c.late),
        }
    }
}
