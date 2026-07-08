//! Named-time core — the pure, `no_std` heart of a trusted, uncertainty-bounded
//! time protocol for ndn-rs.
//!
//! Named-time treats **time as data**: a clock reading is a named, signed Data
//! packet, so NDN's naming ("the nearest good clock answers") and security
//! (nothing acts on unvalidated data) apply directly. This crate is the part
//! that has no I/O and no hardware — the taxonomy and the math — so it is
//! `no_std`, allocation-free, and unit-testable with a simulated clock. The
//! concrete sources (GNSS/RTC/NTP shims, the peer-derived source) and the wire
//! carriage live in sibling crates.
//!
//! # The load-bearing ideas
//!
//! - **Uncertainty is first-class** ([`TimeInterval`]): a reading is an interval
//!   `[center ± radius]`, never a point. "I don't know the time well enough" is
//!   representable, which is what makes the system safe under degradation *and*
//!   under attack.
//! - **A measurement carries its adversary exposure, not just its noise**
//!   ([`Measured`], [`MeasurementProvenance`]). Signing proves *who* and
//!   *whether-altered*; it does nothing about delay, replay, or relay. So a
//!   sample states whether it is distance-bounded, replay-protected, and
//!   authenticated — and the combiner reasons over that lattice rather than
//!   counting green checkmarks.
//! - **Capabilities are self-describing** ([`ClockCapability`], [`Holdover`]):
//!   a GPS-disciplined OCXO and an ESP32 RC oscillator are the same type with
//!   different honest numbers, and holdover turns "time since last sync" into a
//!   growing uncertainty.
//! - **Robustness is not admission** ([`combine::marzullo`]): the Marzullo
//!   combiner rejects a *minority* of false tickers; it does nothing against a
//!   fabricated majority. Admission (who may speak for time) happens upstream in
//!   the trust schema; this crate assumes its inputs were already admitted.
//! - **Enforcement ratchets soft → hard** ([`ratchet`]): certificate validity
//!   windows can only be enforced once wall-clock uncertainty is tight enough.
//!   The ratchet is fail-closed (soft withholds high-stakes actions, never
//!   grants leniently) and its grants are append-only, which is what makes the
//!   bootstrap terminate rather than deadlock.
//! - **The best local clock self-elects** ([`election`]): clock quality becomes
//!   the CCLF election weight, so the tightest clock beacons the anchor first
//!   and worse clocks overhear and cancel — a local GPS out-elects a WAN NTP
//!   uplink by construction, and losing a reference *is* yielding.
//! - **Offsets come from timestamps three ways** ([`measure`]): two-way (PTP
//!   `t1..t4`), one-way (a stamped broadcast + modelled delay), and common-view
//!   (two receivers of one event, cancelling the transmitter's clock). Each
//!   yields a `Measured<i64>` offset whose uncertainty reflects the path — and
//!   common-view is forced `distance_bounded = false` because a relay defeats it.
//! - **One loop ties it together** ([`discipline`]): SENSE per-peer samples →
//!   DECIDE (age by holdover, admit, Marzullo-combine, regress offset + frequency
//!   skew) → ACT (a capability-gated slew/step/track, or a fail-closed withhold).
//!   It only ever moves the *wall* estimate; the monotonic floor is untouched.
//!
//! See the contributor book's "named-time" material and ADR 0007 for the crate
//! boundary (why the stamp types live here rather than in `ndn-frame-io`).
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod beacon;
pub mod capability;
pub mod combine;
pub mod discipline;
pub mod domain_map;
pub mod election;
pub mod interval;
pub mod link_clock;
pub mod measure;
pub mod provenance;
pub mod ratchet;
pub mod sample;
pub mod stamp;

pub use beacon::TimeBeacon;
pub use capability::{ClockCapability, Holdover, TimeSourceKind, Traceability};
pub use discipline::{Correction, Discipline, PeerSample, TimePolicy, TimeState};
pub use election::{ElectionParams, anchor_weight};
pub use domain_map::DomainMap;
pub use interval::TimeInterval;
pub use link_clock::{RadioClockKind, RadioTimeSource};
pub use measure::{RxObs, TwoWay, common_view, offset_to_wall, one_way, two_way};
pub use provenance::{Authenticity, KeyId, Measured, MeasurementProvenance, PathId};
pub use ratchet::{Ratchet, WindowEnforcement};
pub use sample::TimeSample;
pub use stamp::{ClockDomainId, LatchPoint, LinkStamp};
