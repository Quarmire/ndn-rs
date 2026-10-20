//! Control-response and status-dataset wire helpers.
//!
//! - `send_response` / `build_mgmt_response_wire` — encode a
//!   `ControlResponse`, signing it when a host signer is wired.
//! - `build_segmented_dataset` + `send_dataset` — segment a status
//!   dataset per ndn-cxx `mgmt/status-dataset-context.cpp`.
//! - `HeldDatasets` — the segments of a multi-segment dataset, served by
//!   exact name after the first answers the dataset Interest (ndn-cxx
//!   `mgmt/dispatcher.cpp` keeps them in an in-memory storage the same way).

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use ndn_face_local::InProcHandle;
use ndn_packet::{
    Name, NameComponent,
    encode::{DataBuilder, encode_data_unsigned},
    meta_info::ContentType,
};

use ndn_mgmt_wire::{ControlResponse, control_response::status};

pub(crate) async fn send_response(
    handle: &InProcHandle,
    name: &Name,
    resp: &ControlResponse,
    signer: Option<&dyn ndn_security::Signer>,
) {
    let content = resp.encode();
    let data = build_mgmt_response_wire(name, &content, signer);
    let data_len = data.len();
    tracing::debug!(target: "mgmt", name = %name, status = resp.status_code, bytes = data_len, "nfd-mgmt: sending Control Data response");
    if let Err(e) = handle.send(data).await {
        tracing::warn!(target: "mgmt", error = %e, "nfd-mgmt: failed to send Data response");
    } else {
        tracing::debug!(target: "mgmt", name = %name, bytes = data_len, "nfd-mgmt: Control Data response queued to engine");
    }
}

/// Encode a management control-response Data packet, signing with
/// `signer` when wired and falling back to `DigestSha256` otherwise.
/// NFD's `ControlCommandResponseDispatcher` signs every response with
/// the daemon's identity key; ndn-cxx clients configured against an NFD
/// trust schema reject the bare-digest variant.
pub(crate) fn build_mgmt_response_wire(
    name: &Name,
    content: &[u8],
    signer: Option<&dyn ndn_security::Signer>,
) -> bytes::Bytes {
    match signer {
        Some(s) => {
            // FreshnessPeriod=0 keeps mgmt responses out of intermediate caches.
            let key_name = s
                .cert_name()
                .cloned()
                .or_else(|| Some(s.key_name().clone()));
            DataBuilder::new(name.clone(), content)
                .freshness(std::time::Duration::ZERO)
                .sign_sync(s.sig_type(), key_name.as_ref(), |region| {
                    s.sign_sync(region).unwrap_or_default()
                })
        }
        None => encode_data_unsigned(name, content),
    }
}

/// Per-Data payload budget for status datasets (matches ndn-cxx
/// `mgmt/status-dataset-context.cpp` — `MAX_NDN_PACKET_SIZE - 800`).
pub(crate) const MAX_DATASET_PAYLOAD_LEN: usize = 8000;

/// Segment a status dataset into Data wires named
/// `<interest>/v=<version>/seg=<n>`. The last segment carries
/// `FinalBlockId = seg=<last>`. Mirrors ndn-cxx
/// `mgmt/dispatcher.cpp` + `mgmt/status-dataset-context.cpp`.
fn build_segmented_dataset(
    base_name: &Name,
    version: u64,
    content: &[u8],
    signer: Option<&dyn ndn_security::Signer>,
) -> Vec<Bytes> {
    let total = content.len();
    let last_seg = if total == 0 {
        0
    } else {
        (total - 1) / MAX_DATASET_PAYLOAD_LEN
    };

    (0..=last_seg)
        .map(|seg| {
            let start = seg * MAX_DATASET_PAYLOAD_LEN;
            let end = ((seg + 1) * MAX_DATASET_PAYLOAD_LEN).min(total);
            let chunk = &content[start..end];

            let seg_name = base_name
                .clone()
                .append_version(version)
                .append_segment(seg as u64);

            let mut builder =
                DataBuilder::new(seg_name, chunk).freshness(std::time::Duration::ZERO);
            if seg == last_seg {
                builder = builder.final_block_id_typed_seg(last_seg as u64);
            }
            sign_segment(builder, signer)
        })
        .collect()
}

/// Audit M-1: sign a dataset Data with the daemon signer when wired (NFD
/// signs datasets with the daemon identity; schema-validating ndn-cxx
/// clients reject the bare-digest variant). Fall back to DigestSha256 only
/// when no signer is configured.
fn sign_segment(builder: DataBuilder, signer: Option<&dyn ndn_security::Signer>) -> Bytes {
    match signer {
        Some(s) => {
            let key_name = s
                .cert_name()
                .cloned()
                .or_else(|| Some(s.key_name().clone()));
            builder.sign_sync(s.sig_type(), key_name.as_ref(), |region| {
                s.sign_sync(region).unwrap_or_default()
            })
        }
        None => builder.sign_digest_sha256(),
    }
}

/// How long the segments of a multi-segment dataset stay fetchable by exact
/// name after the dataset is answered. A local reader fetches them within
/// milliseconds; the margin covers a slow or busy one.
const HELD_DATASET_LIFETIME: Duration = Duration::from_secs(10);

/// At most this many bytes of segments are held; past it the oldest datasets
/// are dropped first (the newest is always held).
const HELD_DATASET_MAX_BYTES: usize = 64 << 20;

/// The segments of recently answered datasets, by versioned name. The
/// dataset Interest is answered with segment 0; a reader fetches the rest by
/// exact name (`<dataset>/v=<version>/seg=<k>`), and [`answer`](Self::answer)
/// serves them from here — the dataset is not computed again, so every
/// segment of a version belongs to the same snapshot.
#[derive(Default)]
pub(crate) struct HeldDatasets {
    inner: Mutex<HeldInner>,
}

#[derive(Default)]
struct HeldInner {
    datasets: VecDeque<HeldDataset>,
    bytes: usize,
    last_version: u64,
}

struct HeldDataset {
    /// `<dataset>/v=<version>`.
    versioned: Name,
    segments: Vec<Bytes>,
    bytes: usize,
    held_until: web_time::Instant,
}

impl HeldInner {
    /// Drop expired datasets, then the oldest while over the byte budget —
    /// never the newest. Lifetimes are equal, so the expired are in front.
    fn expire(&mut self, now: web_time::Instant) {
        while let Some(front) = self.datasets.front() {
            let expired = front.held_until <= now;
            let over_budget = self.bytes > HELD_DATASET_MAX_BYTES && self.datasets.len() > 1;
            if !expired && !over_budget {
                break;
            }
            self.bytes -= front.bytes;
            self.datasets.pop_front();
        }
    }
}

impl HeldDatasets {
    /// A version for the next dataset: the wall clock in milliseconds (NFD's
    /// choice), but above every version this daemon gave before, so two
    /// answers within one millisecond never share a name.
    fn next_version(&self) -> u64 {
        // `web_time` proxies to `Date.now()` in the browser; `std::time` on
        // native. `std::time::SystemTime::now()` panics on wasm32.
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let version = now_ms.max(inner.last_version.saturating_add(1));
        inner.last_version = version;
        version
    }

    fn hold(&self, versioned: Name, segments: Vec<Bytes>) {
        let now = web_time::Instant::now();
        let bytes = segments.iter().map(Bytes::len).sum();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.bytes += bytes;
        inner.datasets.push_back(HeldDataset {
            versioned,
            segments,
            bytes,
            held_until: now + HELD_DATASET_LIFETIME,
        });
        inner.expire(now);
    }

    /// The answer to an Interest for one segment of a dataset version —
    /// a name ending in a version and a segment component, which no command
    /// name does: the held segment, or, once the version is gone (expired,
    /// or never this daemon's), a Data of ContentType Nack at that name
    /// carrying a 404 `ControlResponse`, so the reader fails at once instead
    /// of waiting out its Interest. `None` for any other name.
    pub(crate) fn answer(
        &self,
        name: &Name,
        signer: Option<&dyn ndn_security::Signer>,
    ) -> Option<Bytes> {
        let (seg, versioned) = segment_of(name)?;
        let held = {
            let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            inner.expire(web_time::Instant::now());
            inner
                .datasets
                .iter()
                .find(|d| d.versioned.components() == versioned)
                .and_then(|d| usize::try_from(seg).ok().and_then(|i| d.segments.get(i)))
                .cloned()
        };
        Some(held.unwrap_or_else(|| {
            let resp = ControlResponse::error(
                status::NOT_FOUND,
                "this dataset version is no longer held: read the dataset again",
            );
            let builder = DataBuilder::new(name.clone(), &resp.encode())
                .content_type(ContentType::Nack)
                .freshness(Duration::ZERO);
            sign_segment(builder, signer)
        }))
    }
}

/// The segment number and the versioned name (`…/v=<n>`) of a dataset
/// segment name `…/v=<n>/seg=<k>`; `None` for any other name.
fn segment_of(name: &Name) -> Option<(u64, &[NameComponent])> {
    let (last, versioned) = name.components().split_last()?;
    let seg = last.as_segment()?;
    versioned.last()?.as_version()?;
    Some((seg, versioned))
}

#[cfg(test)]
/// NDN NonNegativeInteger: 1, 2, 4, or 8 bytes big-endian (shortest form).
fn seg_to_nni(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    if v <= 0xFF {
        vec![be[7]]
    } else if v <= 0xFFFF {
        vec![be[6], be[7]]
    } else if v <= 0xFFFF_FFFF {
        vec![be[4], be[5], be[6], be[7]]
    } else {
        be.to_vec()
    }
}

/// Answer a dataset Interest named `name`: segment 0 goes out now; when the
/// dataset spans more, every segment is held in `held` for exact-name fetch.
pub(crate) async fn send_dataset(
    handle: &InProcHandle,
    name: &Name,
    content: Bytes,
    signer: Option<&dyn ndn_security::Signer>,
    held: &HeldDatasets,
) {
    let version = held.next_version();
    let segments = build_segmented_dataset(name, version, &content, signer);
    let first = segments[0].clone();
    if segments.len() > 1 {
        held.hold(name.clone().append_version(version), segments);
    }
    if let Err(e) = handle.send(first).await {
        tracing::warn!(target: "engine", error = %e, "nfd-mgmt: failed to send dataset segment");
    }
}

#[cfg(test)]
mod e04_tests {
    use super::*;
    use ndn_packet::Data;

    /// A single-segment payload still gets `<base>/v=<v>/seg=0` naming
    /// and `FinalBlockId = seg=0`, per ndn-cxx
    /// `mgmt/dispatcher.cpp:282-297`.
    #[test]
    fn e04_single_segment_response_carries_version_segment_and_final_block_id() {
        let base: Name = "/localhost/nfd/faces/list".parse().unwrap();
        let content = vec![0x42u8; 100];
        let segments = build_segmented_dataset(&base, 17, &content, None);

        assert_eq!(segments.len(), 1, "small dataset must produce 1 segment");

        let data = Data::decode(segments[0].clone()).expect("segment must parse");
        let comps = data.name.components();
        let n = comps.len();

        assert_eq!(comps[n - 2].typ, ndn_packet::tlv_type::VERSION);
        assert_eq!(comps[n - 1].typ, ndn_packet::tlv_type::SEGMENT);
        assert_eq!(comps[n - 1].as_segment(), Some(0));

        let mi = data.meta_info().expect("must carry MetaInfo");
        let fb = mi.final_block_id.as_ref().expect("FinalBlockId required");
        // SegmentNameComponent TLV: type=0x32 len=0x01 value=0x00.
        assert_eq!(fb.as_ref(), &[0x32u8, 0x01, 0x00]);
    }

    /// Payloads larger than `MAX_DATASET_PAYLOAD_LEN` produce multiple
    /// segments; only the last carries `FinalBlockId`.
    #[test]
    fn e04_multi_segment_response_marks_only_last_segment_as_final() {
        let base: Name = "/localhost/nfd/rib/list".parse().unwrap();
        let content = vec![0xABu8; MAX_DATASET_PAYLOAD_LEN * 2 + 100];
        let segments = build_segmented_dataset(&base, 42, &content, None);

        assert_eq!(segments.len(), 3, "expected 3 segments for 2.x payload");

        for (i, wire) in segments.iter().enumerate() {
            let data = Data::decode(wire.clone()).expect("segment must parse");
            let comps = data.name.components();
            assert_eq!(
                comps[comps.len() - 1].as_segment(),
                Some(i as u64),
                "segment {i} must be named seg={i}"
            );
            let fb = data.meta_info().and_then(|mi| mi.final_block_id.clone());
            if i == segments.len() - 1 {
                let fb = fb.expect("last segment must carry FinalBlockId");
                // SegmentNameComponent TLV: type=0x32, len, NNI value.
                let last_nni = seg_to_nni((segments.len() - 1) as u64);
                let mut expected = vec![0x32u8, last_nni.len() as u8];
                expected.extend_from_slice(&last_nni);
                assert_eq!(
                    fb.as_ref(),
                    expected.as_slice(),
                    "FinalBlockId must be a SegmentNameComponent TLV for the last segment"
                );
            } else {
                assert!(
                    fb.is_none(),
                    "non-final segment must not carry FinalBlockId"
                );
            }
        }
    }

    /// Every segment of a held version is served by exact name, byte for
    /// byte; a version no longer held is answered at once with a Nack Data;
    /// any other name is not a segment fetch.
    #[test]
    fn held_segments_answer_exact_names() {
        let held = HeldDatasets::default();
        let base: Name = "/localhost/nfd/rib/list".parse().unwrap();
        let version = held.next_version();
        assert!(held.next_version() > version, "versions never repeat");
        let segments = build_segmented_dataset(
            &base,
            version,
            &vec![0xABu8; MAX_DATASET_PAYLOAD_LEN * 2 + 1],
            None,
        );
        let versioned = base.clone().append_version(version);
        held.hold(versioned.clone(), segments.clone());

        for (k, wire) in segments.iter().enumerate() {
            let name = versioned.clone().append_segment(k as u64);
            assert_eq!(held.answer(&name, None).as_ref(), Some(wire), "seg={k}");
        }

        for gone in [
            versioned.clone().append_segment(3),
            base.clone().append_version(version + 7).append_segment(1),
        ] {
            let wire = held
                .answer(&gone, None)
                .expect("a segment name is answered");
            let data = Data::decode(wire).unwrap();
            assert_eq!(*data.name, gone);
            assert_eq!(
                data.meta_info().map(|m| m.content_type),
                Some(ContentType::Nack)
            );
            let resp = ControlResponse::decode(data.content().unwrap().clone()).unwrap();
            assert_eq!(resp.status_code, status::NOT_FOUND);
        }

        assert!(
            held.answer(&base, None).is_none(),
            "the dataset name itself"
        );
        let unversioned = base.clone().append_segment(1);
        assert!(held.answer(&unversioned, None).is_none());
    }
}
