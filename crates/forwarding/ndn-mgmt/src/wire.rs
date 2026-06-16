//! Control-response and status-dataset wire helpers.
//!
//! - `send_response` / `build_mgmt_response_wire` — encode a
//!   `ControlResponse`, signing it when a host signer is wired.
//! - `build_segmented_dataset` + `send_dataset` — segment a status
//!   dataset per ndn-cxx `mgmt/status-dataset-context.cpp`.

use ndn_face_local::InProcHandle;
use ndn_packet::{Name, encode::encode_data_unsigned};

use ndn_mgmt_wire::ControlResponse;

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
    use ndn_packet::encode::DataBuilder;
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
const MAX_DATASET_PAYLOAD_LEN: usize = 8000;

/// Segment a status dataset into Data wires named
/// `<interest>/v=<version>/seg=<n>`. The last segment carries
/// `FinalBlockId = seg=<last>`. Mirrors ndn-cxx
/// `mgmt/dispatcher.cpp` + `mgmt/status-dataset-context.cpp`.
fn build_segmented_dataset(base_name: &Name, version: u64, content: &[u8]) -> Vec<bytes::Bytes> {
    use ndn_packet::encode::DataBuilder;

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
            builder.sign_digest_sha256()
        })
        .collect()
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

pub(crate) async fn send_dataset(handle: &InProcHandle, name: &Name, content: bytes::Bytes) {
    // `web_time` proxies to `Date.now()` in the browser; `std::time` on
    // native. `std::time::SystemTime::now()` panics on wasm32.
    let version = web_time::SystemTime::now()
        .duration_since(web_time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    for wire in build_segmented_dataset(name, version, &content) {
        if let Err(e) = handle.send(wire).await {
            tracing::warn!(target: "engine", error = %e, "nfd-mgmt: failed to send dataset segment");
            return;
        }
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
        let segments = build_segmented_dataset(&base, 17, &content);

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
        let segments = build_segmented_dataset(&base, 42, &content);

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
}
