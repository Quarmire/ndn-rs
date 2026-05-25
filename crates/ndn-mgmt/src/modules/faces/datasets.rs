//! `faces/list`, `faces/link-quality`, and `faces/counters` datasets.

use ndn_config::{ControlResponse, nfd_dataset};
use ndn_engine::ForwarderEngine;
use ndn_transport::{FaceKind, FacePersistency, FaceScope};

pub(super) fn faces_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    use std::sync::atomic::Ordering;
    let entries = engine.faces().face_info();
    let face_states = engine.face_states();
    let mut buf = bytes::BytesMut::new();
    for info in &entries {
        let state = face_states.get(&info.id);
        let persistency = state
            .as_ref()
            .map(|s| s.persistency)
            .unwrap_or(FacePersistency::OnDemand);
        let face_persistency = match persistency {
            FacePersistency::Persistent => 0,
            FacePersistency::OnDemand => 1,
            FacePersistency::Permanent => 2,
        };
        let (
            n_in_interests,
            n_in_data,
            n_out_interests,
            n_out_data,
            n_in_bytes,
            n_out_bytes,
            n_satisfied_interests,
            n_unsatisfied_interests,
            face_flags,
            n_in_nacks,
            n_out_nacks,
        ) = state
            .as_ref()
            .map(|s| {
                (
                    s.counters.in_interests.load(Ordering::Relaxed),
                    s.counters.in_data.load(Ordering::Relaxed),
                    s.counters.out_interests.load(Ordering::Relaxed),
                    s.counters.out_data.load(Ordering::Relaxed),
                    s.counters.in_bytes.load(Ordering::Relaxed),
                    s.counters.out_bytes.load(Ordering::Relaxed),
                    s.counters.in_satisfied_interests.load(Ordering::Relaxed),
                    s.counters.in_unsatisfied_interests.load(Ordering::Relaxed),
                    s.face_flags_raw(),
                    s.counters.in_nacks.load(Ordering::Relaxed),
                    s.counters.out_nacks.load(Ordering::Relaxed),
                )
            })
            .unwrap_or_default();
        let face_scope =
            if ndn_transport::face::resolve_scope(info.kind, info.remote_uri.as_deref())
                == FaceScope::Local
            {
                1
            } else {
                0
            };
        let link_type = match info.kind {
            FaceKind::EtherMulticast | FaceKind::Multicast => 1,
            _ => 0,
        };
        let uri = info
            .remote_uri
            .clone()
            .unwrap_or_else(|| format!("internal://{}", info.kind));

        // ndn-rs extension fields from the face's LinkService snapshot
        // + feature counters. Bare NFD shape when the face has no
        // Lp-side (Passthrough: empty feature_set, None counters).
        let mut effective_mtu = None;
        let mut base_cong_interval = None;
        let mut def_cong_threshold = None;
        let mut feature_set = Vec::new();
        let mut reliability_counters = None;
        let mut congestion_counters = None;
        if let Some(face) = engine.faces().get(info.id) {
            let snap = face.link_service.snapshot();
            effective_mtu = snap.effective_mtu;
            base_cong_interval = snap.base_congestion_marking_interval.map(duration_to_us);
            def_cong_threshold = snap.default_congestion_threshold;
            feature_set = face
                .link_service
                .feature_names()
                .into_iter()
                .map(String::from)
                .collect();
            reliability_counters = face.link_service.reliability_counters();
            congestion_counters = face.link_service.congestion_counters();
        }
        let (n_lp_resent_packets, rto_micros) = match reliability_counters {
            Some((resent, rto)) => (Some(resent), Some(rto)),
            None => (None, None),
        };
        let (n_congestion_marks_sent, n_congestion_marks_received) = match congestion_counters {
            Some((sent, recv)) => (Some(sent), Some(recv)),
            None => (None, None),
        };

        let fs = nfd_dataset::FaceStatus {
            face_id: info.id.0,
            uri,
            local_uri: info.local_uri.clone().unwrap_or_default(),
            face_scope,
            face_persistency,
            link_type,
            mtu: None,
            base_congestion_marking_interval: base_cong_interval,
            default_congestion_threshold: def_cong_threshold,
            n_in_interests,
            n_in_data,
            n_in_nacks,
            n_out_interests,
            n_out_data,
            n_out_nacks,
            n_in_bytes,
            n_out_bytes,
            n_satisfied_interests,
            n_unsatisfied_interests,
            flags: face_flags,
            n_lp_acks_received: None,
            n_lp_resent_packets,
            n_lp_rto_expirations: None,
            n_congestion_marks_sent,
            n_congestion_marks_received,
            effective_mtu,
            feature_set,
            rto_micros,
        };
        buf.extend_from_slice(&fs.encode());
    }
    buf.freeze()
}

// faces/link-quality: ndn-rs-local cross-layer telemetry dataset
//
// NOT an NFD dataset — observability only. TLV codes are ndn-rs-local
// (application range, single-byte). Each entry: LqEntry{ FaceId, [Rssi],
// [Snr], [Congestion], UpdatedMs }. RSSI/SNR are signed dB(m) carried as one
// two's-complement byte; congestion is 0=Low,1=Medium,2=High.
pub(super) mod link_quality_tlv {
    pub const ENTRY: u8 = 0xC0;
    pub const FACE_ID: u8 = 0x69; // reuse NFD FaceId
    pub const RSSI: u8 = 0xC1;
    pub const SNR: u8 = 0xC2;
    pub const CONGESTION: u8 = 0xC3;
    pub const UPDATED_MS: u8 = 0xC4;
}

/// Pure encoder for the link-quality dataset (testable without an engine).
pub(super) fn encode_link_quality(entries: &[(u64, ndn_strategy::LinkSignals)]) -> bytes::Bytes {
    use ndn_strategy::CongestionLevel;
    use link_quality_tlv as t;

    fn tlv(buf: &mut Vec<u8>, typ: u8, val: &[u8]) {
        buf.push(typ);
        buf.push(val.len() as u8);
        buf.extend_from_slice(val);
    }

    let mut out = bytes::BytesMut::new();
    for (face_id, sig) in entries {
        let mut body = Vec::new();
        tlv(&mut body, t::FACE_ID, &face_id.to_be_bytes());
        if let Some(r) = sig.rssi_dbm {
            tlv(&mut body, t::RSSI, &[r as u8]);
        }
        if let Some(s) = sig.snr_db {
            tlv(&mut body, t::SNR, &[s as u8]);
        }
        if let Some(c) = sig.congestion {
            let code = match c {
                CongestionLevel::Low => 0u8,
                CongestionLevel::Medium => 1,
                CongestionLevel::High => 2,
            };
            tlv(&mut body, t::CONGESTION, &[code]);
        }
        tlv(&mut body, t::UPDATED_MS, &sig.updated_ms.to_be_bytes());

        out.extend_from_slice(&[t::ENTRY, body.len() as u8]);
        out.extend_from_slice(&body);
    }
    out.freeze()
}

pub(super) fn faces_link_quality_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let mut links: Vec<(u64, ndn_strategy::LinkSignals)> = engine
        .signals()
        .dump_links()
        .into_iter()
        .map(|(f, s)| (f.0, s))
        .collect();
    links.sort_by_key(|(f, _)| *f); // deterministic dataset order
    encode_link_quality(&links)
}

fn duration_to_us(d: std::time::Duration) -> u64 {
    d.as_micros().min(u64::MAX as u128) as u64
}

pub(super) fn faces_counters(engine: &ForwarderEngine) -> ControlResponse {
    use std::sync::atomic::Ordering;
    let face_states = engine.face_states();
    let entries = engine.faces().face_info();
    let mut text = format!("{} faces\n", entries.len());
    for info in &entries {
        if let Some(s) = face_states.get(&info.id) {
            text.push_str(&format!(
                "  faceid={} in_interests={} in_data={} out_interests={} out_data={} in_bytes={} out_bytes={}\n",
                info.id.0,
                s.counters.in_interests.load(Ordering::Relaxed),
                s.counters.in_data.load(Ordering::Relaxed),
                s.counters.out_interests.load(Ordering::Relaxed),
                s.counters.out_data.load(Ordering::Relaxed),
                s.counters.in_bytes.load(Ordering::Relaxed),
                s.counters.out_bytes.load(Ordering::Relaxed),
            ));
        }
    }
    ControlResponse::ok_empty(text)
}
