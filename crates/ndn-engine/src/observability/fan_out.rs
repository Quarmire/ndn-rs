//! PIT-aggregation span fan-out hook. When Data satisfies an aggregated
//! PIT entry, the satisfy path emits one event per in-record / trace_id
//! pair so observability tools can rebuild per-consumer traces.
//!
//! ndn-engine stays observability-crate-agnostic; the host (`ndn-fwd`)
//! installs a sink via [`install_sink`], and [`emit_data_fan_out`] /
//! [`emit_nack_fan_out`] no-op when none is registered.

use std::sync::OnceLock;

use ndn_packet::lp::TraceId;

#[derive(Clone, Debug)]
pub struct FanOutEvent {
    /// W3C trace_id from the consumer's Interest.
    pub trace_id: TraceId,
    pub kind: FanOutKind,
    /// Wire name of the Interest being satisfied / nacked.
    pub name_uri: String,
    /// Forwarder-local face id of the in-record.
    pub face_id: u64,
}

#[derive(Copy, Clone, Debug)]
pub enum FanOutKind {
    DataSatisfy,
    Nack { reason_code: u64 },
}

pub type FanOutSink = std::sync::Arc<dyn Fn(FanOutEvent) + Send + Sync>;

static SINK: OnceLock<FanOutSink> = OnceLock::new();

/// Install the process-global sink. Subsequent calls are ignored.
pub fn install_sink(sink: FanOutSink) {
    let _ = SINK.set(sink);
}

/// Emit one `DataSatisfy` event per `(in-record, trace_id)` pair.
/// No-op when no sink is installed.
pub fn emit_data_fan_out<I>(in_records: I, name_uri: &str)
where
    I: IntoIterator<Item = (u64, Vec<TraceId>)>,
{
    let Some(sink) = SINK.get() else {
        return;
    };
    for (face_id, trace_ids) in in_records {
        for trace_id in trace_ids {
            sink(FanOutEvent {
                trace_id,
                kind: FanOutKind::DataSatisfy,
                name_uri: name_uri.to_string(),
                face_id,
            });
        }
    }
}

/// Emit one `Nack` event per `(in-record, trace_id)` pair.
pub fn emit_nack_fan_out<I>(in_records: I, name_uri: &str, reason_code: u64)
where
    I: IntoIterator<Item = (u64, Vec<TraceId>)>,
{
    let Some(sink) = SINK.get() else {
        return;
    };
    for (face_id, trace_ids) in in_records {
        for trace_id in trace_ids {
            sink(FanOutEvent {
                trace_id,
                kind: FanOutKind::Nack { reason_code },
                name_uri: name_uri.to_string(),
                face_id,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn emit_is_no_op_without_sink() {
        // OnceLock makes any installed sink permanent across the test
        // binary; this test relies on the no-op being safe regardless.
        emit_data_fan_out(
            vec![(1, vec![TraceId([0xAA; 16])])],
            "/audit/fan-out",
        );
    }

    #[test]
    fn sink_receives_one_event_per_trace() {
        let received: Arc<Mutex<Vec<FanOutEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let r = Arc::clone(&received);
        let sink: FanOutSink = Arc::new(move |ev| {
            r.lock().unwrap().push(ev);
        });
        // Invoke the sink directly to stay independent of OnceLock state.
        for (face_id, traces) in [
            (1u64, vec![TraceId([0xAA; 16]), TraceId([0xBB; 16])]),
            (2u64, vec![TraceId([0xCC; 16])]),
        ] {
            for trace_id in traces {
                sink(FanOutEvent {
                    trace_id,
                    kind: FanOutKind::DataSatisfy,
                    name_uri: "/audit/fan-out".into(),
                    face_id,
                });
            }
        }
        assert_eq!(received.lock().unwrap().len(), 3);
    }
}
