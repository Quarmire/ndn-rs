//! `/localhost/nfd/compute/list` — read-only introspection of the
//! in-network compute function table. Backend is
//! `ndn-compute::ComputeService` (via the [`ComputeMgmtBackend`] trait).
//!
//! Unlike `coding`/`rate-limit`, the `compute` module is list-only: the
//! function table is owned by the `ComputeService` API, not mutated over
//! the wire. The dataset is a concatenation of `ComputeFunction` TLVs:
//!
//! ```text
//! ComputeFunction = COMPUTE-FUNCTION-TYPE TLV-LENGTH
//!                     Name              ; the function prefix (TLV 0x07)
//!                     Determinism       ; 1 byte: 0 transparent, 1 opaque
//!                     FnKind            ; 1 byte: 0 raw,1 typed,2 executor,
//!                                       ;          3 reflexive,4 job
//!                     [Fuel]            ; optional NonNegativeInteger
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{
    ComputeDeterminism, ComputeFnKind, ComputeFunctionInfo, ComputeMgmtBackend, MgmtResponse,
};

// Dataset TLV codes (ndn-rs application range; scoped to this Data content).
const TYPE_COMPUTE_FUNCTION: u64 = 0xC0;
// Standard NDN Name TLV; written verbatim via `Name::encode_to_tlv`.
#[cfg_attr(not(test), allow(dead_code))]
const TYPE_NAME: u64 = 0x07;
const TYPE_COMPUTE_DETERMINISM: u64 = 0xC2;
const TYPE_COMPUTE_FNKIND: u64 = 0xC4;
const TYPE_COMPUTE_FUEL: u64 = 0xC6;

fn determinism_code(d: ComputeDeterminism) -> u8 {
    match d {
        ComputeDeterminism::Transparent => 0,
        ComputeDeterminism::Opaque => 1,
    }
}

fn fnkind_code(k: ComputeFnKind) -> u8 {
    match k {
        ComputeFnKind::Raw => 0,
        ComputeFnKind::Typed => 1,
        ComputeFnKind::Executor => 2,
        ComputeFnKind::Reflexive => 3,
        ComputeFnKind::Job => 4,
    }
}

fn handle_compute(verb_name: &[u8], handler: Option<&Arc<dyn ComputeMgmtBackend>>) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "compute module not wired (no ComputeMgmtBackend installed)",
        )
        .into();
    };
    match verb_name {
        v if v == verb::LIST => MgmtResponse::Dataset(compute_list_dataset(&handler.list())),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown compute verb (only `list`)").into(),
    }
}

/// Big-endian, leading zeros trimmed — NDN NonNegativeInteger convention.
fn nni_be(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

fn compute_list_dataset(rows: &[ComputeFunctionInfo]) -> bytes::Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    for info in rows {
        w.write_nested(TYPE_COMPUTE_FUNCTION, |inner| {
            // `encode_to_tlv()` is the full Name TLV (TYPE_NAME header +
            // value), written verbatim into the function container.
            inner.write_raw(&info.prefix.encode_to_tlv());
            inner.write_tlv(
                TYPE_COMPUTE_DETERMINISM,
                &[determinism_code(info.determinism)],
            );
            inner.write_tlv(TYPE_COMPUTE_FNKIND, &[fnkind_code(info.kind)]);
            if let Some(fuel) = info.fuel {
                inner.write_tlv(TYPE_COMPUTE_FUEL, &nni_be(fuel));
            }
        });
    }
    w.finish()
}

pub(crate) struct ComputeModule;

#[async_trait]
impl MgmtModule for ComputeModule {
    fn name(&self) -> &'static [u8] {
        module::COMPUTE
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_compute(verb, ctx.compute_handler)
    }
}

#[cfg(test)]
mod compute_tests {
    use super::*;
    use ndn_packet::Name;
    use std::sync::Mutex;

    struct StubBackend {
        rows: Mutex<Vec<ComputeFunctionInfo>>,
    }
    impl ComputeMgmtBackend for StubBackend {
        fn list(&self) -> Vec<ComputeFunctionInfo> {
            self.rows.lock().unwrap().clone()
        }
    }

    fn backend(rows: Vec<ComputeFunctionInfo>) -> Arc<dyn ComputeMgmtBackend> {
        Arc::new(StubBackend {
            rows: Mutex::new(rows),
        })
    }

    #[test]
    fn returns_404_when_no_backend() {
        let resp = handle_compute(verb::LIST, None);
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn unknown_verb_returns_404() {
        let h = backend(vec![]);
        let resp = handle_compute(b"set", Some(&h));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn list_encodes_each_function() {
        let prefix: Name = "/calc/add".parse().unwrap();
        let rows = vec![
            ComputeFunctionInfo {
                prefix: prefix.clone(),
                determinism: ComputeDeterminism::Transparent,
                kind: ComputeFnKind::Typed,
                fuel: None,
            },
            ComputeFunctionInfo {
                prefix: "/img/thumb".parse().unwrap(),
                determinism: ComputeDeterminism::Transparent,
                kind: ComputeFnKind::Executor,
                fuel: Some(1_000_000),
            },
        ];
        let h = backend(rows);
        let resp = handle_compute(verb::LIST, Some(&h));
        let bytes = match resp {
            MgmtResponse::Dataset(b) => b,
            _ => panic!("expected dataset"),
        };
        // Two ComputeFunction TLVs at the top level.
        let mut r = ndn_tlv::TlvReader::new(bytes);
        let (t0, v0) = r.read_tlv().expect("first function");
        assert_eq!(t0, TYPE_COMPUTE_FUNCTION);
        // Inner: Name TLV first.
        let mut ir = ndn_tlv::TlvReader::new(v0);
        let (nt, nv) = ir.read_tlv().expect("name tlv");
        assert_eq!(nt, TYPE_NAME);
        let decoded = Name::decode(nv).expect("decode name");
        assert_eq!(decoded, prefix);
        let (t1, _) = r.read_tlv().expect("second function");
        assert_eq!(t1, TYPE_COMPUTE_FUNCTION);
        assert!(r.is_empty());
    }
}
