use smallvec::SmallVec;

use ndn_pipeline::ForwardingAction;
use ndn_strategy::{FibNexthop, StrategyContext};
use ndn_transport::FaceId;

/// Per-invocation host state exposed to the WASM guest.
///
/// Created fresh for each strategy call from the current `StrategyContext`.
/// The guest calls imported host functions (`get_in_face`, `get_nexthop`, etc.)
/// which read from this state, and action functions (`forward`, `nack`, `suppress`)
/// which write to `actions`.
pub(crate) struct HostState {
    pub in_face: u32,
    pub nexthops: Vec<FibNexthop>,
    pub actions: SmallVec<[ForwardingAction; 2]>,
    // Cross-layer data (flat, for easy WASM access)
    pub rtt_ns: Vec<(u32, f64)>,       // (face_id, rtt_ns)
    pub rssi: Vec<(u32, i32)>,         // (face_id, rssi_dbm widened to i32)
    pub satisfaction: Vec<(u32, f32)>, // (face_id, satisfaction_rate)
}

impl HostState {
    pub fn from_context(ctx: &StrategyContext<'_>) -> Self {
        let nexthops = ctx
            .fib_entry
            .map(|e| e.nexthops.clone())
            .unwrap_or_default();

        // Extract cross-layer data from extensions if available.
        let mut rtt_ns = Vec::new();
        let mut rssi = Vec::new();
        let satisfaction = Vec::new();

        if let Some(snapshot) = ctx.extensions.get::<ndn_strategy::LinkQualitySnapshot>() {
            for lq in &snapshot.per_face {
                if let Some(r) = lq.rssi_dbm {
                    rssi.push((lq.face_id.0, r as i32));
                }
                if let Some(rtt) = lq.observed_rtt_ms {
                    rtt_ns.push((lq.face_id.0, rtt * 1_000_000.0));
                }
            }
        }

        Self {
            in_face: ctx.in_face.0,
            nexthops,
            actions: SmallVec::new(),
            rtt_ns,
            rssi,
            satisfaction,
        }
    }

    pub fn take_actions(self) -> SmallVec<[ForwardingAction; 2]> {
        self.actions
    }
}

/// Define host functions that the WASM module can import.
pub(crate) fn add_host_functions(linker: &mut wasmtime::Linker<HostState>) -> anyhow::Result<()> {
    // get_in_face() -> u32
    linker.func_wrap(
        "ndn",
        "get_in_face",
        |caller: wasmtime::Caller<'_, HostState>| -> u32 { caller.data().in_face },
    )?;

    // get_nexthop_count() -> u32
    linker.func_wrap(
        "ndn",
        "get_nexthop_count",
        |caller: wasmtime::Caller<'_, HostState>| -> u32 { caller.data().nexthops.len() as u32 },
    )?;

    // get_nexthop(index: u32, out_face_id: u32, out_cost: u32)
    // Writes face_id and cost to guest memory at the given offsets.
    linker.func_wrap(
        "ndn",
        "get_nexthop",
        |mut caller: wasmtime::Caller<'_, HostState>,
         index: u32,
         out_face: u32,
         out_cost: u32|
         -> u32 {
            let nh = match caller.data().nexthops.get(index as usize) {
                Some(nh) => *nh,
                None => return 1, // error: out of bounds
            };
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return 1,
            };
            let data = mem.data_mut(&mut caller);
            let face_bytes = nh.face_id.0.to_le_bytes();
            let cost_bytes = nh.cost.to_le_bytes();
            let f = out_face as usize;
            let c = out_cost as usize;
            if f + 4 > data.len() || c + 4 > data.len() {
                return 1;
            }
            data[f..f + 4].copy_from_slice(&face_bytes);
            data[c..c + 4].copy_from_slice(&cost_bytes);
            0 // success
        },
    )?;

    // get_rtt_ns(face_id: u32) -> f64
    // Returns RTT in nanoseconds, or -1.0 if unavailable.
    linker.func_wrap(
        "ndn",
        "get_rtt_ns",
        |caller: wasmtime::Caller<'_, HostState>, face_id: u32| -> f64 {
            caller
                .data()
                .rtt_ns
                .iter()
                .find(|(fid, _)| *fid == face_id)
                .map_or(-1.0, |(_, rtt)| *rtt)
        },
    )?;

    // get_rssi(face_id: u32) -> i32
    // Returns RSSI in dBm, or -128 if unavailable.
    linker.func_wrap(
        "ndn",
        "get_rssi",
        |caller: wasmtime::Caller<'_, HostState>, face_id: u32| -> i32 {
            caller
                .data()
                .rssi
                .iter()
                .find(|(fid, _)| *fid == face_id)
                .map_or(-128, |(_, rssi)| *rssi)
        },
    )?;

    // get_satisfaction(face_id: u32) -> f32
    // Returns satisfaction rate [0.0, 1.0], or -1.0 if unavailable.
    linker.func_wrap(
        "ndn",
        "get_satisfaction",
        |caller: wasmtime::Caller<'_, HostState>, face_id: u32| -> f32 {
            caller
                .data()
                .satisfaction
                .iter()
                .find(|(fid, _)| *fid == face_id)
                .map_or(-1.0, |(_, sat)| *sat)
        },
    )?;

    // forward(face_ids_ptr: u32, count: u32)
    // Reads `count` u32 face IDs from guest memory at `face_ids_ptr`.
    linker.func_wrap(
        "ndn",
        "forward",
        |mut caller: wasmtime::Caller<'_, HostState>, ptr: u32, count: u32| {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return,
            };
            let data = mem.data(&caller);
            let start = ptr as usize;
            let end = start + (count as usize) * 4;
            if end > data.len() {
                return;
            }

            let mut faces = SmallVec::<[FaceId; 4]>::new();
            for i in 0..count as usize {
                let offset = start + i * 4;
                let fid = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                faces.push(FaceId(fid));
            }
            caller
                .data_mut()
                .actions
                .push(ForwardingAction::Forward(faces));
        },
    )?;

    // nack(reason: u32)
    linker.func_wrap(
        "ndn",
        "nack",
        |mut caller: wasmtime::Caller<'_, HostState>, reason: u32| {
            let nr = match reason {
                0 => ndn_pipeline::NackReason::NoRoute,
                1 => ndn_pipeline::NackReason::Duplicate,
                2 => ndn_pipeline::NackReason::Congestion,
                3 => ndn_pipeline::NackReason::NotYet,
                _ => ndn_pipeline::NackReason::NoRoute,
            };
            caller.data_mut().actions.push(ForwardingAction::Nack(nr));
        },
    )?;

    // suppress()
    linker.func_wrap(
        "ndn",
        "suppress",
        |mut caller: wasmtime::Caller<'_, HostState>| {
            caller.data_mut().actions.push(ForwardingAction::Suppress);
        },
    )?;

    Ok(())
}
