//! Register the deterministic `_nc/<vector>` recode as an `ndn-compute`
//! function (feature `f2-recode-compute`).
//!
//! The `_nc/<vector>` mode (doctrine §8) is literally "compute the linear
//! function `<vector>` over this generation" — a *deterministic, transparent*
//! computation. Registering it as a Tier-0 [`ComputeHandler`] surfaces it in
//! `/localhost/nfd/compute/list` and lets it compose with the compute
//! machinery, exactly as the doctrine reserved. The `RecoderFace` still serves
//! the same name natively; this is the alternative compute-framed realization,
//! not a replacement.

use std::sync::{Arc, Mutex};

use ndn_compute::{ComputeError, ComputeHandler, ComputeService};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};

use crate::recode::{CodedMetadata, GenerationBuffer, naming};

/// A [`ComputeHandler`] answering `…/_gen/<id>/_nc/<vector>` with the exact
/// deterministic combination for `<vector>`, computed from a shared
/// [`GenerationBuffer`]. Deterministic ⇒ `Determinism::Transparent`,
/// freshness-cacheable like any computed Data.
pub struct NcComputeHandler {
    object: Name,
    generation_id: u64,
    buffer: Arc<Mutex<GenerationBuffer>>,
}

impl NcComputeHandler {
    pub fn new(object: Name, generation_id: u64, buffer: Arc<Mutex<GenerationBuffer>>) -> Self {
        Self {
            object,
            generation_id,
            buffer,
        }
    }
}

impl ComputeHandler for NcComputeHandler {
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let (object, generation_id, vector) = naming::parse_vector_request(&interest.name)
            .ok_or_else(|| ComputeError::BadArguments("not a _nc/<vector> name".into()))?;
        if object != self.object || generation_id != self.generation_id {
            return Err(ComputeError::NotFound);
        }
        let (combo, k, field) = {
            let buf = self.buffer.lock().unwrap();
            (
                buf.recode_exact(&vector),
                buf.descriptor().k,
                buf.descriptor().field,
            )
        };
        let combo =
            combo.ok_or_else(|| ComputeError::ComputeFailed("generation not full rank".into()))?;
        let meta = CodedMetadata {
            generation_id,
            k,
            field,
            vector: combo.vector,
        };
        let content = meta.prepend(&combo.payload);
        let name = (*interest.name).clone();
        let wire = DataBuilder::new(name, &content).sign_digest_sha256();
        Data::decode(wire).map_err(|e| ComputeError::ComputeFailed(format!("encode: {e}")))
    }
}

/// Register the `_nc` subtree of a generation as a compute function on
/// `service`. After this, `<object>/_gen/<id>/_nc/<vector>` Interests route to
/// the compute face and are answered by [`NcComputeHandler`]; the function
/// shows up (transparent) in the `compute/list` dataset.
pub fn register_named_recode(
    service: &ComputeService,
    object: Name,
    generation_id: u64,
    buffer: Arc<Mutex<GenerationBuffer>>,
) {
    let prefix = naming::generation_name(&object, generation_id).append(naming::NC_MARKER);
    service.register(prefix, NcComputeHandler::new(object, generation_id, buffer));
}
