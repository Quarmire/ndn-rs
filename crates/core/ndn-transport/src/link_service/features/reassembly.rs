//! Reassembly feature — inert marker. The engine's TLV decode stage
//! reassembles LP fragments before the pipeline sees them.

use super::super::LinkServiceFeature;

#[derive(Default)]
pub struct ReassemblyFeature;

impl ReassemblyFeature {
    pub fn new() -> Self {
        Self
    }
}

impl LinkServiceFeature for ReassemblyFeature {
    fn name(&self) -> &'static str {
        "reassembly"
    }
}
