//! Nack feature — inert marker. NDNLPv2 `Nack` (TLV 0x320) handling lives
//! in the TLV decode stage and the pipeline's NackStage today.

use super::super::LinkServiceFeature;

#[derive(Default)]
pub struct NackFeature;

impl NackFeature {
    pub fn new() -> Self {
        Self
    }
}

impl LinkServiceFeature for NackFeature {
    fn name(&self) -> &'static str {
        "nack"
    }
}
