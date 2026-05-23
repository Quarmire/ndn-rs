//! Local fields feature — gate for NFD `LocalFieldsEnabled` (bit 0 of
//! [`crate::face_options::BIT_LOCAL_FIELDS`]). When set, authorises
//! [`super::IncomingFaceIdFeature`] to stamp `IncomingFaceId` (TLV 0x32C)
//! on egress LP frames. Currently the engine reads the bit directly.

use super::super::LinkServiceFeature;

#[derive(Default)]
pub struct LocalFieldsFeature;

impl LocalFieldsFeature {
    pub fn new() -> Self {
        Self
    }
}

impl LinkServiceFeature for LocalFieldsFeature {
    fn name(&self) -> &'static str {
        "local-fields"
    }
}
