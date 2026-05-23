//! IncomingFaceId feature — stamps the originating face on egress LP
//! frames as `IncomingFaceId` (TLV 0x32C). Gated by `LocalFieldsEnabled`.
//! Currently inert; behaviour lives in `send_bytes_with_source` for
//! passthrough faces and dispatcher tag-bag plumbing for non-local.

use super::super::LinkServiceFeature;

#[derive(Default)]
pub struct IncomingFaceIdFeature;

impl IncomingFaceIdFeature {
    pub fn new() -> Self {
        Self
    }
}

impl LinkServiceFeature for IncomingFaceIdFeature {
    fn name(&self) -> &'static str {
        "incoming-face-id"
    }
}
