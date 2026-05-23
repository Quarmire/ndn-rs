//! Fragmentation feature — inert marker. The actual fragmenter lives in
//! [`super::super::LpLinkService::send`]; this exists so `feature_set`
//! FaceStatus lists "fragmentation".

use super::super::LinkServiceFeature;

#[derive(Default)]
pub struct FragmentationFeature;

impl FragmentationFeature {
    pub fn new() -> Self {
        Self
    }
}

impl LinkServiceFeature for FragmentationFeature {
    fn name(&self) -> &'static str {
        "fragmentation"
    }
}
