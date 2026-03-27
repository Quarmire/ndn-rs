use ndn_transport::FaceId;

/// Manages nl80211 channel assignments for multi-radio research experiments.
///
/// Reads nl80211 survey data and per-station metrics via Netlink, publishes
/// link state as named NDN content under `/radio/local/<iface>/state`, and
/// subscribes to neighbor radio state via standing Interests.
///
/// When the strategy decides a channel switch would improve throughput, it
/// calls `switch()` which issues the nl80211 channel switch via Netlink and
/// invalidates the flow table entries for the affected interface.
pub struct ChannelManager {
    // TODO: add netlink socket and flow table reference
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Switch the radio underlying `face_id` to `channel`.
    ///
    /// The interface will be briefly unavailable during the switch (~10–50 ms).
    /// The caller should flush XDP/userspace forwarding cache entries for this
    /// face before calling.
    pub async fn switch(&self, _face_id: FaceId, _channel: u8) -> Result<(), SwitchError> {
        Err(SwitchError::NotImplemented)
    }
}

impl Default for ChannelManager {
    fn default() -> Self { Self::new() }
}

#[derive(Debug)]
pub enum SwitchError {
    NotImplemented,
    NetlinkError(String),
    InterfaceNotFound,
}

impl std::fmt::Display for SwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwitchError::NotImplemented       => write!(f, "channel switching not yet implemented"),
            SwitchError::NetlinkError(e)       => write!(f, "nl80211 error: {e}"),
            SwitchError::InterfaceNotFound    => write!(f, "interface not found"),
        }
    }
}

impl std::error::Error for SwitchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn switch_returns_not_implemented() {
        let mgr = ChannelManager::new();
        let result = mgr.switch(FaceId(0), 6).await;
        assert!(matches!(result, Err(SwitchError::NotImplemented)));
    }

    #[test]
    fn switch_error_display() {
        assert!(!SwitchError::NotImplemented.to_string().is_empty());
        assert!(!SwitchError::NetlinkError("x".into()).to_string().is_empty());
        assert!(!SwitchError::InterfaceNotFound.to_string().is_empty());
    }
}
