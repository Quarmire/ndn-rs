//! Shared types for streaming tool output to callers.

/// A single event emitted by a running tool.
#[derive(Debug, Clone)]
pub struct ToolEvent {
    /// Human-readable text line (suitable for display in a log pane).
    pub text: String,
    /// Severity level for colouring and filtering.
    pub level: EventLevel,
    /// Optional structured payload for driving rich UI widgets.
    pub structured: Option<ToolData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Info,
    Warn,
    Error,
    Summary,
}

/// Structured data variants emitted alongside text events.
/// The dashboard uses these to update live widgets (speed dial, result cards, etc.)
/// without having to parse the human-readable text.
#[derive(Debug, Clone)]
pub enum ToolData {
    PingResult {
        seq: u64,
        rtt_us: u64,
    },
    PingSummary {
        sent: u64,
        received: u64,
        nacks: u64,
        timeouts: u64,
        loss_pct: f64,
        rtt_min_us: u64,
        rtt_avg_us: u64,
        rtt_max_us: u64,
        rtt_p50_us: u64,
        rtt_p99_us: u64,
        rtt_stddev: f64,
    },
    IperfInterval {
        bytes: u64,
        throughput_bps: f64,
        rtt_avg_us: u64,
    },
    IperfSummary {
        duration_secs: f64,
        transferred_bytes: u64,
        throughput_bps: f64,
        sent: u64,
        received: u64,
        loss_pct: f64,
        rtt_avg_us: u64,
        rtt_p99_us: u64,
    },
    /// Emitted by the server when a client session is negotiated.
    IperfClientConnected {
        flow_id: String,
        duration_secs: u64,
        sign_mode: String,
        payload_size: usize,
        reverse: bool,
    },
    /// Emitted after a single or segmented peek completes.
    PeekResult {
        name: String,
        bytes_received: u64,
        /// Set when content was written to a file.
        saved_to: Option<String>,
    },
    /// Emitted during segmented fetch to update a progress widget.
    FetchProgress {
        received: usize,
        total: usize,
    },
    /// Emitted during file transfer (send/recv) to update a progress bar.
    TransferProgress {
        bytes_done: u64,
        bytes_total: Option<u64>,
    },
}

impl ToolEvent {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Info,
            structured: None,
        }
    }
    pub fn warn(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Warn,
            structured: None,
        }
    }
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Error,
            structured: None,
        }
    }
    pub fn summary(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Summary,
            structured: None,
        }
    }
    pub fn with_data(mut self, data: ToolData) -> Self {
        self.structured = Some(data);
        self
    }
}

/// Connection parameters for tools that connect to an external router.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Path to the router face socket.
    pub face_socket: String,
    /// Use shared memory for the data plane (set false for `--no-shm` behaviour).
    pub use_shm: bool,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        #[cfg(unix)]
        let face_socket = "/run/nfd/nfd.sock".to_string();
        #[cfg(windows)]
        let face_socket = r"\\.\pipe\ndn".to_string();
        Self {
            face_socket,
            use_shm: true,
        }
    }
}
