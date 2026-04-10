// Typed data models and text-response parsers for NDN management protocol.

// ── Log entries ──────────────────────────────────────────────────────────────

/// Severity level of a captured router log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "TRACE" => Some(Self::Trace),
            "DEBUG" => Some(Self::Debug),
            "INFO"  => Some(Self::Info),
            "WARN"  => Some(Self::Warn),
            "ERROR" => Some(Self::Error),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info  => "INFO",
            Self::Warn  => "WARN",
            Self::Error => "ERROR",
        }
    }

    /// CSS foreground colour for this level.
    pub fn color(self) -> &'static str {
        match self {
            Self::Trace => "#8b949e",
            Self::Debug => "#58a6ff",
            Self::Info  => "#3fb950",
            Self::Warn  => "#d29922",
            Self::Error => "#f85149",
        }
    }

    /// CSS background colour for this level.
    pub fn bg(self) -> &'static str {
        match self {
            Self::Trace => "#1c2128",
            Self::Debug => "#0c2d6b",
            Self::Info  => "#1a4731",
            Self::Warn  => "#3d3000",
            Self::Error => "#4e1717",
        }
    }
}

/// A single parsed log entry from the router process.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level:     LogLevel,
    pub thread_id: Option<String>,
    pub target:    String,
    pub message:   String,
}

/// Strip ANSI escape sequences from `s` (e.g. `\x1b[32m`, `\x1b[0m`).
///
/// Only handles the common CSI sequences (`ESC [ ... letter`) that
/// tracing-subscriber emits.  Other forms fall through unchanged.
fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\x1b' && bytes.get(i + 1) == Some(&b'[') {
            // Skip: ESC [ (params) (final-byte A-Za-z)
            i += 2;
            while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            i += 1; // skip the final letter
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl LogEntry {
    /// Parse a single compact-format tracing line.
    ///
    /// Format: `"TIMESTAMP  LEVEL target: message key=val key2=val2"`
    ///
    /// Falls back to a raw Info entry if the line cannot be parsed.
    pub fn parse_line(s: &str) -> Self {
        // Always strip ANSI codes — the router emits plain text when piped,
        // but strip defensively in case of terminal-mode restarts.
        let s = strip_ansi(s);
        let s = s.trim();
        Self::parse_line_inner(s)
    }

    fn parse_line_inner(s: &str) -> Self {
        let raw_fallback = || Self {
            timestamp: String::new(),
            level:     LogLevel::Info,
            thread_id: None,
            target:    String::new(),
            message:   s.to_owned(),
        };

        // Split off timestamp (first space-separated token)
        let (timestamp, rest) = match s.split_once(' ') {
            Some(pair) => pair,
            None => return raw_fallback(),
        };
        let rest = rest.trim_start();

        // Split off level (next space-separated token)
        let (level_str, rest) = match rest.split_once(' ') {
            Some(pair) => pair,
            None => return raw_fallback(),
        };
        let level = match LogLevel::parse(level_str.trim()) {
            Some(l) => l,
            None => return raw_fallback(),
        };
        let rest = rest.trim_start();

        // Skip optional ThreadId(N) token emitted when thread_ids are enabled.
        let (thread_id, rest) = if rest.starts_with("ThreadId(") {
            match rest.split_once(' ') {
                Some((tid, r)) => (Some(tid.to_owned()), r.trim_start()),
                None => (None, rest),
            }
        } else {
            (None, rest)
        };

        // Split "target: message" on the first ": "
        let (target, message) = match rest.find(": ") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None    => ("", rest),
        };

        Self {
            timestamp: timestamp.to_owned(),
            level,
            thread_id,
            target: target.to_owned(),
            message: message.to_owned(),
        }
    }
}
// The current router returns human-readable text in ControlResponse::status_text.
// Each parser converts that text into structured types for the UI.
// Phase 2 will add structured JSON endpoints to replace these parsers.

// ── Forwarder status ────────────────────────────────────────────────────────

/// Parsed from `status/general` response: `"faces=5 fib=10 pit=3 cs=100"`
#[derive(Debug, Clone, Default)]
pub struct ForwarderStatus {
    pub n_faces: u64,
    pub n_fib: u64,
    pub n_pit: u64,
    pub n_cs: u64,
}

impl ForwarderStatus {
    pub fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for token in text.split_whitespace() {
            if let Some((k, v)) = token.split_once('=') {
                match k {
                    "faces" => s.n_faces = v.parse().unwrap_or(0),
                    "fib"   => s.n_fib   = v.parse().unwrap_or(0),
                    "pit"   => s.n_pit   = v.parse().unwrap_or(0),
                    "cs"    => s.n_cs    = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        s
    }
}

// ── Faces ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FaceInfo {
    pub face_id: u64,
    pub remote_uri: Option<String>,
    pub local_uri: Option<String>,
    pub persistency: String,
    pub kind: Option<String>,
}

impl FaceInfo {
    /// Parse from `faces/list` response text.
    ///
    /// Format per entry (one per line, indented):
    /// ```text
    /// faceid=1 remote=udp4://192.168.1.1:6363 local=udp4://0.0.0.0:0 persistency=Persistent
    /// faceid=2 kind=App persistency=OnDemand
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut faces = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("faceid=") {
                continue;
            }
            let mut f = FaceInfo {
                face_id: 0,
                remote_uri: None,
                local_uri: None,
                persistency: "Unknown".into(),
                kind: None,
            };
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "faceid"      => f.face_id   = v.parse().unwrap_or(0),
                        "remote"      => f.remote_uri = Some(v.into()),
                        "local"       => f.local_uri  = Some(v.into()),
                        "persistency" => f.persistency = v.into(),
                        "kind"        => f.kind = Some(v.into()),
                        _ => {}
                    }
                }
            }
            faces.push(f);
        }
        faces
    }

    /// Short label derived from the URI scheme or explicit kind field.
    pub fn kind_label(&self) -> &str {
        if let Some(k) = &self.kind {
            return k.as_str();
        }
        let uri = self.remote_uri.as_deref().or(self.local_uri.as_deref()).unwrap_or("");
        match uri {
            u if u.starts_with("udp4://") || u.starts_with("udp://") => "UDP",
            u if u.starts_with("tcp4://") || u.starts_with("tcp://") => "TCP",
            u if u.starts_with("ws://")   || u.starts_with("wss://") => "WS",
            u if u.starts_with("ether://")                            => "Ether",
            u if u.starts_with("shm://")                              => "SHM",
            u if u.starts_with("unix://")                             => "Unix",
            _ => "?",
        }
    }

    /// CSS class for the kind badge colour.
    pub fn kind_badge_class(&self) -> &str {
        match self.kind_label() {
            "UDP"   => "badge badge-green",
            "TCP"   => "badge badge-blue",
            "WS"    => "badge badge-yellow",
            "Ether" => "badge badge-yellow",
            "SHM"   => "badge badge-gray",
            _       => "badge badge-gray",
        }
    }
}

// ── FIB routes ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NextHop {
    pub face_id: u64,
    pub cost: u32,
}

#[derive(Debug, Clone)]
pub struct FibEntry {
    pub prefix: String,
    pub nexthops: Vec<NextHop>,
}

impl FibEntry {
    /// Parse from `fib/list` response text.
    ///
    /// Format per entry:
    /// ```text
    ///   /ndn nexthops=[faceid=1 cost=10, faceid=2 cost=5]
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with('/') {
                continue;
            }
            let (prefix, nexthops_text) = match line.find(" nexthops=") {
                Some(i) => (&line[..i], &line[i + " nexthops=".len()..]),
                None    => (line, "[]"),
            };
            entries.push(FibEntry {
                prefix: prefix.trim().to_string(),
                nexthops: parse_nexthops(nexthops_text),
            });
        }
        entries
    }
}

fn parse_nexthops(text: &str) -> Vec<NextHop> {
    let inner = text.trim_matches(|c| c == '[' || c == ']');
    inner.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() { return None; }
            let mut nh = NextHop { face_id: 0, cost: 0 };
            for token in part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "faceid" => nh.face_id = v.parse().unwrap_or(0),
                        "cost"   => nh.cost    = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            Some(nh)
        })
        .collect()
}

// ── Content store ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CsInfo {
    pub capacity_bytes: u64,
    pub n_entries: u64,
    pub used_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub variant: String,
}

impl CsInfo {
    /// Parse from `cs/info` response text.
    ///
    /// Format: `"capacity=67108864B entries=42 used=1234B hits=100 misses=50 variant=lru"`
    pub fn parse(text: &str) -> Option<Self> {
        let mut info = CsInfo {
            capacity_bytes: 0,
            n_entries: 0,
            used_bytes: 0,
            hits: 0,
            misses: 0,
            variant: String::new(),
        };
        let mut found = false;
        for token in text.split_whitespace() {
            if let Some((k, v)) = token.split_once('=') {
                found = true;
                // Strip trailing 'B' from byte values
                let v = v.trim_end_matches('B');
                match k {
                    "capacity" => info.capacity_bytes = v.parse().unwrap_or(0),
                    "entries"  => info.n_entries      = v.parse().unwrap_or(0),
                    "used"     => info.used_bytes      = v.parse().unwrap_or(0),
                    "hits"     => info.hits            = v.parse().unwrap_or(0),
                    "misses"   => info.misses          = v.parse().unwrap_or(0),
                    "variant"  => info.variant         = v.to_string(),
                    _ => {}
                }
            }
        }
        found.then_some(info)
    }

    pub fn hit_rate_pct(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 * 100.0 }
    }

    pub fn capacity_mb(&self) -> f64 {
        self.capacity_bytes as f64 / 1_048_576.0
    }

    pub fn used_mb(&self) -> f64 {
        self.used_bytes as f64 / 1_048_576.0
    }
}

// ── Face traffic counters ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FaceCounter {
    pub face_id:       u64,
    pub in_interests:  u64,
    pub in_data:       u64,
    pub out_interests: u64,
    pub out_data:      u64,
    pub in_bytes:      u64,
    pub out_bytes:     u64,
}

impl FaceCounter {
    /// Parse from `faces/counters` response text.
    ///
    /// Format per line:
    /// ```text
    ///   faceid=1 in_interests=10 in_data=5 out_interests=2 out_data=3 in_bytes=1024 out_bytes=512
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("faceid=") {
                continue;
            }
            let mut c = FaceCounter::default();
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    let n: u64 = v.parse().unwrap_or(0);
                    match k {
                        "faceid"        => c.face_id       = n,
                        "in_interests"  => c.in_interests  = n,
                        "in_data"       => c.in_data       = n,
                        "out_interests" => c.out_interests = n,
                        "out_data"      => c.out_data      = n,
                        "in_bytes"      => c.in_bytes      = n,
                        "out_bytes"     => c.out_bytes     = n,
                        _ => {}
                    }
                }
            }
            out.push(c);
        }
        out
    }
}

// ── Measurements ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FaceRtt {
    pub face_id: u64,
    pub srtt_ms: f64,
}

#[derive(Debug, Clone)]
pub struct MeasurementEntry {
    pub prefix: String,
    pub satisfaction_rate: f32,
    pub face_rtts: Vec<FaceRtt>,
}

impl MeasurementEntry {
    /// Parse from `measurements/list` response text.
    ///
    /// Format per line:
    /// ```text
    ///   prefix=/ndn sat_rate=0.950 rtt=[face1=2.1ms face2=4.5ms]
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("prefix=") {
                continue;
            }
            let mut prefix = String::new();
            let mut sat_rate = 0.0f32;
            let mut face_rtts = Vec::new();

            // Extract rtt=[...] block first to avoid splitting on its contents
            let (main_part, rtt_part) = match line.find(" rtt=[") {
                Some(i) => (&line[..i], &line[i + " rtt=[".len()..line.len()-1]),
                None    => (line, ""),
            };

            for token in main_part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix"   => prefix   = v.to_string(),
                        "sat_rate" => sat_rate = v.parse().unwrap_or(0.0),
                        _ => {}
                    }
                }
            }

            // Parse "face1=2.1ms face2=4.5ms"
            for token in rtt_part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    let face_id: u64 = k.strip_prefix("face").unwrap_or("0").parse().unwrap_or(0);
                    let srtt_ms: f64 = v.trim_end_matches("ms").parse().unwrap_or(0.0);
                    face_rtts.push(FaceRtt { face_id, srtt_ms });
                }
            }

            if !prefix.is_empty() {
                out.push(MeasurementEntry { prefix, satisfaction_rate: sat_rate, face_rtts });
            }
        }
        out
    }

    /// Satisfaction rate as a CSS color class.
    pub fn sat_rate_class(&self) -> &'static str {
        if self.satisfaction_rate >= 0.9 { "badge badge-green" }
        else if self.satisfaction_rate >= 0.5 { "badge badge-yellow" }
        else { "badge badge-red" }
    }
}

// ── Throughput history ────────────────────────────────────────────────────────

/// One sample of aggregated traffic (summed across all faces).
#[derive(Debug, Clone, Default)]
pub struct ThroughputSample {
    pub in_bytes:      u64,
    pub out_bytes:     u64,
    pub in_interests:  u64,
    pub out_interests: u64,
}

impl ThroughputSample {
    /// Compute per-second rate between two cumulative counter snapshots.
    /// `elapsed_secs` is the poll interval (typically 3.0).
    pub fn rate_from_delta(prev: &ThroughputSample, curr: &ThroughputSample, elapsed_secs: f64) -> ThroughputSample {
        let delta = |a: u64, b: u64| b.saturating_sub(a);
        ThroughputSample {
            in_bytes:      (delta(prev.in_bytes,      curr.in_bytes)      as f64 / elapsed_secs) as u64,
            out_bytes:     (delta(prev.out_bytes,     curr.out_bytes)     as f64 / elapsed_secs) as u64,
            in_interests:  (delta(prev.in_interests,  curr.in_interests)  as f64 / elapsed_secs) as u64,
            out_interests: (delta(prev.out_interests, curr.out_interests) as f64 / elapsed_secs) as u64,
        }
    }

    /// Sum all face counters into a single aggregate snapshot.
    pub fn from_counters(counters: &[FaceCounter]) -> ThroughputSample {
        ThroughputSample {
            in_bytes:      counters.iter().map(|c| c.in_bytes).sum(),
            out_bytes:     counters.iter().map(|c| c.out_bytes).sum(),
            in_interests:  counters.iter().map(|c| c.in_interests).sum(),
            out_interests: counters.iter().map(|c| c.out_interests).sum(),
        }
    }

    /// Cumulative snapshot from a single face counter (raw values, not rates).
    pub fn from_face_counter(c: &FaceCounter) -> ThroughputSample {
        ThroughputSample {
            in_bytes:      c.in_bytes,
            out_bytes:     c.out_bytes,
            in_interests:  c.in_interests,
            out_interests: c.out_interests,
        }
    }
}

// ── Session recording ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub kind:   String,
    pub params: String,
}

// ── Neighbors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub node_name:   String,
    pub state:       String,   // "Established", "Stale", "Probing", "Absent"
    pub last_seen_s: Option<f64>,
    pub rtt_us:      Option<u32>,
    pub face_ids:    Vec<u64>,
}

impl NeighborInfo {
    /// Parse from `neighbors/list` response text.
    ///
    /// Format per entry:
    /// ```text
    ///   /ndn/site/host  state=Established  last_seen=2.5s ago  rtt=1234us  faces=[1,2]
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with('/') {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let node_name = match tokens.next() {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Collect remaining text, extract faces=[...] block
            let rest: Vec<&str> = tokens.collect();
            let rest_str = rest.join(" ");

            let (main_part, faces_part) = match rest_str.find("faces=[") {
                Some(i) => (&rest_str[..i], &rest_str[i + "faces=[".len()..]),
                None    => (rest_str.as_str(), ""),
            };
            let faces_part = faces_part.trim_end_matches(']');

            let face_ids: Vec<u64> = faces_part
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            let mut state = "Unknown".to_string();
            let mut last_seen_s: Option<f64> = None;
            let mut rtt_us: Option<u32> = None;

            for token in main_part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "state"     => state = v.to_string(),
                        "last_seen" => {
                            // "2.5s" — strip trailing 's'
                            last_seen_s = v.trim_end_matches('s').parse().ok();
                        }
                        "rtt" => {
                            if v != "None" {
                                rtt_us = v.trim_end_matches("us").parse().ok();
                            }
                        }
                        _ => {}
                    }
                }
            }

            out.push(NeighborInfo { node_name, state, last_seen_s, rtt_us, face_ids });
        }
        out
    }

    pub fn state_badge_class(&self) -> &'static str {
        match self.state.as_str() {
            "Established" => "badge badge-green",
            "Stale"       => "badge badge-yellow",
            "Probing"     => "badge badge-blue",
            _             => "badge badge-gray",
        }
    }
}

// ── Security ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityKeyInfo {
    pub name:        String,
    pub has_cert:    bool,
    pub valid_until: String,
}

impl SecurityKeyInfo {
    /// Days remaining until certificate expiry.
    ///
    /// Returns `None` for permanent ("never") or missing ("-") certs.
    /// Returns a negative value if the cert has already expired.
    pub fn days_to_expiry(&self) -> Option<i64> {
        if self.valid_until == "never" || self.valid_until == "-" {
            return None;
        }
        // Router format: "{N}ns" — nanoseconds since Unix epoch.
        if let Some(ns_str) = self.valid_until.strip_suffix("ns")
            && let Ok(ns) = ns_str.parse::<u64>()
        {
            let expiry_secs = (ns / 1_000_000_000) as i64;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            return Some((expiry_secs - now_secs) / 86400);
        }
        None
    }

    /// CSS badge class and label for certificate expiry.
    pub fn expiry_badge(&self) -> (&'static str, String) {
        match self.days_to_expiry() {
            None if self.valid_until == "never" => ("badge badge-green", "permanent".to_string()),
            None => ("badge badge-gray", "—".to_string()),
            Some(d) if d < 0 => ("badge badge-red", "expired".to_string()),
            Some(0) => ("badge badge-red", "< 1d".to_string()),
            Some(d) if d < 7 => ("badge badge-red", format!("{d}d left")),
            Some(d) if d < 30 => ("badge badge-yellow", format!("{d}d left")),
            Some(d) => ("badge badge-green", format!("{d}d left")),
        }
    }

    /// Parse from `security/identity-list` response text.
    ///
    /// Format per entry:
    /// ```text
    ///   name=/ndn/test has_cert=true valid_until=never
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("name=") {
                continue;
            }
            let mut name = String::new();
            let mut has_cert = false;
            let mut valid_until = "-".to_string();
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "name"        => name = v.to_string(),
                        "has_cert"    => has_cert = v == "true",
                        "valid_until" => valid_until = v.to_string(),
                        _ => {}
                    }
                }
            }
            if !name.is_empty() {
                out.push(SecurityKeyInfo { name, has_cert, valid_until });
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnchorInfo {
    pub name: String,
}

impl AnchorInfo {
    /// Parse from `security/anchor-list` response text.
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("name=") {
                out.push(AnchorInfo { name: name.to_string() });
            }
        }
        out
    }
}

// ── Forwarding strategies ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StrategyEntry {
    pub prefix: String,
    pub strategy: String,
}

impl StrategyEntry {
    /// Parse from `strategy-choice/list` response text.
    ///
    /// Format per entry:
    /// ```text
    ///   prefix=/ strategy=best-route
    /// ```
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("prefix=") {
                continue;
            }
            let mut prefix = String::new();
            let mut strategy = String::new();
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix"   => prefix   = v.to_string(),
                        "strategy" => strategy = v.to_string(),
                        _ => {}
                    }
                }
            }
            if !prefix.is_empty() {
                entries.push(StrategyEntry { prefix, strategy });
            }
        }
        entries
    }

    /// Short display name from the strategy name (strips NDN name prefix/version).
    pub fn short_name(&self) -> &str {
        // e.g. "/ndn/strategy/best-route/v5" → "best-route"
        // or "best-route" → "best-route"
        self.strategy
            .rsplit('/')
            .find(|s| !s.starts_with('v') || !s[1..].chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(&self.strategy)
    }
}

// ── CA / NDNCERT info ────────────────────────────────────────────────────────

/// Parsed from `security/ca-info` response text.
///
/// Format (newline-separated key=value):
/// ```text
/// ca_prefix=/ndn/site
/// ca_info=Site CA
/// max_validity_days=365
/// challenges=token,pin
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaInfo {
    pub ca_prefix: String,
    pub ca_info: String,
    pub max_validity_days: u32,
    pub challenges: Vec<String>,
}

impl CaInfo {
    pub fn parse(text: &str) -> Option<Self> {
        let mut s = Self::default();
        let mut found = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "ca_prefix" => { s.ca_prefix = v.to_string(); found = true; }
                    "ca_info"   => s.ca_info = v.to_string(),
                    "max_validity_days" => s.max_validity_days = v.parse().unwrap_or(365),
                    "challenges" => s.challenges = v.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect(),
                    _ => {}
                }
            }
        }
        found.then_some(s)
    }
}
