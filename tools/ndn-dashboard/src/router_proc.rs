/// Managed subprocess for the `ndn-router` binary.
///
/// `RouterProc` owns the child process.  stdout and stderr are captured into
/// a shared ring-buffer (`log_buf`) by background Tokio tasks.  Since those
/// tasks only hold an `Arc<Mutex<_>>` (which is `Send`), they work fine on
/// Dioxus's `current_thread` Tokio runtime.
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::types::LogEntry;

// ── RouterProc ────────────────────────────────────────────────────────────────

pub struct RouterProc {
    child:   Child,
    log_buf: Arc<Mutex<VecDeque<LogEntry>>>,
}

const LOG_BUF_CAP: usize = 2000;

impl RouterProc {
    /// Spawn `ndn-router` at `binary`, wiring stdout/stderr to the log buffer.
    /// If `config_path` is `Some`, passes `--config <path>` to the process.
    pub async fn start(binary: &PathBuf, config_path: Option<&str>) -> anyhow::Result<Self> {
        let log_buf = Arc::new(Mutex::new(VecDeque::with_capacity(LOG_BUF_CAP)));

        let mut cmd = Command::new(binary);
        if let Some(path) = config_path {
            cmd.args(["--config", path]);
        }
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // stdout capture task
        if let Some(stdout) = child.stdout.take() {
            let buf = log_buf.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let entry = LogEntry::parse_line(&line);
                    let mut q = buf.lock().unwrap();
                    q.push_back(entry);
                    if q.len() > LOG_BUF_CAP { q.pop_front(); }
                }
            });
        }

        // stderr capture task
        if let Some(stderr) = child.stderr.take() {
            let buf = log_buf.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let entry = LogEntry::parse_line(&line);
                    let mut q = buf.lock().unwrap();
                    q.push_back(entry);
                    if q.len() > LOG_BUF_CAP { q.pop_front(); }
                }
            });
        }

        Ok(Self { child, log_buf })
    }

    /// Returns `true` if the child process has not yet exited.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Send SIGKILL / TerminateProcess and wait for the child to exit.
    pub async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }

    /// Drain all buffered log entries (clears the buffer).
    pub fn drain_logs(&self) -> Vec<LogEntry> {
        self.log_buf.lock().unwrap().drain(..).collect()
    }
}

// ── Temp config writer ────────────────────────────────────────────────────────

/// Write `toml` to a temporary file and return its path.
/// Used by StartRouterModal "Start with Config" to pass the current config
/// to the router without requiring the user to save it manually.
pub fn write_temp_config(toml: &str) -> std::io::Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join("ndn-dashboard-config.toml");
    std::fs::write(&path, toml)?;
    Ok(path)
}

// ── Binary discovery ──────────────────────────────────────────────────────────

/// Search `$PATH` and the directory containing this executable for `ndn-router`.
pub fn find_binary() -> Option<PathBuf> {
    #[cfg(windows)]
    const NAME: &str = "ndn-router.exe";
    #[cfg(not(windows))]
    const NAME: &str = "ndn-router";

    // 1. $PATH
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(NAME);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // 2. Adjacent to the running executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let adjacent = parent.join(NAME);
        if adjacent.exists() {
            return Some(adjacent);
        }
    }

    None
}
