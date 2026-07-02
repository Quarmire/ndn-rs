//! Platform-agnostic IPC transport for the NDN management socket: Unix
//! domain sockets on Linux/macOS, Windows Named Pipes on Windows.
//! [`IpcFace`] boxes the read/write halves so the concrete type is identical
//! on every platform.
//!
//! | Platform | Default path |
//! |----------|-------------|
//! | Unix     | `/run/nfd/nfd.sock` |
//! | Windows  | `\\.\pipe\ndn` |

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

use ndn_transport::{FaceId, FaceKind, StreamFace, TlvCodec};

type DynRead = Box<dyn AsyncRead + Send + Sync + Unpin>;
type DynWrite = Box<dyn AsyncWrite + Send + Sync + Unpin>;

pub type IpcFace = StreamFace<DynRead, DynWrite, TlvCodec>;

fn make_face(id: FaceId, kind: FaceKind, uri: String, r: DynRead, w: DynWrite) -> IpcFace {
    StreamFace::new(id, kind, None, Some(uri), r, w, TlvCodec)
}

/// Unix: binds a domain socket at `path`, removing any stale file first;
/// call [`IpcListener::cleanup`] on shutdown.
/// Windows: `path` is a named pipe (`\\.\pipe\…`); cleanup is automatic.
pub struct IpcListener {
    inner: PlatformListener,
}

impl IpcListener {
    pub fn bind(path: &str) -> io::Result<Self> {
        Ok(Self {
            inner: PlatformListener::bind(path)?,
        })
    }

    /// Accept a connection as an operator-trusted `FaceKind::Management` face
    /// (the NFD management socket; trust is gated by `0600` filesystem perms).
    pub async fn accept(&self, face_id: FaceId) -> io::Result<IpcFace> {
        self.accept_as(face_id, FaceKind::Management).await
    }

    /// Accept a connection with an explicit [`FaceKind`]. Use
    /// `FaceKind::App` for ordinary client connections that should *not*
    /// inherit operator-level management trust (privileged verbs then go
    /// through signed-command auth, not face-kind).
    pub async fn accept_as(&self, face_id: FaceId, kind: FaceKind) -> io::Result<IpcFace> {
        let (r, w, uri) = self.inner.accept().await?;
        Ok(make_face(face_id, kind, uri, r, w))
    }

    pub fn cleanup(&self) {
        self.inner.cleanup();
    }

    pub fn uri(&self) -> &str {
        self.inner.uri()
    }
}

pub async fn ipc_face_connect(id: FaceId, path: &str) -> io::Result<IpcFace> {
    let (r, w, uri) = platform_connect(path).await?;
    Ok(make_face(id, FaceKind::Unix, uri, r, w))
}

/// Adopt an already-connected `SOCK_STREAM` fd as an [`IpcFace`], taking
/// ownership of it. The mobile counterpart to [`ipc_face_connect`]: where there
/// is no socket path to dial — Android hands the UI one half of a `socketpair()`
/// across Binder as a `ParcelFileDescriptor` — the fd *is* the rendezvous. The
/// resulting face is the same `StreamFace` type as the path-based constructors.
///
/// Unix only; the mobile targets (`aarch64-apple-ios`, `aarch64-linux-android`)
/// are Unix, and the unsafe-fd-adoption idiom is already used elsewhere in this
/// crate (`l2/af_packet.rs`, `local/shm/spsc.rs`).
#[cfg(unix)]
pub fn ipc_face_from_raw_fd(
    id: FaceId,
    kind: FaceKind,
    fd: std::os::fd::RawFd,
) -> io::Result<IpcFace> {
    use std::os::fd::FromRawFd;
    // SAFETY: the caller transfers ownership of a valid, connected SOCK_STREAM
    // fd; `UnixStream` becomes its sole owner and closes it on drop.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    let (r, w) = tokio::net::UnixStream::from_std(std_stream)?.into_split();
    Ok(make_face(
        id,
        kind,
        format!("fd://{fd}"),
        Box::new(r),
        Box::new(w),
    ))
}

#[cfg(unix)]
struct PlatformListener {
    listener: tokio::net::UnixListener,
    path: String,
}

#[cfg(unix)]
impl PlatformListener {
    fn bind(path: &str) -> io::Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
        let listener = tokio::net::UnixListener::bind(path)?;
        // When the forwarder runs as root (required to bind a socket under
        // /run and to open privileged faces) the socket inherits root
        // ownership and the process umask — typically denying connect() to
        // the unprivileged user running ndn-ctl or the dashboard. Make it
        // world-RW so local management clients can connect; commands are
        // still gated by `require_signed_commands`. Mirrors NFD, whose local
        // unix socket is reachable by local clients.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
        }
        Ok(Self {
            listener,
            path: path.to_owned(),
        })
    }

    async fn accept(&self) -> io::Result<(DynRead, DynWrite, String)> {
        let (stream, _) = self.listener.accept().await?;
        let (r, w) = stream.into_split();
        let uri = format!("unix://{}", self.path);
        Ok((Box::new(r), Box::new(w), uri))
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    fn uri(&self) -> &str {
        &self.path
    }
}

#[cfg(unix)]
async fn platform_connect(path: &str) -> io::Result<(DynRead, DynWrite, String)> {
    let stream = tokio::net::UnixStream::connect(path).await?;
    let (r, w) = stream.into_split();
    let uri = format!("unix://{path}");
    Ok((Box::new(r), Box::new(w), uri))
}

#[cfg(windows)]
struct PlatformListener {
    path: String,
    first: std::sync::atomic::AtomicBool,
}

#[cfg(windows)]
impl PlatformListener {
    fn bind(path: &str) -> io::Result<Self> {
        if !path.starts_with(r"\\.\pipe\") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Windows IPC path must start with \\\\.\\pipe\\ (got {path:?}). \
                     Use e.g. \\\\.\\pipe\ndn"
                ),
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            first: std::sync::atomic::AtomicBool::new(true),
        })
    }

    async fn accept(&self) -> io::Result<(DynRead, DynWrite, String)> {
        use std::sync::atomic::Ordering;
        use tokio::net::windows::named_pipe::ServerOptions;

        let first = self.first.swap(false, Ordering::AcqRel);
        let server = ServerOptions::new()
            .first_pipe_instance(first)
            .access_inbound(true)
            .access_outbound(true)
            .create(&self.path)?;

        server.connect().await?;

        let (r, w) = tokio::io::split(server);
        let uri = format!("pipe://{}", self.path);
        Ok((Box::new(r), Box::new(w), uri))
    }

    fn cleanup(&self) {}

    fn uri(&self) -> &str {
        &self.path
    }
}

#[cfg(windows)]
async fn platform_connect(path: &str) -> io::Result<(DynRead, DynWrite, String)> {
    use tokio::net::windows::named_pipe::ClientOptions;

    // ERROR_PIPE_BUSY: all server instances busy — retry.
    let client = loop {
        match ClientOptions::new().open(path) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    };

    let (r, w) = tokio::io::split(client);
    let uri = format!("pipe://{path}");
    Ok((Box::new(r), Box::new(w), uri))
}

#[cfg(not(any(unix, windows)))]
compile_error!(
    "ndn-face-local IPC transport requires Unix domain sockets (unix) \
     or Windows Named Pipes (windows)"
);
