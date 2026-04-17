//! Platform-agnostic IPC transport for the NDN management socket.
//!
//! Abstracts over Unix domain sockets (Linux / macOS) and Windows Named Pipes
//! so that `MgmtClient`, `run_face_listener`, and `ndn-ctl` compile and run on
//! all three platforms without conditional-compilation scaffolding at each call
//! site.
//!
//! # Face type
//!
//! [`IpcFace`] uses boxed trait objects for the read / write halves so the
//! concrete type is identical on every platform:
//!
//! ```text
//! IpcFace = StreamFace<
//!     Box<dyn AsyncRead + Send + Unpin>,
//!     Box<dyn AsyncWrite + Send + Unpin>,
//!     TlvCodec,
//! >
//! ```
//!
//! The boxing overhead is negligible for management traffic.
//!
//! # Default socket paths
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

/// Platform-agnostic NDN face over the management IPC socket.
///
/// On Unix this is backed by a `UnixStream`; on Windows by a Named Pipe.
/// The concrete type is the same on all platforms.
pub type IpcFace = StreamFace<DynRead, DynWrite, TlvCodec>;

fn make_face(id: FaceId, kind: FaceKind, uri: String, r: DynRead, w: DynWrite) -> IpcFace {
    StreamFace::new(id, kind, false, None, Some(uri), r, w, TlvCodec)
}

/// Listens for IPC connections on the management socket path.
///
/// # Unix
/// Binds a Unix domain socket at `path`, removing any stale file first.
/// Call [`IpcListener::cleanup`] on shutdown to remove the socket file.
///
/// # Windows
/// `path` must be a named pipe path such as `\\.\pipe\ndn`.
/// Named pipes are cleaned up automatically when all handles close.
pub struct IpcListener {
    inner: PlatformListener,
}

impl IpcListener {
    pub fn bind(path: &str) -> io::Result<Self> {
        Ok(Self {
            inner: PlatformListener::bind(path)?,
        })
    }

    pub async fn accept(&self, face_id: FaceId) -> io::Result<IpcFace> {
        let (r, w, uri) = self.inner.accept().await?;
        Ok(make_face(face_id, FaceKind::Management, uri, r, w))
    }

    pub fn cleanup(&self) {
        self.inner.cleanup();
    }

    pub fn uri(&self) -> &str {
        self.inner.uri()
    }
}

/// Connect to the IPC socket at `path` and return an [`IpcFace`].
///
/// On Unix, `path` is a filesystem path to a Unix domain socket.
/// On Windows, `path` is a named pipe path such as `\\.\pipe\ndn`.
pub async fn ipc_face_connect(id: FaceId, path: &str) -> io::Result<IpcFace> {
    let (r, w, uri) = platform_connect(path).await?;
    Ok(make_face(id, FaceKind::Unix, uri, r, w))
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

    // ERROR_PIPE_BUSY (231): all server instances busy — retry.
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
