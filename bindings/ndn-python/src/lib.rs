//! PyO3 Python bindings for ndn-rs.
//!
//! Exposes a `ndn_rs` Python module with blocking `Consumer` and `Producer`
//! classes backed by `ndn-app`'s internal Tokio runtime. No async runtime or
//! `asyncio` is required on the Python side.
//!
//! # Build
//!
//! ```bash
//! pip install maturin
//! maturin develop           # editable install for the current Python env
//! maturin build --release   # produce a wheel
//! ```
//!
//! # Usage
//!
//! ```python
//! from ndn_rs import Consumer, Producer
//!
//! # Fetch content
//! c = Consumer("/tmp/ndn-faces.sock")
//! raw = c.get("/ndn/sensor/temperature")  # bytes
//!
//! # Serve data
//! p = Producer("/tmp/ndn-faces.sock", "/ndn/sensor")
//! p.serve(lambda name: b"23.5" if "temperature" in name else None)
//! ```

// PyO3 0.22 + Rust 2024 edition: the #[pymethods] macro expands internal
// unsafe fn calls that trigger the unsafe_op_in_unsafe_fn lint. These are
// genuine false positives from macro expansion; the user-written methods
// are all safe.
#![allow(unsafe_op_in_unsafe_fn)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use ndn_app::AppError;
use ndn_app::blocking::{BlockingConsumer, BlockingProducer};

// ── Error conversion ──────────────────────────────────────────────────────────

fn to_py_err(e: AppError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

// ── Data ──────────────────────────────────────────────────────────────────────

/// An NDN Data packet returned by :class:`Consumer`.
///
/// Attributes
/// ----------
/// name : str
///     Full NDN name as a URI string, e.g. ``"/ndn/sensor/temperature"``.
/// content : bytes
///     Raw content payload.
#[pyclass]
struct Data {
    name: String,
    content: Vec<u8>,
}

#[pymethods]
impl Data {
    /// Full NDN name as a URI string.
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    /// Raw content payload.
    #[getter]
    fn content(&self) -> &[u8] {
        &self.content
    }

    fn __repr__(&self) -> String {
        format!(
            "Data(name={:?}, content_len={})",
            self.name,
            self.content.len()
        )
    }
}

impl Data {
    fn from_packet(data: ndn_packet::Data) -> Self {
        Self {
            name: data.name.to_string(),
            content: data.content().map(|b| b.to_vec()).unwrap_or_default(),
        }
    }
}

// ── Consumer ──────────────────────────────────────────────────────────────────

/// Synchronous NDN consumer.
///
/// Connects to a running ``ndn-router`` via its Unix socket. All calls block
/// the calling thread (and the Python GIL) for up to the Interest lifetime
/// (default 4.5 s). For concurrent fetches, use ``asyncio.to_thread`` or
/// create one :class:`Consumer` per thread.
///
/// Parameters
/// ----------
/// socket : str
///     Path to the router's face socket, e.g. ``"/tmp/ndn-faces.sock"``.
///
/// Raises
/// ------
/// RuntimeError
///     If the connection to the router fails.
///
/// Examples
/// --------
/// ::
///
///     c = ndn_rs.Consumer("/tmp/ndn-faces.sock")
///     raw   = c.get("/ndn/sensor/temperature")   # bytes
///     data  = c.fetch("/ndn/sensor/temperature")  # Data object
///     print(data.name, data.content)
#[pyclass]
struct Consumer {
    inner: BlockingConsumer,
}

#[pymethods]
impl Consumer {
    #[new]
    fn new(socket: &str) -> PyResult<Self> {
        BlockingConsumer::connect(socket)
            .map(|inner| Self { inner })
            .map_err(to_py_err)
    }

    /// Fetch the content bytes for a name.
    ///
    /// Parameters
    /// ----------
    /// name : str
    ///     NDN name URI, e.g. ``"/ndn/sensor/temperature"``.
    ///
    /// Returns
    /// -------
    /// bytes
    ///     Content of the Data packet that satisfies the Interest.
    ///
    /// Raises
    /// ------
    /// RuntimeError
    ///     On timeout, Nack, or connection error.
    fn get(&mut self, name: &str) -> PyResult<Vec<u8>> {
        self.inner.get(name).map(|b| b.to_vec()).map_err(to_py_err)
    }

    /// Fetch a full :class:`Data` packet for a name.
    ///
    /// Returns a :class:`Data` object with both the name and content, useful
    /// when the exact name of the returned Data matters (e.g. versioned names).
    ///
    /// Raises
    /// ------
    /// RuntimeError
    ///     On timeout, Nack, or connection error.
    fn fetch(&mut self, name: &str) -> PyResult<Data> {
        self.inner
            .fetch(name)
            .map(Data::from_packet)
            .map_err(to_py_err)
    }
}

// ── Producer ─────────────────────────────────────────────────────────────────

/// Synchronous NDN producer.
///
/// Connects to a running ``ndn-router``, registers a name prefix, and serves
/// Interests via a Python callback.
///
/// Parameters
/// ----------
/// socket : str
///     Path to the router's face socket.
/// prefix : str
///     NDN name prefix to register, e.g. ``"/ndn/sensor"``.
///
/// Raises
/// ------
/// RuntimeError
///     If the connection or prefix registration fails.
///
/// Examples
/// --------
/// ::
///
///     p = ndn_rs.Producer("/tmp/ndn-faces.sock", "/ndn/sensor")
///
///     def handler(name: str) -> bytes | None:
///         if name.endswith("/temperature"):
///             return b"23.5"
///         return None   # drop the Interest
///
///     p.serve(handler)  # blocks until connection closes
#[pyclass]
struct Producer {
    inner: BlockingProducer,
}

#[pymethods]
impl Producer {
    #[new]
    fn new(socket: &str, prefix: &str) -> PyResult<Self> {
        BlockingProducer::connect(socket, prefix)
            .map(|inner| Self { inner })
            .map_err(to_py_err)
    }

    /// Run the producer serve loop.
    ///
    /// Calls ``handler(name: str) -> bytes | None`` for each incoming Interest.
    /// Return ``bytes`` to satisfy it with a Data packet; return ``None`` to
    /// drop the Interest silently.
    ///
    /// The Python GIL is released while waiting for the next Interest,
    /// allowing other threads to run. The GIL is re-acquired only during
    /// each call to ``handler``.
    ///
    /// This method blocks until the router connection closes or an error occurs.
    ///
    /// Parameters
    /// ----------
    /// handler : callable
    ///     ``(name: str) -> bytes | None``
    fn serve(&mut self, py: Python<'_>, handler: PyObject) -> PyResult<()> {
        // Arc<Mutex<>> makes the PyObject Send + Sync, satisfying
        // BlockingProducer::serve's F: Fn(..) + Send + Sync + 'static bound.
        let handler = Arc::new(Mutex::new(handler));

        py.allow_threads(|| {
            self.inner.serve(move |interest| {
                let name_str = interest.name.to_string();
                let h = Arc::clone(&handler);

                // Re-acquire GIL only for the Python callback invocation.
                Python::with_gil(|py| -> Option<Bytes> {
                    let locked = h.lock().ok()?;
                    let result = locked.bind(py).call1((name_str,)).ok()?;
                    if result.is_none() {
                        return None;
                    }
                    let raw: Vec<u8> = result.extract().ok()?;
                    Some(Bytes::from(raw))
                })
            })
        })
        .map_err(to_py_err)
    }
}

// ── Module ────────────────────────────────────────────────────────────────────

#[pymodule]
fn ndn_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Data>()?;
    m.add_class::<Consumer>()?;
    m.add_class::<Producer>()?;
    Ok(())
}
