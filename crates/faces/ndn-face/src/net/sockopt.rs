//! Best-effort UDP socket tuning shared by the unicast and multicast faces.
//!
//! NDN forwarders run bursty datagram traffic; the OS default socket buffers
//! (often 128–256 KiB) drop packets under load before the per-face reader task
//! drains them. We request larger `SO_RCVBUF`/`SO_SNDBUF` after bind. This is
//! advisory — the kernel clamps to `net.core.{r,w}mem_max` and may halve/double
//! the value — so failures are logged, never fatal.
//!
//! Unix only (`setsockopt` via `libc`); a no-op elsewhere until a Windows path
//! is added.
//!
//! NOTE: on Linux the request is capped by `net.core.rmem_max` /
//! `net.core.wmem_max` (often only ~208 KiB on a stock host), so realising the
//! full 4 MiB needs `sysctl -w net.core.rmem_max=...` (or `SO_RCVBUFFORCE`,
//! which needs `CAP_NET_ADMIN`). The request is harmless where it is clamped.

/// Bind a UDP socket with `SO_REUSEPORT` + `SO_REUSEADDR` set *before* bind, so
/// several sockets can share `addr` and the kernel load-balances inbound
/// datagrams across them per flow (Linux 4-tuple hash) — the basis for
/// multi-core RX sharding on the listener. Receive buffer is tuned like the
/// faces. Unix only; callers use this to open N listener sockets.
#[cfg(unix)]
pub fn bind_reuseport_udp(addr: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket() yields an owned fd (closed on error before return).
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let set_flag = |opt: libc::c_int| -> std::io::Result<()> {
        let one: libc::c_int = 1;
        // SAFETY: fd is live; &one is a valid c_int option buffer.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(one).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    let bind_result = (|| {
        set_flag(libc::SO_REUSEADDR)?;
        set_flag(libc::SO_REUSEPORT)?;
        let (storage, len) = sockaddr_to_storage(&addr);
        // SAFETY: storage/len describe a valid sockaddr for `fd`'s family.
        let rc = unsafe { libc::bind(fd, std::ptr::addr_of!(storage).cast(), len) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })();
    if let Err(e) = bind_result {
        // SAFETY: fd is live and owned; close it before erroring out.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: fd is a freshly bound UDP socket we exclusively own.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    tune_datagram_socket(&sock, "udp-listener");
    Ok(sock)
}

/// Render a `SocketAddr` into a `sockaddr_storage` + valid length (v4/v6).
#[cfg(unix)]
pub(crate) fn sockaddr_to_storage(
    addr: &std::net::SocketAddr,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        std::net::SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// Default UDP receive buffer request (4 MiB). Subject to kernel clamping.
pub const DEFAULT_UDP_RCVBUF: usize = 4 * 1024 * 1024;
/// Default UDP send buffer request (1 MiB).
pub const DEFAULT_UDP_SNDBUF: usize = 1024 * 1024;

/// Apply the default send/receive buffer sizes to a bound datagram socket.
/// `label` is only used for log context (`udp` / `multicast`).
#[cfg(unix)]
pub fn tune_datagram_socket<F: std::os::unix::io::AsRawFd>(sock: &F, label: &str) {
    let fd = sock.as_raw_fd();
    set_buf(fd, libc::SO_RCVBUF, DEFAULT_UDP_RCVBUF, "SO_RCVBUF", label);
    set_buf(fd, libc::SO_SNDBUF, DEFAULT_UDP_SNDBUF, "SO_SNDBUF", label);
}

#[cfg(not(unix))]
pub fn tune_datagram_socket<F>(_sock: &F, _label: &str) {}

#[cfg(unix)]
fn set_buf(
    fd: std::os::unix::io::RawFd,
    opt: libc::c_int,
    bytes: usize,
    opt_name: &str,
    label: &str,
) {
    let val = bytes as libc::c_int;
    // SAFETY: fd is a live socket owned by the caller for the call's duration;
    // &val/size describe a valid c_int option buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            std::ptr::addr_of!(val).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            target: "face.udp",
            face_kind = label,
            opt = opt_name,
            requested = bytes,
            error = %std::io::Error::last_os_error(),
            "could not enlarge UDP socket buffer (using OS default)"
        );
    }
}

/// Read back the effective receive-buffer size (test helper).
#[cfg(all(unix, test))]
pub(crate) fn recv_buffer_size<F: std::os::unix::io::AsRawFd>(sock: &F) -> std::io::Result<usize> {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: out-params are valid for the call; fd is a live socket.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of_mut!(val).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val as usize)
}
