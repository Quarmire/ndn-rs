//! Batched UDP send via Linux `sendmmsg(2)` — one syscall ships a burst of
//! datagrams to the same peer (e.g. the NDNLPv2 fragments of one large packet),
//! amortising the per-datagram syscall cost on the egress path. The symmetric
//! counterpart to [`super::recvmmsg`].
//!
//! Behind the off-by-default `udp-sendmmsg` feature (Linux); validate +
//! benchmark before trusting in production. The single-`send_to` path is the
//! default everywhere.

#![cfg(all(feature = "udp-sendmmsg", target_os = "linux"))]

use std::net::SocketAddr;
use std::os::unix::io::RawFd;

use bytes::Bytes;

/// Render a `SocketAddr` into a `sockaddr_storage` + valid length.
fn to_storage(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
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

/// One non-blocking `sendmmsg` of `wires` to `peer`. Returns the number of
/// datagrams accepted (the kernel may send a prefix); `WouldBlock` is returned
/// as an error so the caller can await writability and resend the remainder.
/// `fd` must be a live UDP socket owned by the caller for the call.
pub(crate) fn sendmmsg_batch(
    fd: RawFd,
    peer: &SocketAddr,
    wires: &[Bytes],
) -> std::io::Result<usize> {
    debug_assert!(!wires.is_empty());
    let (storage, addr_len) = to_storage(peer);
    let name_ptr = &storage as *const _ as *mut libc::c_void;

    let mut iovecs: Vec<libc::iovec> = wires
        .iter()
        .map(|w| libc::iovec {
            iov_base: w.as_ptr() as *mut libc::c_void,
            iov_len: w.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = (0..wires.len())
        .map(|_| unsafe { std::mem::zeroed::<libc::mmsghdr>() })
        .collect();
    for (i, msg) in msgs.iter_mut().enumerate() {
        let hdr = &mut msg.msg_hdr;
        hdr.msg_name = name_ptr;
        hdr.msg_namelen = addr_len;
        hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(i) };
        hdr.msg_iovlen = 1;
    }

    // SAFETY: msgs/iovecs reference the live `wires` slices and the shared
    // `storage` for the duration of the call; sendmmsg only reads them.
    let sent = unsafe {
        libc::sendmmsg(
            fd,
            msgs.as_mut_ptr(),
            wires.len() as libc::c_uint,
            // `flags` is c_int on glibc but c_uint on musl — coerce to the
            // target's type so this builds for both (e.g. aarch64 musl boards).
            libc::MSG_DONTWAIT as _,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(sent as usize)
}
