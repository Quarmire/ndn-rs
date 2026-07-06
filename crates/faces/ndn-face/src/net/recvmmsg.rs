//! Batched UDP receive via Linux `recvmmsg(2)` — one syscall drains up to
//! `BATCH` datagrams, amortising the per-packet syscall cost that dominates
//! a busy forwarder's receive path.
//!
//! **Unvalidated on this machine.** This is unsafe FFI gated behind the
//! off-by-default `udp-recvmmsg` feature; it must be benchmarked and tested on
//! Linux before being enabled in production (see the UDP batched-I/O note).
//! The non-batched single-`recv_from` path remains the default everywhere.

#![cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;

use bytes::Bytes;

/// Datagrams drained per `recvmmsg` call.
pub(crate) const BATCH: usize = 16;
/// Per-datagram buffer (matches the single-recv path's 9000-byte buffer,
/// covering a jumbo frame / reassembled fragment).
const BUFSZ: usize = 9000;

/// One non-blocking `recvmmsg`. Returns up to `BATCH` `(payload, source)`
/// pairs. A `WouldBlock` error means "no data ready" — the caller should await
/// socket readiness and retry. The `fd` must be a live, non-blocking-capable
/// UDP socket owned by the caller for the duration of the call.
pub(crate) fn recvmmsg_batch(fd: RawFd) -> std::io::Result<Vec<(Bytes, SocketAddr)>> {
    let mut bufs = vec![[0u8; BUFSZ]; BATCH];
    let mut addrs = vec![unsafe { std::mem::zeroed::<libc::sockaddr_storage>() }; BATCH];
    let mut iovecs = vec![
        libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0
        };
        BATCH
    ];
    let mut msgs: Vec<libc::mmsghdr> = (0..BATCH)
        .map(|_| unsafe { std::mem::zeroed::<libc::mmsghdr>() })
        .collect();

    for (i, msg) in msgs.iter_mut().enumerate() {
        iovecs[i] = libc::iovec {
            iov_base: bufs[i].as_mut_ptr().cast(),
            iov_len: BUFSZ,
        };
        let hdr = &mut msg.msg_hdr;
        hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(i) };
        hdr.msg_iovlen = 1;
        hdr.msg_name = unsafe { addrs.as_mut_ptr().add(i) }.cast();
        hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    }

    // SAFETY: msgs/iovecs/addrs/bufs are all live and correctly cross-linked
    // for the call; recvmmsg writes only into the buffers we provided and sets
    // each msg_len / msg_namelen.
    let n = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            BATCH as libc::c_uint,
            // c_int on glibc, c_uint on musl — coerce to the target's type.
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let len = msgs[i].msg_len as usize;
        // SAFETY: addrs[i] was filled by the kernel for the i-th message.
        if let Some(src) = unsafe { to_socket_addr(&addrs[i]) } {
            out.push((Bytes::copy_from_slice(&bufs[i][..len.min(BUFSZ)]), src));
        }
    }
    Ok(out)
}

/// Convert a kernel-filled `sockaddr_storage` to a `SocketAddr` (v4/v6).
///
/// SAFETY: `storage` must be a `sockaddr_storage` the kernel populated; we read
/// the family tag and reinterpret as the matching `sockaddr_in`/`in6`.
unsafe fn to_socket_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
