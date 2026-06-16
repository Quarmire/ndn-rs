//! Dynamic network interface add/remove watcher.
//!
//! Linux: `RTMGRP_LINK` netlink (`RTM_NEWLINK` / `RTM_DELLINK`). Other
//! platforms log a warning and exit.

#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    Added(String),
    Removed(String),
}

/// Watch for interface add/remove events, emitting on `tx`. Exits when the
/// receiver is dropped, `cancel` is triggered, or the platform is unsupported.
pub async fn watch_interfaces(
    tx: tokio::sync::mpsc::Sender<InterfaceEvent>,
    cancel: tokio_util::sync::CancellationToken,
) {
    #[cfg(target_os = "linux")]
    {
        watch_interfaces_linux(tx, cancel).await;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tx, cancel);
        tracing::warn!(
            target: "face.system",
            "`watch_interfaces` is only supported on Linux; \
             interface hotplug disabled on this platform"
        );
    }
}

#[cfg(target_os = "linux")]
async fn watch_interfaces_linux(
    tx: tokio::sync::mpsc::Sender<InterfaceEvent>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use std::os::unix::io::OwnedFd;
    use tokio::io::unix::AsyncFd;

    const RTM_NEWLINK: u16 = 16;

    let fd: i32 = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        tracing::warn!(
            target: "face.system",
            error = %std::io::Error::last_os_error(),
            "failed to open netlink socket for interface watching"
        );
        return;
    }

    // SAFETY: sockaddr_nl is plain C; nl_pid=0 lets the kernel assign,
    // nl_pad=0 is reserved.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = 1; // RTMGRP_LINK
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc != 0 {
        tracing::warn!(
            target: "face.system",
            error = %std::io::Error::last_os_error(),
            "failed to bind netlink socket — interface hotplug disabled"
        );
        unsafe {
            libc::close(fd);
        }
        return;
    }

    let owned: OwnedFd = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
    let async_fd = match AsyncFd::new(owned) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "face.system", error=%e, "failed to register netlink fd with tokio");
            return;
        }
    };

    tracing::info!(target: "face.system", "interface watcher active (netlink RTMGRP_LINK)");

    let mut buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = async_fd.readable() => {
                let mut guard = match result {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::warn!(target: "face.system", error=%e, "netlink read error");
                        break;
                    }
                };
                let n = unsafe {
                    libc::recv(
                        async_fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                guard.clear_ready();
                if n <= 0 {
                    continue;
                }
                let msgs = parse_rtm_link_messages(&buf[..n as usize]);
                for (msg_type, iface_name) in msgs {
                    let event = if msg_type == RTM_NEWLINK {
                        InterfaceEvent::Added(iface_name.clone())
                    } else {
                        InterfaceEvent::Removed(iface_name.clone())
                    };
                    tracing::debug!(
                        target: "face.system",
                        iface = %iface_name,
                        event = if msg_type == RTM_NEWLINK { "added" } else { "removed" },
                        "interface event"
                    );
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Returns `(msg_type, interface_name)` for every `IFLA_IFNAME` attribute
/// found in `RTM_NEWLINK` / `RTM_DELLINK` messages.
#[cfg(target_os = "linux")]
fn parse_rtm_link_messages(buf: &[u8]) -> Vec<(u16, String)> {
    const NLMSG_HDR: usize = 16;
    const IFINFO_HDR: usize = 16;
    const RTA_HDR: usize = 4;
    const IFLA_IFNAME: u16 = 3;
    const RTM_NEWLINK: u16 = 16;
    const RTM_DELLINK: u16 = 17;

    let mut results = Vec::new();
    let mut offset = 0usize;

    while offset + NLMSG_HDR <= buf.len() {
        let nlmsg_len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        let nlmsg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());

        if nlmsg_len < NLMSG_HDR || offset + nlmsg_len > buf.len() {
            break;
        }

        if nlmsg_type == RTM_NEWLINK || nlmsg_type == RTM_DELLINK {
            let attr_start = offset + NLMSG_HDR + IFINFO_HDR;
            let attr_end = offset + nlmsg_len;
            let mut attr_off = attr_start;

            while attr_off + RTA_HDR <= attr_end {
                let rta_len =
                    u16::from_ne_bytes(buf[attr_off..attr_off + 2].try_into().unwrap()) as usize;
                let rta_type =
                    u16::from_ne_bytes(buf[attr_off + 2..attr_off + 4].try_into().unwrap());
                if rta_len < RTA_HDR || attr_off + rta_len > attr_end {
                    break;
                }
                if rta_type == IFLA_IFNAME {
                    let data = &buf[attr_off + RTA_HDR..attr_off + rta_len];
                    let name = data.split(|&b| b == 0).next().unwrap_or(data);
                    if let Ok(s) = std::str::from_utf8(name) {
                        results.push((nlmsg_type, s.to_owned()));
                    }
                }
                let aligned = (rta_len + 3) & !3;
                attr_off += aligned;
            }
        }

        let aligned = (nlmsg_len + 3) & !3;
        offset += aligned;
    }

    results
}
