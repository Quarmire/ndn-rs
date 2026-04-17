//! Network interface enumeration and name filtering.
//!
//! Provides a cross-platform [`list_interfaces`] function and glob-based
//! whitelist/blacklist filtering used by the face system auto-configuration.

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4_addrs: Vec<Ipv4Addr>,
    pub is_up: bool,
    pub is_multicast: bool,
    pub is_loopback: bool,
}

/// Returns `true` if `name` passes the whitelist/blacklist filter.
///
/// - Blacklist is checked first: any match → denied.
/// - Whitelist is checked next: at least one match required (empty = allow all).
pub fn interface_allowed(name: &str, whitelist: &[String], blacklist: &[String]) -> bool {
    if blacklist
        .iter()
        .any(|p| glob_match(p.as_bytes(), name.as_bytes()))
    {
        return false;
    }
    whitelist.is_empty()
        || whitelist
            .iter()
            .any(|p| glob_match(p.as_bytes(), name.as_bytes()))
}

/// Minimal glob matcher supporting `*` (any sequence) and `?` (one char).
///
/// Operates on byte slices; interface names are always ASCII so this is safe.
pub fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern, name) {
            ([], []) => true,
        ([], _) => false,
        ([b'*', rest @ ..], _) => {
            glob_match(rest, name) || (!name.is_empty() && glob_match(pattern, &name[1..]))
        }
        ([b'?', p_rest @ ..], [_, n_rest @ ..]) => glob_match(p_rest, n_rest),
        ([b'?', ..], []) => false,
        ([p, p_rest @ ..], [n, n_rest @ ..]) if p == n => glob_match(p_rest, n_rest),
        _ => false,
    }
}

/// Enumerate all network interfaces on this host.
///
/// Returns an empty `Vec` on unsupported platforms or when the OS call fails.
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    #[cfg(unix)]
    {
        list_interfaces_unix()
    }
    #[cfg(windows)]
    {
        list_interfaces_windows()
    }
    #[cfg(not(any(unix, windows)))]
    {
        vec![]
    }
}

#[cfg(unix)]
fn list_interfaces_unix() -> Vec<InterfaceInfo> {
    use std::collections::HashMap;

    let mut map: HashMap<String, InterfaceInfo> = HashMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "getifaddrs failed — interface enumeration unavailable"
            );
            return vec![];
        }

        let mut ifa = ifap;
        while !ifa.is_null() {
            let name_ptr = (*ifa).ifa_name;
            if name_ptr.is_null() {
                ifa = (*ifa).ifa_next;
                continue;
            }
            let name = std::ffi::CStr::from_ptr(name_ptr)
                .to_string_lossy()
                .into_owned();

            let flags = (*ifa).ifa_flags;
            let is_up =
                flags & (libc::IFF_UP as u32) != 0 && flags & (libc::IFF_RUNNING as u32) != 0;
            let is_multicast = flags & (libc::IFF_MULTICAST as u32) != 0;
            let is_loopback = flags & (libc::IFF_LOOPBACK as u32) != 0;

            let entry = map.entry(name.clone()).or_insert_with(|| InterfaceInfo {
                name: name.clone(),
                ipv4_addrs: Vec::new(),
                is_up,
                is_multicast,
                is_loopback,
            });
            entry.is_up = is_up;
            entry.is_multicast = is_multicast;
            entry.is_loopback = is_loopback;

            if !(*ifa).ifa_addr.is_null() {
                let sa_family = (*(*ifa).ifa_addr).sa_family as i32;
                if sa_family == libc::AF_INET {
                    let sin = (*ifa).ifa_addr as *const libc::sockaddr_in;
                    let raw = u32::from_be((*sin).sin_addr.s_addr);
                    entry.ipv4_addrs.push(Ipv4Addr::from(raw));
                }
            }

            ifa = (*ifa).ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    map.into_values().collect()
}

#[cfg(windows)]
fn list_interfaces_windows() -> Vec<InterfaceInfo> {
    use std::collections::HashMap;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    const AF_UNSPEC: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

    let mut buf_len: u32 = 16 * 1024;
    let mut buf: Vec<u8> = vec![0u8; buf_len as usize];

    let rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };
    if rc == ERROR_BUFFER_OVERFLOW {
        buf.resize(buf_len as usize, 0);
    } else if rc != 0 {
        return vec![];
    }

    let rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };
    if rc != 0 {
        return vec![];
    }

    let mut map: HashMap<String, InterfaceInfo> = HashMap::new();
    unsafe {
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let friendly = if (*adapter).FriendlyName.is_null() {
                String::new()
            } else {
                    let mut len = 0usize;
                let ptr = (*adapter).FriendlyName;
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
            };

            let is_up = (*adapter).OperStatus == 1; // IfOperStatusUp
            let is_loopback = (*adapter).IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            // Windows doesn't expose a per-adapter multicast flag;
            // treat all non-loopback UP adapters as multicast-capable.
            let is_multicast = is_up && !is_loopback;

            let entry = map
                .entry(friendly.clone())
                .or_insert_with(|| InterfaceInfo {
                    name: friendly.clone(),
                    ipv4_addrs: Vec::new(),
                    is_up,
                    is_multicast,
                    is_loopback,
                });

            let mut ua = (*adapter).FirstUnicastAddress;
            while !ua.is_null() {
                let sa = (*ua).Address.lpSockaddr;
                if !sa.is_null() && (*sa).sa_family == AF_INET as u16 {
                    let sin = sa as *const SOCKADDR_IN;
                    let raw = u32::from_be((*sin).sin_addr.S_un.S_addr);
                    entry.ipv4_addrs.push(Ipv4Addr::from(raw));
                }
                ua = (*ua).Next;
            }

            adapter = (*adapter).Next;
        }
    }

    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact() {
        assert!(glob_match(b"eth0", b"eth0"));
        assert!(!glob_match(b"eth0", b"eth1"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match(b"eth*", b"eth0"));
        assert!(glob_match(b"eth*", b"eth10"));
        assert!(!glob_match(b"eth*", b"enp3s0"));
    }

    #[test]
    fn glob_star_all() {
        assert!(glob_match(b"*", b"eth0"));
        assert!(glob_match(b"*", b"lo"));
        assert!(glob_match(b"*", b""));
    }

    #[test]
    fn glob_question_mark() {
        assert!(glob_match(b"eth?", b"eth0"));
        assert!(!glob_match(b"eth?", b"eth10"));
    }

    #[test]
    fn glob_docker_blacklist() {
        assert!(glob_match(b"docker*", b"docker0"));
        assert!(glob_match(b"docker*", b"docker_gwbridge"));
        assert!(!glob_match(b"docker*", b"eth0"));
    }

    #[test]
    fn interface_allowed_basic() {
        let wl = vec!["eth*".to_owned(), "en*".to_owned()];
        let bl = vec!["lo".to_owned(), "docker*".to_owned()];
        assert!(interface_allowed("eth0", &wl, &bl));
        assert!(interface_allowed("en0", &wl, &bl));
        assert!(!interface_allowed("lo", &wl, &bl));
        assert!(!interface_allowed("docker0", &wl, &bl));
        assert!(!interface_allowed("virbr0", &wl, &bl)); // not in whitelist
    }

    #[test]
    fn interface_allowed_empty_whitelist_allows_all() {
        let bl = vec!["lo".to_owned()];
        assert!(interface_allowed("eth0", &[], &bl));
        assert!(!interface_allowed("lo", &[], &bl));
    }
}
