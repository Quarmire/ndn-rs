//! Which local users' sockets are program faces, and the user / group
//! database lookups behind it.
//!
//! A Unix-socket peer is a program ([`ndn_transport::FaceTrust::Program`],
//! its Data believed without validation) only when it is the daemon's own
//! user, root, or a member of a group the operator listed in `[security]
//! program_groups`. Every other user who can open the (world-connectable)
//! socket gets a validated face: a forged Data from such a user is refused
//! and never cached (trust-context.md §6.6). The same lookups also back the
//! management gate's `trust_admin_groups` and `transit_groups` checks, which
//! are separate policies over the same facts.

use ndn_transport::PeerCredentials;

/// Who may be a program peer on a local socket: the daemon's user and root,
/// plus the members of the groups of `[security] program_groups`.
///
/// Membership in those groups skips Data validation for that user's sockets:
/// anything such a user's process sends is believed and may enter the content
/// store. List only groups whose members you trust as much as the daemon's own
/// user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramPeers {
    daemon_uid: u32,
    groups: Vec<String>,
}

impl ProgramPeers {
    /// This process's effective uid, root, and the members of `groups`.
    pub fn new(groups: &[String]) -> Self {
        Self::with_daemon_uid(daemon_euid(), groups)
    }

    /// This process's effective uid and root only: the policy for a face that
    /// serves the app of the process's own user (an in-app forwarder, a
    /// mobile app's socket pair, a dialled client socket).
    pub fn this_user() -> Self {
        Self::new(&[])
    }

    /// As [`new`](Self::new) for a daemon running as `daemon_uid`: lets a test
    /// stand a daemon of another user in front of this process's socket.
    pub fn with_daemon_uid(daemon_uid: u32, groups: &[String]) -> Self {
        Self {
            daemon_uid,
            groups: groups.to_vec(),
        }
    }

    /// Whether the peer the kernel reported is the daemon's user, root, or in
    /// one of the program groups.
    pub fn contains(&self, peer: &PeerCredentials) -> bool {
        peer.uid == self.daemon_uid
            || peer.uid == 0
            || (!self.groups.is_empty() && peer_in_any_group(peer, &self.groups, "program_groups"))
    }
}

/// The forwarder's own effective uid.
#[cfg(unix)]
pub fn daemon_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Windows has no uid: nothing is attested there, so no peer ever matches.
#[cfg(not(unix))]
pub fn daemon_euid() -> u32 {
    0
}

/// `true` if `peer` belongs to any group named in `groups` (the `[security]
/// <key>` list): its primary gid is the group's gid, its user name is in the
/// group's member list, or (Linux, pid known) the gid is among its
/// supplementary groups. `key` names the configuration key in the warning
/// about a group the system does not know.
#[cfg(unix)]
pub fn peer_in_any_group(peer: &PeerCredentials, groups: &[String], key: &str) -> bool {
    let mut user: Option<Option<String>> = None;
    #[cfg(target_os = "linux")]
    let mut supplementary: Option<Vec<u32>> = None;
    for name in groups {
        let Some(group) = lookup_group(name) else {
            tracing::warn!(
                group = %name,
                "[security] {key} names a group this system does not know: no one is let in \
                 through it; create the group or remove it from the configuration"
            );
            continue;
        };
        if peer.gid == group.gid {
            return true;
        }
        if !group.members.is_empty()
            && let Some(user) = user.get_or_insert_with(|| user_name(peer.uid)).as_deref()
            && group.members.iter().any(|m| m == user)
        {
            return true;
        }
        #[cfg(target_os = "linux")]
        if let Some(pid) = peer.pid
            && supplementary
                .get_or_insert_with(|| proc_supplementary_groups(pid, peer.uid))
                .contains(&group.gid)
        {
            return true;
        }
    }
    false
}

/// Windows has no user / group database lookup here: no peer matches.
#[cfg(not(unix))]
pub fn peer_in_any_group(_peer: &PeerCredentials, _groups: &[String], _key: &str) -> bool {
    false
}

#[cfg(unix)]
mod lookup {
    use std::ffi::{CStr, CString};

    /// Upper bound for the getgrnam_r / getpwuid_r scratch buffer.
    const MAX_BUF: usize = 1 << 20;

    pub(super) struct Group {
        pub(super) gid: u32,
        pub(super) members: Vec<String>,
    }

    pub(super) fn lookup_group(name: &str) -> Option<Group> {
        let cname = CString::new(name).ok()?;
        let mut buf: Vec<libc::c_char> = vec![0; 1024];
        loop {
            // SAFETY: `group` is plain old data; getgrnam_r fills it, pointing
            // its string fields into `buf`, which outlives every read below.
            let mut grp: libc::group = unsafe { std::mem::zeroed() };
            let mut result: *mut libc::group = std::ptr::null_mut();
            let rc = unsafe {
                libc::getgrnam_r(
                    cname.as_ptr(),
                    &mut grp,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == libc::ERANGE && buf.len() < MAX_BUF {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc != 0 || result.is_null() {
                return None;
            }
            let mut members = Vec::new();
            let mut p = grp.gr_mem;
            if !p.is_null() {
                // SAFETY: `gr_mem` is a NULL-terminated array of C strings in `buf`.
                unsafe {
                    while !(*p).is_null() {
                        members.push(CStr::from_ptr(*p).to_string_lossy().into_owned());
                        p = p.add(1);
                    }
                }
            }
            return Some(Group {
                gid: grp.gr_gid,
                members,
            });
        }
    }

    pub(super) fn user_name(uid: u32) -> Option<String> {
        let mut buf: Vec<libc::c_char> = vec![0; 1024];
        loop {
            // SAFETY: as in `lookup_group`; `pw_name` points into `buf`.
            let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = unsafe {
                libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
            };
            if rc == libc::ERANGE && buf.len() < MAX_BUF {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
                return None;
            }
            // SAFETY: non-null NUL-terminated string inside `buf`.
            return Some(
                unsafe { CStr::from_ptr(pwd.pw_name) }
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

/// The account name of `uid`, when the system's user database knows it.
#[cfg(unix)]
pub fn user_name(uid: u32) -> Option<String> {
    lookup::user_name(uid)
}

#[cfg(unix)]
use lookup::lookup_group;

/// Supplementary gids from `/proc/<pid>/status` `Groups:`. Empty unless the
/// process's effective uid (`Uid:` 2nd field) still equals the socket peer's
/// uid, so a recycled pid cannot lend another process's groups.
#[cfg(target_os = "linux")]
fn proc_supplementary_groups(pid: i32, uid: u32) -> Vec<u32> {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return Vec::new();
    };
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|rest| {
                rest.split_whitespace()
                    .filter_map(|t| t.parse::<u32>().ok())
            })
    };
    if field("Uid:").and_then(|mut ids| ids.nth(1)) != Some(uid) {
        return Vec::new();
    }
    field("Groups:")
        .map(|ids| ids.collect())
        .unwrap_or_default()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn peer(uid: u32, gid: u32) -> PeerCredentials {
        PeerCredentials {
            uid,
            gid,
            pid: None,
        }
    }

    /// The daemon's user and root are always program peers; another user is
    /// one only through a listed group, and an empty list lets no one in.
    #[test]
    fn daemon_user_and_root_are_program_peers_and_others_are_not() {
        let peers = ProgramPeers::with_daemon_uid(990, &[]);
        assert!(peers.contains(&peer(990, 990)));
        assert!(peers.contains(&peer(0, 0)));
        assert!(!peers.contains(&peer(991, 991)));
    }

    /// A group that names a gid the peer has admits it; a name the system
    /// does not know admits no one.
    #[test]
    fn a_listed_group_admits_its_members_and_an_unknown_one_admits_no_one() {
        // gid 0 is `root` on every unix this builds for, by primary gid.
        let Some(root_group) = ["root", "wheel"]
            .into_iter()
            .find(|g| lookup_group(g).is_some())
        else {
            return;
        };
        let gid = lookup_group(root_group).unwrap().gid;
        let admitted = ProgramPeers::with_daemon_uid(990, &[root_group.to_owned()]);
        assert!(admitted.contains(&peer(991, gid)));
        let unknown = ProgramPeers::with_daemon_uid(990, &["no-such-group-ndn".to_owned()]);
        assert!(!unknown.contains(&peer(991, gid)));
    }
}
