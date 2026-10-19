//! What a device asks to be certified as when it enrolls with a link: the
//! namespace and the identity `/<ns>/<role>/<device>`.
//!
//! An invite (`ndn-trust://invite`) names its role (`member` or `guest`);
//! another role asked with it is asked for under the invite's namespace (the
//! CA then refuses what the token does not admit). An anchor link
//! (`ndn-trust://anchor`) names no role: a device enrolling with it asks for
//! a role the namespace certifies on an admin's approval, so the role must
//! be given.

// Boxing the error variants would change the public API; these are cold control-plane results.
#![allow(clippy::result_large_err)]

use std::fmt;

use ndn_packet::Name;

use crate::invite::{InviteEnrollError, InviteLink};
use crate::onboarding::{AdoptError, AnchorLink};
use crate::roles::{Role, RoleError, device_identity};

/// The namespace and identity a device enrolling with a link asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollTarget {
    pub namespace: Name,
    pub identity: Name,
}

/// Why no identity follows from a link.
#[derive(Debug)]
pub enum EnrollTargetError {
    /// The invite's device identity is refused (an invalid device name).
    Invite(InviteEnrollError),
    /// The device identity of the role asked is refused.
    Device(RoleError),
    /// The link is neither an invite nor an anchor link (the anchor link's
    /// reason).
    NotALink(AdoptError),
    /// An anchor link without a role.
    NoRole { namespace: Name },
}

impl fmt::Display for EnrollTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invite(e) => e.fmt(f),
            Self::Device(e) => e.fmt(f),
            Self::NotALink(e) => write!(
                f,
                "the link is neither an invite (`ndn-fwd-tokens new` prints one) nor \
                 the namespace's anchor link (`ndn-fwd init` prints it as anchor_uri): {e}"
            ),
            Self::NoRole { namespace } => write!(
                f,
                "an anchor link names no role; add --role admin or --role node (a \
                 role {namespace} certifies on an admin's approval), or enroll a member or guest with an \
                 invite link"
            ),
        }
    }
}

impl std::error::Error for EnrollTargetError {}

impl EnrollTarget {
    /// What enrolling `device` with the link `uri` asks for, as `role`
    /// when given: an invite's own role (its device identity) unless
    /// another role is given; an anchor link needs the role.
    pub fn of_link(
        uri: &str,
        role: Option<Role>,
        device: &str,
    ) -> Result<Self, EnrollTargetError> {
        if let Ok(invite) = InviteLink::from_uri(uri) {
            let identity = match role {
                Some(role) if role != invite.role => {
                    device_identity(&invite.namespace, role, device)
                        .map_err(EnrollTargetError::Device)?
                }
                _ => invite
                    .device_identity(device)
                    .map_err(EnrollTargetError::Invite)?,
            };
            return Ok(Self {
                namespace: invite.namespace,
                identity,
            });
        }
        let anchor = AnchorLink::from_uri(uri).map_err(EnrollTargetError::NotALink)?;
        let Some(role) = role else {
            return Err(EnrollTargetError::NoRole {
                namespace: anchor.namespace,
            });
        };
        let identity =
            device_identity(&anchor.namespace, role, device).map_err(EnrollTargetError::Device)?;
        Ok(Self {
            namespace: anchor.namespace,
            identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use ndn_trust_envelope::TrustEnvelope;

    use super::*;

    fn invite() -> String {
        TrustEnvelope::Invite {
            ca_prefix: "/home/bob".into(),
            identity_namespace: "/home/bob/member".into(),
            token: "member-aa".into(),
            ttl_secs: None,
            anchor_fingerprint: Some([1; 32]),
        }
        .to_uri()
    }

    fn anchor() -> String {
        TrustEnvelope::Anchor {
            namespace: Some("/home/bob".into()),
            fingerprint: Some([1; 32]),
            version: None,
            context_data: None,
            context_content: None,
        }
        .to_uri()
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn an_invite_names_the_identity_and_another_role_is_asked_under_its_namespace() {
        let target = EnrollTarget::of_link(&invite(), None, "phone").unwrap();
        assert_eq!(target.namespace, name("/home/bob"));
        assert_eq!(target.identity, name("/home/bob/member/phone"));
        let same = EnrollTarget::of_link(&invite(), Some(Role::Member), "phone").unwrap();
        assert_eq!(same, target);
        let admin = EnrollTarget::of_link(&invite(), Some(Role::Admin), "phone").unwrap();
        assert_eq!(admin.identity, name("/home/bob/admin/phone"));
        assert!(matches!(
            EnrollTarget::of_link(&invite(), None, "KEY"),
            Err(EnrollTargetError::Invite(_))
        ));
    }

    #[test]
    fn an_anchor_link_needs_a_role() {
        let err = EnrollTarget::of_link(&anchor(), None, "vps").unwrap_err();
        assert!(err.to_string().starts_with("an anchor link names no role"), "{err}");
        assert!(err.to_string().contains("a role /home/bob certifies"), "{err}");
        let node = EnrollTarget::of_link(&anchor(), Some(Role::Node), "vps").unwrap();
        assert_eq!(node.identity, name("/home/bob/node/vps"));
        assert!(matches!(
            EnrollTarget::of_link(&anchor(), Some(Role::Node), "a/b"),
            Err(EnrollTargetError::Device(_))
        ));
        assert!(matches!(
            EnrollTarget::of_link("https://example.com/x", None, "vps"),
            Err(EnrollTargetError::NotALink(_))
        ));
    }
}
