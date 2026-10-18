//! The host's words in the library's refusals and logs: [`HostWords`].
//!
//! A refusal says what to do next. What the person at the device does —
//! a command, an app action, a configuration key, where keys are kept — is
//! the host's, so the library quotes the phrases the host supplies
//! ([`crate::ParticipantParts::words`]) and keeps the rest of each message.
//! The [`Default`] words are neutral: they name no command, configuration
//! or storage of any host.
//!
//! Each message that quotes them is built by a method here, so a host can
//! check how its words read in every one.

use std::fmt::Display;

use ndn_packet::Name;

/// How the person at a device does what a refusal or a log line asks of
/// them, in the host's own terms (its commands or app actions, its
/// configuration, its key storage).
///
/// Each phrase is quoted inside a sentence of the library's; the field docs
/// say where. `{role}` and `{namespace}` in a phrase stand for the role and
/// the namespace the message is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostWords {
    /// How to start a new enrollment after one ended, quoted as "ask again
    /// (…)". E.g. "`ndn-fwd enroll`".
    pub enroll_again: String,
    /// How to enroll before renewing, quoted as "Enroll first (…)". E.g.
    /// "`ndn-fwd enroll <invite>`".
    pub enroll_first: String,
    /// How to enroll with an invite link, after "ask an admin for an invite
    /// and …". E.g. "run `ndn-fwd enroll <invite link>`".
    pub enroll_with_invite: String,
    /// How to enroll as `{role}` with an invite link, after "ask an admin for
    /// an invite and …". E.g. "run `ndn-fwd enroll <invite link> --role
    /// {role}`".
    pub enroll_with_invite_as: String,
    /// How a device becomes an admin device, after "a device becomes one
    /// with …". E.g. "`ndn-fwd enroll <anchor link> --role admin`".
    pub enroll_as_admin: String,
    /// Where an invite link comes from, in parentheses after "give an
    /// ndn-trust://invite link". E.g. "`ndn-fwd-tokens new` prints one".
    pub invite_origin: String,
    /// How an admin makes an invite for `{role}`, in parentheses after "ask
    /// for a {role} invite" (and before "on the root device"). E.g.
    /// "`ndn-fwd-tokens new --role {role}`".
    pub role_invite: String,
    /// Where a namespace's anchor link comes from, in parentheses after
    /// "its ndn-trust://anchor link". E.g. "`ndn-fwd init` prints it as
    /// anchor_uri".
    pub anchor_link_origin: String,
    /// How to adopt a namespace, quoted as "adopt it first (…)". E.g.
    /// "`ndn-fwd adopt`".
    pub adopt: String,
    /// How to adopt a namespace from its anchor link, in parentheses after
    /// "Adopt it first with the namespace's anchor link". E.g. "`ndn-fwd
    /// adopt <ndn-trust://anchor/…>`, the link `ndn-fwd init` printed".
    pub adopt_anchor_link: String,
    /// How to check `{namespace}`'s trust context for a newer version,
    /// before "completes the check". E.g. "`ndn-fwd context refresh
    /// {namespace}`".
    pub refresh_context: String,
    /// Where an admin sees the pending requests, after "check the code on
    /// the new device against …". E.g. "`ndn-fwd approvals list`".
    pub list_approvals: String,
    /// How an admin decides requests, starting a sentence that goes on "…
    /// on the namespace's root device". E.g. "Run `ndn-fwd approvals`".
    pub decide_approvals: String,
    /// How to see that this device holds a namespace's root key, in
    /// parentheses. E.g. "`ndn-fwd root-key status`".
    pub root_key_status: String,
    /// Where device keys and certificates are kept, as a noun. E.g. "the
    /// PIB".
    pub key_storage: String,
    /// Where device keys and certificates are kept, as something to fix
    /// ("fix …"). E.g. "the PIB directory".
    pub key_storage_dir: String,
    /// How to make the key storage readable, a sentence without its period.
    /// E.g. "Make the PIB readable by this daemon".
    pub make_key_storage_readable: String,
    /// What the host's configuration calls the margin before expiry at
    /// which certificates are renewed. E.g. "[security] renew_before".
    pub renew_before: String,
    /// Why this device serves no trust context by name, after "not
    /// published:". E.g. "[security] serve_contexts = false".
    pub contexts_not_served: String,
    /// How to enroll another key for a namespace this device holds a
    /// certificate in, after "To enroll another key anyway,". E.g. "run
    /// again with --force and another --device name".
    pub enroll_another_key: String,
    /// How a recovery goes on from the held version when nothing answers,
    /// after "and you know no version newer than v<N> was made,". E.g.
    /// "retry with --from-held".
    pub recover_from_held: String,
}

impl Default for HostWords {
    fn default() -> Self {
        Self {
            enroll_again: "enroll this device again".into(),
            enroll_first: "with an invite link".into(),
            enroll_with_invite: "enroll this device with the invite link".into(),
            enroll_with_invite_as: "enroll this device as {role} with the invite link".into(),
            enroll_as_admin: "an enrollment as admin from the namespace's anchor link".into(),
            invite_origin: "an admin of the namespace makes one".into(),
            role_invite: "an admin makes it for the role {role}".into(),
            anchor_link_origin: "the root device shows it".into(),
            adopt: "open its anchor link on this device".into(),
            adopt_anchor_link: "the link the root device shows".into(),
            refresh_context: "a refresh of {namespace}'s trust context".into(),
            list_approvals: "the list of pending requests".into(),
            decide_approvals: "Decide requests".into(),
            root_key_status: "it keeps the root key".into(),
            key_storage: "the key storage".into(),
            key_storage_dir: "the key storage".into(),
            make_key_storage_readable: "Make the key storage readable".into(),
            renew_before: "the renewal margin".into(),
            contexts_not_served: "this device serves no trust contexts".into(),
            enroll_another_key: "enroll again, forcing it, with another device name".into(),
            recover_from_held: "retry, vouching that the held version is the newest".into(),
        }
    }
}

/// `phrase` with `{role}` replaced by `role`.
fn for_role(phrase: &str, role: &str) -> String {
    phrase.replace("{role}", role)
}

impl HostWords {
    /// The device holds a certificate in `namespace` already
    /// (`still_valid`; `judged`: the clause on the trust context it was
    /// judged against, or empty).
    pub fn already_certified(&self, namespace: &Name, still_valid: &str, judged: &str) -> String {
        format!(
            "this node already holds a certificate in {namespace}: {still_valid}{judged}. To \
             enroll another key anyway, {} (the CA certifies a new key for a device name it \
             already certified only once that certificate is revoked or an admin approves the \
             new key); the certificate this node holds stays valid until it expires or is \
             revoked",
            self.enroll_another_key
        )
    }

    /// Enrollment's check of the trust context ran out of its budget.
    pub fn context_check_timed_out(&self, budget_secs: u64, namespace: &Name) -> String {
        format!(
            "no newer version was confirmed within {budget_secs}s (following several versions \
             takes longer); {} completes the check",
            self.refresh_context
                .replace("{namespace}", &namespace.to_string())
        )
    }

    /// A request the CA never answered ended here at its expiry (a log).
    pub fn request_expired_unanswered(&self) -> String {
        format!(
            "the CA never answered before the request expired; it ended here and its key was \
             deleted: ask again ({})",
            self.enroll_again
        )
    }

    /// The link given to enroll is neither an invite nor an anchor link.
    pub fn not_an_enroll_link(&self, error: impl Display) -> String {
        format!(
            "the link is neither an invite nor an anchor link ({error}): give an \
             ndn-trust://invite link ({}) or, for a role the namespace certifies on an admin's \
             approval, its ndn-trust://anchor link ({})",
            self.invite_origin, self.anchor_link_origin
        )
    }

    /// The invite admits `invite_role`, not the `role` asked for, which the
    /// namespace certifies by invite.
    pub fn invite_for_another_role(
        &self,
        namespace: &Name,
        invite_role: impl Display,
        role: impl Display,
    ) -> String {
        let role = role.to_string();
        format!(
            "the invite admits a {invite_role} device, not a {role} device; {namespace} \
             certifies {role} devices by invite: ask for a {role} invite ({})",
            for_role(&self.role_invite, &role)
        )
    }

    /// An anchor link was given for `role`, which the namespace certifies by
    /// invite (`policy`: what it certifies on an admin's approval).
    pub fn role_by_invite(
        &self,
        namespace: &Name,
        role: impl Display,
        policy: impl Display,
    ) -> String {
        let role = role.to_string();
        format!(
            "{namespace} certifies {role} devices by invite, not on an admin's approval \
             ({policy}): ask an admin for an invite ({} on the root device) and {}",
            for_role(&self.role_invite, &role),
            self.enroll_with_invite
        )
    }

    /// An anchor link was given for `role`, which the namespace certifies
    /// only on an invite and an admin's approval.
    pub fn role_by_invite_and_approval(&self, namespace: &Name, role: impl Display) -> String {
        let role = role.to_string();
        format!(
            "{namespace} certifies a {role} device only on an invite AND an admin's approval: \
             ask an admin for an invite and {}",
            for_role(&self.enroll_with_invite_as, &role)
        )
    }

    /// What to do when the certificate an invite got could not be kept.
    pub fn invite_spent(&self) -> String {
        format!(
            "The token is spent: fix {} and ask for a new invite",
            self.key_storage_dir
        )
    }

    /// What to do when the certificate an approval got could not be kept.
    pub fn approval_used(&self) -> String {
        format!(
            "The approval is used: fix {}, ask again ({}) and have an admin approve the new \
             request",
            self.key_storage_dir, self.enroll_again
        )
    }

    /// The CA holds a request this device could not record (its key, at
    /// `location`, was deleted).
    pub fn request_not_recorded(
        &self,
        request_id: &str,
        code: &str,
        error: impl Display,
        location: &str,
    ) -> String {
        format!(
            "the CA holds request {request_id} (code {code}), but this node could not record it \
             ({error}), so it would never finish it: the key was deleted. Fix {} ({location}) \
             and ask again; an admin can deny request {request_id}",
            self.key_storage_dir
        )
    }

    /// An enrollment installed its certificate (a log).
    pub fn enrolled(&self) -> String {
        format!(
            "enrolled; {}'s default identity is now this one",
            self.key_storage
        )
    }

    /// A request record whose namespace or CA does not parse.
    pub fn request_names_no_ca(&self) -> String {
        format!(
            "the request record names no valid namespace or CA; ask again ({})",
            self.enroll_again
        )
    }

    /// A request record whose namespace, CA, identity or key does not parse.
    pub fn request_names_no_key(&self) -> String {
        format!(
            "the request record names no valid namespace, CA, identity or key; ask again ({})",
            self.enroll_again
        )
    }

    /// The key of an approved request is gone (`why`).
    pub fn request_key_gone(&self, key: &Name, why: impl Display) -> String {
        format!(
            "the key {key} of this request is {why}; nothing can be certified for it: ask again \
             ({})",
            self.enroll_again
        )
    }

    /// No pending request shows `target` at the CAs `at` names.
    pub fn no_pending_request(&self, target: &str, at: &str) -> String {
        format!(
            "no pending request shows {target:?} at {at}: check the code on the new device \
             against {} (a request that expired or was decided is not pending)",
            self.list_approvals
        )
    }

    /// The device neither runs a CA nor administers a namespace.
    pub fn nothing_to_approve(&self) -> String {
        format!(
            "this node neither runs a CA that takes approval requests nor holds a current admin \
             certificate of a namespace whose CA runs elsewhere: there is nothing to approve \
             here. {} on the namespace's root device (its CA host) or on an admin device; a \
             device becomes one with {}, approved by an admin",
            self.decide_approvals, self.enroll_as_admin
        )
    }

    /// The device holds no trust context for `namespace`.
    pub fn no_context(&self, namespace: &Name) -> String {
        format!(
            "this node holds no trust context for {namespace}; adopt it first ({})",
            self.adopt
        )
    }

    /// The certificates to renew could not be read (`why`).
    pub fn renewal_unreadable(&self, why: impl Display) -> String {
        format!(
            "{why}: nothing was renewed. {}, then renew again",
            self.make_key_storage_readable
        )
    }

    /// The device holds no certificate to renew in the key storage at
    /// `location`.
    pub fn nothing_to_renew(&self, location: &str) -> String {
        format!(
            "this node holds no certificate a namespace CA issued to it in {location}: nothing \
             to renew. Enroll first ({})",
            self.enroll_first
        )
    }

    /// The renewal timer cannot read the key storage (a log).
    pub fn renewal_waits_for_storage(&self) -> String {
        format!(
            "no certificate is renewed while {} cannot be read; they expire unless it becomes \
             readable",
            self.key_storage
        )
    }

    /// The renewal margin is no shorter than the certificates' lifetime (a
    /// log).
    pub fn renew_before_too_long(&self) -> String {
        format!(
            "{} is at least the lifetime of the certificates this CA issues; renewing them once \
             a third of their lifetime is left instead",
            self.renew_before
        )
    }

    /// The detail of a kept version this device does not serve.
    pub fn not_published(&self) -> String {
        format!(
            "; not published: {}, so no node fetches it from this one",
            self.contexts_not_served
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContextStore;

    /// The neutral words name no host's command, configuration or storage.
    #[test]
    fn default_words_name_no_host() {
        let w = HostWords::default();
        let ns: Name = "/home/bob".parse().unwrap();
        let refused = |state| {
            let refresh = crate::ContextRefreshInfo {
                namespace: ns.to_string(),
                state,
                held_version: 3,
                version: 3,
                revoked: Vec::new(),
                detail: "nothing answered".into(),
            };
            crate::admin::newest_of(&ns, &refresh, false, &w)
                .unwrap_err()
                .to_string()
        };
        let not_held = crate::admin::NewestRefusal::NotHeld {
            namespace: ns.clone(),
            adopt_anchor_link: w.adopt_anchor_link.clone(),
        };
        let messages = [
            w.already_certified(&ns, "/home/bob/member/phone/KEY/k1", ""),
            w.context_check_timed_out(4, &ns),
            w.request_expired_unanswered(),
            w.not_an_enroll_link("bad"),
            w.invite_for_another_role(&ns, "member", "admin"),
            w.role_by_invite(&ns, "member", "admin, node"),
            w.role_by_invite_and_approval(&ns, "node"),
            w.invite_spent(),
            w.approval_used(),
            w.request_not_recorded("r1", "123456", "disk full", "/keys"),
            w.enrolled(),
            w.request_names_no_ca(),
            w.request_names_no_key(),
            w.request_key_gone(&ns, "gone"),
            w.no_pending_request("123456", "this node's CA"),
            w.nothing_to_approve(),
            w.no_context(&ns),
            w.renewal_unreadable("unreadable"),
            w.nothing_to_renew("/keys"),
            w.renewal_waits_for_storage(),
            w.renew_before_too_long(),
            w.not_published(),
            refused(crate::RefreshState::Source),
            refused(crate::RefreshState::Unreachable),
            not_held.to_string(),
            crate::PibContextStore::new("/keys").location(),
        ];
        for m in &messages {
            for host_word in [
                "ndn-fwd",
                "PIB",
                "[security]",
                "`",
                " --",
                "{role}",
                "{namespace}",
            ] {
                assert!(!m.contains(host_word), "{m:?} names {host_word:?}");
            }
        }
        assert_eq!(
            w.role_by_invite_and_approval(&ns, "node"),
            "/home/bob certifies a node device only on an invite AND an admin's approval: ask \
             an admin for an invite and enroll this device as node with the invite link"
        );
        assert_eq!(
            w.context_check_timed_out(4, &ns),
            "no newer version was confirmed within 4s (following several versions takes \
             longer); a refresh of /home/bob's trust context completes the check"
        );
    }
}
