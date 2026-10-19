//! Wording the library's refusals and details in a host's terms:
//! [`HostWords`].
//!
//! Every refusal ([`TrustRefusal`]) and every detail of an outcome
//! ([`Detail`]) the library produces carries a stable code with its
//! parameters and a neutral sentence that names no host's command,
//! configuration or storage. A client words its own message from the code:
//! [`HostWords::render`] / [`HostWords::render_detail`] rebuild the
//! library's sentence with the client's phrases (its commands or app
//! actions, its configuration, where it keeps keys) for every code whose
//! sentence quotes one, and give the neutral sentence for every other code.
//! The neutral sentence is the same rendering with [`HostWords::default`].
//!
//! A host also quotes its words in its own log lines
//! ([`HostWords::enrolled`] and the other log builders).

use std::fmt::Display;
use std::sync::LazyLock;

use ndn_cert::report::{Detail, Params, RefusalCode, TrustRefusal, code, detail_code};

/// How the person at a device does what a refusal, a detail or a log line
/// asks of them, in the host's own terms (its commands or app actions, its
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
    /// How to give this device a route for `{namespace}`, in parentheses
    /// after "a route for {namespace} toward a node that holds the
    /// namespace's context". E.g. "`ndn-ctl route add {namespace} --face
    /// <face-id>`".
    pub add_route: String,
    /// How to see this device's routes, in parentheses after "check the
    /// route". E.g. "`ndn-ctl route list`".
    pub list_routes: String,
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
    /// which certificates are renewed. E.g. "\[security\] renew_before".
    pub renew_before: String,
    /// Why this device serves no trust context by name, after "not
    /// published:". E.g. "\[security\] serve_contexts = false".
    pub contexts_not_served: String,
    /// How to enroll another key for a namespace this device holds a
    /// certificate in, after "To enroll another key anyway,". E.g. "run
    /// again with --force and another --device name".
    pub enroll_another_key: String,
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
            add_route: "add one toward such a node".into(),
            list_routes: "this device's routes".into(),
            refresh_context: "a refresh of {namespace}'s trust context".into(),
            list_approvals: "the list of pending requests".into(),
            decide_approvals: "Decide requests".into(),
            key_storage: "the key storage".into(),
            key_storage_dir: "the key storage".into(),
            make_key_storage_readable: "Make the key storage readable".into(),
            renew_before: "the renewal margin".into(),
            contexts_not_served: "this device serves no trust contexts".into(),
            enroll_another_key: "enroll again, forcing it, with another device name".into(),
        }
    }
}

/// The neutral words: the library's default sentences.
static NEUTRAL: LazyLock<HostWords> = LazyLock::new(HostWords::default);

pub(crate) fn neutral() -> &'static HostWords {
    &NEUTRAL
}

/// A refusal of `kind` with `params`, worded neutrally by
/// [`HostWords::render`]: for the codes whose sentence a host words.
pub(crate) fn refuse<'a>(
    kind: RefusalCode,
    params: impl IntoIterator<Item = (&'a str, String)>,
) -> TrustRefusal {
    let params: Params = params.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    let reason = neutral().phrase(kind.code, &params).unwrap_or_default();
    let mut refusal = TrustRefusal::new(kind, reason);
    refusal.params = params;
    refusal
}

/// A detail `code` with `params`, worded neutrally by
/// [`HostWords::render_detail`]: for the codes whose sentence a host
/// words, or that nest a cause a host words.
pub(crate) fn detail<'a>(
    code: &str,
    params: impl IntoIterator<Item = (&'a str, String)>,
) -> Detail {
    let params: Params = params.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    let text = neutral().phrase(code, &params).unwrap_or_default();
    let mut detail = Detail::new(code, text);
    detail.params = params;
    detail
}

/// `phrase` with `{role}` replaced by `role`.
fn for_role(phrase: &str, role: &str) -> String {
    phrase.replace("{role}", role)
}

impl HostWords {
    /// `refusal` in these words: the library's sentence for its code and
    /// parameters, quoting these phrases; the refusal's own (neutral)
    /// reason for a code whose sentence quotes none, or one this build
    /// does not know.
    pub fn render(&self, refusal: &TrustRefusal) -> String {
        self.phrase(&refusal.code, &refusal.params)
            .unwrap_or_else(|| refusal.reason.clone())
    }

    /// `detail` in these words, as [`render`](Self::render).
    pub fn render_detail(&self, detail: &Detail) -> String {
        self.phrase(&detail.code, &detail.params)
            .unwrap_or_else(|| detail.text.clone())
    }

    /// The sentence of `code` with `params` in these words, for every code
    /// whose sentence quotes a phrase of the host or nests one that does;
    /// `None` for the others (their neutral sentence is the only one).
    fn phrase(&self, code: &str, p: &Params) -> Option<String> {
        let get = |k: &str| p.get(k).map(String::as_str).unwrap_or_default();
        let has = |k: &str| p.contains_key(k);
        // A nested cause in these words, else the cause's text kept in
        // `text_key`. A cause shares the params of what wraps it, so one
        // naming the wrapping code itself is not worded again.
        let cause = |text_key: &str| {
            p.get("cause")
                .filter(|c| c.as_str() != code)
                .and_then(|c| self.phrase(c, p))
                .unwrap_or_else(|| get(text_key).to_owned())
        };
        let text = match code {
            c if c == code::CONTEXT_NOT_HELD.code => self.no_context(get("namespace")),
            c if c == code::CONTEXT_UNREACHABLE.code && has("source") => {
                let ns = get("namespace");
                format!(
                    "could not fetch the trust context of {ns}: {}. Check that this node has a \
                     route for {ns} toward a node that holds the namespace's context ({}), or \
                     use an anchor link with the context inline",
                    get("source"),
                    self.add_route.replace("{namespace}", ns)
                )
            }
            c if c == code::CONTEXT_REFUSED.code && has("wrong_context") => {
                let ns = get("namespace");
                format!(
                    "the reply for {ns} carried a trust context that this node refused ({}): it \
                     is not the namespace the link names. This node's route for {ns} leads to \
                     another namespace's node or to an impersonator — check the route ({}) and \
                     that you scanned the right code",
                    get("wrong_context"),
                    self.list_routes
                )
            }
            c if c == code::NOT_AN_ENROLL_LINK.code => self.not_an_enroll_link(get("error")),
            c if c == code::INVITE_FOR_ANOTHER_ROLE.code => {
                self.invite_for_another_role(get("namespace"), get("invite_role"), get("role"))
            }
            c if c == code::ROLE_BY_INVITE.code => {
                self.role_by_invite(get("namespace"), get("role"), get("policy"))
            }
            c if c == code::ROLE_NEEDS_INVITE_AND_APPROVAL.code => {
                self.role_by_invite_and_approval(get("namespace"), get("role"))
            }
            c if c == code::ALREADY_CERTIFIED.code => {
                let judged = if has("judged_version") {
                    format!(
                        " (judged against the trust context v{} this node holds; whether a \
                         newer version revokes it could not be checked: {})",
                        get("judged_version"),
                        cause("judged_detail")
                    )
                } else {
                    String::new()
                };
                self.already_certified(get("namespace"), get("still_valid"), &judged)
            }
            c if c == code::REQUEST_NOT_RECORDED.code => self.request_not_recorded(
                get("request"),
                get("code"),
                get("error"),
                get("location"),
            ),
            c if c == code::CERTIFICATE_NOT_KEPT.code => self.certificate_not_kept(
                get("certificate"),
                get("location"),
                get("error"),
                get("spent") == "invite",
            ),
            c if c == code::CONTEXT_NOT_STORED.code => self.context_not_stored(
                get("namespace"),
                get("version"),
                get("error"),
                get("location"),
            ),
            c if c == code::CONTEXT_SUPERSEDED.code => {
                context_superseded(get("namespace"), get("version"), get("now"))
            }
            c if c == code::RENEWAL_KEYS_UNREADABLE.code => self.renewal_unreadable(get("error")),
            c if c == code::NOTHING_TO_RENEW.code => self.nothing_to_renew(get("location")),
            c if c == code::NOTHING_TO_APPROVE.code => self.nothing_to_approve(),
            c if c == code::APPROVAL_NOT_PENDING.code => {
                let at = if get("scope") == "local-and-administered" {
                    "this node's CA or at the CAs of the namespaces it administers"
                } else {
                    "the CAs of the namespaces this node administers"
                };
                let mut reason = self.no_pending_request(get("target"), at);
                if has("unasked") {
                    reason.push_str(&format!(
                        "; not every CA could be asked: {}",
                        get("unasked")
                    ));
                }
                reason
            }
            c if c == code::APPROVAL_UNKNOWN_TARGET.code => format!(
                "no pending request {:?}: give the request id or the six-digit code {} shows",
                get("target"),
                self.list_approvals
            ),
            c if c == code::APPROVAL_NO_CODE_MATCH.code => format!(
                "no pending request shows the code {}: check the code on the new device against \
                 {} (a request that expired or was decided is not pending)",
                get("code"),
                self.list_approvals
            ),
            c if c == code::APPROVAL_AMBIGUOUS.code && has("matches") => format!(
                "requests in several namespaces show {:?}: {}; decide by request id",
                get("target"),
                get("matches")
            ),
            c if c == code::APPROVAL_AMBIGUOUS.code => format!(
                "several pending requests show the code {}: decide by request id ({} shows \
                 them)",
                get("code"),
                self.list_approvals
            ),
            c if c == code::APPROVAL_REFUSED_BY_CA.code => {
                format!("the CA {} refused: {}", get("ca"), cause("error"))
            }
            c if c == detail_code::CONTEXT_CHECK_TIMED_OUT => {
                self.context_check_timed_out(get("budget_secs"), get("namespace"))
            }
            c if c == detail_code::CONTEXT_UPDATED => {
                let through = match p.get("walked") {
                    Some(walked) if !walked.is_empty() => format!(
                        " through {} (each signed by an anchor of the version before it)",
                        walked
                            .split(',')
                            .map(|v| format!("v{v}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    _ => String::new(),
                };
                let ca = ca_part(p);
                match p.get("stored") {
                    Some(stored) => format!(
                        "adopted v{} (signed by {}, an anchor of v{}){through}; stored \
                         {stored}{}{ca}",
                        get("version"),
                        get("signer"),
                        get("from"),
                        self.publication(get("published") == "true")
                    ),
                    None => format!(
                        "adopted v{}{through} for this run, but {}{ca}",
                        get("version"),
                        cause("error")
                    ),
                }
            }
            c if c == detail_code::UPDATE_ADOPTED => {
                let adopted = format!(
                    "adopted v{} (signed by {}, an anchor of v{})",
                    get("version"),
                    get("signer"),
                    get("held")
                );
                let ca = ca_part(p);
                match p.get("stored") {
                    Some(stored) => format!(
                        "{adopted}; stored {stored}{}{ca}",
                        self.publication(get("published") == "true")
                    ),
                    None => format!("{adopted}, but {}{ca}", cause("error")),
                }
            }
            c if c == detail_code::REQUEST_NAMES_NO_CA => self.request_names_no_ca(),
            c if c == detail_code::REQUEST_NAMES_NO_KEY => self.request_names_no_key(),
            c if c == detail_code::REQUEST_KEY_GONE => {
                self.request_key_gone(get("key"), get("why"))
            }
            c if c == detail_code::REQUEST_ENDED => {
                let what = cause("error");
                match (p.get("key"), get("deleted")) {
                    (Some(key), "true") => format!("{what}; the key {key} was deleted"),
                    (Some(key), _) => format!(
                        "{what}; the key {key} could not be deleted ({}): delete it from {}",
                        get("delete_error"),
                        get("location")
                    ),
                    (None, _) => what,
                }
            }
            _ => return None,
        };
        Some(text)
    }

    /// The device holds a certificate in `namespace` already
    /// (`still_valid`; `judged`: the clause on the trust context it was
    /// judged against, or empty).
    pub fn already_certified(
        &self,
        namespace: impl Display,
        still_valid: &str,
        judged: &str,
    ) -> String {
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
    pub fn context_check_timed_out(
        &self,
        budget_secs: impl Display,
        namespace: impl Display,
    ) -> String {
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
        namespace: impl Display,
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
        namespace: impl Display,
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
    pub fn role_by_invite_and_approval(
        &self,
        namespace: impl Display,
        role: impl Display,
    ) -> String {
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

    /// The CA issued `certificate`, but storing it at `location` failed
    /// (`error`); `invite`: an invite's token got it (else an approval).
    pub fn certificate_not_kept(
        &self,
        certificate: impl Display,
        location: impl Display,
        error: impl Display,
        invite: bool,
    ) -> String {
        format!(
            "the CA issued {certificate}, but storing it in {location} failed ({error}); \
             nothing was kept and nothing changed. {}",
            if invite {
                self.invite_spent()
            } else {
                self.approval_used()
            }
        )
    }

    /// Version `version` of `namespace` holds for this run, but storing it
    /// at `location` failed (`error`).
    pub fn context_not_stored(
        &self,
        namespace: impl Display,
        version: impl Display,
        error: impl Display,
        location: impl Display,
    ) -> String {
        format!(
            "adopted {namespace} v{version} for this run, but storing it failed ({error}); it \
             will be gone after a restart — fix {} ({location})",
            self.key_storage_dir
        )
    }

    /// The CA holds a request this device could not record (its key, at
    /// `location`, was deleted).
    pub fn request_not_recorded(
        &self,
        request_id: impl Display,
        code: impl Display,
        error: impl Display,
        location: impl Display,
    ) -> String {
        format!(
            "the CA holds request {request_id} (code {code}), but this node could not record it \
             ({error}), so it would never finish it: the key was deleted. Fix {} ({location}) \
             and ask again; an admin can deny request {request_id}",
            self.key_storage_dir
        )
    }

    /// An enrollment installed its certificate (a log): `node_identity`, it
    /// is the device's first identity and became its node identity.
    pub fn enrolled(&self, node_identity: bool) -> String {
        if node_identity {
            format!(
                "enrolled; {}'s default identity is now this one, the node identity",
                self.key_storage
            )
        } else {
            "enrolled; this identity signs its trusted prefix's Data beside the others, and the \
             node identity stays"
                .to_owned()
        }
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
    pub fn request_key_gone(&self, key: impl Display, why: impl Display) -> String {
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
    pub fn no_context(&self, namespace: impl Display) -> String {
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
    pub fn nothing_to_renew(&self, location: impl Display) -> String {
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

    /// The clause of a kept version's detail on whether it is published.
    pub fn publication(&self, published: bool) -> String {
        if published {
            " and published".into()
        } else {
            self.not_published()
        }
    }

    /// The detail of a kept version this device does not serve.
    pub fn not_published(&self) -> String {
        format!(
            "; not published: {}, so no node fetches it from this one",
            self.contexts_not_served
        )
    }
}

/// `namespace` v`version` was adopted, but v`held` meanwhile.
fn context_superseded(namespace: &str, version: &str, held: &str) -> String {
    format!(
        "{namespace} v{version} was adopted, but v{held} was adopted meanwhile by another \
         command; v{held} is the version this node holds, stores and publishes"
    )
}

/// What this device's CA of the namespace stopped serving because a kept
/// version revokes it (`ca_revoked`), and whether it could record that
/// (`ca_not_persisted`), worded to end a detail; empty when neither.
fn ca_part(p: &Params) -> String {
    let mut detail = String::new();
    if let Some(revoked) = p.get("ca_revoked") {
        detail = format!(
            "; this node's CA no longer serves {revoked} (the version revokes their keys) and \
             their device names are free for a new key"
        );
    }
    if let Some(e) = p.get("ca_not_persisted") {
        detail.push_str(&format!(
            "; the CA could not record that in its store ({e}): it holds for this run, and the \
             CA follows the stored trust context again when the daemon starts"
        ));
    }
    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code the library words itself names no host's command,
    /// configuration or storage in its neutral sentence.
    #[test]
    fn neutral_sentences_name_no_host() {
        let p = |pairs: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
            pairs.iter().map(|(k, v)| (*k, v.to_string())).collect()
        };
        let ns = [("namespace", "/home/bob")];
        let refusals = [
            refuse(code::CONTEXT_NOT_HELD, p(&ns)),
            refuse(
                code::CONTEXT_UNREACHABLE,
                p(&[("namespace", "/home/bob"), ("source", "no route")]),
            ),
            refuse(
                code::CONTEXT_REFUSED,
                p(&[("namespace", "/home/bob"), ("wrong_context", "other root")]),
            ),
            refuse(code::NOT_AN_ENROLL_LINK, p(&[("error", "bad")])),
            refuse(
                code::INVITE_FOR_ANOTHER_ROLE,
                p(&[
                    ("namespace", "/home/bob"),
                    ("invite_role", "member"),
                    ("role", "admin"),
                ]),
            ),
            refuse(
                code::ROLE_BY_INVITE,
                p(&[
                    ("namespace", "/home/bob"),
                    ("role", "member"),
                    ("policy", "admin, node"),
                ]),
            ),
            refuse(
                code::ROLE_NEEDS_INVITE_AND_APPROVAL,
                p(&[("namespace", "/home/bob"), ("role", "node")]),
            ),
            refuse(
                code::ALREADY_CERTIFIED,
                p(&[
                    ("namespace", "/home/bob"),
                    ("still_valid", "/home/bob/member/phone/KEY/k1"),
                    ("judged_version", "2"),
                    ("cause", detail_code::CONTEXT_CHECK_TIMED_OUT),
                    ("budget_secs", "4"),
                ]),
            ),
            refuse(
                code::REQUEST_NOT_RECORDED,
                p(&[
                    ("request", "r1"),
                    ("code", "123456"),
                    ("error", "full"),
                    ("location", "/keys"),
                ]),
            ),
            refuse(
                code::CERTIFICATE_NOT_KEPT,
                p(&[
                    ("certificate", "/c"),
                    ("location", "/keys"),
                    ("error", "full"),
                    ("spent", "invite"),
                ]),
            ),
            refuse(
                code::CERTIFICATE_NOT_KEPT,
                p(&[
                    ("certificate", "/c"),
                    ("location", "/keys"),
                    ("error", "full"),
                    ("spent", "approval"),
                ]),
            ),
            refuse(
                code::CONTEXT_NOT_STORED,
                p(&[
                    ("namespace", "/home/bob"),
                    ("version", "3"),
                    ("error", "full"),
                    ("location", "/keys"),
                ]),
            ),
            refuse(code::RENEWAL_KEYS_UNREADABLE, p(&[("error", "unreadable")])),
            refuse(code::NOTHING_TO_RENEW, p(&[("location", "/keys")])),
            refuse(code::NOTHING_TO_APPROVE, p(&[])),
            refuse(
                code::APPROVAL_NOT_PENDING,
                p(&[("target", "123456"), ("scope", "administered")]),
            ),
        ];
        let details = [
            detail(
                detail_code::CONTEXT_CHECK_TIMED_OUT,
                p(&[("budget_secs", "4"), ("namespace", "/home/bob")]),
            ),
            detail(
                detail_code::CONTEXT_UPDATED,
                p(&[
                    ("version", "4"),
                    ("signer", "/home/bob/KEY/root"),
                    ("from", "3"),
                    ("stored", "/keys/c"),
                    ("published", "false"),
                ]),
            ),
            detail(
                detail_code::UPDATE_ADOPTED,
                p(&[
                    ("version", "4"),
                    ("signer", "/home/bob/KEY/root"),
                    ("held", "3"),
                    ("cause", code::CONTEXT_NOT_STORED.code),
                    ("namespace", "/home/bob"),
                    ("error", "full"),
                    ("location", "/keys"),
                ]),
            ),
            detail(detail_code::REQUEST_NAMES_NO_CA, p(&[])),
            detail(detail_code::REQUEST_NAMES_NO_KEY, p(&[])),
            detail(
                detail_code::REQUEST_KEY_GONE,
                p(&[("key", "/k"), ("why", "gone")]),
            ),
        ];
        let w = HostWords::default();
        let mut sentences: Vec<String> = refusals.iter().map(|r| r.reason.clone()).collect();
        sentences.extend(details.iter().map(|d| d.text.clone()));
        sentences.extend([
            w.request_expired_unanswered(),
            w.enrolled(true),
            w.enrolled(false),
            w.renewal_waits_for_storage(),
            w.renew_before_too_long(),
        ]);
        for s in &sentences {
            assert!(!s.is_empty());
            for host_word in [
                "ndn-fwd",
                "PIB",
                "[security]",
                "`",
                " --",
                "{role}",
                "{namespace}",
            ] {
                assert!(!s.contains(host_word), "{s:?} names {host_word:?}");
            }
        }
        // The neutral sentence is the rendering with the default words.
        for r in &refusals {
            assert_eq!(w.render(r), r.reason);
        }
        for d in &details {
            assert_eq!(w.render_detail(d), d.text);
        }
    }

    /// A host's words reach every sentence that quotes them, a nested
    /// cause's included; a code the library does not word renders as its
    /// own sentence.
    #[test]
    fn rendering_uses_the_host_words() {
        let host = HostWords {
            key_storage_dir: "HOST-STORAGE".into(),
            contexts_not_served: "HOST-NOT-SERVED".into(),
            refresh_context: "HOST-REFRESH {namespace}".into(),
            ..HostWords::default()
        };
        let updated = detail(
            detail_code::UPDATE_ADOPTED,
            [
                ("version", "4".to_owned()),
                ("signer", "/s".to_owned()),
                ("held", "3".to_owned()),
                ("cause", code::CONTEXT_NOT_STORED.code.to_owned()),
                ("error", "full".to_owned()),
                ("location", "/keys".to_owned()),
            ],
        );
        assert!(host.render_detail(&updated).contains("HOST-STORAGE"));
        let published = detail(
            detail_code::CONTEXT_UPDATED,
            [
                ("stored", "/c".to_owned()),
                ("published", "false".to_owned()),
            ],
        );
        assert!(host.render_detail(&published).contains("HOST-NOT-SERVED"));
        let certified = refuse(
            code::ALREADY_CERTIFIED,
            [
                ("judged_version", "2".to_owned()),
                ("cause", detail_code::CONTEXT_CHECK_TIMED_OUT.to_owned()),
                ("namespace", "/home/bob".to_owned()),
            ],
        );
        assert!(host.render(&certified).contains("HOST-REFRESH /home/bob"));
        let other = TrustRefusal::new(code::ENROLL_BUSY, "busy");
        assert_eq!(host.render(&other), "busy");
    }
}
