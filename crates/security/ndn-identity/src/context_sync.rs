//! Context-sync subscription (NDF F11): the push alternative to the pull
//! refresh.
//!
//! Subscribes to a trust context's SVS group so a republished
//! [`SignedTrustContext`](ndn_security::SignedTrustContext) propagates to
//! fleet nodes without polling, and adopts each new version into the local
//! [`Keyring`] under the same rule as the pull refresh. This is the
//! *subscribe* half; a publisher puts the signed context Data into the group
//! (see *Wire*).
//!
//! # Layering
//!
//! The orchestrator lives here, in `ndn-identity`, because it composes layers
//! that already meet here: the SVS primitive ([`ndn_sync`]), the update check
//! ([`ndn_cert::open_context_update`]) and [`Keyring`] adoption
//! ([`ndn_security`]). `ndn-sync` stays free of any trust-context dependency
//! (sync is the lower layer).
//!
//! # Wire
//!
//! A namespace's group is [`group_prefix`]: `/<ns>/32=trust-context/32=sync`,
//! beside the RDR publication of its versions. A member's SVS node name is
//! `<group>/<member>`, so the Data it publishes, `<group>/<member>/seg=N`,
//! is routed like the group itself.
//!
//! The synced payload is the context's **signed Data** exactly as the root
//! signed it (`/<ns>/32=trust-context/v=<N>`, the wire of
//! [`sign_into_data`](ndn_security::SignedTrustContext::sign_into_data) or of
//! a stored context), carried as the Content of the group Data at
//! `<group>/<publisher>/seg=N` ([`group_data`]). The SVS sequence number is
//! the version the publisher republishes at; whether the update is adopted is
//! decided by the signed version inside. Anchors, schema blobs, CA endpoints,
//! enrollment hint, revocations and source-bundle hash arrive intact because
//! the signed Content is carried verbatim. The group Data itself is signed
//! with DigestSha256 (integrity only), like the RDR metadata: what it carries
//! is checked by its own signature, and a validating forwarder admits a
//! DigestSha256 Data without a schema rule for its name, where a key-signed
//! one would be dropped one hop away.
//!
//! # Adoption rule
//!
//! An update is adopted only under the **continuity rule** of the pull
//! refresh ([`ndn_cert::open_context_update`], then
//! [`Keyring::adopt_update_from`]): it is a self-consistent signed context of a
//! namespace this node already holds, it is signed by a key that is an anchor
//! of the **held** version, and it is strictly newer. Who published it into
//! the group, and whether the group Data itself was validated, does not
//! matter: a group member that is not the namespace root cannot produce an
//! update this node adopts. A namespace this node does not hold yet is never
//! adopted from the group — first adoption needs a link or invite
//! (`ndn-fwd adopt` / `ndn-fwd enroll`).
//!
//! When the newest version is not signed by an anchor of the held one — a
//! recovery kit installed a new root in a version this node missed — the
//! publisher's sequence numbers from the one after the held version (each
//! the version it republished) are fetched oldest first and followed one by
//! one, each under the continuity rule from the one before
//! ([`ndn_cert::follow_versions`], the same walk as the pull refresh); the
//! newest is adopted only if the walk reaches it.
//!
//! # Keeping what was adopted
//!
//! An adopted version is held in the keyring only; [`ContextSyncOutcome::Adopted`]
//! carries its signed Data and the versions walked through (an
//! [`ndn_cert::ContextUpdate`], as a pull refresh returns), and [`run`] hands
//! each to the caller's `keep`, which persists and serves them — so this node
//! comes back with the version it adopted, and the nodes behind it can follow
//! the same versions by name.
//!
//! # What an announcement proves
//!
//! Nothing. A group's Sync Interests are not authenticated (the daemon
//! joins with an insecure SVS signer and validator), so anyone reaching the
//! group can name any member and any sequence number. A version is known to
//! exist only once its signed Data, fetched from the group, passed
//! [`ndn_cert::open_context_update`] against the held version or against a
//! version walked through from it ([`Processed::verified`]); [`run`] hands
//! those, and only those, to its caller's `verified`.
//!
//! # Retries
//!
//! SVS reports each sequence number once, so a version whose fetch was lost
//! would otherwise wait for the publisher's next version or the next pull
//! refresh. [`run`] keeps a publisher's announcement while its sequence
//! number (the version the publisher put into the group) is newer than the
//! held version and the newest version itself could not be fetched (or
//! another adoption replaced the held version while it was checked), and
//! tries again with exponential backoff ([`Retry`]), each failure logged
//! with its reason. The announcement is dropped once the held version
//! reaches it (adopted from another publisher, by refresh, or by this
//! retry), once the version is refused for what it is, and once a walk to
//! it stopped: a walk is not tried again for that announcement, since a
//! member can serve a forged newest version and let every version in
//! between time out; the pull refresh follows a genuine one by name.
//!
//! What an announcement can cost is bounded. Each costs one
//! fetch of the newest version, plus — when it does not follow from the
//! held version — a walk of at most [`ndn_cert::MAX_CATCH_UP_VERSIONS`]
//! positions that starts no fetch after [`ndn_cert::MAX_CATCH_UP_TIME`].
//! Retries of a member none of whose announced versions ever passed the
//! continuity rule stop after [`UNPROVEN_TRIES`] tries, and at most
//! [`UNPROVEN_PENDING`] such members wait at once; a member whose announced
//! version passed is retried while its announcement is newer than the held
//! version (at most one try per backoff step), and goes first when retries
//! are due. Fetches run one at a time, new announcements before retries.
//!
//! # Transport seam
//!
//! `ndn-sync` is sans-IO (the caller wires the SVS Interest channels to a
//! face), and fetching the group Data is likewise abstracted behind
//! [`ContextFetcher`] so this module needs no face/engine of its own and is unit
//! testable.
//!
//! # Relation to the pull refresh
//!
//! The pull refresh ([`ndn_cert::refresh_context`] via
//! [`crate::refresh_context_via_engine`]) fetches the newest version's name
//! over RDR metadata, then the signed context Data itself, and every holder
//! stores and republishes each adopted version so updates travel hop by hop
//! through relays that hold the context. It needs no sync group and no
//! per-namespace setup; its latency is the refresh period. This module adds
//! the push: a version the root puts into the group reaches the members at
//! once. Both apply the same check, so neither can adopt what the other
//! would refuse. The `ndn-fwd` daemon runs both when `[security]
//! context_sync = true` (the refresh alone by default).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_cert::{
    ContextStep, ContextUpdate, MAX_CATCH_UP_TIME, UpdateRefusal, Unfetched, VersionSource,
    follow_versions, open_context_update,
};
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::{Keyring, SignedTrustContext, context_namespace_of};
use ndn_sync::{SyncHandle, SyncUpdate};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

/// The name of `namespace`'s context-sync group:
/// `/<ns>/32=trust-context/32=sync`.
pub fn group_prefix(namespace: &Name) -> Name {
    ndn_cert::rdr_prefix(namespace).append_component(NameComponent::keyword(Bytes::from_static(
        b"sync",
    )))
}

/// The group Data a member named `publisher` (`<group>/<member>`) publishes
/// for the signed context Data `context`: named
/// `<publisher>/seg=<version>`, Content = `context`'s wire verbatim, signed
/// with DigestSha256. `None` when `context` is not named
/// `/<ns>/32=trust-context/v=<N>`.
pub fn group_data(publisher: &Name, context: &Data) -> Option<Bytes> {
    context_namespace_of(&context.name)?;
    let version = context.name.components().last()?.as_version()?;
    Some(
        ndn_packet::encode::DataBuilder::new(publisher.clone().append_segment(version), context.raw())
            .build(),
    )
}

/// Fetches the Content bytes of the Data published at a name. The caller backs
/// this with its consumer/face; an in-process engine, an `ndn-app` `Consumer`,
/// or a test stub all satisfy it. For a context-sync group the Content is the
/// signed context Data wire. `Err` says why nothing usable arrived.
#[async_trait::async_trait]
pub trait ContextFetcher: Send + Sync {
    async fn fetch_content(&self, name: Name) -> Result<Bytes, ContextFetchError>;
}

/// Why [`ContextFetcher::fetch_content`] brought nothing.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ContextFetchError {
    /// Nothing usable arrived (a timeout, a Nack and its reason, no
    /// Content): why. The version may be fetched later.
    #[error("{0}")]
    Missing(String),
    /// This node's forwarder refused the Data that answered: why. A final
    /// verdict on that Data — it is refused for what it is, not lost.
    #[error("this node's forwarder refused it ({0})")]
    Refused(String),
}

/// What happened when a sync update was processed.
#[derive(Debug)]
pub enum ContextSyncOutcome {
    /// A newer version, signed by an anchor of the held one (directly or
    /// through the versions walked), was adopted into the keyring. Keep
    /// (persist and serve) its `data` and every step of its `walked`.
    Adopted(ContextUpdate),
    /// The update is for a namespace this node holds no context for; nothing
    /// to continue from, so nothing was adopted.
    NotHeld { namespace: Name },
    /// The update failed the continuity check or is not newer than the held
    /// version ([`UpdateRefusal::NotNewer`] is the ordinary stale-update
    /// case). The held version stays in force.
    Refused(UpdateRefusal),
    /// Another adoption replaced the held version `held` (by `now`, older
    /// than this update) while this update was checked against it, so
    /// nothing was adopted; the next update is checked against the version
    /// held then.
    ChangedMeanwhile { held: u64, now: u64 },
    /// The group Data at `name` could not be fetched: why.
    FetchFailed { name: Name, reason: String },
    /// The fetched Content is not a Data named
    /// `/<ns>/32=trust-context/v=<N>`.
    DecodeFailed,
}

/// What [`process_update`] did with one update, and which version it proved
/// to exist.
#[derive(Debug)]
pub struct Processed {
    pub outcome: ContextSyncOutcome,
    /// The newest version whose signed context Data this update's group
    /// Data carried and that passed [`open_context_update`] against the held
    /// version, or against a version walked through from it: a version of
    /// the namespace known to exist, whether or not it was adopted (a walk
    /// that stopped past it, another adoption meanwhile). `None` when
    /// nothing fetched passed. The sequence number alone proves nothing: a
    /// group's Sync Interests are not authenticated, so anyone reaching the
    /// group can name any member and any number.
    pub verified: Option<u64>,
}

/// Fetch, check, and adopt the context advertised by one [`SyncUpdate`].
/// The highest sequence is fetched first: a trust context fully supersedes
/// its predecessor, so when the newest is signed by an anchor of the held
/// version nothing else is needed. When it is not, every sequence number
/// from the one after the held version up to it is followed oldest first
/// ([`follow_versions`]) — not only those from the update's low end, which
/// says only what this member last heard, not which versions exist —
/// fetching for [`MAX_CATCH_UP_TIME`] at most, as a refresh does. The newest
/// is adopted only if it passes
/// [`open_context_update`] against the held version of its namespace —
/// directly or through that walk — and [`Keyring::adopt_update_from`] (that
/// version still held, strictly newer, atomic); see the module docs.
pub async fn process_update(
    update: &SyncUpdate,
    fetcher: &dyn ContextFetcher,
    keyring: &Keyring,
) -> Processed {
    let mut verified = None;
    let outcome = check_and_adopt(update, fetcher, keyring, &mut verified).await;
    Processed { outcome, verified }
}

/// [`process_update`], recording in `verified` each version that passed the
/// continuity rule.
async fn check_and_adopt(
    update: &SyncUpdate,
    fetcher: &dyn ContextFetcher,
    keyring: &Keyring,
    verified: &mut Option<u64>,
) -> ContextSyncOutcome {
    let fetch_name = update.name.clone().append_segment(update.high_seq);
    let content = match fetcher.fetch_content(fetch_name.clone()).await {
        Ok(content) => content,
        Err(ContextFetchError::Missing(reason)) => {
            return ContextSyncOutcome::FetchFailed {
                name: fetch_name,
                reason,
            };
        }
        Err(ContextFetchError::Refused(reason)) => {
            return ContextSyncOutcome::Refused(UpdateRefusal::DroppedByForwarder(format!(
                "{fetch_name}: {reason}"
            )));
        }
    };
    let Ok(data) = Data::decode(content) else {
        return ContextSyncOutcome::DecodeFailed;
    };
    let Some(namespace) = context_namespace_of(&data.name) else {
        return ContextSyncOutcome::DecodeFailed;
    };
    let Some(held) = keyring
        .contexts()
        .into_iter()
        .find(|c| *c.namespace() == namespace)
    else {
        return ContextSyncOutcome::NotHeld { namespace };
    };

    let (newest, walked) = match open_context_update(&held, &data).await {
        Ok((context, signer)) => (
            ContextStep {
                context: Arc::new(context),
                data,
                signer,
            },
            Vec::new(),
        ),
        Err(refusal @ UpdateRefusal::NotSignedByHeldAnchor { .. }) => {
            // The sequence numbers are the versions republished: walk every
            // one newer than the held version, as a refresh does. An
            // earlier announcement of this member that was dropped or
            // refused may have carried the version that links them.
            let first = held.version() + 1;
            if first >= update.high_seq {
                return ContextSyncOutcome::Refused(refusal);
            }
            let offered = data
                .name
                .components()
                .last()
                .and_then(NameComponent::as_version)
                .unwrap_or(update.high_seq);
            let mut group = GroupVersions {
                fetcher,
                group: &update.name,
                newest: Some((update.high_seq, data)),
                reached: held.version(),
                deadline: Instant::now() + MAX_CATCH_UP_TIME,
            };
            let walk = follow_versions(&held, first..=update.high_seq, &mut group).await;
            // Each version the walk went on from passed the continuity rule.
            if group.reached > held.version() {
                *verified = Some(group.reached);
            }
            match walk {
                Ok(mut walked) => match walked.pop() {
                    Some(newest) => (newest, walked),
                    None => return ContextSyncOutcome::Refused(refusal),
                },
                Err(stop) => {
                    return ContextSyncOutcome::Refused(UpdateRefusal::CatchUp {
                        held: held.version(),
                        offered,
                        stop,
                    });
                }
            }
        }
        Err(refusal) => return ContextSyncOutcome::Refused(refusal),
    };
    let ContextStep {
        context,
        data,
        signer,
    } = newest;
    *verified = Some(context.version());
    match keyring.adopt_update_from(&held, Arc::clone(&context)) {
        Ok(()) => ContextSyncOutcome::Adopted(ContextUpdate {
            previous: held.version(),
            revoked: context
                .revocations()
                .iter()
                .filter(|r| !held.revocations().contains(r))
                .cloned()
                .collect(),
            context,
            data,
            signer,
            walked,
        }),
        // Another adoption changed the namespace while this one was checked.
        Err(Some(now)) if now >= context.version() => {
            ContextSyncOutcome::Refused(UpdateRefusal::NotNewer {
                offered: context.version(),
                held: now,
            })
        }
        Err(Some(now)) => ContextSyncOutcome::ChangedMeanwhile {
            held: held.version(),
            now,
        },
        Err(None) => ContextSyncOutcome::NotHeld { namespace },
    }
}

/// The walk's [`VersionSource`] over a sync group: position `n` is the
/// publisher's group Data `<group>/seg=n`, whose Content is a signed context
/// Data.
struct GroupVersions<'a> {
    fetcher: &'a dyn ContextFetcher,
    group: &'a Name,
    /// The newest version, fetched already.
    newest: Option<(u64, Data)>,
    /// The newest version the walk went on from: the held one, or one that
    /// passed the continuity rule from it.
    reached: u64,
    /// No fetch starts after this ([`MAX_CATCH_UP_TIME`], as a refresh's
    /// walk): a publisher that serves the newest version and lets every
    /// version in between time out costs that long at most.
    deadline: Instant,
}

impl VersionSource for GroupVersions<'_> {
    async fn fetch(&mut self, position: u64, from: &SignedTrustContext) -> Result<Data, Unfetched> {
        self.reached = self.reached.max(from.version());
        if let Some((_, data)) = self.newest.take_if(|(seq, _)| *seq == position) {
            return Ok(data);
        }
        if Instant::now() >= self.deadline {
            return Err(Unfetched::Missing(format!(
                "the walk fetches for {}s at most",
                MAX_CATCH_UP_TIME.as_secs()
            )));
        }
        let name = self.group.clone().append_segment(position);
        let content = self.fetcher.fetch_content(name.clone()).await.map_err(|e| match e {
            ContextFetchError::Missing(reason) => {
                Unfetched::Missing(format!("{name} could not be fetched: {reason}"))
            }
            ContextFetchError::Refused(reason) => Unfetched::Dropped(format!("{name}: {reason}")),
        })?;
        Data::decode(content)
            .map_err(|e| Unfetched::Missing(format!("{name} carries no Data packet: {e}")))
    }
}

/// How [`run`] tries again to obtain a version announced in the group that
/// it could not obtain: after `first`, then after twice the previous delay,
/// at most `max` apart, while the announcement is newer than the held
/// version — [`UNPROVEN_TRIES`] times at most for a member that never served
/// a version passing the continuity rule (see the module docs, *Retries*).
#[derive(Clone, Copy, Debug)]
pub struct Retry {
    pub first: Duration,
    pub max: Duration,
}

impl Default for Retry {
    /// 1 s, doubling to once a minute.
    fn default() -> Self {
        Self {
            first: Duration::from_secs(1),
            max: Duration::from_secs(60),
        }
    }
}

/// How many times [`run`] tries to obtain an announcement of a member none
/// of whose announced versions ever passed the continuity rule, the first
/// try included, before leaving the version to the pull refresh: with
/// [`Retry::default`], over about half a minute.
pub const UNPROVEN_TRIES: u32 = 6;

/// How many announcements of such members [`run`] keeps to try again at
/// once; one more that fails is tried once only.
pub const UNPROVEN_PENDING: usize = 8;

/// A version of the namespace [`run`] found exists
/// ([`Processed::verified`]): its signed Data passed the continuity rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedVersion {
    pub version: u64,
    /// The member (`<group>/<member>`) whose group Data carried it.
    pub served_by: Name,
}

/// A publisher's announcement not obtained yet.
struct Pending {
    update: SyncUpdate,
    /// The tries that failed so far.
    tries: u32,
    /// The delay `at` was set with.
    delay: Duration,
    at: Instant,
}

/// Run the subscription loop of `namespace`'s group until `cancel` fires or
/// the sync group closes: each peer update is fetched and adopted via
/// [`process_update`], and tried again under `retry` while it could not be
/// obtained and is still newer than the held version (module docs,
/// *Retries*). The caller has already [`join`](ndn_sync::join_svs_group)ed
/// the group for the context and spawns this on its runtime. The keyring
/// holds an adopted version in memory only: `keep` is handed each adoption
/// to persist and serve its signed Data and the versions walked through.
/// `verified` is handed each version an update proved to exist
/// ([`Processed::verified`]), adopted or not — never a bare sequence
/// number, which anyone reaching the group can send.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut handle: SyncHandle,
    namespace: Name,
    fetcher: Arc<dyn ContextFetcher>,
    keyring: Arc<Keyring>,
    keep: impl Fn(&ContextUpdate) + Send,
    verified: impl Fn(&VerifiedVersion) + Send,
    retry: Retry,
    cancel: CancellationToken,
) {
    // By publisher (its node name): the announcement to try again.
    let mut pending: HashMap<Name, Pending> = HashMap::new();
    // The publishers whose announced version passed the continuity rule at
    // least once: tried again for as long as they announce a version newer
    // than the held one. Each joined with a version newer than the one held
    // then, so the set grows no faster than the namespace root makes
    // versions.
    let mut proven: HashSet<Name> = HashSet::new();
    loop {
        let due = pending.values().map(|p| p.at).min();
        let (update, tries, delay) = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            update = handle.recv() => {
                let Some(mut update) = update else { break };
                // A new announcement is tried at once, and backs off from
                // the start again; the tries it already cost still count.
                let mut tries = 0;
                if let Some(earlier) = pending.remove(&update.name) {
                    update.high_seq = update.high_seq.max(earlier.update.high_seq);
                    tries = earlier.tries;
                }
                (update, tries, retry.first)
            }
            () = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                // A due announcement of a proven publisher goes first: those
                // of members that never served a version cannot hold it up.
                let now = Instant::now();
                let Some(publisher) = pending
                    .iter()
                    .filter(|(_, p)| p.at <= now)
                    .min_by_key(|(publisher, p)| (!proven.contains(*publisher), p.at))
                    .map(|(publisher, _)| publisher.clone())
                else {
                    continue;
                };
                let Some(again) = pending.remove(&publisher) else { continue };
                (again.update, again.tries, again.delay.saturating_mul(2).min(retry.max))
            }
        };
        let obtained = obtain(&update, &namespace, fetcher.as_ref(), &keyring).await;
        if let Some(version) = obtained.verified {
            verified(&VerifiedVersion {
                version,
                served_by: update.name.clone(),
            });
        }
        if obtained.proven {
            proven.insert(update.name.clone());
        }
        let reason = match obtained.result {
            Ok(Some(adopted)) => {
                keep(&adopted);
                continue;
            }
            Ok(None) => continue,
            Err(reason) => reason,
        };
        let tries = tries.saturating_add(1);
        if !proven.contains(&update.name) {
            let waiting = pending.keys().filter(|p| !proven.contains(*p)).count();
            let given_up = if tries >= UNPROVEN_TRIES {
                Some(format!("tried {tries} times"))
            } else if waiting >= UNPROVEN_PENDING {
                Some(format!("{waiting} such announcements already wait"))
            } else {
                None
            };
            if let Some(given_up) = given_up {
                tracing::warn!(
                    target: "ndn::trust",
                    publisher = %update.publisher,
                    announced = update.high_seq,
                    held = ?keyring.version_of(&namespace),
                    %reason,
                    %given_up,
                    "context-sync could not obtain a trust-context version announced by a member \
                     that never served one passing the continuity rule, and does not try again; \
                     the periodic refresh fetches the namespace's newest version by name (run \
                     `ndn-fwd context refresh` to fetch it now)"
                );
                continue;
            }
        }
        tracing::warn!(
            target: "ndn::trust",
            publisher = %update.publisher,
            announced = update.high_seq,
            held = ?keyring.version_of(&namespace),
            %reason,
            tries,
            retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "context-sync could not obtain an announced trust-context version; trying again"
        );
        pending.insert(
            update.name.clone(),
            Pending {
                update,
                tries,
                delay,
                at: Instant::now() + delay,
            },
        );
    }
}

/// What [`obtain`] made of one announcement.
struct Obtained {
    /// `Ok(Some(_))` adopted, to keep; `Ok(None)` not needed, or refused for
    /// what it is (logged); `Err(why)` not obtained for now, worth trying
    /// again.
    result: Result<Option<ContextUpdate>, String>,
    /// [`Processed::verified`].
    verified: Option<u64>,
    /// The announced version itself passed the continuity rule (adopted, or
    /// checked while another adoption replaced the held version).
    proven: bool,
}

/// Obtain the version `update` announces, unless the held version of
/// `namespace` already reaches it (a publisher's sequence number is the
/// version it put into the group).
async fn obtain(
    update: &SyncUpdate,
    namespace: &Name,
    fetcher: &dyn ContextFetcher,
    keyring: &Keyring,
) -> Obtained {
    match keyring.version_of(namespace) {
        Some(held) if held < update.high_seq => {}
        held => {
            tracing::debug!(
                target: "ndn::trust", announced = update.high_seq, ?held, publisher = %update.publisher,
                "context-sync announcement is not newer than the held version"
            );
            return Obtained {
                result: Ok(None),
                verified: None,
                proven: false,
            };
        }
    }
    let Processed { outcome, verified } = process_update(update, fetcher, keyring).await;
    let proven = matches!(
        outcome,
        ContextSyncOutcome::Adopted(_) | ContextSyncOutcome::ChangedMeanwhile { .. }
    );
    let result = match outcome {
        ContextSyncOutcome::Adopted(adopted) => {
            tracing::info!(
                target: "ndn::trust",
                previous = adopted.previous,
                version = adopted.context.version(),
                revoked = ?adopted.revoked.iter().map(Name::to_string).collect::<Vec<_>>(),
                publisher = %update.publisher,
                "context-sync adopted a newer trust context"
            );
            Ok(Some(adopted))
        }
        ContextSyncOutcome::Refused(UpdateRefusal::NotNewer { offered, held }) => {
            tracing::debug!(
                target: "ndn::trust", %offered, %held,
                "context-sync update not newer than the held version"
            );
            Ok(None)
        }
        // The newest does not follow from the held version, and the walk
        // through the publisher's earlier sequence numbers did not reach it.
        // Final for this announcement: whoever announced it may serve a
        // forged newest and let every version in between time out, and
        // trying again would cost that walk each time. A genuine version
        // still arrives by name through the refresh's own walk.
        ContextSyncOutcome::Refused(refusal @ UpdateRefusal::CatchUp { .. }) => {
            tracing::warn!(
                target: "ndn::trust", %refusal, publisher = %update.publisher, ?verified,
                "context-sync could not follow the announced trust-context version from the held \
                 one and does not try this announcement again; the held version stays, and the \
                 periodic refresh follows the namespace's versions by name (run `ndn-fwd context \
                 refresh` to follow them now)"
            );
            Ok(None)
        }
        ContextSyncOutcome::Refused(refusal) => {
            tracing::warn!(
                target: "ndn::trust", %refusal, publisher = %update.publisher,
                "context-sync refused a trust-context update; the held version stays"
            );
            Ok(None)
        }
        ContextSyncOutcome::FetchFailed { name, reason } => {
            Err(format!("{name} could not be fetched: {reason}"))
        }
        ContextSyncOutcome::ChangedMeanwhile { held, now } => Err(format!(
            "another update replaced the held version v{held} by v{now} while it was checked"
        )),
        other @ (ContextSyncOutcome::NotHeld { .. } | ContextSyncOutcome::DecodeFailed) => {
            tracing::warn!(
                target: "ndn::trust", ?other, publisher = %update.publisher,
                "context-sync could not adopt an update"
            );
            Ok(None)
        }
    };
    Obtained {
        result,
        verified,
        proven,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    use ndn_cert::{CatchUpStop, NamespaceInit, anchor_fingerprint, init_namespace};
    use ndn_security::{Ed25519Signer, SecurityManager, Signer};

    const GROUP: &str = "/home/bob/_sync/v1/devices/device-a";

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// Maps a fetch name → group Data Content (a signed context Data wire).
    struct MapFetcher(DashMap<String, Bytes>);

    impl MapFetcher {
        fn new() -> Self {
            Self(DashMap::new())
        }
        /// Publish `context` (signed Data) into the group at `seq`.
        fn publish(&self, seq: u64, context: &Data) {
            self.publish_raw(seq, context.raw().clone());
        }
        fn publish_raw(&self, seq: u64, content: Bytes) {
            self.0
                .insert(n(GROUP).append_segment(seq).to_string(), content);
        }
    }

    #[async_trait::async_trait]
    impl ContextFetcher for MapFetcher {
        async fn fetch_content(&self, name: Name) -> Result<Bytes, ContextFetchError> {
            self.0
                .get(&name.to_string())
                .map(|c| c.value().clone())
                .ok_or_else(|| ContextFetchError::Missing("nothing published".to_string()))
        }
    }

    fn update_at(seq: u64) -> SyncUpdate {
        SyncUpdate {
            publisher: "device-a".into(),
            name: n(GROUP),
            low_seq: seq,
            high_seq: seq,
            mapping: None,
            serving_party: None,
        }
    }

    /// A root device for `/home/bob`: its signing key lives in the manager.
    struct Root {
        mgr: SecurityManager,
        init: NamespaceInit,
    }

    impl Root {
        fn new() -> Self {
            let mgr = SecurityManager::new();
            let init = init_namespace(&mgr, &n("/home/bob")).unwrap();
            Self { mgr, init }
        }

        /// Version `version` of the context with `revoked` added, signed by
        /// this root's key.
        fn version(&self, version: u64, revoked: &[&str]) -> Data {
            let content = self.init.context.encode_content();
            let mut ctx = SignedTrustContext::decode_content(&content, version).unwrap();
            for r in revoked {
                ctx = ctx.with_revocation(n(r));
            }
            let signer = self.mgr.get_signer_sync(&self.init.anchor_key).unwrap();
            ctx.sign_into_data(signer.as_ref()).unwrap()
        }
    }

    /// A node holding `root`'s v1, adopted from its link.
    fn node_holding(root: &Root) -> Keyring {
        let keyring = Keyring::new();
        ndn_cert::adopt_with_tofu(
            &keyring,
            &root.init.context_data,
            &n("/home/bob"),
            &anchor_fingerprint(&root.init.anchor),
        )
        .unwrap();
        keyring
    }

    fn held_version(keyring: &Keyring) -> u64 {
        keyring.version_of(&n("/home/bob")).unwrap()
    }

    #[tokio::test]
    async fn an_update_signed_by_the_held_root_is_adopted_intact() {
        let root = Root::new();
        let keyring = node_holding(&root);
        let fetcher = MapFetcher::new();
        let revoked = "/home/bob/member/phone/KEY/k1";
        let v2 = root.version(2, &[revoked]);
        fetcher.publish(2, &v2);

        match process_update(&update_at(2), &fetcher, &keyring).await.outcome {
            ContextSyncOutcome::Adopted(adopted) => {
                assert_eq!((adopted.previous, adopted.context.version()), (1, 2));
                assert_eq!(adopted.revoked, vec![n(revoked)]);
                // The signed Data exactly as published: what the caller keeps.
                assert_eq!(adopted.data.raw(), v2.raw());
            }
            other => panic!("update from the held root not adopted: {other:?}"),
        }
        let held = keyring.context_for(&n("/home/bob"));
        assert_eq!(held.version(), 2);
        assert!(held.is_revoked(&n(revoked)));
        // Everything else is carried over verbatim.
        assert_eq!(held.ca_endpoints(), root.init.context.ca_endpoints());
        let bodies = |c: &SignedTrustContext| {
            c.published_schemas()
                .into_iter()
                .map(|s| s.body)
                .collect::<Vec<_>>()
        };
        assert_eq!(bodies(&held), bodies(&root.init.context));
    }

    #[tokio::test]
    async fn an_update_not_signed_by_a_held_anchor_is_never_adopted() {
        let root = Root::new();
        let keyring = node_holding(&root);
        // Another root claiming the same namespace (its key is also named
        // /home/bob/KEY/root) publishes a higher version into the group.
        let forged = Root::new();
        let fetcher = MapFetcher::new();
        fetcher.publish(9, &forged.version(9, &["/home/bob/admin/desk/KEY/device"]));

        // The walk from the held version finds no version linking the two
        // (positions 2..8 are not published), so the update stays refused.
        match process_update(&update_at(9), &fetcher, &keyring).await.outcome {
            ContextSyncOutcome::Refused(UpdateRefusal::CatchUp {
                held: 1,
                offered: 9,
                ..
            }) => {}
            other => panic!("forged update not refused: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 1, "the held version stays");

        // Bare Content (the old wire) is unauthenticated and never adopted.
        fetcher.publish_raw(10, root.init.context.encode_content());
        assert!(matches!(
            process_update(&update_at(10), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::DecodeFailed
        ));
        // Neither is a genuine context whose signature no longer verifies.
        let genuine = root.version(11, &[]);
        let mut wire = genuine.raw().to_vec();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        fetcher.publish_raw(11, Bytes::from(wire));
        assert!(matches!(
            process_update(&update_at(11), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::Refused(UpdateRefusal::Unauthentic(_))
        ));
        assert_eq!(held_version(&keyring), 1, "the held version stays");
    }

    #[tokio::test]
    async fn a_lower_or_equal_version_never_replaces_the_held_one() {
        let root = Root::new();
        let keyring = node_holding(&root);
        let fetcher = MapFetcher::new();
        fetcher.publish(5, &root.version(5, &[]));
        assert!(matches!(
            process_update(&update_at(5), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::Adopted(a) if a.context.version() == 5
        ));
        // A different v5 and an older v3, both genuinely signed.
        fetcher.publish(6, &root.version(5, &["/home/bob/member/x/KEY/k"]));
        fetcher.publish(3, &root.version(3, &[]));
        for seq in [6, 3] {
            assert!(matches!(
                process_update(&update_at(seq), &fetcher, &keyring).await.outcome,
                ContextSyncOutcome::Refused(UpdateRefusal::NotNewer { held: 5, .. })
            ));
        }
        let held = keyring.context_for(&n("/home/bob"));
        assert_eq!(held.version(), 5);
        assert!(!held.is_revoked(&n("/home/bob/member/x/KEY/k")));
    }

    #[tokio::test]
    async fn a_namespace_not_held_is_never_adopted_from_the_group() {
        let root = Root::new();
        let keyring = Keyring::new();
        let fetcher = MapFetcher::new();
        fetcher.publish(2, &root.version(2, &[]));
        assert!(matches!(
            process_update(&update_at(2), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::NotHeld { .. }
        ));
        assert!(keyring.is_empty());
    }

    #[tokio::test]
    async fn fetch_and_decode_failures_are_reported() {
        let keyring = Keyring::new();
        let fetcher = MapFetcher::new();
        assert!(matches!(
            process_update(&update_at(1), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::FetchFailed { .. }
        ));
        fetcher.publish_raw(1, Bytes::from_static(b"not a trust context"));
        assert!(matches!(
            process_update(&update_at(1), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::DecodeFailed
        ));
    }

    /// A node that missed a recovery follows it from the group: it holds v2
    /// (listing a recovery key); the publisher republished v3 (the recovery
    /// key installs a new root) and v4 (the new root's, newest). v4 alone
    /// does not follow from v2, so the sequence numbers in between are
    /// followed one by one. A forged v3 stops it and the held version stays.
    #[tokio::test]
    async fn a_node_behind_a_recovery_follows_the_sequence_numbers_in_between() {
        let root = Root::new();
        let ns = n("/home/bob");
        let root_signer = root.mgr.get_signer_sync(&root.init.anchor_key).unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let recovery: Arc<dyn Signer> = Arc::new(seed.signer(&ns));
        let kit = ndn_cert::recovery_anchor(Arc::clone(&recovery)).await.unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root_signer.as_ref(), &root.init.context_data, &kit)
            .await
            .unwrap();
        let keyring = node_holding(&root);
        let fetcher = MapFetcher::new();
        fetcher.publish(2, &v2.data);
        assert!(matches!(
            process_update(&update_at(2), &fetcher, &keyring).await.outcome,
            ContextSyncOutcome::Adopted(a) if a.context.version() == 2
        ));

        let new_root_mgr = SecurityManager::new();
        let new_root_key = n("/home/bob/KEY/root2");
        new_root_mgr.generate_ed25519(new_root_key.clone()).unwrap();
        let new_root = new_root_mgr.get_signer_sync(&new_root_key).unwrap();
        let new_anchor = new_root_mgr
            .issue_self_signed_async(&new_root_key, new_root.public_key().unwrap(), u64::MAX)
            .await
            .unwrap();
        let plan = ndn_cert::RecoveryPlan {
            new_root: &new_anchor,
            new_root_device_keys: &[],
            old_root: ndn_cert::OldRoot::Destroyed,
            kept_kits: &[],
        };
        let v3 = ndn_cert::recovery_version(recovery.as_ref(), &v2.data, &plan)
            .await
            .unwrap()
            .bump;
        let v4 = ndn_cert::reissue_version(new_root.as_ref(), &v3.data).await.unwrap();
        let missed = SyncUpdate {
            low_seq: 3,
            ..update_at(4)
        };

        let stranger: Arc<dyn Signer> =
            Arc::new(Ed25519Signer::from_seed(&[7; 32], n("/home/bob/KEY/stranger")));
        let forged = SignedTrustContext::decode_content(v2.data.content().unwrap(), 3).unwrap();
        forged.add_anchor(ndn_cert::recovery_anchor(Arc::clone(&stranger)).await.unwrap());
        let forged_group = MapFetcher::new();
        forged_group.publish(3, &forged.sign_into_data_async(stranger.as_ref()).await.unwrap());
        forged_group.publish(4, &v4.data);
        match process_update(&missed, &forged_group, &keyring).await.outcome {
            ContextSyncOutcome::Refused(UpdateRefusal::CatchUp {
                stop: CatchUpStop::Refused { version: 3, .. },
                ..
            }) => {}
            other => panic!("a forged intermediate version was not refused: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 2, "the held version stays");

        fetcher.publish(3, &v3.data);
        fetcher.publish(4, &v4.data);
        match process_update(&missed, &fetcher, &keyring).await.outcome {
            ContextSyncOutcome::Adopted(adopted) => {
                assert_eq!((adopted.previous, adopted.context.version()), (2, 4));
                // The newest and the version walked through, as signed: what
                // the caller keeps and serves for the nodes behind it.
                assert_eq!(adopted.data.raw(), v4.data.raw());
                let walked: Vec<_> = adopted.walked.iter().map(|s| s.data.raw()).collect();
                assert_eq!(walked, vec![v3.data.raw()]);
            }
            other => panic!("the recovery was not followed: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 4);
    }

    /// The walk starts after the held version, not at the update's low end:
    /// a node holding v1 whose announcements of v2 and v3 were lost hears
    /// only `[4, 4]`, and still follows v2 (a recovery anchor added) and v3
    /// (the recovery) to the re-issued v4.
    #[tokio::test]
    async fn the_walk_starts_after_the_held_version_not_at_the_low_end() {
        let root = Root::new();
        let ns = n("/home/bob");
        let keyring = node_holding(&root);
        let root_signer = root.mgr.get_signer_sync(&root.init.anchor_key).unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let recovery: Arc<dyn Signer> = Arc::new(seed.signer(&ns));
        let kit = ndn_cert::recovery_anchor(Arc::clone(&recovery)).await.unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root_signer.as_ref(), &root.init.context_data, &kit)
            .await
            .unwrap();
        let new_root_mgr = SecurityManager::new();
        let new_root_key = n("/home/bob/KEY/root2");
        new_root_mgr.generate_ed25519(new_root_key.clone()).unwrap();
        let new_root = new_root_mgr.get_signer_sync(&new_root_key).unwrap();
        let new_anchor = new_root_mgr
            .issue_self_signed_async(&new_root_key, new_root.public_key().unwrap(), u64::MAX)
            .await
            .unwrap();
        let plan = ndn_cert::RecoveryPlan {
            new_root: &new_anchor,
            new_root_device_keys: &[],
            old_root: ndn_cert::OldRoot::Destroyed,
            kept_kits: &[],
        };
        let v3 = ndn_cert::recovery_version(recovery.as_ref(), &v2.data, &plan)
            .await
            .unwrap()
            .bump;
        let v4 = ndn_cert::reissue_version(new_root.as_ref(), &v3.data).await.unwrap();
        let fetcher = MapFetcher::new();
        for (seq, data) in [(2, &v2.data), (3, &v3.data), (4, &v4.data)] {
            fetcher.publish(seq, data);
        }

        match process_update(&update_at(4), &fetcher, &keyring).await.outcome {
            ContextSyncOutcome::Adopted(adopted) => {
                assert_eq!((adopted.previous, adopted.context.version()), (1, 4));
                let walked: Vec<_> = adopted.walked.iter().map(|s| s.data.raw()).collect();
                assert_eq!(walked, vec![v2.data.raw(), v3.data.raw()]);
            }
            other => panic!("the versions below the low end were not walked: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 4);
    }

    /// A group whose fetches fail while `failing` is above zero (counting
    /// down) and for names nothing is published at, counting every fetch.
    struct Flaky {
        group: MapFetcher,
        failing: std::sync::atomic::AtomicUsize,
        fetches: DashMap<String, usize>,
    }

    impl Flaky {
        fn new(failing: usize) -> Arc<Self> {
            Arc::new(Self {
                group: MapFetcher::new(),
                failing: failing.into(),
                fetches: DashMap::new(),
            })
        }
        fn fetches(&self, name: &Name) -> usize {
            self.fetches.get(&name.to_string()).map_or(0, |n| *n)
        }
    }

    #[async_trait::async_trait]
    impl ContextFetcher for Flaky {
        async fn fetch_content(&self, name: Name) -> Result<Bytes, ContextFetchError> {
            *self.fetches.entry(name.to_string()).or_insert(0) += 1;
            let lost = self
                .failing
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| n.checked_sub(1),
                )
                .is_ok();
            if lost {
                return Err(ContextFetchError::Missing("timed out".into()));
            }
            self.group.fetch_content(name).await
        }
    }

    const QUICK: Retry = Retry {
        first: std::time::Duration::from_millis(20),
        max: std::time::Duration::from_millis(80),
    };

    /// The versions [`run`] handed to `verified`, in order.
    type Verified = tokio::sync::mpsc::UnboundedReceiver<VerifiedVersion>;

    fn drain(verified: &mut Verified) -> Vec<VerifiedVersion> {
        std::iter::from_fn(|| verified.try_recv().ok()).collect()
    }

    /// [`run`] over `keyring` and `fetcher`, fed the updates sent on the
    /// returned channel; the number of adoptions kept is counted in `kept`,
    /// and the versions verified are returned.
    fn subscribe(
        keyring: &Arc<Keyring>,
        fetcher: &Arc<Flaky>,
        kept: &Arc<std::sync::atomic::AtomicUsize>,
        cancel: &CancellationToken,
    ) -> (tokio::sync::mpsc::Sender<SyncUpdate>, Verified) {
        let (updates, rx) = tokio::sync::mpsc::channel(8);
        let (publish, _) = tokio::sync::mpsc::channel(1);
        let handle = SyncHandle::new(rx, publish, CancellationToken::new());
        let kept = Arc::clone(kept);
        let (record, verified) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(run(
            handle,
            n("/home/bob"),
            Arc::clone(fetcher) as Arc<dyn ContextFetcher>,
            Arc::clone(keyring),
            move |_| {
                kept.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
            move |v| {
                let _ = record.send(v.clone());
            },
            QUICK,
            cancel.clone(),
        ));
        (updates, verified)
    }

    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !done() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}"));
    }

    /// SVS reports a sequence number once: a version whose fetch was lost
    /// (seen in the end-to-end harness, ndn-fwd/testbed/e2e `lifecycle-push`:
    /// a fetch aggregated onto a PIT entry that went nowhere) is fetched
    /// again while the announcement is newer than the held version, and
    /// adopted once it arrives.
    #[tokio::test]
    async fn an_announced_version_whose_fetch_was_lost_is_fetched_again_until_obtained() {
        let root = Root::new();
        let keyring = Arc::new(node_holding(&root));
        let fetcher = Flaky::new(3);
        fetcher.group.publish(2, &root.version(2, &["/home/bob/member/phone/KEY/k1"]));
        let kept = Arc::default();
        let cancel = CancellationToken::new();
        let (updates, _) = subscribe(&keyring, &fetcher, &kept, &cancel);

        updates.send(update_at(2)).await.unwrap();
        until("the lost version was never fetched again", || held_version(&keyring) == 2).await;
        assert_eq!(fetcher.fetches(&n(GROUP).append_segment(2)), 4, "three lost, then obtained");
        assert_eq!(kept.load(std::sync::atomic::Ordering::SeqCst), 1);
        cancel.cancel();
    }

    /// Retries cannot storm: they back off; they stop once the held version
    /// reaches the announcement, here through another member that announced
    /// it; and a version refused for what it is is fetched once.
    #[tokio::test]
    async fn retries_back_off_and_stop_once_the_held_version_reaches_the_announcement() {
        let root = Root::new();
        let keyring = Arc::new(node_holding(&root));
        // Nothing is published under GROUP: that publisher is unreachable.
        let fetcher = Flaky::new(0);
        let other = n("/home/bob/_sync/v1/devices/device-b");
        fetcher
            .group
            .0
            .insert(other.clone().append_segment(2).to_string(), root.version(2, &[]).raw().clone());
        let kept = Arc::default();
        let cancel = CancellationToken::new();
        let (updates, _) = subscribe(&keyring, &fetcher, &kept, &cancel);
        let unreachable = n(GROUP).append_segment(2);

        updates.send(update_at(2)).await.unwrap();
        let started = tokio::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let tries = fetcher.fetches(&unreachable);
        // 20, 40, then 80 ms apart: at most 8 in the first 500 ms (fewer
        // on a slow machine, never more).
        assert!(tries >= 2, "the lost version was not fetched again: {tries}");
        let elapsed = started.elapsed().as_millis();
        assert!(tries <= 8 + (elapsed.saturating_sub(500) / 80) as usize, "{tries} fetches in {elapsed} ms");

        updates
            .send(SyncUpdate {
                publisher: "device-b".into(),
                name: other.clone(),
                ..update_at(2)
            })
            .await
            .unwrap();
        until("the version announced by the other member was not adopted", || {
            held_version(&keyring) == 2
        })
        .await;
        let tries = fetcher.fetches(&unreachable);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(fetcher.fetches(&unreachable), tries, "retried after v2 was held");

        // A v3 another root signed is refused, and not fetched again.
        let forged = Root::new().version(3, &[]);
        fetcher.group.publish(3, &forged);
        updates.send(update_at(3)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(fetcher.fetches(&n(GROUP).append_segment(3)), 1);
        assert_eq!(held_version(&keyring), 2);
        assert_eq!(kept.load(std::sync::atomic::Ordering::SeqCst), 1);
        cancel.cancel();
    }

    /// `<group>/<name>`, the member `name` of the test group.
    fn member(name: &str) -> Name {
        n(&format!("/home/bob/_sync/v1/devices/{name}"))
    }

    fn update_from(name: &str, low_seq: u64, high_seq: u64) -> SyncUpdate {
        SyncUpdate {
            publisher: name.into(),
            name: member(name),
            low_seq,
            high_seq,
            mapping: None,
            serving_party: None,
        }
    }

    impl Flaky {
        /// Serve `context` as member `name`'s group Data at `seq`.
        fn serve(&self, name: &str, seq: u64, context: &Data) {
            self.group
                .0
                .insert(member(name).append_segment(seq).to_string(), context.raw().clone());
        }
    }

    /// The group's Sync Interests are not authenticated: a sequence number
    /// alone, or a version that does not follow from the held one, never
    /// counts as a version that exists (the daemon would report `behind`
    /// and refuse `ndn-fwd recover` over it). A version whose signed Data
    /// passed the continuity rule does — the newest, or one a walk went
    /// through before it stopped.
    #[tokio::test]
    async fn unverified_announcement_is_not_a_known_version() {
        let root = Root::new();
        let keyring = Arc::new(node_holding(&root));
        let fetcher = Flaky::new(0);
        let kept = Arc::default();
        let cancel = CancellationToken::new();
        let (updates, mut verified) = subscribe(&keyring, &fetcher, &kept, &cancel);

        // A made-up member announcing v1000 and serving nothing, and one
        // serving a v9 another root signed.
        fetcher.serve("forger", 9, &Root::new().version(9, &[]));
        updates.send(update_from("ghost", 1000, 1000)).await.unwrap();
        updates.send(update_from("forger", 1, 9)).await.unwrap();
        until("the announcements were not tried", || {
            fetcher.fetches(&member("ghost").append_segment(1000)) >= UNPROVEN_TRIES as usize
                && fetcher.fetches(&member("forger").append_segment(8)) == 1
        })
        .await;
        assert_eq!(drain(&mut verified), vec![], "an unverified version counted");
        assert_eq!(held_version(&keyring), 1);

        fetcher.serve("device-b", 2, &root.version(2, &[]));
        updates.send(update_from("device-b", 2, 2)).await.unwrap();
        let mut seen = Vec::new();
        until("the genuine v2 was not verified", || {
            seen.extend(drain(&mut verified));
            !seen.is_empty()
        })
        .await;
        let v2 = VerifiedVersion {
            version: 2,
            served_by: member("device-b"),
        };
        assert_eq!(seen, vec![v2]);
        assert_eq!(held_version(&keyring), 2);

        // A walk through a genuine v3, stopped by a forged v4: v3 exists,
        // v4 does not.
        fetcher.serve("device-c", 3, &root.version(3, &[]));
        fetcher.serve("device-c", 4, &Root::new().version(4, &[]));
        updates.send(update_from("device-c", 3, 4)).await.unwrap();
        let mut seen = Vec::new();
        until("the walked v3 was not verified", || {
            seen.extend(drain(&mut verified));
            !seen.is_empty()
        })
        .await;
        let v3 = VerifiedVersion {
            version: 3,
            served_by: member("device-c"),
        };
        assert_eq!(seen, vec![v3]);
        assert_eq!(held_version(&keyring), 2, "nothing adopted from a stopped walk");
        cancel.cancel();
    }

    /// A member serving a newest version that does not follow from the held
    /// one, and nothing in between, costs one walk per announcement: a
    /// stopped walk is not tried again, and the walk starts no fetch after
    /// [`MAX_CATCH_UP_TIME`].
    #[tokio::test]
    async fn refused_newest_version_is_not_retried_unbounded() {
        let root = Root::new();
        let keyring = Arc::new(node_holding(&root));
        let fetcher = Flaky::new(0);
        fetcher.serve("forger", 100, &Root::new().version(100, &[]));
        let kept = Arc::default();
        let cancel = CancellationToken::new();
        let (updates, _) = subscribe(&keyring, &fetcher, &kept, &cancel);

        updates.send(update_from("forger", 1, 100)).await.unwrap();
        until("the walk did not run", || {
            fetcher.fetches(&member("forger").append_segment(99)) == 1
        })
        .await;
        // Retries under QUICK would have walked again several times by now.
        tokio::time::sleep(Duration::from_millis(400)).await;
        for seq in 2..=100 {
            let fetches = fetcher.fetches(&member("forger").append_segment(seq));
            assert_eq!(fetches, 1, "seq {seq} fetched {fetches} times");
        }
        assert_eq!(held_version(&keyring), 1);
        cancel.cancel();

        // Past the deadline no position in between is fetched.
        let held = keyring.context_for(&n("/home/bob"));
        let group = member("forger");
        let counting = Flaky::new(0);
        let mut walk = GroupVersions {
            fetcher: counting.as_ref(),
            group: &group,
            newest: Some((100, Root::new().version(100, &[]))),
            reached: held.version(),
            deadline: Instant::now(),
        };
        assert!(matches!(
            follow_versions(&held, 2..=100, &mut walk).await,
            Err(CatchUpStop::Missing {
                first: 2,
                last: 99,
                version: 100,
                ..
            })
        ));
        assert!(counting.fetches.is_empty(), "fetched past the walk's deadline");
    }

    /// Member names are made up at will: a member that never served a
    /// version passing the continuity rule is tried [`UNPROVEN_TRIES`] times
    /// at most, and at most [`UNPROVEN_PENDING`] such members wait to be
    /// tried again.
    #[tokio::test]
    async fn retries_of_members_that_never_served_a_version_are_bounded() {
        let root = Root::new();
        let keyring = Arc::new(node_holding(&root));
        let fetcher = Flaky::new(0);
        let kept = Arc::default();
        let cancel = CancellationToken::new();
        let (updates, _) = subscribe(&keyring, &fetcher, &kept, &cancel);

        let ghosts = 20;
        for i in 0..ghosts {
            updates.send(update_from(&format!("ghost-{i}"), 5, 5)).await.unwrap();
        }
        let total = || fetcher.fetches.iter().map(|e| *e.value()).sum::<usize>();
        // Under QUICK the last retry is due 300 ms after the first try.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let settled = total();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(total(), settled, "still trying");
        let bound = ghosts + UNPROVEN_PENDING * (UNPROVEN_TRIES as usize - 1);
        assert!(settled <= bound, "{settled} fetches, more than {bound}");
        for i in 0..ghosts {
            let fetches = fetcher.fetches(&member(&format!("ghost-{i}")).append_segment(5));
            assert!(fetches <= UNPROVEN_TRIES as usize, "ghost-{i} fetched {fetches} times");
        }
        cancel.cancel();
    }
}
