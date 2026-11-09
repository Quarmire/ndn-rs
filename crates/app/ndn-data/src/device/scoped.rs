//! Members' namespaces adopted for their folders (spec §6.3). A device
//! adopts by name — version 1 fetched and checked as the genesis the name
//! hashes, the newest reached from it — every self-certifying namespace
//! (`/user/<0xA1: …>`) that an owner-signed members record in force here
//! lists as a writer, or keeps by a removal cut, and that its node does not
//! hold, up to [`SCOPE_PER_SUBJECT`] for one subject and
//! [`SCOPE_NAMESPACES`] in all. It judges with it exactly that namespace's
//! packets about the subjects (folders, collections) whose records list it:
//! log entries of collections under them, and the summary nodes on the way
//! to them. The adoption is the host's
//! ([`crate::intro::Introducer::adopt_scoped`]) and goes into no keyring the
//! node judges by; the device judges through a view of its validator
//! ([`Validator::scoped_view`]) that no other path sees. A held context of
//! the namespace is used as is, and never replaced. The newest version
//! adopted of each namespace is kept in the store, signed: after a restart
//! it judges again at once and is refreshed from by continuity, never
//! walked to from the genesis again, and no older version is adopted.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::{Data, Name};
use ndn_security::self_certifying::{Genesis, personal_namespace_of};
use ndn_security::{ScopedContext, SignedTrustContext, Validator};
use sha2::{Digest, Sha256};

use super::{Inner, REFRESH_PAUSE_MAX, Rejudge, St, Subject, refuses_more, under};
use crate::collection::Members;
use crate::rt::{self, Instant};
use crate::wire::{
    namespace_of, parse_entry_name, parse_head_name, parse_log_name, parse_piece_name,
    parse_signal_run_name, parse_summary_name,
};

/// The first pause before a namespace the host could not adopt is asked
/// again; it doubles on each refusal, up to [`SCOPE_PAUSE_MAX`].
const SCOPE_PAUSE: Duration = Duration::from_secs(2);

/// The longest pause between two asks for one namespace.
const SCOPE_PAUSE_MAX: Duration = Duration::from_secs(64);

/// The most namespaces the host adopts at once for this device: a record
/// listing many writers, or unreachable ones, costs at most this many
/// adoptions in flight (each bounded by the walk's limits), the others
/// waiting their turn.
pub(super) const SCOPE_ASKS: usize = 4;

/// The most persons' namespaces one subject's record adopts here: its
/// writer prefixes, then its cuts' prefixes, in the record's order. The
/// rest are not adopted for it, and its watchers are told
/// ([`Change::NotAdopted`](crate::Change::NotAdopted)).
pub(super) const SCOPE_PER_SUBJECT: usize = 64;

/// The most persons' namespaces listed here for all subjects together,
/// counted whether or not the node holds them; subjects are served in name
/// order (a collection before a folder of the same name), so the cap falls
/// the same way whatever order their records came in.
pub(super) const SCOPE_NAMESPACES: usize = 256;

/// Where the store keeps the newest version of each person's namespace
/// adopted here for a folder (`/localhost/ndn-data/scoped/<namespace>`: the
/// version, 8 octets big-endian, and the SHA-256 of the context's content,
/// 32 octets; then, when the host gave it, the genesis's signed Data, its
/// length first in 4 octets big-endian, and the newest version's signed
/// Data — none past version 1, which is the genesis). An older version, or
/// that version with other content, is never adopted again; with the
/// signed Data, the version is judged by again after a restart and
/// refreshed from by continuity (spec §6.3).
pub(super) fn scoped_prefix() -> Name {
    "/localhost/ndn-data/scoped".parse().expect("a valid name")
}

/// The newest version adopted of a namespace, and its content's digest.
pub(super) type Reached = (u64, [u8; 32]);

/// What the store keeps of `ctx` ([`scoped_prefix`]).
fn encode_kept(ctx: &ScopedContext) -> Bytes {
    let (version, digest) = reached_of(ctx.context());
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&digest);
    if let Some(newest) = ctx.data() {
        let genesis = ctx.genesis().data().raw();
        out.extend_from_slice(&(genesis.len() as u32).to_be_bytes());
        out.extend_from_slice(genesis);
        if version != 1 {
            out.extend_from_slice(newest);
        }
    }
    Bytes::from(out)
}

/// The version and digest of a [`scoped_prefix`] record.
pub(super) fn decode_reached(value: &[u8]) -> Option<Reached> {
    let version = u64::from_be_bytes(value.get(..8)?.try_into().ok()?);
    Some((version, value.get(8..40)?.try_into().ok()?))
}

/// The context a [`scoped_prefix`] record keeps, opened again: its genesis
/// checked as stored ([`Genesis::open_stored`]: signature and genesis
/// rule, no clock), the newest version's signature checked, both of `ns`,
/// and the version and digest the record names.
async fn open_kept(ns: &Name, value: &Bytes) -> Result<ScopedContext, String> {
    let reached = decode_reached(value).ok_or("a malformed record")?;
    let rest = value.slice(40..);
    let len = rest
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or("only its version number was kept (the host gave no signed Data)")?
        as usize;
    if rest.len() < 4 + len {
        return Err("a malformed record".into());
    }
    let genesis = Data::decode(rest.slice(4..4 + len)).map_err(|e| format!("{e:?}"))?;
    let genesis = Genesis::open_stored(&genesis)
        .await
        .map_err(|e| e.to_string())?;
    if genesis.namespace() != ns {
        return Err(format!("its genesis is of {}", genesis.namespace()));
    }
    let ctx = match reached.0 {
        1 => {
            let v1 = Arc::clone(genesis.context());
            ScopedContext::new(genesis, v1).map_err(|e| e.to_string())?
        }
        _ => {
            let newest = Data::decode(rest.slice(4 + len..)).map_err(|e| format!("{e:?}"))?;
            let (opened, _) = SignedTrustContext::open_signed(&newest)
                .await
                .map_err(|e| e.to_string())?;
            ScopedContext::new(genesis, Arc::new(opened))
                .and_then(|c| c.with_data(&newest))
                .map_err(|e| e.to_string())?
        }
    };
    if reached_of(ctx.context()) != reached {
        return Err("its signed Data is not the version it names".into());
    }
    Ok(ctx)
}

/// `ctx`'s version and the digest of its content.
fn reached_of(ctx: &SignedTrustContext) -> Reached {
    (ctx.version(), Sha256::digest(ctx.encode_content()).into())
}

/// What a packet is about, for the scope that judges it: its subject (the
/// collection of a log entry, a head or a piece; the node of a summary; the
/// scope of a signal run header) and whether, as a summary node, it may
/// also lie on the way to a scope.
pub(super) struct About {
    subject: Name,
    toward: bool,
}

/// What the packet named `name` is about, if it is a packet a scope may
/// judge: a log entry of a collection (its pieces, its block entries), a
/// one-key head, a summary root, node or page, or a signal run header of a
/// folder or collection (spec §20). Nothing else — a snapshot, a seal key,
/// a grant — is about a folder.
pub(super) fn about(name: &Name) -> Option<About> {
    let of_entry = |entry: &Name| {
        parse_log_name(entry)?.subject.map(|subject| About {
            subject,
            toward: false,
        })
    };
    if let Some(run) = parse_signal_run_name(name) {
        return Some(About {
            subject: run.scope,
            toward: false,
        });
    }
    if let Some(s) = parse_summary_name(name) {
        return Some(About {
            subject: s.subject,
            toward: true,
        });
    }
    if let Some((_, collection, _)) = parse_head_name(name) {
        return Some(About {
            subject: collection,
            toward: false,
        });
    }
    if let Some(a) = of_entry(name) {
        return Some(a);
    }
    if let Some(p) = parse_piece_name(name) {
        return of_entry(&p.version);
    }
    parse_entry_name(name).and_then(|(version, _)| of_entry(&version))
}

/// A person's namespace a record in force lists, as adopted here.
enum Adopted {
    /// The host is adopting it.
    Asking,
    /// Adopted: the context, and the view of the device's validator that
    /// judges by it.
    Held {
        ctx: ScopedContext,
        judge: Arc<Validator>,
    },
    /// The host could not adopt it (it said why, logged): when to ask
    /// again, and the pause that led there.
    Refused { again: Instant, pause: Duration },
}

/// What one subject's own record in force lists of persons' namespaces —
/// writer prefixes, then cuts' prefixes, each once — in the record's order.
struct Lists {
    /// The first [`SCOPE_PER_SUBJECT`]: those it may adopt.
    first: Vec<Name>,
    /// The rest: never adopted for it.
    rest: Vec<Name>,
}

/// Persons' namespaces a subject's record lists that are not adopted for
/// it, past [`SCOPE_PER_SUBJECT`] or [`SCOPE_NAMESPACES`] (spec §6.3).
pub(super) struct Excess {
    pub(super) subject: Subject,
    pub(super) namespaces: Vec<Name>,
    /// Why, and what to do.
    pub(super) why: String,
}

/// The persons' namespaces the records in force list, and what is adopted
/// of them (spec §6.3).
#[derive(Default)]
pub(super) struct Scopes {
    /// Per subject — a folder or a collection, by name and kind: a folder
    /// and a collection may share a name, and each has its own record —
    /// what its own record in force lists.
    wants: BTreeMap<Subject, Lists>,
    /// Per person's namespace, the subjects it is listed for within
    /// [`SCOPE_PER_SUBJECT`] and [`SCOPE_NAMESPACES`]: only these are
    /// adopted, and judged for.
    listed: BTreeMap<Name, BTreeSet<Subject>>,
    /// Per subject, what its record lists past the caps, as last told.
    over: BTreeMap<Subject, Vec<Name>>,
    adopted: HashMap<Name, Adopted>,
    /// Held namespaces a new record listed since their last adoption: they
    /// are refreshed (by continuity from the version held).
    stale: BTreeSet<Name>,
    /// Held namespaces being refreshed (judging goes on with what is held).
    refreshing: BTreeSet<Name>,
    /// When each adopted namespace was last asked to refresh for a new
    /// record ([`Self::asks_due`]): a burst of records refreshes it once per
    /// [`REFRESH_PAUSE_MAX`], not once per record.
    refreshed: HashMap<Name, Instant>,
    /// The pause before a namespace whose refresh failed is refreshed again
    /// (a restored one whose devices are away): doubling from twice
    /// [`REFRESH_PAUSE_MAX`] up to [`SCOPE_PAUSE_MAX`]; gone once one
    /// succeeds.
    refresh_pause: HashMap<Name, Duration>,
    /// Whether a wake for a deferred refresh is pending (one at a time).
    waking: bool,
    /// Per namespace, the newest version adopted here and its content's
    /// digest, kept in the store ([`scoped_prefix`]) and never gone back
    /// from: released and adopted again, or after a restart, an older
    /// version is refused.
    newest: HashMap<Name, Reached>,
    /// The store's records read back at start, to open again
    /// ([`Inner::restore_scoped`]).
    kept: Vec<(Name, Bytes)>,
}

impl Scopes {
    /// The subject `s`'s own record in force is now `own` (`None`: it has
    /// none): note the persons' namespaces it lists, by its writer prefixes
    /// and the prefixes of its cuts, within [`SCOPE_PER_SUBJECT`] for it and
    /// [`SCOPE_NAMESPACES`] in all. A namespace it lists that is adopted
    /// already is refreshed: a new record is where a writer's newer version
    /// (a recovery, a revocation) is looked for. Returns the subjects whose
    /// namespaces past the caps changed, and are not none: to be told.
    pub(super) fn note(&mut self, s: &Subject, own: Option<&Members>) -> Vec<Excess> {
        self.wants.remove(s);
        if let Some(m) = own {
            let mut seen = HashSet::new();
            let (mut first, mut rest) = (Vec::new(), Vec::new());
            let prefixes = m.writers.iter().chain(m.cuts.iter().map(|c| &c.of));
            for ns in prefixes.filter_map(personal_namespace_of) {
                if !seen.insert(ns.clone()) {
                    continue;
                }
                match first.len() < SCOPE_PER_SUBJECT {
                    true => first.push(ns),
                    false => rest.push(ns),
                }
            }
            if !first.is_empty() {
                self.wants.insert(s.clone(), Lists { first, rest });
            }
        }
        // Listed again from every subject's record, in subject order, so
        // that the caps fall the same way whatever order records came in.
        let mut listed: BTreeMap<Name, BTreeSet<Subject>> = BTreeMap::new();
        let mut past: BTreeMap<Subject, (usize, Vec<Name>)> = BTreeMap::new();
        for (subject, lists) in &self.wants {
            for ns in &lists.first {
                if listed.contains_key(ns) || listed.len() < SCOPE_NAMESPACES {
                    listed
                        .entry(ns.clone())
                        .or_default()
                        .insert(subject.clone());
                } else {
                    let p = past.entry(subject.clone()).or_default();
                    p.0 += 1;
                    p.1.push(ns.clone());
                }
            }
            if !lists.rest.is_empty() {
                past.entry(subject.clone())
                    .or_default()
                    .1
                    .extend(lists.rest.iter().cloned());
            }
        }
        for ns in listed
            .iter()
            .filter(|(_, ss)| ss.contains(s))
            .map(|(ns, _)| ns)
        {
            if matches!(self.adopted.get(ns), Some(Adopted::Held { .. })) {
                self.stale.insert(ns.clone());
            }
        }
        self.listed = listed;
        let mut told = Vec::new();
        let mut over = BTreeMap::new();
        for (subject, (device_wide, names)) in past {
            if self.over.get(&subject) != Some(&names) {
                let why = excess_why(&subject, names.len() - device_wide, device_wide);
                told.push(Excess {
                    subject: subject.clone(),
                    namespaces: names.clone(),
                    why,
                });
            }
            over.insert(subject, names);
        }
        self.over = over;
        told
    }

    /// Whether `ns` is adopted here for a folder (a context of it is held
    /// for the records that list it).
    pub(super) fn adopted(&self, ns: &Name) -> bool {
        matches!(self.adopted.get(ns), Some(Adopted::Held { .. }))
    }

    /// The store's [`scoped_prefix`] records read back at start: their
    /// newest versions are never gone back from, and their contexts are
    /// opened again ([`Inner::restore_scoped`]).
    pub(super) fn restore_newest(&mut self, kept: Vec<(Name, Bytes)>) {
        for (ns, value) in kept {
            if let Some(reached) = decode_reached(&value) {
                self.newest.insert(ns.clone(), reached);
                self.kept.push((ns, value));
            }
        }
    }

    /// Why `ctx` may not be adopted for `ns`: it is older than the newest
    /// version adopted here before, or that version with other content.
    fn behind(&self, ns: &Name, ctx: &SignedTrustContext) -> Option<String> {
        let &(version, digest) = self.newest.get(ns)?;
        let (offered, got) = reached_of(ctx);
        if offered < version {
            return Some(format!(
                "this device adopted version {version} of {ns}'s trust context before, and the \
                 host reached version {offered} only: an older version would trust again what a \
                 later one revoked, so it is not adopted (spec §6.3); reach a device or relay that \
                 serves version {version} of {ns} or newer"
            ));
        }
        if offered == version && got != digest {
            return Some(format!(
                "the host reached a version {version} of {ns}'s trust context other than the one \
                 this device adopted before (two versions of one number: a fork), so it is not \
                 adopted (spec §6.3); reach a device or relay that serves the version {ns}'s \
                 owner signed"
            ));
        }
        None
    }

    /// `ctx` was adopted for `ns`: the newest version moves on to it, and
    /// what the store keeps of it now — with its signed Data, when the host
    /// gave that; nothing new when it gave none for the version kept.
    fn reached(&mut self, ns: &Name, ctx: &ScopedContext) -> Option<Bytes> {
        let now = reached_of(ctx.context());
        let moved = self.newest.get(ns).is_none_or(|before| before.0 < now.0);
        if moved {
            self.newest.insert(ns.clone(), now);
        }
        (moved || ctx.data().is_some()).then(|| encode_kept(ctx))
    }

    /// The view judging a packet of `ns`, a person's namespace no context
    /// held covers, about `subject`: the scoped one when a record in force
    /// lists `ns` for a subject the packet lies in — or, `toward` (a
    /// summary node), lies on the way to — and `ns` is adopted; else `None`
    /// (the device's own validator, which refuses it).
    fn judge(&self, ns: &Name, subject: &Name, toward: bool) -> Option<Arc<Validator>> {
        let inside = self
            .listed
            .get(ns)?
            .iter()
            .any(|s| subject.has_prefix(&s.name) || (toward && s.name.has_prefix(subject)));
        match self.adopted.get(ns) {
            Some(Adopted::Held { judge, .. }) if inside => Some(Arc::clone(judge)),
            _ => None,
        }
    }

    /// What to ask the host for now: each namespace listed that the node
    /// does not hold (`held`), not adopted, not being adopted and past its
    /// pause — and each adopted one a new record listed, at most once per
    /// [`REFRESH_PAUSE_MAX`] — while fewer than [`SCOPE_ASKS`] adoptions
    /// are in flight; each with the version held, to refresh from. Marks
    /// them in flight. Also when to look again for a refresh deferred by
    /// that pause, unless a wake is pending already.
    fn asks_due(
        &mut self,
        held: impl Fn(&Name) -> bool,
        now: Instant,
    ) -> (Vec<(Name, Option<ScopedContext>)>, Option<Instant>) {
        let mut flying = self.refreshing.len()
            + self
                .adopted
                .values()
                .filter(|a| matches!(a, Adopted::Asking))
                .count();
        let mut out = Vec::new();
        let mut wake: Option<Instant> = None;
        for ns in self.listed.keys() {
            if flying >= SCOPE_ASKS {
                break;
            }
            if held(ns) {
                continue;
            }
            let ask = match self.adopted.get(ns) {
                None => Some(None),
                Some(Adopted::Refused { again, .. }) if *again <= now => Some(None),
                Some(Adopted::Held { ctx, .. })
                    if self.stale.contains(ns) && !self.refreshing.contains(ns) =>
                {
                    match self
                        .refreshed
                        .get(ns)
                        .map(|t| {
                            *t + self
                                .refresh_pause
                                .get(ns)
                                .copied()
                                .unwrap_or(REFRESH_PAUSE_MAX)
                        })
                        .filter(|at| now < *at)
                    {
                        Some(at) => {
                            wake = Some(wake.map_or(at, |w| w.min(at)));
                            None
                        }
                        None => Some(Some(ctx.clone())),
                    }
                }
                _ => None,
            };
            let Some(from) = ask else {
                continue;
            };
            flying += 1;
            out.push((ns.clone(), from));
        }
        for (ns, from) in &out {
            match from {
                Some(_) => {
                    self.stale.remove(ns);
                    self.refreshing.insert(ns.clone());
                    self.refreshed.insert(ns.clone(), now);
                }
                None => {
                    self.adopted.insert(ns.clone(), Adopted::Asking);
                }
            }
        }
        let wake = wake.filter(|_| !self.waking);
        if wake.is_some() {
            self.waking = true;
        }
        (out, wake)
    }

    /// The adopted namespaces no record in force lists any more, or that
    /// the node now holds (its held context judges them from now on):
    /// dropped here, for the host to release.
    fn release_unlisted(&mut self, held: impl Fn(&Name) -> bool) -> Vec<Name> {
        let gone: Vec<Name> = self
            .adopted
            .iter()
            .filter(|(ns, a)| {
                matches!(a, Adopted::Held { .. }) && (!self.listed.contains_key(*ns) || held(ns))
            })
            .map(|(ns, _)| ns.clone())
            .collect();
        for ns in &gone {
            self.adopted.remove(ns);
            self.stale.remove(ns);
            self.refreshed.remove(ns);
            self.refresh_pause.remove(ns);
        }
        // A refusal no record calls for any more is forgotten.
        let listed = &self.listed;
        self.adopted
            .retain(|ns, a| !matches!(a, Adopted::Refused { .. }) || listed.contains_key(ns));
        self.refreshed.retain(|ns, _| listed.contains_key(ns));
        self.refresh_pause.retain(|ns, _| listed.contains_key(ns));
        gone
    }
}

/// Why `s`'s record has namespaces not adopted for it: `per_subject` past
/// [`SCOPE_PER_SUBJECT`], `device_wide` past [`SCOPE_NAMESPACES`].
fn excess_why(s: &Subject, per_subject: usize, device_wide: usize) -> String {
    let kind = if s.folder { "folder" } else { "collection" };
    let name = &s.name;
    let mut why = Vec::new();
    if per_subject > 0 {
        why.push(format!(
            "{per_subject} past the first {SCOPE_PER_SUBJECT} its record lists, the most one \
             folder or collection adopts"
        ));
    }
    if device_wide > 0 {
        why.push(format!(
            "{device_wide} past the {SCOPE_NAMESPACES} persons' namespaces this device adopts \
             for all folders together"
        ));
    }
    format!(
        "the members record of {kind} {name} lists too many writers' namespaces to adopt here \
         (spec §6.3): {}; their versions in {name} are refused while not adopted. The owner \
         lists too many writers: have it list fewer, or adopt those namespaces on this device's \
         node (an anchor link naming them)",
        why.join(", and ")
    )
}

impl Inner {
    /// The validator that judges the packet named `name`: for a packet of a
    /// person's namespace the node does not hold, about a subject a record
    /// in force lists that namespace for, the view adopted for it (spec
    /// §6.3); else the device's own, which judges every other packet — and
    /// refuses that namespace's packets about anything else.
    pub(super) fn judge(&self, name: &Name) -> Arc<Validator> {
        let scoped = self
            .validator
            .keyring()
            .unheld_personal_namespace(name)
            .and_then(|ns| Some((ns, about(name)?)))
            .and_then(|(ns, about)| {
                self.st
                    .lock()
                    .scopes
                    .judge(&ns, &about.subject, about.toward)
            });
        scoped.unwrap_or_else(|| Arc::clone(&self.validator))
    }

    /// The validator that judges key `key`'s packets about `scope`, read
    /// from `st` (held by the caller): what [`Self::judge`] picks for a
    /// packet of `key`'s device about `scope` (spec §20: whether a signal
    /// sender's key is revoked is asked of it).
    pub(super) fn judge_signer(&self, st: &St, key: &Name, scope: &Name) -> Arc<Validator> {
        let scoped = self
            .validator
            .keyring()
            .unheld_personal_namespace(key)
            .and_then(|ns| st.scopes.judge(&ns, scope, false));
        scoped.unwrap_or_else(|| Arc::clone(&self.validator))
    }

    /// At start, after the records are read back: each namespace a record
    /// in force lists, which the node does not hold, is held again at the
    /// version kept in the store ([`scoped_prefix`]) — judging at once, and
    /// refreshed from by continuity (the host carrying it again in transit
    /// as the refresh succeeds), never walked to from the genesis again, so
    /// a branch that does not descend from it is refused (spec §6.3). A
    /// record that cannot be opened is reported, and that namespace adopted
    /// from its genesis, no older than the version it names.
    pub(super) async fn restore_scoped(self: &Arc<Self>) {
        let keyring = self.validator.keyring();
        let kept: Vec<(Name, Bytes)> = {
            let mut st = self.st.lock();
            let kept = std::mem::take(&mut st.scopes.kept);
            kept.into_iter()
                .filter(|(ns, _)| {
                    st.scopes.listed.contains_key(ns) && keyring.held_for(ns).is_none()
                })
                .collect()
        };
        let mut restored = Vec::new();
        for (ns, value) in kept {
            match open_kept(&ns, &value).await {
                Ok(ctx) => {
                    tracing::info!(me = %self.device, %ns, version = ctx.context().version(), "held again at the version kept, for the folders that list it as a writer; refreshed from it");
                    let judge = Arc::new(self.validator.scoped_view(&ctx));
                    let mut st = self.st.lock();
                    st.scopes
                        .adopted
                        .insert(ns.clone(), Adopted::Held { ctx, judge });
                    st.scopes.stale.insert(ns.clone());
                    restored.push(ns);
                }
                Err(why) => {
                    tracing::warn!(me = %self.device, %ns, "the version kept of it cannot be held again ({why}): it is adopted from its genesis, and no version older than the one kept is taken");
                }
            }
        }
        for ns in restored {
            self.adopted_scoped(&ns, Some(false)).await;
        }
    }

    /// Ask the host to adopt, for their scopes, the persons' namespaces the
    /// records in force list that the node does not hold (and to refresh
    /// those a new record listed), and to release those nothing lists any
    /// more (spec §6.3). Without a host that adopts, they are not adopted,
    /// and the records' versions of those writers wait, refused here.
    pub(super) fn scope_writers(self: &Arc<Self>) {
        let keyring = self.validator.keyring();
        let held = |ns: &Name| keyring.held_for(ns).is_some();
        let (asks, released, wake) = {
            let mut st = self.st.lock();
            let released = st.scopes.release_unlisted(held);
            let (asks, wake) = st.scopes.asks_due(held, Instant::now());
            (asks, released, wake)
        };
        if let Some(at) = wake {
            // A refresh a burst of records deferred: asked once its pause
            // ends, the namespace still stale meanwhile.
            let inner = Arc::clone(self);
            rt::spawn(async move {
                rt::sleep(at.saturating_duration_since(Instant::now())).await;
                inner.st.lock().scopes.waking = false;
                inner.scope_writers();
            });
        }
        if asks.is_empty() && released.is_empty() {
            return;
        }
        let Some(host) = self.config.introducer.clone() else {
            for (ns, from) in asks {
                self.scoped(
                    &ns,
                    from,
                    Err(format!(
                        "a members record lists {ns} as a writer, and this device has no host \
                         to adopt it for the folder (Config::introducer): configure one and \
                         start the device again, or adopt {ns} on its node"
                    )),
                );
            }
            return;
        };
        for ns in released {
            tracing::info!(me = %self.device, %ns, "no members record lists it any more, or the node holds it: released");
            host.release_scoped(&ns);
        }
        for (ns, from) in asks {
            let inner = Arc::clone(self);
            let host = Arc::clone(&host);
            rt::spawn(async move {
                let got = host.adopt_scoped(&ns, from.as_ref()).await;
                let refuses = inner.scoped(&ns, from, got);
                inner.adopted_scoped(&ns, refuses).await;
            });
        }
    }

    /// Take the host's answer for `ns`, adopted from `from` (the version
    /// held, for a refresh): whether the version now held may refuse more
    /// than the one before it, if one is held now. A refusal keeps a
    /// version held before (judging goes on with it) and is asked again
    /// after a pause. A version older than the newest adopted here before
    /// (kept across restarts), or that version with other content, is
    /// refused; the newest adopted is kept in the store.
    fn scoped(
        self: &Arc<Self>,
        ns: &Name,
        from: Option<ScopedContext>,
        got: Result<ScopedContext, String>,
    ) -> Option<bool> {
        let mut st = self.st.lock();
        st.scopes.refreshing.remove(ns);
        let listed = st.scopes.listed.contains_key(ns);
        // A fresh adoption the host made and this device refuses: the
        // host's carrying of it is released.
        let mut release = false;
        let got = match got {
            Ok(ctx) if listed => match st.scopes.behind(ns, ctx.context()) {
                Some(why) => {
                    release = from.is_none();
                    Err(why)
                }
                None => Ok(ctx),
            },
            other => other,
        };
        match got {
            Ok(ctx) if listed => {
                let refuses = refuses_more(from.as_ref().map(|f| &**f.context()), ctx.context());
                tracing::info!(me = %self.device, %ns, version = ctx.context().version(), "adopted by name for judging the data of the folders that list it as a writer");
                if let Some(kept) = st.scopes.reached(ns, &ctx) {
                    self.store.insert(under(&scoped_prefix(), ns), kept);
                }
                st.scopes.refresh_pause.remove(ns);
                let judge = Arc::new(self.validator.scoped_view(&ctx));
                st.scopes
                    .adopted
                    .insert(ns.clone(), Adopted::Held { ctx, judge });
                Some(refuses)
            }
            // Adopted after the last record listing it went: released.
            Ok(_) => {
                st.scopes.adopted.remove(ns);
                drop(st);
                if let Some(host) = &self.config.introducer {
                    host.release_scoped(ns);
                }
                None
            }
            Err(why) => {
                if from.is_some() {
                    // A refresh that failed: the version held still judges,
                    // and is refreshed again after a growing pause.
                    let pause = st
                        .scopes
                        .refresh_pause
                        .get(ns)
                        .copied()
                        .unwrap_or(REFRESH_PAUSE_MAX)
                        .saturating_mul(2)
                        .min(SCOPE_PAUSE_MAX);
                    st.scopes.refresh_pause.insert(ns.clone(), pause);
                    tracing::info!(me = %self.device, %ns, "not refreshed: {why}; the version held judges meanwhile, and it is refreshed again in {pause:?}");
                    st.scopes.stale.insert(ns.clone());
                    return None;
                }
                let pause = match st.scopes.adopted.get(ns) {
                    Some(Adopted::Refused { pause, .. }) => (*pause * 2).min(SCOPE_PAUSE_MAX),
                    _ => SCOPE_PAUSE,
                };
                tracing::warn!(me = %self.device, %ns, "a members record lists it as a writer, and it is not adopted for the folder: {why}; its versions there wait, and it is asked again in {pause:?}");
                st.scopes.adopted.insert(
                    ns.clone(),
                    Adopted::Refused {
                        again: Instant::now() + pause,
                        pause,
                    },
                );
                drop(st);
                if release && let Some(host) = &self.config.introducer {
                    host.release_scoped(ns);
                }
                let inner = Arc::clone(self);
                rt::spawn(async move {
                    rt::sleep(pause).await;
                    inner.scope_writers();
                });
                None
            }
        }
    }

    /// Once `ns` is adopted for its scopes (`refuses`: whether the version
    /// may refuse more than the one before), what is held of it is judged
    /// again, and the summaries of every namespace whose subjects list it
    /// are refreshed, so what was refused for want of it is fetched again.
    /// Its group is joined, and announced into, when this device publishes
    /// about a subject listing it (one of its own namespace, or one it wrote
    /// into): only now is it a group a change is published into (spec §12).
    /// Then the next namespaces waiting are asked for.
    async fn adopted_scoped(self: &Arc<Self>, ns: &Name, refuses: Option<bool>) {
        if let Some(refuses) = refuses {
            self.rejudge(match refuses {
                true => Rejudge::Namespace(ns.clone()),
                false => Rejudge::Withdrawn(None),
            })
            .await;
            let (owners, joins) = {
                let st = self.st.lock();
                let subjects: Vec<&Subject> =
                    st.scopes.listed.get(ns).into_iter().flatten().collect();
                let owners: BTreeSet<Name> = subjects
                    .iter()
                    .filter_map(|s| namespace_of(&s.name))
                    .collect();
                let joins = !st.groups.contains_key(ns)
                    && st.scopes.adopted(ns)
                    && subjects.iter().any(|s| {
                        namespace_of(&s.name).as_ref() == Some(&self.ns)
                            || st.colls.iter().any(|(c, x)| {
                                c.has_prefix(&s.name) && x.entries.contains_key(&self.writer)
                            })
                    });
                (owners, joins)
            };
            for o in owners {
                self.refresh_group(&o);
            }
            if joins {
                match self.join(ns).await {
                    Ok(()) => self.publish(ns),
                    Err(e) => {
                        tracing::debug!(me = %self.device, %ns, "the group of a writer adopted for a folder is not joined: {e}")
                    }
                }
            }
        }
        // Roots refused unasked for want of it are judged now: owed.
        self.owe_unjudged_roots();
        self.scope_writers();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_tests.rs"]
mod tests;
