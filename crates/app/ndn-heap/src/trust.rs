//! The validator bridge and the adoption of persons per space (spec §9).
//!
//! [`Judge::validate`] is the one place an entry's signature is checked: it
//! runs the durable rule of [`ndn_security::Validator`] (certificate chain to
//! the trust anchors of the context that governs the name, no clock except
//! where a role needs a cut) and says, for the log, who signed it and by what
//! key, or why it is refused, or what it waits for. A verdict is data the
//! log keeps; this module keeps no verdict.
//!
//! A person's namespace (`/user/<0xA1: …>`) this node does not hold is judged
//! only by that person's own trust context, which a host adopts *for a space*:
//! every self-certifying person a space's members list, up to
//! [`SCOPE_PER_SPACE`] for one space and [`SCOPE_NAMESPACES`] in all, is
//! adopted through the [`Adopter`] and judges, through a view of the node's
//! validator ([`Validator::scoped_view`]) that no other path sees, exactly the
//! packets about the spaces that list her. The adoption goes into no keyring
//! the node judges by. The newest version adopted of each person is kept in
//! the store, signed: after a restart it judges again at once and is
//! refreshed from by continuity, never walked to from the genesis again, and
//! no older version is adopted.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::cert_name::key_name_of;
use ndn_security::safe_data::TrustPath;
use ndn_security::self_certifying::{Genesis, in_personal_namespace, personal_namespace_of};
use ndn_security::{
    SafeData, ScopedContext, SignedTrustContext, TrustError, ValidationResult, Validator,
};
use ndn_sync::DataStore;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::error::{Cut, Refusal, Timestamp};
use crate::rt::{self, Instant};
use crate::store::Kind;
use crate::wire::{device_of, log_prefix};

/// The first pause before a person the host could not adopt is asked again;
/// it doubles on each refusal, up to [`SCOPE_PAUSE_MAX`].
const SCOPE_PAUSE: Duration = Duration::from_secs(2);

/// The longest pause between two asks for one person.
const SCOPE_PAUSE_MAX: Duration = Duration::from_secs(64);

/// The most adoptions in flight at once: a space listing many persons, or
/// unreachable ones, costs at most this many asks of the host at a time (each
/// bounded by the walk's own limits), the others waiting their turn.
const SCOPE_ASKS: usize = 4;

/// The most persons one space adopts here: its writers, then its readers,
/// then those kept only by a cut, in the order the listing gives. The rest are
/// not adopted for it, and [`Judge::note`] warns of them.
pub(crate) const SCOPE_PER_SPACE: usize = 64;

/// The most persons listed here for all spaces together, whether or not the
/// node holds them; spaces are served in name order, so the cap falls the same
/// way whatever order their listings came in.
pub(crate) const SCOPE_NAMESPACES: usize = 256;

// ---- the host's side ---------------------------------------------------------------------------

/// The future of an [`Adopter::adopt_scoped`].
#[cfg(not(target_arch = "wasm32"))]
pub type Scoping<'a> = futures::future::BoxFuture<'a, Result<ScopedContext, String>>;
/// The future of an [`Adopter::adopt_scoped`].
#[cfg(target_arch = "wasm32")]
pub type Scoping<'a> = futures::future::LocalBoxFuture<'a, Result<ScopedContext, String>>;

/// What the host does so that a space can judge the persons its members list:
/// adopt a person's trust context by name, for this node's data layer alone.
pub trait Adopter: Send + Sync {
    /// Adopt the self-certifying person `namespace` for the spaces that list
    /// her: fetch her genesis (version 1, checked as the genesis her name
    /// hashes) and reach her newest version from it, or, when `held` is the
    /// version this node already judges her by, from that version by
    /// continuity. The result judges nothing by itself: the layer judges her
    /// packets through a view of its validator.
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a>;

    /// No space lists `namespace` any more (or the node holds her context
    /// itself): the host stops carrying what it kept for her. It must neither
    /// block nor call back into the layer.
    fn release_scoped(&self, namespace: &Name);
}

// ---- verdicts ----------------------------------------------------------------------------------

/// What a packet's judgement waits for: the same packet, judged again when it
/// is held, is decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Waiting {
    /// The person's trust context, which this node does not hold and no
    /// listed space has had adopted yet.
    Adoption(Name),
    /// A certificate or a cut manifest of the signer's chain that could not be
    /// had now.
    Chain,
}

impl fmt::Display for Waiting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Waiting::Adoption(person) => write!(
                f,
                "it waits for the trust context of {person}, which this node does not hold: it \
                 is judged once a space whose members list {person} has had it adopted (the \
                 host adopts it by name), or once this node adopts {person} itself"
            ),
            Waiting::Chain => f.write_str(
                "it waits for a certificate or a cut manifest of its signer's chain, which \
                 nobody answered yet: it is judged again when that arrives",
            ),
        }
    }
}

/// A packet that verified: who signed it, and by which key. The packet itself
/// is the caller's (it passed it in); nothing here borrows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    /// The key that signed it, `<device>/KEY/<id>`.
    pub key: Name,
    /// The device the key belongs to, `<device>`.
    pub device: Name,
    /// The device's person: the namespace of the trust context that vouched
    /// for the key (the self-certifying namespace of an adopted person).
    pub person: Name,
    /// The digest of the public key that verified the signature, as its
    /// certificate stores it: one verification, so a cut can bind to it.
    pub key_digest: [u8; 32],
}

/// The verdict on one packet.
#[derive(Debug)]
pub(crate) enum Judged {
    /// It verifies.
    Valid(Verified),
    /// It is refused, for the reason given.
    Refused(Refusal),
    /// It is neither: the judgement waits.
    Pending(Waiting),
}

// ---- what the members list ---------------------------------------------------------------------

/// The persons one space's members entries list, in the order the caps fall.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    /// Persons that may write.
    pub writers: Vec<Name>,
    /// Persons that may read.
    pub readers: Vec<Name>,
    /// Persons removed whose entries up to a removal tip still count: their
    /// context judges those entries, and nothing else of theirs.
    pub cut: Vec<Name>,
}

/// What the log re-checks on: a trust context the keyring adopted, or a
/// person adopted for spaces. Delivered in order by [`Judge::adoptions`].
#[derive(Clone, Debug)]
pub(crate) enum Adoption {
    /// The keyring adopted this context (a new namespace, or a newer version).
    Context(Arc<SignedTrustContext>),
    /// A person was adopted (or restored, or refreshed) for these spaces.
    Person {
        /// Her namespace.
        person: Name,
        /// The spaces that list her now.
        spaces: Vec<Name>,
        /// Whether the version may refuse more than the one before it (a
        /// first adoption does): the entries held of her are judged again
        /// to withdraw what it refuses; when it may not, only what waited for
        /// her is.
        refuses: bool,
    },
}

/// Whether `name` is a person: a self-certifying namespace `/user/<0xA1: …>`
/// itself, not a name below one.
fn is_person(name: &Name) -> bool {
    in_personal_namespace(name) && name.len() == 2
}

// ---- adoption state ----------------------------------------------------------------------------

/// A person's namespace listed for adoption, as adopted here.
#[derive(Default)]
struct Person {
    /// Adopted: the context, and the view of the node's validator that
    /// judges by it.
    held: Option<(ScopedContext, Arc<Validator>)>,
    /// The host is adopting her, or refreshing the version held (judging goes
    /// on with that meanwhile).
    asking: bool,
    /// Held, and a new listing named her since: to be refreshed (by
    /// continuity from the version held).
    stale: bool,
    /// After a failed ask: when to try again, and the pause that led there.
    retry: Option<(Instant, Duration)>,
}

/// What one space's listing names, once capped.
#[derive(Debug, PartialEq, Eq)]
struct Lists {
    /// The first [`SCOPE_PER_SPACE`]: those it may adopt.
    first: Vec<Name>,
    /// The rest: never adopted for it.
    rest: usize,
    /// Of both, those that write or read (not only kept by a cut).
    members: HashSet<Name>,
}

/// The newest version adopted of a person, and its content's digest.
type Reached = (u64, [u8; 32]);

/// The persons the listings name, and what is adopted of them.
#[derive(Default)]
struct Scopes {
    /// Per space, what its own listing names.
    wants: BTreeMap<Name, Lists>,
    /// Per person, the spaces she is listed for within the caps: only these
    /// are adopted, and judged for.
    listed: BTreeMap<Name, BTreeSet<Name>>,
    /// How many persons the listings name past the caps, as last warned of.
    over: usize,
    adopted: HashMap<Name, Person>,
    /// Whether a wake for a deferred ask is pending (one at a time).
    waking: bool,
    /// Whether the records kept in the store were opened again (or there are
    /// none): no ask goes to the host before, or it would walk to a person
    /// from her genesis whose newest version is on record.
    ready: bool,
    /// Per person, the newest version adopted here and its content's digest,
    /// kept in the store ([`Kind::SCOPED`]) and never gone back from: released
    /// and adopted again, or after a restart, an older version is refused.
    newest: HashMap<Name, Reached>,
    /// The store's records read back at start, to open again
    /// ([`Judge::restore`]).
    kept: Vec<(Name, Bytes)>,
}

impl Scopes {
    /// The space `space`'s listing is now `listing`: note the persons it
    /// names, within [`SCOPE_PER_SPACE`] for it and [`SCOPE_NAMESPACES`] in
    /// all. A person it names that is adopted already is refreshed: a changed
    /// listing is where a person's newer version (a recovery, a revocation) is
    /// looked for. Returns the warning to give when the number of persons
    /// left out by the caps changed.
    fn note(&mut self, space: &Name, listing: &Listing) -> Option<String> {
        let mut seen = HashSet::new();
        let mut named = listing
            .writers
            .iter()
            .chain(&listing.readers)
            .chain(&listing.cut)
            .filter(|p| is_person(p) && seen.insert(*p));
        let first: Vec<Name> = named.by_ref().take(SCOPE_PER_SPACE).cloned().collect();
        let rest = named.count();
        let members: HashSet<Name> = listing
            .writers
            .iter()
            .chain(&listing.readers)
            .filter(|p| is_person(p))
            .cloned()
            .collect();
        let new = (!first.is_empty()).then_some(Lists {
            first,
            rest,
            members,
        });
        if self.wants.get(space) == new.as_ref() {
            return None;
        }
        self.wants.remove(space);
        self.wants.extend(new.map(|lists| (space.clone(), lists)));
        // Listed again from every space's listing, in space order, so that
        // the caps fall the same way whatever order listings came in.
        let mut listed: BTreeMap<Name, BTreeSet<Name>> = BTreeMap::new();
        let mut over = 0;
        for (name, lists) in &self.wants {
            for person in &lists.first {
                if listed.contains_key(person) || listed.len() < SCOPE_NAMESPACES {
                    listed
                        .entry(person.clone())
                        .or_default()
                        .insert(name.clone());
                } else {
                    over += 1;
                }
            }
            over += lists.rest;
        }
        for (person, spaces) in &listed {
            if let Some(p) = self.adopted.get_mut(person)
                && p.held.is_some()
                && spaces.contains(space)
            {
                p.stale = true;
            }
        }
        self.listed = listed;
        let warning = (over != self.over && over > 0).then(|| over_cap_warning(over));
        self.over = over;
        warning
    }

    /// The view that judges a packet of `person`, a namespace no context held
    /// covers, about `space`: the adopted one when a listing of `space` names
    /// her (`member`: as a writer or a reader) and she is adopted.
    fn view(&self, person: &Name, space: &Name, member: bool) -> Option<Arc<Validator>> {
        let lists = self.wants.get(space)?;
        if !self.listed.get(person)?.contains(space) || member && !lists.members.contains(person) {
            return None;
        }
        let (_, view) = self.adopted.get(person)?.held.as_ref()?;
        Some(Arc::clone(view))
    }

    /// Why `ctx` may not be adopted for `person`: it is older than the newest
    /// version adopted here before, or that version with other content.
    fn behind(&self, person: &Name, ctx: &SignedTrustContext) -> Option<String> {
        let &(version, digest) = self.newest.get(person)?;
        let (offered, got) = reached_of(ctx);
        if offered < version {
            return Some(format!(
                "this node adopted version {version} of {person}'s trust context before, and \
                 the host reached version {offered} only: an older version would trust again \
                 what a later one revoked, so it is not adopted; reach a device or relay that \
                 serves version {version} of {person} or newer"
            ));
        }
        if offered == version && got != digest {
            return Some(format!(
                "the host reached a version {version} of {person}'s trust context other than \
                 the one this node adopted before (two versions of one number: a fork), so it \
                 is not adopted; reach a device or relay that serves the version {person}'s \
                 owner signed"
            ));
        }
        None
    }

    /// `ctx` was adopted for `person`: the newest version moves on to it, and
    /// what the store keeps of it now — with its signed Data, when the host
    /// gave that; nothing new when it gave none for the version kept.
    fn reached(&mut self, person: &Name, ctx: &ScopedContext) -> Option<Bytes> {
        let now = reached_of(ctx.context());
        let moved = self
            .newest
            .get(person)
            .is_none_or(|before| before.0 < now.0);
        if moved {
            self.newest.insert(person.clone(), now);
        }
        (moved || ctx.data().is_some()).then(|| encode_kept(ctx))
    }

    /// What to ask the host for now: each person listed that the node does not
    /// hold (`held`), not adopted, not being adopted and past her pause — and
    /// each adopted one a new listing named, past its backoff — while fewer
    /// than [`SCOPE_ASKS`] adoptions are in flight; each with the version
    /// held, to refresh from. Marks them in flight. Also when to look again
    /// for an ask deferred by a pause, unless a wake is pending already.
    fn asks_due(
        &mut self,
        held: impl Fn(&Name) -> bool,
        now: Instant,
    ) -> (Vec<(Name, Option<ScopedContext>)>, Option<Instant>) {
        let mut flying = self.adopted.values().filter(|p| p.asking).count();
        let mut out = Vec::new();
        let mut wake: Option<Instant> = None;
        let mut later = |at: Instant| wake = Some(wake.map_or(at, |w| w.min(at)));
        for person in self.listed.keys() {
            if flying >= SCOPE_ASKS {
                break;
            }
            if held(person) {
                continue;
            }
            let (from, retry) = match self.adopted.get(person) {
                None => (None, None),
                Some(p) if p.asking => continue,
                Some(p) => match &p.held {
                    None => (None, p.retry),
                    Some((ctx, _)) if p.stale => (Some(ctx.clone()), p.retry),
                    Some(_) => continue,
                },
            };
            if let Some((at, _)) = retry.filter(|(at, _)| now < *at) {
                later(at);
                continue;
            }
            flying += 1;
            let p = self.adopted.entry(person.clone()).or_default();
            (p.asking, p.stale) = (true, false);
            if from.is_none() {
                // A fresh ask starts over: a failure of it is the first of a run.
                p.retry = None;
            }
            out.push((person.clone(), from));
        }
        let wake = wake.filter(|_| !self.waking);
        if wake.is_some() {
            self.waking = true;
        }
        (out, wake)
    }

    /// The adopted persons no listing names any more, or that the node now
    /// holds (its held context judges them from now on): dropped here, for the
    /// host to release.
    fn release_unlisted(&mut self, held: impl Fn(&Name) -> bool) -> Vec<Name> {
        let listed = &self.listed;
        let mut gone = Vec::new();
        self.adopted.retain(|person, p| {
            let listed = listed.contains_key(person);
            // A refusal no listing calls for any more is forgotten.
            let keep = match p.held {
                None => p.asking || listed,
                Some(_) => listed && !held(person),
            };
            if !keep && p.held.is_some() {
                gone.push(person.clone());
            }
            keep
        });
        gone
    }
}

/// The one warning for `over` persons the caps leave out, with why and what to
/// do.
fn over_cap_warning(over: usize) -> String {
    format!(
        "the members lists of the spaces list too many persons' namespaces to adopt here: \
         {over} are past the first {SCOPE_PER_SPACE} of a space or the {SCOPE_NAMESPACES} \
         this node adopts for all spaces together; their entries are judged by no view \
         while they are not adopted. The owners list too many persons: have them list \
         fewer, or adopt those namespaces on this node itself (an anchor link naming them)"
    )
}

// ---- the record the store keeps ----------------------------------------------------------------

/// `ctx`'s version and the digest of its content.
fn reached_of(ctx: &SignedTrustContext) -> Reached {
    (ctx.version(), Sha256::digest(ctx.encode_content()).into())
}

/// What the store keeps of `ctx` ([`Kind::SCOPED`]): the version, 8 octets
/// big-endian, and the SHA-256 of the context's content, 32 octets; then, when
/// the host gave it, the genesis's signed Data, its length first in 4 octets
/// big-endian, and the newest version's signed Data (none past version 1,
/// which is the genesis). An older version, or that version with other
/// content, is never adopted again; with the signed Data, the version is
/// judged by again after a restart and refreshed from by continuity.
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

/// The version and digest of a [`Kind::SCOPED`] record.
fn decode_reached(value: &[u8]) -> Option<Reached> {
    let version = u64::from_be_bytes(value.get(..8)?.try_into().ok()?);
    Some((version, value.get(8..40)?.try_into().ok()?))
}

/// The context a [`Kind::SCOPED`] record keeps, opened again: its genesis
/// checked as stored ([`Genesis::open_stored`]: signature and genesis rule, no
/// clock), the newest version's signature checked, both of `person`, and the
/// version and digest the record names.
async fn open_kept(person: &Name, value: &Bytes) -> Result<ScopedContext, String> {
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
    if genesis.namespace() != person {
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

/// Whether a trust context `new` taken after `old` (of the same namespace) may
/// refuse an entry `old` accepted: it revokes a name `old` did not, has a
/// revocation cut accept less than `old`'s did (dropped, shrunk, or bound to
/// another manifest or key), lists a role whose Data requires a cut that `old`
/// did not, or drops a trust anchor. `None` (no context before): it may.
fn refuses_more(old: Option<&SignedTrustContext>, new: &SignedTrustContext) -> bool {
    let Some(old) = old else {
        return true;
    };
    let revokes = new
        .revocations()
        .iter()
        .any(|r| !old.revocations().contains(r));
    let shrinks = old.revocation_cuts().iter().any(|was| {
        new.revocation_cut(was.key())
            .is_none_or(|now| !now.covers(was))
    });
    let lapses = new
        .data_requires_cut()
        .iter()
        .any(|role| !old.data_requires_cut().contains(role));
    let anchors = old
        .anchors()
        .iter()
        .any(|a| !new.anchors().contains_key(a.key()));
    revokes || shrinks || lapses || anchors
}

// ---- the judge ---------------------------------------------------------------------------------

/// The validator bridge of a node, and the persons it has adopted for its
/// spaces.
pub(crate) struct Judge {
    pub(crate) validator: Arc<Validator>,
    store: Arc<dyn DataStore>,
    adopter: Option<Arc<dyn Adopter>>,
    scopes: Mutex<Scopes>,
    /// What the log re-checks on, in order.
    events: mpsc::UnboundedSender<Adoption>,
    /// How many person adoptions so far refused more than the version before
    /// them: what a keyring's own revocation epoch counts for its contexts.
    scoped_revocations: AtomicU64,
}

impl Judge {
    /// A judge over `validator` (the node's own: its keyring holds the
    /// namespaces the node holds), keeping what it adopts in `store`, and
    /// adopting through `adopter`; without one, persons the node does not hold
    /// are never adopted and their entries wait. The records kept in the store
    /// before are read back here and opened again by [`Self::restore`], which
    /// the caller runs once the listings of the spaces it holds are noted
    /// ([`Self::note`]). With it, the stream of what the log re-checks on:
    /// its one reader.
    pub(crate) fn new(
        validator: Arc<Validator>,
        store: Arc<dyn DataStore>,
        adopter: Option<Arc<dyn Adopter>>,
    ) -> (Arc<Judge>, mpsc::UnboundedReceiver<Adoption>) {
        let (events, inbox) = mpsc::unbounded_channel();
        let mut scopes = Scopes::default();
        for (person, value) in Kind::SCOPED.named(&*store) {
            if !is_person(&person) {
                continue;
            }
            if let Some(reached) = decode_reached(&value) {
                scopes.newest.insert(person.clone(), reached);
                scopes.kept.push((person, value));
            }
        }
        scopes.ready = scopes.kept.is_empty();
        let judge = Arc::new(Judge {
            validator,
            store,
            adopter,
            scopes: Mutex::new(scopes),
            events,
            scoped_revocations: AtomicU64::new(0),
        });
        // The listener runs on the adopting thread: it only releases what the
        // node holds now itself, and queues the announcement.
        let weak = Arc::downgrade(&judge);
        judge.validator.keyring().on_adoption(move |ctx| {
            if let Some(judge) = weak.upgrade() {
                judge.context_adopted(ctx);
            }
        });
        (judge, inbox)
    }

    /// A counter that moves whenever a verdict given before may have changed
    /// for the worse: the keyring adopted a revoking context, or a person's
    /// newer version refuses more than the one before. Read it before
    /// judging; if it reads the same after, the verdict stands.
    pub(crate) fn generation(&self) -> u64 {
        self.validator
            .keyring()
            .revocation_epoch()
            .wrapping_add(self.scoped_revocations.load(Ordering::SeqCst))
    }

    /// The version of `person`'s context adopted here for spaces, if one is.
    #[cfg(test)]
    pub(crate) fn adopted_version(&self, person: &Name) -> Option<u64> {
        let (ctx, _) = self.scopes.lock().adopted.get(person)?.held.clone()?;
        Some(ctx.context().version())
    }

    // -- judging --

    /// Judge `data`, an entry or other packet about `space`, by the durable
    /// rule: its signature and certificate chain to the trust anchors of the
    /// context that governs its name (fetching certificates and cut manifests
    /// through the validator's fetcher), its key's revocation and role rules.
    ///
    /// A person's namespace this node does not hold is judged by the view
    /// adopted for her only when a listing of `space` names her; otherwise
    /// the packet waits for her adoption. A [`Refusal::Lapsed`] is no
    /// decision: only this node's clock refuses it, and it is judged again
    /// when fetched again.
    pub(crate) async fn validate(&self, data: &Data, space: &Name) -> Judged {
        let view = self.view_for(&data.name, space, false);
        decide(&view, data, space).await
    }

    /// Judge `data`, a packet signed by a device key that is not about a
    /// space's entries (a seal key `<device>/32=seal/<pk>`, a grant answer),
    /// for `space`: as [`Self::validate`], by the view adopted for the person
    /// only when `space`'s members list her as a writer or a reader, and
    /// valid only if the key belongs to `device`, the device the packet's
    /// name is under.
    pub(crate) async fn validate_device_packet(
        &self,
        data: &Data,
        device: &Name,
        space: &Name,
    ) -> Judged {
        let view = self.view_for(&data.name, space, true);
        match decide(&view, data, space).await {
            Judged::Valid(v) if v.device != *device => {
                tracing::debug!(name = %data.name, key = %v.key, "not verified: it is signed by a key of another device than the one its name is under");
                Judged::Refused(Refusal::BadSignature)
            }
            other => other,
        }
    }

    /// The validator that judges `name` about `space`: for a person's
    /// namespace the node does not hold, the view adopted for her if the
    /// listings say so (`member`: only as a writer or reader, not as a person
    /// a cut keeps); else the node's own, which refuses it as not held. The
    /// signal gate judges live data by it.
    pub(crate) fn view_for(&self, name: &Name, space: &Name, member: bool) -> Arc<Validator> {
        self.validator
            .keyring()
            .unheld_personal_namespace(name)
            .and_then(|person| self.scopes.lock().view(&person, space, member))
            .unwrap_or_else(|| Arc::clone(&self.validator))
    }

    /// Whether the trust context that governs `key` for `space` revokes it
    /// (or the key's device, by a revocation naming a name above it).
    pub(crate) fn key_revoked(&self, key: &Name, space: &Name) -> bool {
        self.view_for(key, space, true)
            .keyring()
            .context_for(key)
            .is_revoked(key)
    }

    /// The revocations of the context that governs `person` for `space` that
    /// name a key under her namespace: what a reader's lost devices are.
    pub(crate) fn revoked_under(&self, person: &Name, space: &Name) -> Vec<Name> {
        self.view_for(person, space, true)
            .keyring()
            .context_for(person)
            .revocations()
            .iter()
            .filter(|r| r.has_prefix(person))
            .cloned()
            .collect()
    }

    /// What the trust contexts this node holds keep of each device's log of `space` by a
    /// revocation cut: `(device, first, last)` runs of the seqs the cut accepts. The entries of a
    /// revoked key a cut keeps are wanted whatever counter the group shows for the key.
    pub(crate) fn cut_runs(&self, space: &Name) -> Vec<(Name, u64, u64)> {
        let mut out = Vec::new();
        for ctx in self.validator.keyring().contexts() {
            for cut in ctx.revocation_cuts() {
                let Some(device) = device_of(cut.key()) else {
                    continue;
                };
                let prefix = log_prefix(&device, space);
                for range in cut.ranges().iter().filter(|r| r.prefix == prefix) {
                    out.extend(range.runs.iter().map(|&(lo, hi)| (device.clone(), lo, hi)));
                }
            }
        }
        out
    }

    // -- adoption --

    /// The listing of `space` is now `listing` (an empty one when no fold
    /// lists anyone): the self-certifying persons it names that the node does
    /// not hold are adopted through the host, those adopted that no listing
    /// names any more are released. When the persons the caps leave out
    /// changed, the one warning is logged.
    pub(crate) fn note(self: &Arc<Self>, space: &Name, listing: &Listing) {
        if let Some(warning) = self.scopes.lock().note(space, listing) {
            tracing::warn!("{warning}");
        }
        self.adopt_listed();
    }

    /// At start, after the listings of the spaces held are noted: each person
    /// they name, which the node does not hold, is held again at the version
    /// kept in the store — judging at once, and refreshed from by continuity,
    /// never walked to from the genesis again, so a branch that does not
    /// descend from it is refused. A record that cannot be opened is
    /// reported, and that person adopted from her genesis, no older than the
    /// version it names. Asks to the host begin here.
    pub(crate) async fn restore(self: &Arc<Self>) {
        let keyring = self.validator.keyring();
        let kept: Vec<(Name, Bytes)> = {
            let mut scopes = self.scopes.lock();
            let kept = std::mem::take(&mut scopes.kept);
            kept.into_iter()
                .filter(|(person, _)| {
                    scopes.listed.contains_key(person) && keyring.held_for(person).is_none()
                })
                .collect()
        };
        let mut restored = Vec::new();
        for (person, value) in kept {
            match open_kept(&person, &value).await {
                Ok(ctx) => {
                    tracing::info!(%person, version = ctx.context().version(), "held again at the version kept, for the spaces that list her; refreshed from it");
                    let held = self.hold(ctx);
                    self.scopes.lock().adopted.insert(
                        person.clone(),
                        Person {
                            stale: true,
                            ..held
                        },
                    );
                    restored.push(person);
                }
                Err(why) => {
                    tracing::warn!(%person, "the version kept of her cannot be held again ({why}): she is adopted from her genesis, and no version older than the one kept is taken");
                }
            }
        }
        self.scopes.lock().ready = true;
        for person in restored {
            self.announce(&person, false);
        }
        self.adopt_listed();
    }

    /// Ask the host to adopt the persons the listings name that the node does
    /// not hold (and to refresh those a new listing named), and to release
    /// those nothing names any more. Without a host that adopts, they are not
    /// adopted, and the entries of those persons wait.
    fn adopt_listed(self: &Arc<Self>) {
        let keyring = self.validator.keyring();
        let held = |person: &Name| keyring.held_for(person).is_some();
        let (asks, released, wake) = {
            let mut scopes = self.scopes.lock();
            let released = scopes.release_unlisted(held);
            if !scopes.ready || self.adopter.is_none() {
                (Vec::new(), released, None)
            } else {
                let (asks, wake) = scopes.asks_due(held, Instant::now());
                (asks, released, wake)
            }
        };
        if let Some(at) = wake {
            // An ask a pause deferred: made once the pause ends.
            let weak = Arc::downgrade(self);
            rt::spawn(async move {
                rt::sleep(at.saturating_duration_since(Instant::now())).await;
                if let Some(judge) = weak.upgrade() {
                    judge.scopes.lock().waking = false;
                    judge.adopt_listed();
                }
            });
        }
        let Some(host) = self.adopter.clone() else {
            return;
        };
        for person in &released {
            tracing::info!(%person, "no space lists her any more, or the node holds her: released");
            host.release_scoped(person);
        }
        for (person, from) in asks {
            let judge = Arc::clone(self);
            let host = Arc::clone(&host);
            rt::spawn(async move {
                let got = host.adopt_scoped(&person, from.as_ref()).await;
                if let Some(refuses) = judge.adopted(&person, from, got) {
                    judge.announce(&person, refuses);
                }
                judge.adopt_listed();
            });
        }
    }

    /// Take the host's answer for `person`, adopted from `from` (the version
    /// held, for a refresh): whether the version now held may refuse more than
    /// the one before it, if one is held now. A refusal keeps a version held
    /// before (judging goes on with it) and is asked again after a growing
    /// pause. A version older than the newest adopted here before (kept
    /// across restarts), or that version with other content, is refused; the
    /// newest adopted is kept in the store.
    fn adopted(
        &self,
        person: &Name,
        from: Option<ScopedContext>,
        got: Result<ScopedContext, String>,
    ) -> Option<bool> {
        let mut scopes = self.scopes.lock();
        if let Some(p) = scopes.adopted.get_mut(person) {
            p.asking = false;
        }
        let listed = scopes.listed.contains_key(person);
        // A fresh adoption the host made and this node refuses: the host's
        // carrying of it is released.
        let mut release = false;
        let got = match got {
            Ok(ctx) if listed => match scopes.behind(person, ctx.context()) {
                Some(why) => {
                    release = from.is_none();
                    Err(why)
                }
                None => Ok(ctx),
            },
            other => other,
        };
        let why = match got {
            Ok(ctx) if listed => {
                let refuses = refuses_more(from.as_ref().map(|f| &**f.context()), ctx.context());
                tracing::info!(%person, version = ctx.context().version(), "adopted by name for judging the entries of the spaces that list her");
                let kept = scopes.reached(person, &ctx);
                scopes.adopted.insert(person.clone(), self.hold(ctx));
                drop(scopes);
                if let Some(kept) = kept {
                    self.store.insert(Kind::SCOPED.of(person), kept);
                }
                if refuses && from.is_some() {
                    // After the new view is in force, as the keyring's own
                    // revocation epoch moves.
                    self.scoped_revocations.fetch_add(1, Ordering::SeqCst);
                }
                return Some(refuses);
            }
            // Adopted after the last listing that named her went: released.
            Ok(_) => {
                scopes.adopted.remove(person);
                drop(scopes);
                self.release(person);
                return None;
            }
            Err(why) => why,
        };
        let pause = scopes
            .adopted
            .get(person)
            .and_then(|p| p.retry)
            .map_or(SCOPE_PAUSE, |(_, last)| (last * 2).min(SCOPE_PAUSE_MAX));
        let again = Instant::now() + pause;
        let p = scopes.adopted.entry(person.clone()).or_default();
        p.retry = Some((again, pause));
        if from.is_some() {
            // A refresh that failed: the version held still judges, and is
            // refreshed again after a growing pause.
            p.stale = true;
            tracing::info!(%person, "not refreshed: {why}; the version held judges meanwhile, and it is refreshed again in {pause:?}");
            return None;
        }
        tracing::warn!(%person, "a space lists her, and she is not adopted for it: {why}; her entries there wait, and she is asked again in {pause:?}");
        drop(scopes);
        if release {
            self.release(person);
        }
        None
    }

    /// The adopted `ctx` and the view of the node's validator that judges by
    /// it.
    fn hold(&self, ctx: ScopedContext) -> Person {
        let view = Arc::new(self.validator.scoped_view(&ctx));
        Person {
            held: Some((ctx, view)),
            ..Person::default()
        }
    }

    /// Tell the host to stop carrying what it kept for `person`.
    fn release(&self, person: &Name) {
        if let Some(host) = &self.adopter {
            host.release_scoped(person);
        }
    }

    /// Tell the log `person` was adopted, restored or refreshed.
    fn announce(&self, person: &Name, refuses: bool) {
        let spaces = self
            .scopes
            .lock()
            .listed
            .get(person)
            .map(|spaces| spaces.iter().cloned().collect())
            .unwrap_or_default();
        let _ = self.events.send(Adoption::Person {
            person: person.clone(),
            spaces,
            refuses,
        });
    }

    /// The keyring adopted `ctx`: the persons it now holds are no longer
    /// adopted for spaces (its held context judges them), and the log is told.
    /// Runs on the adopting thread, so it only releases and queues.
    fn context_adopted(&self, ctx: &Arc<SignedTrustContext>) {
        let keyring = self.validator.keyring();
        let released = self
            .scopes
            .lock()
            .release_unlisted(|person| keyring.held_for(person).is_some());
        for person in &released {
            self.release(person);
        }
        let _ = self.events.send(Adoption::Context(Arc::clone(ctx)));
    }
}

// ---- the verdicts of the durable rule ----------------------------------------------------------

/// What `ctx`'s revocation of `key` keeps of `device`'s log of `space`: the
/// highest seq its cut accepts there. A revocation with no cut for that log
/// keeps nothing (tip 0).
fn cut_of(ctx: &SignedTrustContext, key: &Name, device: Name, space: &Name) -> Cut {
    let prefix = log_prefix(&device, space);
    let keeps_to = ctx
        .revocation_cut(&key_name_of(key))
        .and_then(|cut| cut.ranges().iter().find(|r| r.prefix == prefix))
        .and_then(|range| range.runs.iter().map(|&(_, last)| last).max())
        .unwrap_or(0);
    Cut { device, keeps_to }
}

/// Judge `data` by the durable rule of `view`.
async fn decide(view: &Validator, data: &Data, space: &Name) -> Judged {
    let verdict = view.validate_durable(data).await;
    let key = data.sig_info().and_then(|s| s.key_locator_name());
    match verdict {
        ValidationResult::Valid(safe) => accept(view, data, *safe, key.as_deref()),
        ValidationResult::Pending => Judged::Pending(Waiting::Chain),
        ValidationResult::Invalid(e) => refuse(view, data, space, key.as_deref(), &e),
    }
}

/// A packet the validator found valid: signed by a key, not by a digest.
fn accept(view: &Validator, data: &Data, safe: SafeData, key: Option<&Name>) -> Judged {
    if matches!(safe.trust_path(), TrustPath::DigestSha256) {
        return Judged::Refused(Refusal::Untrusted {
            why: "it is signed by a digest alone, which names no signer (anyone can compute it)"
                .into(),
        });
    }
    let (Some(key), Some(key_digest)) = (key, safe.signer_key_digest()) else {
        return Judged::Refused(Refusal::BadSignature);
    };
    let Some(device) = device_of(key) else {
        return Judged::Refused(Refusal::Untrusted {
            why: format!("its key {key} is no key name `<device>/KEY/<id>`"),
        });
    };
    let person = view.keyring().context_for(&data.name).namespace().clone();
    Judged::Valid(Verified {
        key: key.clone(),
        device,
        person,
        key_digest,
    })
}

/// A packet the validator refused, by cause.
fn refuse(
    view: &Validator,
    data: &Data,
    space: &Name,
    key: Option<&Name>,
    e: &TrustError,
) -> Judged {
    let untrusted = || Judged::Refused(Refusal::Untrusted { why: e.to_string() });
    match e {
        // The signing key itself (not an issuer above it) is revoked: its
        // revocation's cut decides.
        TrustError::Revoked { name, .. } => {
            let Some(key) = key else {
                return untrusted();
            };
            let signing = name
                .parse::<Name>()
                .is_ok_and(|n| key_name_of(&n) == key_name_of(key));
            let ctx = view.keyring().context_for(&data.name);
            match (signing && ctx.is_revoked(key), device_of(key)) {
                (true, Some(device)) => {
                    tracing::debug!(name = %data.name, %key, "refused: its key is revoked and the cut does not accept it");
                    Judged::Refused(Refusal::OutsideCut(cut_of(&ctx, key, device, space)))
                }
                // Only a certificate of its key, or an issuer above it, is
                // revoked: no cut excuses that.
                _ => untrusted(),
            }
        }
        // The signing key's role needs a cut and no certificate of it is valid
        // by this clock: only the clock refuses.
        TrustError::Lapsed { not_after, now, .. } => {
            tracing::debug!(name = %data.name, "refused: its key's certificate lapsed by this node's clock");
            Judged::Refused(Refusal::Lapsed {
                not_after: Timestamp(*not_after),
                now: Timestamp(*now),
            })
        }
        TrustError::PersonalNamespaceNotHeld { namespace, .. } => {
            match personal_namespace_of(&data.name).or_else(|| namespace.parse().ok()) {
                Some(person) => Judged::Pending(Waiting::Adoption(person)),
                None => untrusted(),
            }
        }
        TrustError::InvalidSignature
        | TrustError::InvalidKey
        | TrustError::UnsupportedSignatureType { .. }
        | TrustError::NotPublicKeySignature { .. }
        // What may verify when fetched from another holder, or once a
        // certificate arrives.
        | TrustError::CertNotFound { .. }
        | TrustError::KeyStore(_)
        | TrustError::NoSigningIdentity { .. } => {
            tracing::debug!(name = %data.name, "not verified: {e}");
            Judged::Refused(Refusal::BadSignature)
        }
        _ => untrusted(),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "trust_tests.rs"]
mod tests;
