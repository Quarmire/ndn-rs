//! Grants follow the membership (spec §10, §11): the grants an offer's admission makes,
//! the grants in force (`Invites::grants`), the judgement of each against **its own
//! space's** members (a person left out of one space loses that space's grant alone, a
//! person whose role changed has the grant told again), the departure mark a held entry
//! that lets a person go leaves in the note (`Invites::departures`,
//! `Surface::take_departure`), the host's own durable ends and renewals
//! (`Invites::end_grant`, `end_grant_in`, `renew_grant`), and the joiner's end.
//!
//! A grant is built at **both ends**. The inviter's end is the grant note ([`notes`]).
//! The joiner's end is the **mirror note** a successful join keeps: the inviter's key,
//! the space, and the inviter's namespace as its owner. It is judged like the inviter's
//! note against the space's members, with two differences the rule requires: it stands
//! only while the members list **this device's person**, and its role is **the
//! inviter's** standing there (a writer when its namespace is listed as a writer, else a
//! reader: never wider than the members say). It joins `Invites::grants`, is told to the
//! host the same way, and **never makes a departure mark**: the person who is let go is
//! told by the inviter, and a mirror grant only admits the inviter's own link. The same
//! notes drive `Invites::joined_folders` and `joined_changes`: what the link to each
//! inviter must route.
//!
//! Every note is re-evaluated on every `Change::Members` of the space it names
//! (`Heap::watch`), and at start (a restart installs every live grant and every
//! departure mark in force through the host again). As the plan's contingency has it,
//! the notes are also judged every `svs.sync_interval / 2` and on every `Change::Alert`,
//! so a change a slow watcher has not yet delivered is still judged.
//!
//! [`notes`]: crate::notes

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Weak};
use std::time::Duration;

use ndn_foundation_types::Name;
use ndn_heap::host::NodeHandle;
use ndn_heap::wire::{is_namespace, log_name, parse_log_name, parse_space_name};
use ndn_heap::{Change, Frontier, Heap, HeapError, Readers, Timestamp};
use ndn_security::self_certifying::personal_namespace_of;
use ndn_sync::{DataStore, StoreOp};
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::error::InviteError;
use crate::host::{Departure, Grant, Host, JOINED_WRITERS_MAX, JoinedFolder, Role};
use crate::invites::{Inner, Invites};
use crate::notes::{
    GrantNote, MAC_KEY_LABEL, MIRROR_MAC_KEY_LABEL, Mark, MirrorNote, Unread, derived_key,
};
use crate::policy::IntroPolicy;
use crate::store;
use crate::wire::{OfferId, offer_name, parse_offer_name};

/// Departure marks one device lets be taken (`Surface::take_departure`) in a minute: a
/// hostile inviter's stream of `Departure` messages costs this many fetches a minute,
/// no more.
const DEPARTURES_PER_MINUTE: usize = 6;

/// The minute those are counted in, in milliseconds of the device's clock.
const DEPARTURE_WINDOW_MS: u64 = 60_000;

/// The shortest wait between two judgements of the notes: a configured sync interval of
/// nothing must not make the loop spin.
const JUDGE_EVERY_MIN: Duration = Duration::from_millis(10);

/// What the members in force for a grant's space make of the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// The space is not open here or its creation is not seen: nothing to judge by, so a
    /// grant of it is not left standing (the host is told to revoke it) until it is read.
    Unknown,
    /// The members list the person neither as a writer nor as a reader (or, in a public
    /// space, an entry removed them).
    Out,
    /// The members list the person in this role (a writer wins over a reader).
    In(Role),
}

/// What the members in force for a mirror note's space make of the note and of this
/// device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MirrorStanding {
    /// The space is not open here or its creation is not seen: nothing to judge by, so
    /// nothing is granted.
    Unknown,
    /// The members do not list this device's person.
    Out,
    /// The members list this device's person: `entry` is the inviter's role in them (the
    /// mirror grant's), `device` this device's (the joined space's).
    In { entry: Role, device: Role },
}

/// A grant note the offer's admission made, to be told to the host once it is durable
/// (`Grants::granted`).
#[derive(Clone, Debug)]
pub(crate) struct PendingGrant {
    note: GrantNote,
}

/// The state of the grants and mirror notes of one device.
pub(crate) struct Grants {
    node: NodeHandle,
    host: Arc<dyn Host>,
    policy: IntroPolicy,
    /// The key the grant notes' MAC is made under.
    note_key: Zeroizing<[u8; 32]>,
    /// The key the mirror notes' MAC is made under.
    mirror_key: Zeroizing<[u8; 32]>,
    /// The one place notes are changed from: a change reads the notes as the one before
    /// left them.
    notes: tokio::sync::Mutex<()>,
    /// The spaces a watcher task follows.
    following: Mutex<BTreeSet<Name>>,
    /// The generation of the joined list, and the list it stands for.
    joined_changes: tokio::sync::watch::Sender<u64>,
    joined_seen: Mutex<Vec<JoinedFolder>>,
    /// The spaces a departure take is in flight for.
    departing: Mutex<BTreeSet<Name>>,
    /// When the departure takes of the last minute began.
    departures_begun: Mutex<VecDeque<Timestamp>>,
    /// The `(key, space)` of each grant the host holds from this device in this run: a
    /// live grant not in it (its space was not known at start) is told when it stands.
    told: Mutex<BTreeSet<([u8; 32], Name)>>,
    /// The `(key, space)` of each grant the host was told to revoke because its space is not
    /// open here (or its creation is not held): while the space cannot be read, the members
    /// cannot say the person is still in, so the grant is not left standing. Told once; the
    /// entry goes when the space can be read again.
    withheld: Mutex<BTreeSet<([u8; 32], Name)>>,
}

/// A take of a space's departure entry under way, let go as it is dropped.
struct Departing<'a> {
    grants: &'a Grants,
    space: Name,
}

impl Drop for Departing<'_> {
    fn drop(&mut self) {
        self.grants.departing.lock().remove(&self.space);
    }
}

impl Grants {
    /// The grants of the device behind `node`, told to `host`, as `policy` bounds them.
    pub(crate) fn new(node: NodeHandle, host: Arc<dyn Host>, policy: IntroPolicy) -> Arc<Grants> {
        let secret = node.recipient().expose();
        let (note_key, mirror_key) = (
            derived_key(secret, MAC_KEY_LABEL),
            derived_key(secret, MIRROR_MAC_KEY_LABEL),
        );
        Arc::new(Grants {
            node,
            host,
            policy,
            note_key,
            mirror_key,
            notes: tokio::sync::Mutex::new(()),
            following: Mutex::new(BTreeSet::new()),
            joined_changes: tokio::sync::watch::channel(0).0,
            joined_seen: Mutex::new(Vec::new()),
            departing: Mutex::new(BTreeSet::new()),
            departures_begun: Mutex::new(VecDeque::new()),
            told: Mutex::new(BTreeSet::new()),
            withheld: Mutex::new(BTreeSet::new()),
        })
    }

    /// Install what is in force through the host (every live grant and every departure
    /// mark: a restart brings them back), then follow the spaces of the notes: each
    /// `Change::Members` of one, and every half sync interval, judges them all.
    pub(crate) fn start(self: &Arc<Self>) {
        for grant in self.live_grants() {
            self.tell(&grant);
        }
        for departure in self.live_departures() {
            self.host.departure(&departure);
        }
        *self.joined_seen.lock() = self.joined_list();
        let weak = Arc::downgrade(self);
        ndn_app::rt::spawn(async move {
            while let Some(grants) = weak.upgrade() {
                grants.follow_spaces();
                grants.judge().await;
                let wait = (grants.node.config().svs.sync_interval / 2).max(JUDGE_EVERY_MIN);
                drop(grants);
                ndn_app::rt::sleep(wait).await;
            }
        });
    }

    // ---- the notes -------------------------------------------------------------------------

    fn store(&self) -> &Arc<dyn DataStore> {
        self.node.store()
    }

    /// Tell the host of `grant`, and remember it was told in this run.
    fn tell(&self, grant: &Grant) {
        self.told.lock().insert((grant.key, grant.folder.clone()));
        self.host.grant(grant);
    }

    /// Whether the host was told of the grant of `key` for `space` in this run.
    fn was_told(&self, key: &[u8; 32], space: &Name) -> bool {
        self.told.lock().contains(&(*key, space.clone()))
    }

    /// Whether `space` is public (its members list everybody as a reader), as the
    /// members here say.
    fn is_public(&self, space: &Name) -> bool {
        self.node
            .space(space)
            .is_some_and(|heap| heap.members().readers == Readers::Anyone)
    }

    /// Every grant note kept that this device reads, held here or not. One that fails
    /// its MAC, or that this version does not read, is ignored, and said so with why.
    fn grant_notes(&self) -> Vec<GrantNote> {
        store::list(&**self.store(), &store::grant_listing())
            .into_iter()
            .filter_map(|(key, value)| match GrantNote::decode(&value, &self.note_key) {
                Ok(note) if self.names_its_offer(&note, &key) => Some(note),
                Ok(_) => {
                    tracing::warn!(%key, "a grant note is kept under a name that is not its offer's: ignored");
                    None
                }
                Err(Unread::Check) => {
                    tracing::warn!(%key, "a grant note fails its integrity check (it was changed in the store, or written under another device secret): ignored, so the person it names has no grant from it; to link with them again, offer the space to them again");
                    None
                }
                Err(Unread::Form) => {
                    tracing::warn!(%key, "a grant note this version does not read: ignored, so the person it names has no grant from it; to link with them again, offer the space to them again");
                    None
                }
            })
            .collect()
    }

    /// Whether `note` is of an offer of this device and is kept under that offer's key.
    fn names_its_offer(&self, note: &GrantNote, key: &Name) -> bool {
        parse_offer_name(&note.offer).is_some_and(|(device, id)| {
            device == *self.node.name() && store::grant_key(&id) == *key
        })
    }

    /// The notes of grants the use marks bear out: the offer is used by the very key the
    /// note names.
    fn used_grants(&self) -> Vec<GrantNote> {
        self.grant_notes()
            .into_iter()
            .filter(|note| self.used_by(note))
            .collect()
    }

    fn used_by(&self, note: &GrantNote) -> bool {
        let Some((_, id)) = parse_offer_name(&note.offer) else {
            return false;
        };
        crate::marks::used_digest(self.store().as_ref(), self.node.recipient(), &id)
            == Some(note.key)
    }

    /// Every mirror note kept that this device reads, ended or not. One that fails its
    /// MAC, or that this version does not read, is ignored, and said so with why.
    fn mirror_notes(&self) -> Vec<MirrorNote> {
        let root = store::root().append("mirror");
        store::list(&**self.store(), &root)
            .into_iter()
            .filter_map(|(key, value)| match MirrorNote::decode(&value, &self.mirror_key) {
                Ok(note) if store::mirror_key(&note.space, &note.key) == key => Some(note),
                Ok(_) => {
                    tracing::warn!(%key, "a mirror note is kept under a name that is not its space's and key's: ignored");
                    None
                }
                Err(Unread::Check) => {
                    tracing::warn!(%key, "a mirror note fails its integrity check (it was changed in the store, or written under another device secret): ignored, so the inviter it names is granted no link on its account; to link with them again, join again with a new offer");
                    None
                }
                Err(Unread::Form) => {
                    tracing::warn!(%key, "a mirror note this version does not read: ignored, so the inviter it names is granted no link on its account; to link with them again, join again with a new offer");
                    None
                }
            })
            .collect()
    }

    fn grant_op(&self, note: &GrantNote) -> Option<StoreOp> {
        let (_, id) = parse_offer_name(&note.offer)?;
        Some(StoreOp::Insert(
            store::grant_key(&id),
            note.encode(&self.note_key),
        ))
    }

    fn mirror_op(&self, note: &MirrorNote) -> StoreOp {
        StoreOp::Insert(
            store::mirror_key(&note.space, &note.key),
            note.encode(&self.mirror_key),
        )
    }

    // ---- what the members make of a person -------------------------------------------------

    fn heap(&self, space: &Name) -> Option<Heap> {
        self.node.space(space).filter(Heap::members_known)
    }

    /// What the members of `space` make of `person`: a writer, or a reader, or out.
    /// A public space lists no reader by being public: there a person is a reader unless
    /// an entry removed them.
    fn standing(&self, person: &Name, space: &Name) -> Standing {
        let Some(heap) = self.heap(space) else {
            return Standing::Unknown;
        };
        let members = heap.members();
        if members.writers.contains(person) {
            return Standing::In(Role::Writer);
        }
        let reads = match &members.readers {
            Readers::Persons(persons) => persons.contains(person),
            Readers::Anyone => heap.removed_by(person).is_none(),
        };
        if reads {
            Standing::In(Role::Reader)
        } else {
            Standing::Out
        }
    }

    /// What the members of the note's space make of the note and of this device.
    fn mirror_standing(&self, note: &MirrorNote) -> MirrorStanding {
        let me = self.node.namespace();
        let device = match self.standing(me, &note.space) {
            Standing::Unknown => return MirrorStanding::Unknown,
            Standing::Out => return MirrorStanding::Out,
            Standing::In(role) => role,
        };
        let inviter_writes = self
            .heap(&note.space)
            .is_some_and(|heap| heap.members().writers.contains(&note.owner));
        MirrorStanding::In {
            entry: if inviter_writes {
                Role::Writer
            } else {
                Role::Reader
            },
            device,
        }
    }

    /// The mirror entries in force: each note not ended whose space's members list this
    /// device, in the inviter's role they give now, with this device's own role.
    fn live_mirrors(&self) -> Vec<(MirrorNote, Role)> {
        self.mirror_notes()
            .into_iter()
            .filter(|note| !note.ended)
            .filter_map(|note| match self.mirror_standing(&note) {
                MirrorStanding::In { entry, device } => Some((
                    MirrorNote {
                        role: entry,
                        ..note
                    },
                    device,
                )),
                MirrorStanding::Out | MirrorStanding::Unknown => None,
            })
            .collect()
    }

    // ---- what is in force ------------------------------------------------------------------

    /// The grants in force (`Invites::grants`): each in the role the members make of the
    /// person now, then the mirror entries in the role they make of the inviter; sorted
    /// by key, then space.
    pub(crate) fn live_grants(&self) -> Vec<Grant> {
        let now = self.node.now();
        let mut grants: Vec<Grant> = self
            .used_grants()
            .into_iter()
            .filter(|note| !note.ended && !note.dated_out(now))
            .filter_map(|note| match self.standing(&note.namespace, &note.space) {
                Standing::In(role) => Some(GrantNote { role, ..note }.grant()),
                Standing::Out | Standing::Unknown => None,
            })
            .collect();
        grants.extend(
            self.live_mirrors()
                .into_iter()
                .map(|(note, _)| note.grant()),
        );
        grants.sort_by(|a, b| (&a.key, &a.folder).cmp(&(&b.key, &b.folder)));
        grants
    }

    /// The departure marks in force (`Invites::departures`): of ended notes whose MAC
    /// checks, not past their date, and not superseded by a live grant of the same key
    /// for the same space (the person was invited again).
    pub(crate) fn live_departures(&self) -> Vec<Departure> {
        let now = self.node.now();
        let notes = self.used_grants();
        let mut marks: Vec<Departure> = notes
            .iter()
            .filter(|note| note.ended)
            .filter_map(GrantNote::departure)
            .filter(|mark| mark.until > now)
            .filter(|mark| {
                !notes.iter().any(|note| {
                    !note.ended
                        && !note.dated_out(now)
                        && note.key == mark.key
                        && note.space == mark.folder
                })
            })
            .collect();
        marks.sort_by(|a, b| (&a.key, &a.folder, &a.record).cmp(&(&b.key, &b.folder, &b.record)));
        marks
    }

    // ---- following the members -------------------------------------------------------------

    /// Follow every space a note names that is open here and not followed yet.
    fn follow_spaces(self: &Arc<Self>) {
        let spaces: BTreeSet<Name> = self
            .grant_notes()
            .into_iter()
            .filter(|note| !note.ended)
            .map(|note| note.space)
            .chain(
                self.mirror_notes()
                    .into_iter()
                    .filter(|note| !note.ended)
                    .map(|note| note.space),
            )
            .collect();
        for space in spaces {
            self.follow(&space);
        }
    }

    /// Judge every note again on each `Change::Members` (and `Change::Alert`) of `space`
    /// until the node stops or the grants are gone.
    fn follow(self: &Arc<Self>, space: &Name) {
        let Some(heap) = self.node.space(space) else {
            return;
        };
        if !self.following.lock().insert(space.clone()) {
            return;
        }
        let (weak, space) = (Arc::downgrade(self), space.clone());
        ndn_app::rt::spawn(async move {
            let ended = Self::watch(&weak, &heap).await;
            if let Some(grants) = weak.upgrade() {
                grants.following.lock().remove(&space);
                if let Err(why) = ended {
                    tracing::debug!(%space, %why, "the members of a space with a grant could not be watched: they are judged again at the next half sync interval");
                }
            }
        });
    }

    async fn watch(weak: &Weak<Grants>, heap: &Heap) -> Result<(), InviteError> {
        // From everything held now: the members change is what is wanted, not a replay of
        // every head (and a read of every value in pieces) of a space at each start.
        let mut changes = heap.watch(&Frontier::everything()).await?;
        // What changed before the watch was subscribed is judged now: nothing of the
        // members' history is missed between a grant and the first change told.
        match weak.upgrade() {
            Some(grants) => grants.judge().await,
            None => return Ok(()),
        }
        while let Some(change) = changes.next().await {
            let Some(grants) = weak.upgrade() else {
                return Ok(());
            };
            match change? {
                Change::Members(_) | Change::Alert(_) | Change::Lagged { .. } => {
                    grants.judge().await;
                }
                Change::Put(_) | Change::Removed(_) | Change::Withdrawn { .. } => {}
            }
        }
        Ok(())
    }

    // ---- judging ---------------------------------------------------------------------------

    /// Judge the notes against the members in force for each note's own space, then
    /// publish the joined list (a joiner's routes follow the members on their own).
    /// Run after every change of a followed space's members, and at a start. A failure
    /// to make a note durable leaves the next run to judge again.
    pub(crate) async fn judge(&self) {
        let _one = self.notes.lock().await;
        self.judge_inviter_notes().await;
        self.judge_mirrors().await;
        self.publish_joined();
    }

    /// The inviter's notes judged against the members of each note's space:
    ///
    /// - the person is out: the host is told, in memory, first, of the departure (when
    ///   the policy keeps a mark and an applied entry that removed the person is found),
    ///   then of the end of this space's grant alone; then the note is marked ended
    ///   (with the mark, under the same MAC) durably;
    /// - the person is in another role than the grant bears: the note takes the role,
    ///   the host is told again and the note is made durable;
    /// - the space is not open here, or its creation is not held: the members cannot say the
    ///   person is still in, so the host is told `revoke_grant` once and the note is left as
    ///   it is (not ended: the space may be closed here and nothing more); the first judgement
    ///   that reads the space again installs the grant if the person is listed, and ends it
    ///   as above if not.
    ///
    /// The person's grants of other spaces are not touched. Called with the notes held.
    async fn judge_inviter_notes(&self) {
        let now = self.node.now();
        let (mut ending, mut retold, mut installing) = (Vec::new(), Vec::new(), Vec::new());
        for note in self.used_grants().into_iter().filter(|note| !note.ended) {
            let standing = self.standing(&note.namespace, &note.space);
            let tracked = (note.key, note.space.clone());
            if standing == Standing::Unknown {
                if self.withheld.lock().insert(tracked.clone()) {
                    self.host.revoke_grant(&note.key, &note.space);
                    self.told.lock().remove(&tracked);
                    tracing::info!(offer = %note.offer, space = %note.space, namespace = %note.namespace, "the space is not open here, or its creation is not held, so its members cannot say the person is still in: its grant to link is revoked until it is; open the space to install it again");
                }
                continue;
            }
            self.withheld.lock().remove(&tracked);
            match standing {
                Standing::Out => {
                    let departure = self.departure_mark(&note, now);
                    ending.push(GrantNote { departure, ..note });
                }
                Standing::In(role) if role != note.role => retold.push(GrantNote { role, ..note }),
                // A grant that stands and the host was not told of in this run: its space
                // was not known when the invitations started.
                Standing::In(_)
                    if !note.dated_out(now) && !self.was_told(&note.key, &note.space) =>
                {
                    installing.push(note);
                }
                Standing::In(_) | Standing::Unknown => {}
            }
        }
        for mut note in ending {
            // The host first: in memory, and the safe direction. A slow or failing
            // flush must not delay the link layer's end. The departure goes before the
            // end, so a link layer that narrows its link at its last entry's end
            // already holds the mark.
            if let Some(departure) = note.departure() {
                self.host.departure(&departure);
            }
            self.host.revoke_grant(&note.key, &note.space);
            self.told.lock().remove(&(note.key, note.space.clone()));
            note.ended = true;
            if let Err(why) = self.keep_grant(&note).await {
                tracing::debug!(offer = %note.offer, %why, "the end of a grant was not durable; the next judgement ends it again");
                continue;
            }
            tracing::info!(offer = %note.offer, space = %note.space, namespace = %note.namespace, record = ?note.departure.as_ref().map(|m| m.record.to_string()), "the space's members leave the person out: its grant to link ended");
        }
        for note in retold {
            self.tell(&note.grant());
            if let Err(why) = self.keep_grant(&note).await {
                tracing::debug!(offer = %note.offer, %why, "a grant's new role was not durable; the next judgement tells it again");
                continue;
            }
            tracing::info!(offer = %note.offer, space = %note.space, namespace = %note.namespace, role = ?note.role, "the space's members change the person's role: its grant to link now bears it");
        }
        for note in installing {
            self.tell(&note.grant());
            tracing::info!(offer = %note.offer, space = %note.space, namespace = %note.namespace, "the space is known and lists the person: its grant to link is installed");
        }
    }

    /// The mirror notes judged against the members of each note's space, the host told
    /// in memory, first, as for the inviter's:
    ///
    /// - the members do not list this device's person: `revoke_grant` with the inviter's
    ///   key and the space, then the note is marked ended durably. **Never a
    ///   departure**: the person who is let go is told by the inviter;
    /// - the members give the inviter another role than the note bears: the note takes
    ///   it, `grant` tells the host again and the note is made durable.
    ///
    /// Space not open here: nothing is done (nothing to judge by). Called with the notes
    /// held.
    async fn judge_mirrors(&self) {
        let (mut ending, mut retold, mut installing) = (Vec::new(), Vec::new(), Vec::new());
        for note in self.mirror_notes().into_iter().filter(|note| !note.ended) {
            match self.mirror_standing(&note) {
                MirrorStanding::Out => ending.push(note),
                MirrorStanding::In { entry, .. } if entry != note.role => {
                    retold.push(MirrorNote {
                        role: entry,
                        ..note
                    });
                }
                MirrorStanding::In { .. } if !self.was_told(&note.key, &note.space) => {
                    installing.push(note);
                }
                MirrorStanding::In { .. } | MirrorStanding::Unknown => {}
            }
        }
        for mut note in ending {
            self.host.revoke_grant(&note.key, &note.space);
            self.told.lock().remove(&(note.key, note.space.clone()));
            note.ended = true;
            self.store().apply(vec![self.mirror_op(&note)]);
            // Published before the flush: the routes follow the memory.
            self.publish_joined();
            if let Err(why) = store::flush(self.store()).await {
                tracing::debug!(space = %note.space, %why, "the end of a mirror grant was not durable; the next judgement ends it again");
                continue;
            }
            tracing::info!(space = %note.space, owner = %note.owner, "the space's members leave this device out: the inviter's mirror grant to link ended");
        }
        for note in retold {
            self.tell(&note.grant());
            if let Err(why) = self.keep_mirror_note(&note).await {
                tracing::debug!(space = %note.space, %why, "a mirror grant's new role was not durable; the next judgement tells it again");
                continue;
            }
            tracing::info!(space = %note.space, owner = %note.owner, role = ?note.role, "the space's members change the inviter's role: its mirror grant to link now bears it");
        }
        for note in installing {
            self.tell(&note.grant());
        }
    }

    async fn keep_grant(&self, note: &GrantNote) -> Result<(), InviteError> {
        let op = self
            .grant_op(note)
            .ok_or_else(|| InviteError::local("a grant note names no offer of this device"))?;
        store::apply_durable(self.store(), vec![op]).await
    }

    async fn keep_mirror_note(&self, note: &MirrorNote) -> Result<(), InviteError> {
        store::apply_durable(self.store(), vec![self.mirror_op(note)]).await
    }

    /// The departure mark the end of `note` by the members makes: the entry that removed
    /// the person (`Heap::removed_by`, the same on every device that holds the same
    /// entries) and the date by this device's clock; `None` when the policy keeps no mark
    /// (`departure_for` is zero) or no entry removed the person (a cut dropped them).
    fn departure_mark(&self, note: &GrantNote, now: Timestamp) -> Option<Mark> {
        let keep = self.policy.departure_for;
        if keep.is_zero() {
            return None;
        }
        let removed = self.node.space(&note.space)?.removed_by(&note.namespace)?;
        let ms = u64::try_from(keep.as_millis()).unwrap_or(u64::MAX);
        Some(Mark {
            record: log_name(&removed.device, &note.space, removed.seq),
            until: Timestamp(now.0.saturating_add(ms)),
        })
    }

    // ---- an admission ----------------------------------------------------------------------

    /// The note of the grant the own offer `id`'s admission of `key` makes, as
    /// `IntroPolicy::grant_for` bounds it from now, and the store operation that keeps
    /// it (to be applied with the use mark, in one durable batch); `None` when the policy
    /// grants nothing (`Some(ZERO)`).
    pub(crate) fn grant_note(
        &self,
        id: &OfferId,
        key: [u8; 32],
        namespace: &Name,
        space: &Name,
        role: Role,
    ) -> Option<(StoreOp, PendingGrant)> {
        if role == Role::Reader && self.is_public(space) {
            // Nobody is listed as a reader of a public space, so no entry could take this
            // grant away: it would be a link slot nothing but the host ends.
            tracing::info!(%space, %namespace, "a Reader of a public space is admitted and granted no link: everybody reads it, and no members' change could end the grant");
            return None;
        }
        let until = match self.policy.grant_for {
            Some(d) if d.is_zero() => return None,
            Some(d) => {
                let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
                Some(Timestamp(self.node.now().0.saturating_add(ms)))
            }
            None => None,
        };
        let note = GrantNote {
            offer: offer_name(self.node.name(), id),
            key,
            namespace: namespace.clone(),
            space: space.clone(),
            role,
            until,
            ended: false,
            departure: None,
        };
        let op = self.grant_op(&note)?;
        Some((op, PendingGrant { note }))
    }

    /// Tell the host of the grant a durable admission made, and begin to follow its
    /// space.
    pub(crate) fn granted(self: &Arc<Self>, pending: &PendingGrant) {
        self.tell(&pending.note.grant());
        self.follow(&pending.note.space);
    }

    // ---- the joiner's end ------------------------------------------------------------------

    /// Keep the mirror note of a join that succeeded: the inviter's `key` (the digest of
    /// the key that signed its answer, verified to belong to the offering device under
    /// the anchor the code named), `owner` (its namespace) and `space`, once the entry
    /// that admits this device is applied. The role is the inviter's in the members.
    /// Durable first, then the host is told and the joined list is published. A second
    /// join of the same space by the same key replaces the note (un-ends it); another
    /// key is another entry.
    ///
    /// No note is kept, and why is said, when `space` is not owned by the inviter's own
    /// namespace (the inviter would be granted a link into a space it does not own), or
    /// when the members no longer list this device (nothing is granted).
    ///
    /// # Errors
    /// [`InviteError::Local`] when the store could not make the note durable.
    pub(crate) async fn keep_mirror(
        self: &Arc<Self>,
        key: [u8; 32],
        owner: &Name,
        space: &Name,
    ) -> Result<(), InviteError> {
        if parse_space_name(space).is_none_or(|parsed| parsed.owner != *owner) {
            tracing::warn!(%space, %owner, "the offer's space is not owned by the inviter's own namespace: no mirror grant is kept, so the inviter is not admitted to link back on its account; join a space of the inviter's namespace");
            return Ok(());
        }
        let _one = self.notes.lock().await;
        let probe = MirrorNote {
            key,
            owner: owner.clone(),
            space: space.clone(),
            role: Role::Reader,
            ended: false,
        };
        let note = match self.mirror_standing(&probe) {
            MirrorStanding::In {
                device: Role::Reader,
                ..
            } if self.is_public(space) => {
                tracing::warn!(%space, "this device only reads a public space: no mirror grant is kept, as nothing could end it but the host");
                return Ok(());
            }
            MirrorStanding::In { entry, .. } => MirrorNote {
                role: entry,
                ..probe
            },
            MirrorStanding::Out | MirrorStanding::Unknown => {
                tracing::warn!(%space, "the space's members do not list this device (or the space is not open here): no mirror grant is kept; ask the inviter for a new offer");
                return Ok(());
            }
        };
        self.keep_mirror_note(&note).await?;
        self.tell(&note.grant());
        self.publish_joined();
        self.follow(space);
        tracing::info!(%space, %owner, role = ?note.role, "joined: the inviter may link back for this space");
        Ok(())
    }

    // ---- the spaces joined -----------------------------------------------------------------

    /// The spaces this device joined, derived now (`Invites::joined_folders`): for each
    /// live mirror entry, the inviter, owner, space, this device's role and the other
    /// writers' namespaces, sorted by space, then inviter.
    pub(crate) fn joined_list(&self) -> Vec<JoinedFolder> {
        let mut out: Vec<JoinedFolder> = self
            .live_mirrors()
            .into_iter()
            .map(|(note, role)| JoinedFolder {
                inviter: note.key,
                writers: self.joined_writers(&note.owner, &note.space),
                owner: note.owner,
                folder: note.space,
                role,
            })
            .collect();
        out.sort_by(|a, b| (&a.folder, &a.inviter).cmp(&(&b.folder, &b.inviter)));
        out
    }

    /// The namespaces of the other writers of `space` a link to its inviter routes. The
    /// members are the inviter's word, so a route is made only for a name that cannot
    /// take a name away from a better route of this device's own: each of
    /// [`Self::writer_namespaces`]'s namespaces `w` is dropped when
    ///
    /// - it is not a namespace, is the owner's, or is this device's own or above or
    ///   below it;
    /// - `IntroPolicy::refuses` refuses it (a reserved name, a broad shared one, one
    ///   with too few components);
    /// - it does not name itself: it is neither the namespace of a trust context held
    ///   here nor a self-certifying person's;
    /// - it lies strictly above or below a namespace held here or adopted for a space
    ///   (an exact match is the same prefix, where cost decides).
    ///
    /// At most [`JOINED_WRITERS_MAX`], in order.
    fn joined_writers(&self, owner: &Name, space: &Name) -> Vec<Name> {
        let mut held: Vec<Name> = self
            .node
            .validator()
            .keyring()
            .contexts()
            .iter()
            .map(|context| context.namespace().clone())
            .collect();
        held.extend(self.node.adopted_persons());
        let own = self.node.namespace();
        self.writer_namespaces(space)
            .into_iter()
            .filter(|w| {
                is_namespace(w)
                    && w != owner
                    && !w.has_prefix(own)
                    && !own.has_prefix(w)
                    && self.policy.refuses(w).is_none()
                    && (self.node.person_of(w) == *w
                        || personal_namespace_of(w).as_ref() == Some(w))
                    && held
                        .iter()
                        .all(|h| h == w || !(w.has_prefix(h) || h.has_prefix(w)))
            })
            .take(JOINED_WRITERS_MAX)
            .collect()
    }

    /// The namespaces `W` whose names a grant link of a person admitted to `space`
    /// carries beyond the space's own (`Surface::writer_namespaces`): each writer person
    /// the members of `space` list now (a person is a namespace: exactly it, never a
    /// broader one it lies under), the space's owner excluded, sorted. Empty when the
    /// space is not open here.
    pub(crate) fn writer_namespaces(&self, space: &Name) -> Vec<Name> {
        let Some(heap) = self.heap(space) else {
            return Vec::new();
        };
        let owner = parse_space_name(space).map(|parsed| parsed.owner);
        let mut writers: Vec<Name> = heap
            .members()
            .writers
            .into_iter()
            .filter(|w| owner.as_ref() != Some(w) && is_namespace(w))
            .collect();
        writers.sort();
        writers.dedup();
        writers
    }

    /// Tell the watchers of `Invites::joined_changes` the list changed: derive it now
    /// and, only when it differs from the one the generation stands for, raise the
    /// generation (never repeating a value).
    pub(crate) fn publish_joined(&self) {
        let list = self.joined_list();
        let mut seen = self.joined_seen.lock();
        if *seen == list {
            return;
        }
        *seen = list;
        self.joined_changes
            .send_modify(|generation| *generation += 1);
    }

    pub(crate) fn joined_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.joined_changes.subscribe()
    }

    // ---- the host's ends -------------------------------------------------------------------

    /// The host ends the grants of `key` (`Invites::end_grant`), all of them, or only
    /// those of `space`: the inviter's notes **and** the mirror notes of that key (and
    /// space). The host ended them itself: no departure mark is made, and the host is
    /// not told.
    pub(crate) async fn end_grant(
        &self,
        key: &[u8; 32],
        space: Option<&Name>,
    ) -> Result<bool, InviteError> {
        let _one = self.notes.lock().await;
        let wanted = |s: &Name| space.is_none_or(|space| s == space);
        let live: Vec<GrantNote> = self
            .used_grants()
            .into_iter()
            .filter(|note| note.key == *key && !note.ended && wanted(&note.space))
            .collect();
        let mirrors: Vec<MirrorNote> = self
            .mirror_notes()
            .into_iter()
            .filter(|note| note.key == *key && !note.ended && wanted(&note.space))
            .collect();
        if live.is_empty() && mirrors.is_empty() {
            return Ok(false);
        }
        let mut ops = Vec::with_capacity(live.len() + mirrors.len());
        for mut note in live {
            note.ended = true;
            note.departure = None;
            ops.extend(self.grant_op(&note));
            tracing::info!(offer = %note.offer, space = %note.space, namespace = %note.namespace, "the host ended a grant to link");
        }
        for mut note in mirrors {
            note.ended = true;
            ops.push(self.mirror_op(&note));
            tracing::info!(space = %note.space, owner = %note.owner, "the host ended a mirror grant to link");
        }
        self.store().apply(ops);
        // The routes follow the memory; the flush below makes the end durable.
        self.publish_joined();
        store::flush(self.store()).await.map_err(|why| {
            InviteError::local(format_args!(
                "the end of the grant was not durable ({why}): end it again once the store \
                 works, or the grant stands at the next start"
            ))
        })?;
        Ok(true)
    }

    /// The host sets the date of the grants of `key` (`Invites::renew_grant`).
    pub(crate) async fn renew_grant(
        &self,
        key: &[u8; 32],
        until: Option<Timestamp>,
    ) -> Result<Option<Grant>, InviteError> {
        let _one = self.notes.lock().await;
        let now = self.node.now();
        let mut renewed: Vec<GrantNote> = self
            .used_grants()
            .into_iter()
            .filter(|note| note.key == *key && !note.ended)
            .filter_map(|note| match self.standing(&note.namespace, &note.space) {
                Standing::In(role) => Some(GrantNote {
                    role,
                    until,
                    ..note
                }),
                Standing::Out | Standing::Unknown => None,
            })
            .collect();
        renewed.sort_by(|a, b| a.offer.cmp(&b.offer));
        let Some(first) = renewed.first() else {
            return Ok(None);
        };
        if until.is_some_and(|t| t <= now) {
            return Err(InviteError::BadRequest {
                why: format!(
                    "the date {} is not after this device's clock ({}): give a later date, or \
                     None for a grant that follows the members, or end the grant with \
                     Invites::end_grant",
                    until.map_or(0, |t| t.0),
                    now.0
                ),
            });
        }
        let grant = first.grant();
        let ops: Vec<StoreOp> = renewed
            .iter()
            .filter_map(|note| self.grant_op(note))
            .collect();
        store::apply_durable(self.store(), ops).await?;
        Ok(Some(grant))
    }

    // ---- the departed person's side --------------------------------------------------------

    /// The departed person's side (`Surface::take_departure`): fetch `record`, a members
    /// entry of `space`, and take it as any held entry.
    ///
    /// Only when the device that told it (`from`) lies under the owner namespace of
    /// `space`, this device has the space open (it is, or was, a member), `record` is a
    /// log entry of `space` whose device lies under a namespace this device holds a trust
    /// context of, no other take for `space` is in flight, and fewer than
    /// [`DEPARTURES_PER_MINUTE`] were begun in the last minute. What is fetched is
    /// validated, merged and judged as every entry is (`NodeHandle::fetch_entry`); the
    /// name is a hint only, so an inviter that names another entry gets nothing taken
    /// that the member could not have fetched by any other path.
    pub(crate) async fn take_departure(
        &self,
        from: &Name,
        space: &Name,
        record: &Name,
    ) -> Result<(), InviteError> {
        let refuse = |why: String| InviteError::BadRequest { why };
        let Some(owner) = parse_space_name(space).map(|parsed| parsed.owner) else {
            return Err(refuse(format!(
                "{space} is no space name (<namespace>/32=data/<path>); a departure names the \
                 space the members entry governs: ignore a hint with another name"
            )));
        };
        if !from.has_prefix(&owner) {
            return Err(refuse(format!(
                "the hint came from {from}, which lies under no namespace of {space} ({owner}): \
                 only a device of the space's own namespace lets a member go of it, so this \
                 device ignores a hint from another; ask the person who invited you (a device \
                 of {owner}) to invite you again if you were let go"
            )));
        }
        let Some(log) = parse_log_name(record).filter(|log| log.space == *space) else {
            return Err(refuse(format!(
                "{record} is no entry of {space} (<device>/32=log/<space>/seq=<n>), so it is no \
                 members entry of that space: ignore a hint that names anything else"
            )));
        };
        if self.node.space(space).is_none() {
            return Err(refuse(format!(
                "{space} is not open here, so this device is no member of it and has nothing to \
                 be let go of: join the space first, or ignore the hint"
            )));
        }
        let held = log.device.has_prefix(self.node.namespace())
            || self
                .node
                .validator()
                .keyring()
                .contexts()
                .iter()
                .any(|context| log.device.has_prefix(context.namespace()));
        if !held {
            return Err(refuse(format!(
                "the entry's device {} lies under no namespace this device holds a trust \
                 context of, so an entry it signed cannot be checked here: ignore the hint",
                log.device
            )));
        }
        let _taking = {
            let mut departing = self.departing.lock();
            if departing.contains(space) {
                return Err(InviteError::NotReady {
                    name: record.clone(),
                    why: format!(
                        "a departure entry of {space} is being fetched already: wait for it, \
                         then ask again if the space's members still list this device"
                    ),
                });
            }
            let now = self.node.now();
            let mut window = self.departures_begun.lock();
            while window
                .front()
                .is_some_and(|t| now.0.saturating_sub(t.0) >= DEPARTURE_WINDOW_MS)
            {
                window.pop_front();
            }
            if window.len() >= DEPARTURES_PER_MINUTE {
                return Err(InviteError::NotReady {
                    name: record.clone(),
                    why: format!(
                        "this device began {DEPARTURES_PER_MINUTE} departure fetches in the \
                         last minute, the most it takes: ask again in a minute"
                    ),
                });
            }
            window.push_back(now);
            departing.insert(space.clone());
            Departing {
                grants: self,
                space: space.clone(),
            }
        };
        match self.node.fetch_entry(record).await {
            Ok(_) => Ok(()),
            Err(HeapError::Unavailable { .. }) => Err(InviteError::NotReady {
                name: record.clone(),
                why: format!(
                    "{record} could not be fetched and verified from the link this hint came \
                     over, or from the devices of its namespace: ask again once the link is up"
                ),
            }),
            Err(e) => Err(e.into()),
        }
    }
}

impl Inner {
    /// Keep the mirror note of a join that succeeded (`Grants::keep_mirror`).
    pub(crate) async fn keep_mirror(
        &self,
        inviter_key: [u8; 32],
        inviter: &Name,
        space: &Name,
    ) -> Result<(), InviteError> {
        self.grants.keep_mirror(inviter_key, inviter, space).await
    }
}

impl Invites {
    /// The grants in force now (spec §10 rule 6): for each used offer of this device
    /// whose admission made one, that has not ended (by the space's members leaving the
    /// person out, or by the host, [`end_grant`](Self::end_grant)), is not past its date
    /// if it has one ([`renew_grant`](Self::renew_grant)), and that the space's members
    /// still list (the namespace is a writer or a reader), **in the role they give it**;
    /// then the **mirror entries**, the grants this device was given by joining a space
    /// (key = the inviter's, `namespaces` = `[owner]`, the space, the role the members
    /// give the inviter, `until` = `None`), each only while the members list this device
    /// and the entry has not ended. Sorted by key, then space. Derived from the notes
    /// kept with the use marks, the mirror notes kept at joins and the members, so it is
    /// the same after a restart, less what ended. A note whose MAC does not check is
    /// ignored.
    ///
    /// A host that links installs these at start: `Invites::start` already tells each to
    /// the host (`Host::grant`).
    pub fn grants(&self) -> Vec<Grant> {
        self.inner().grants.live_grants()
    }

    /// The departure marks in force (spec §11 rule 14): for each grant ended by the
    /// members leaving the person out (when `IntroPolicy::departure_for` keeps a mark),
    /// the entry's log name and the date by this device's clock after which it is no
    /// longer shown. A mark a later grant of the same key for the same space supersedes
    /// is not listed. Sorted by key, then space.
    pub fn departures(&self) -> Vec<Departure> {
        self.inner().grants.live_departures()
    }

    /// End the grants of `key` for good, durably: every grant note of that key not yet
    /// ended (for every space), the inviter's notes and the mirror notes alike, is marked
    /// ended before this returns, so a restart does not bring it back. `true` if there
    /// was one not yet ended, `false` if none. Tells the host nothing: the host that
    /// calls this ends its link layer's grant itself. The person stays a member of the
    /// space: removing them is a members entry, not this, and the host's end makes no
    /// departure mark.
    ///
    /// # Errors
    /// [`InviteError::Local`] when the store could not make the end durable: call it
    /// again once it works.
    pub async fn end_grant(&self, key: &[u8; 32]) -> Result<bool, InviteError> {
        self.inner().grants.end_grant(key, None).await
    }

    /// [`end_grant`](Self::end_grant) for the grants of `key` of `space` alone: the
    /// person's grants of other spaces stand.
    ///
    /// # Errors
    /// As [`end_grant`](Self::end_grant).
    pub async fn end_grant_in(&self, key: &[u8; 32], space: &Name) -> Result<bool, InviteError> {
        self.inner().grants.end_grant(key, Some(space)).await
    }

    /// Set the date of the grants of `key`, durably: `Some(t)` makes it the date after
    /// which they are over, `None` gives them no date (they follow the members). Only a
    /// grant the space's members still list the person for, and not ended, is renewed:
    /// one past its old date is renewable, one ended is not (offer the space again).
    /// Returns the grant as it now stands (the first, by offer, when several offers
    /// admitted the key), or `None` when there is none to renew. Tells the host nothing:
    /// the caller installs the returned grant. A mirror entry has no date and is left
    /// untouched.
    ///
    /// # Errors
    /// [`InviteError::BadRequest`] for a date not after this device's clock (give a later
    /// one, `None`, or end the grant); [`InviteError::Local`] when the store could not
    /// make the change durable.
    pub async fn renew_grant(
        &self,
        key: &[u8; 32],
        until: Option<Timestamp>,
    ) -> Result<Option<Grant>, InviteError> {
        self.inner().grants.renew_grant(key, until).await
    }

    /// The spaces this device joined, for the link layer's routes (spec §11 rule 18):
    /// for each live mirror entry whose space's members still list this device, its
    /// [`JoinedFolder`]: the inviter's key, the space and its owner, this device's role
    /// and the other writers' namespaces (at most [`JOINED_WRITERS_MAX`]). Sorted by
    /// space, then inviter. Derived on every call: nothing is cached, so an entry that
    /// adds a writer or ends the mirror shows at the next call.
    pub fn joined_folders(&self) -> Vec<JoinedFolder> {
        self.inner().grants.joined_list()
    }

    /// The generation of [`joined_folders`](Self::joined_folders): the value changes
    /// (never repeating within a run) whenever the list changed, and only then. A watcher
    /// reads `joined_folders` after each change (and once when it starts: the generation
    /// says nothing of what came before it).
    pub fn joined_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner().grants.joined_changes()
    }
}
