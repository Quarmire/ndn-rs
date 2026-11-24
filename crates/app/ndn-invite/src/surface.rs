//! What this device's invitations serve over a link (spec §13, ndn-link §8.6–§8.8): the
//! host's link layer asks the [`Surface`] whether to take a stranger's link at all and
//! which names each kind of link carries, so a stranger gets the one exchange an open
//! offer needs and nothing else the device holds by name, a person admitted to a space
//! gets that space's names, and a person let go gets the one entry that lets them go.
//! The surface holds the invitations weakly: a host whose links outlive them serves
//! nothing.

use std::sync::Weak;

use ndn_foundation_types::Name;

use crate::error::InviteError;
use crate::folder_scope::{departure_carries, folder_carries, writer_carries};
use crate::host::JoinedFolder;
use crate::invites::{Inner, Invites};

/// What this device's invitations serve over a link (spec §13): a host that takes such
/// links gives it to its link layer (ndn-link's `LinkHints::serve`). `Clone + Send +
/// Sync`; it holds the invitations weakly, so the host's links never keep them alive.
/// The prefixes a dialled introduction link routes are
/// [`introduction_prefixes`](crate::introduction_prefixes), a free function.
#[derive(Clone)]
pub struct Surface {
    inner: Weak<Inner>,
}

impl std::fmt::Debug for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Surface")
            .field("alive", &(self.inner.strong_count() > 0))
            .finish()
    }
}

impl Surface {
    pub(crate) fn new(inner: Weak<Inner>) -> Surface {
        Surface { inner }
    }

    /// Whether some offer of this device has not expired by its clock: a stranger's
    /// introduction link is worth taking. A closed offer counts, since it still answers
    /// the key it admitted until it expires (spec §13.1); with none, a stranger gets no
    /// link at all.
    pub fn open(&self) -> bool {
        self.inner.upgrade().is_some_and(|inner| inner.intro_open())
    }

    /// Whether an Interest for `name` may cross an introduction link: an ask
    /// (`<D>/32=intro/<digest>`) while an offer is open, or an offer's own packet
    /// (`<D>/32=intro/offer/<id>`) that has not expired, or the hint record of a short
    /// code (`<D>/32=hint/<token>`, the token of one of this device's own offers: open,
    /// or closed or expired, when its gone mark is the answer). Another log entry, a hint
    /// token this device does not hold or any other packet this device holds by name is
    /// not carried.
    pub fn carries(&self, name: &Name) -> bool {
        self.inner
            .upgrade()
            .is_some_and(|inner| inner.intro_carries(name))
    }

    /// Whether an Interest for `name`, or the Data answering it, may cross the grant
    /// link of a person admitted to `space` (spec §13.3, ndn-link §8.7):
    /// [`folder_carries`], or a name that lets a member reach the **other writers** the
    /// members of `space` list ([`writer_carries`]: their devices' seal keys and the
    /// grant asks to them), for the namespaces [`writer_namespaces`](Self::writer_namespaces)
    /// derives. Read **live on every call** from the members, nothing cached: a writer
    /// the members no longer list drops out at the next call, one they list appears at
    /// the next. `false` once the invitations are gone.
    pub fn grant_carries(&self, space: &Name, name: &Name) -> bool {
        let Some(inner) = self.inner.upgrade() else {
            return false;
        };
        folder_carries(space, name)
            || writer_carries(space, &inner.grants.writer_namespaces(space), name)
    }

    /// Whether `name` may cross the departure link of a person let go by the members
    /// entry `record` ([`departure_carries`]).
    pub fn departure_carries(&self, record: &Name, name: &Name) -> bool {
        departure_carries(record, name)
    }

    /// The namespaces `W` whose devices' seal keys and grant asks a grant link of a
    /// person admitted to `space` carries ([`writer_carries`]): the writer persons the
    /// members of `space` list now, the space's owner excluded, sorted. Read **live**
    /// from the members, as [`grant_carries`](Self::grant_carries) is, which uses this
    /// very list. Empty once the invitations are gone, or when `space` is not open here.
    pub fn writer_namespaces(&self, space: &Name) -> Vec<Name> {
        self.inner
            .upgrade()
            .map(|inner| inner.grants.writer_namespaces(space))
            .unwrap_or_default()
    }

    /// The departed person's side (spec §11 rule 15): this device was told, by the link
    /// layer of the person that invited it, which entry `record` of `space` leaves it
    /// out. Fetch the entry, over the link or from the devices of its namespace
    /// (`NodeHandle::fetch_entry`), and take it as any held entry: validated by its
    /// signatures, merged, judged as ever, so this device's own space then no longer
    /// lists it and it withdraws what it wrote after the cut. The name carries no
    /// authority.
    ///
    /// `from` is the **authenticated device** of the peer that told it (its certificate
    /// validated in a namespace this device holds, on a full link: never an enrollment
    /// or introduction link). Only a device under the space's own namespace
    /// (`<namespace>/32=data/<path>`) can let this device go of the space, so a hint from
    /// any other is refused before it can hold the space's fetch or spend the minute's
    /// bound.
    ///
    /// Taken only when this device has `space` open, `record` is a log entry of `space`
    /// (`<device>/32=log/<space>/seq=<n>`) whose device lies under a namespace this
    /// device holds a trust context of; at most one take of `space` is in flight, and a
    /// bounded number begin in a minute.
    ///
    /// # Errors
    /// [`InviteError::BadRequest`] for a hint that is none of those, or told by a device
    /// outside the space's namespace (ignore it); [`InviteError::NotReady`] while another
    /// take of `space` is under way or when the minute's bound is used up (ask again);
    /// [`InviteError::Heap`] for what the fetch says (not ready, refused, unavailable);
    /// [`InviteError::Local`] once the invitations are gone.
    pub async fn take_departure(
        &self,
        from: &Name,
        space: &Name,
        record: &Name,
    ) -> Result<(), InviteError> {
        let Some(inner) = self.inner.upgrade() else {
            return Err(InviteError::local(
                "the invitations have stopped: a departure is taken by a device that runs",
            ));
        };
        inner.grants.take_departure(from, space, record).await
    }

    /// [`Invites::joined_folders`] through the weak surface, for a link layer that must
    /// not keep the invitations alive. Empty once they are gone.
    pub fn joined_folders(&self) -> Vec<JoinedFolder> {
        self.inner
            .upgrade()
            .map(|inner| inner.grants.joined_list())
            .unwrap_or_default()
    }

    /// [`Invites::joined_changes`] through the weak surface: the generation of
    /// [`joined_folders`](Self::joined_folders). Once the invitations are gone the
    /// receiver is of a channel nothing sends on any more: its value never changes and
    /// its `changed()` returns an error at once, which ends a watcher that follows it.
    pub fn joined_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        match self.inner.upgrade() {
            Some(inner) => inner.grants.joined_changes(),
            None => tokio::sync::watch::channel(0).1,
        }
    }
}

impl Invites {
    /// What this device's invitations serve over a link a stranger dialled, a person
    /// admitted dialled, or a person let go dialled: a host that takes such links gives
    /// it to its link layer. It holds the invitations weakly.
    pub fn surface(&self) -> Surface {
        Surface::new(std::sync::Arc::downgrade(self.inner()))
    }
}
