//! Host notes (spec §19.9): a small durable key-value surface a host keeps in the device's local
//! store, for what it learned and wants after a restart: the addresses a link layer reached its
//! peers at, say. Never served, announced or trusted: a note is local, unauthenticated host data.
//!
//! Layout in the store: `/localhost/ndn-data/host/<area>/<key>`, the value the note's octets as
//! given, under a local name no device serves ([`Inner::packet_for`] answers no such name, and
//! the device's producer is registered under the device's own prefix only).

use std::sync::{Arc, Weak};

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};

use super::{Device, Inner, local};
use crate::error::DataError;

/// Notes are counted and written under this lock, not the device's state lock: counting an area
/// reads its notes from the store, and no question of the layer waits for that. It is shared by
/// every device of the process; a note's write is a store write and nothing else.
static WRITING: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// The longest area or key, in octets.
pub const NOTE_PART_MAX: usize = 64;

/// The largest value of a note, in octets.
pub const NOTE_VALUE_MAX: usize = 4096;

/// How many notes one area holds.
pub const NOTES_PER_AREA_MAX: usize = 1024;

fn host_prefix() -> Name {
    "/localhost/ndn-data/host".parse().expect("a valid name")
}

/// Whether `name` is a stored name of host notes (the restore of the log skips them).
pub(super) fn is_stored(name: &Name) -> bool {
    name.has_prefix(&host_prefix())
}

fn area_name(area: &str) -> Name {
    host_prefix().append_component(NameComponent::generic(Bytes::copy_from_slice(
        area.as_bytes(),
    )))
}

fn note_name(area: &str, key: &str) -> Name {
    area_name(area).append_component(NameComponent::generic(Bytes::copy_from_slice(
        key.as_bytes(),
    )))
}

/// `part` (an area or a key) as the rules of spec §19.9 allow it, or the rule it breaks.
fn check_part(what: &str, part: &str) -> Result<(), DataError> {
    let refuse = |why: String| DataError::BadRequest {
        name: host_prefix(),
        why: format!(
            "a note {what} {part:?} {why}; use 1 to {NOTE_PART_MAX} octets with no '/' and no \
             control character"
        ),
    };
    if part.is_empty() {
        return Err(refuse("is empty".into()));
    }
    if part.len() > NOTE_PART_MAX {
        return Err(refuse(format!("is {} octets long", part.len())));
    }
    if part.contains('/') {
        return Err(refuse("contains a '/'".into()));
    }
    if part.chars().any(char::is_control) {
        return Err(refuse("contains a control character".into()));
    }
    Ok(())
}

/// The notes of one area of a device (spec §19.9): small values by key, durable once
/// [`put`](Self::put) or [`remove`](Self::remove) returns. Cheap to clone; it does not keep the
/// device alive: once the device stopped, every call but the reads is a [`DataError::Local`].
#[derive(Clone)]
pub struct LocalNotes {
    inner: Weak<Inner>,
    area: String,
}

impl std::fmt::Debug for LocalNotes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalNotes")
            .field("area", &self.area)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// The notes of `area` in this device's local store (spec §19.9). Nothing is read or written
    /// here; an `area` the rules refuse (empty, over [`NOTE_PART_MAX`] octets, a '/' or a control
    /// character in it) is refused by each call on the result, as a key is.
    pub fn local_notes(&self, area: &str) -> LocalNotes {
        LocalNotes {
            inner: Arc::downgrade(&self.inner),
            area: area.to_owned(),
        }
    }
}

impl LocalNotes {
    /// The area these notes are in.
    pub fn area(&self) -> &str {
        &self.area
    }

    fn device(&self) -> Result<Arc<Inner>, DataError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or_else(|| local("the device these notes belong to was dropped; start it again"))?;
        if inner.stopped.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(local(
                "the device these notes belong to stopped; start it again",
            ));
        }
        Ok(inner)
    }

    /// The note `key`: `None` when there is none, [`DataError::BadRequest`] when the area or the
    /// key breaks a rule of spec §19.9.
    pub fn get(&self, key: &str) -> Result<Option<Bytes>, DataError> {
        check_part("area", &self.area)?;
        check_part("key", key)?;
        let inner = self.device()?;
        Ok(inner.store.get(&note_name(&self.area, key)))
    }

    /// Every note of the area, `(key, value)` by key.
    pub fn list(&self) -> Result<Vec<(String, Bytes)>, DataError> {
        check_part("area", &self.area)?;
        let inner = self.device()?;
        Ok(listed(&inner, &self.area))
    }

    /// Keep `value` as the note `key`, replacing one: returns once the store's durability barrier
    /// passed, so a note a `put` returned for survives a power loss.
    ///
    /// [`DataError::BadRequest`] when the area or key breaks a rule of spec §19.9, when `value`
    /// is over [`NOTE_VALUE_MAX`] octets, or when the area holds [`NOTES_PER_AREA_MAX`] notes
    /// already and `key` is not one of them (remove one first); nothing is written.
    /// [`DataError::Local`] when the device stopped, or its store cannot make the write durable.
    pub async fn put(&self, key: &str, value: &[u8]) -> Result<(), DataError> {
        check_part("area", &self.area)?;
        check_part("key", key)?;
        if value.len() > NOTE_VALUE_MAX {
            return Err(DataError::BadRequest {
                name: note_name(&self.area, key),
                why: format!(
                    "a note's value is at most {NOTE_VALUE_MAX} octets and this is {}; keep \
                     less in a note",
                    value.len()
                ),
            });
        }
        let inner = self.device()?;
        let name = note_name(&self.area, key);
        {
            // The count and the write are one step: two puts cannot both take the last place.
            let _write = WRITING.lock();
            if !inner.store.contains(&name)
                && listed(&inner, &self.area).len() >= NOTES_PER_AREA_MAX
            {
                return Err(DataError::BadRequest {
                    name,
                    why: format!(
                        "the area {:?} holds {NOTES_PER_AREA_MAX} notes already, the most an \
                         area may; remove one before keeping another",
                        self.area
                    ),
                });
            }
            inner.store.insert(name, Bytes::copy_from_slice(value));
        }
        inner.barrier_for_notes().await
    }

    /// Remove the note `key` (none is not an error): returns once the store's durability barrier
    /// passed, so a removal that returned is not undone by a power loss. Refusals as [`put`].
    ///
    /// [`put`]: Self::put
    pub async fn remove(&self, key: &str) -> Result<(), DataError> {
        check_part("area", &self.area)?;
        check_part("key", key)?;
        let inner = self.device()?;
        {
            let _write = WRITING.lock();
            inner.store.remove(&note_name(&self.area, key));
        }
        inner.barrier_for_notes().await
    }
}

impl Inner {
    async fn barrier_for_notes(&self) -> Result<(), DataError> {
        if self.barrier().await {
            Ok(())
        } else {
            Err(local(
                "the device stopped before the note was durable; start it again",
            ))
        }
    }
}

/// The notes of `area`, by key.
fn listed(inner: &Inner, area: &str) -> Vec<(String, Bytes)> {
    let prefix = area_name(area);
    let depth = prefix.components().len();
    let mut out: Vec<(String, Bytes)> = inner
        .store
        .scan_under(&prefix, 0)
        .into_iter()
        .filter_map(|(name, value)| {
            let comps = name.components();
            if comps.len() != depth + 1 {
                return None;
            }
            let key = std::str::from_utf8(&comps[depth].value).ok()?.to_owned();
            Some((key, value))
        })
        .collect();
    out.sort();
    out
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "notes_tests.rs"]
mod tests;
