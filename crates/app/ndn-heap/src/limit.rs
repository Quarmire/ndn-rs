//! A bound on how much of one thing runs at once for one key: the grant asks
//! of one asker device, the run headers of one sender namespace waiting for
//! certificates.

use std::collections::HashMap;

use ndn_foundation_types::Name;
use parking_lot::Mutex;

/// How many places of each key are taken.
#[derive(Default)]
pub(crate) struct Counts(Mutex<HashMap<Name, usize>>);

/// One place of a key, given back when dropped.
pub(crate) struct Place<'a> {
    counts: &'a Counts,
    key: Name,
}

impl Counts {
    /// A place for `key`, unless `max` are taken for it already.
    pub(crate) fn take(&self, key: &Name, max: usize) -> Option<Place<'_>> {
        let mut by = self.0.lock();
        let taken = by.entry(key.clone()).or_default();
        if *taken >= max {
            return None;
        }
        *taken += 1;
        Some(Place {
            counts: self,
            key: key.clone(),
        })
    }

    /// How many keys have a place taken.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.lock().len()
    }
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        let mut by = self.counts.0.lock();
        if let Some(taken) = by.get_mut(&self.key) {
            *taken -= 1;
            if *taken == 0 {
                by.remove(&self.key);
            }
        }
    }
}
