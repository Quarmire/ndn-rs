//! Store writes kept together (spec §4.2, "One batch per put").
//!
//! A put makes several store writes: the entry and its pieces, the written
//! marker, the verified marker. Made one by one each is a call into the
//! engine (a `write(2)` on fjall, an fsynced transaction on redb), and a
//! kill between two of them leaves a state no put leaves. The device wraps
//! the store it is given in a [`Stage`] and opens a [`Batch`] around the
//! stretch of a put that writes: every write the thread makes through the
//! stage meanwhile is kept, and handed to the store as ONE
//! [`DataStore::apply`] when the batch ends.
//!
//! A batch is always opened by a thread holding the device's state lock, in
//! a stretch with no `await`, and ends before that lock is released: no
//! other thread publishes (the committer reads the log head under that
//! lock) what a batch of this thread still holds. Writes of any thread
//! with no batch open go straight through, in the order made.

use std::sync::Arc;
use std::thread::ThreadId;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_sync::{DataStore, StoreOp};
use parking_lot::Mutex;

/// The batch open on one thread: what it has written so far.
struct Open {
    owner: ThreadId,
    /// Batches of the owner nested in this one (inner ones join the outer).
    depth: usize,
    ops: Vec<StoreOp>,
}

/// The device's store, with batches ([`Self::batch`]).
pub(crate) struct Stage {
    store: Arc<dyn DataStore>,
    open: Mutex<Option<Open>>,
}

/// Writes made by the thread that opened it, kept until it is dropped
/// ([`Stage::batch`]).
#[must_use = "a batch ends, and writes what it kept, when it is dropped"]
pub(crate) struct Batch<'a> {
    /// The stage whose batch this thread opened or joined; `None` when
    /// another thread's batch was open (this thread then writes straight
    /// through, as before batches).
    stage: Option<&'a Stage>,
}

impl Stage {
    pub(crate) fn new(store: Arc<dyn DataStore>) -> Arc<Stage> {
        Arc::new(Stage {
            store,
            open: Mutex::new(None),
        })
    }

    /// Open a batch on this thread, or join the one it has open. Writes this
    /// thread makes through the stage are kept until the outermost guard
    /// drops, and then reach the store as one [`DataStore::apply`], in the
    /// order made.
    pub(crate) fn batch(&self) -> Batch<'_> {
        let me = std::thread::current().id();
        let mut open = self.open.lock();
        match open.as_mut() {
            Some(o) if o.owner == me => {
                o.depth += 1;
                Batch { stage: Some(self) }
            }
            // Another thread's batch is open: this one writes through.
            Some(_) => Batch { stage: None },
            None => {
                *open = Some(Open {
                    owner: me,
                    depth: 1,
                    ops: Vec::new(),
                });
                Batch { stage: Some(self) }
            }
        }
    }

    /// Keep `op` in this thread's open batch; give it back when this thread
    /// has none.
    fn keep(&self, op: StoreOp) -> Option<StoreOp> {
        let mut open = self.open.lock();
        match open.as_mut() {
            Some(o) if o.owner == std::thread::current().id() => {
                o.ops.push(op);
                None
            }
            _ => Some(op),
        }
    }

    /// What this thread's open batch says of `name`: `Some(Some(wire))` it
    /// stores it, `Some(None)` it removes it, `None` nothing (read the
    /// store).
    fn staged(&self, name: &Name) -> Option<Option<Bytes>> {
        let open = self.open.lock();
        let o = open
            .as_ref()
            .filter(|o| o.owner == std::thread::current().id())?;
        o.ops.iter().rev().find_map(|op| match op {
            StoreOp::Insert(n, wire) if n == name => Some(Some(wire.clone())),
            StoreOp::Remove(n) if n == name => Some(None),
            _ => None,
        })
    }

    /// Hand what this thread's open batch holds so far to the store (a
    /// boundary: a read by prefix must see it), and go on keeping.
    fn settle(&self) {
        let ops = {
            let mut open = self.open.lock();
            match open.as_mut() {
                Some(o) if o.owner == std::thread::current().id() => std::mem::take(&mut o.ops),
                _ => return,
            }
        };
        if !ops.is_empty() {
            self.store.apply(ops);
        }
    }
}

impl Drop for Batch<'_> {
    fn drop(&mut self) {
        let Some(stage) = self.stage else { return };
        let ops = {
            let mut open = stage.open.lock();
            let o = open
                .as_mut()
                .expect("a batch's stage holds the batch it opened until the batch drops");
            o.depth -= 1;
            if o.depth > 0 {
                return;
            }
            open.take().map(|o| o.ops).unwrap_or_default()
        };
        if !ops.is_empty() {
            stage.store.apply(ops);
        }
    }
}

impl DataStore for Stage {
    fn insert(&self, name: Name, wire: Bytes) {
        if let Some(StoreOp::Insert(name, wire)) = self.keep(StoreOp::Insert(name, wire)) {
            self.store.insert(name, wire);
        }
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        match self.staged(name) {
            Some(own) => own,
            None => self.store.get(name),
        }
    }

    fn contains(&self, name: &Name) -> bool {
        match self.staged(name) {
            Some(own) => own.is_some(),
            None => self.store.contains(name),
        }
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.settle();
        self.store.find_under(prefix)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.settle();
        self.store.scan_under(prefix, limit)
    }

    fn remove(&self, name: &Name) {
        if let Some(StoreOp::Remove(name)) = self.keep(StoreOp::Remove(name.clone())) {
            self.store.remove(&name);
        }
    }

    fn apply(&self, ops: Vec<StoreOp>) {
        let mut open = self.open.lock();
        match open.as_mut() {
            Some(o) if o.owner == std::thread::current().id() => o.ops.extend(ops),
            _ => {
                drop(open);
                self.store.apply(ops);
            }
        }
    }

    fn sync(&self) -> std::io::Result<()> {
        self.store.sync()
    }

    fn sync_is_immediate(&self) -> bool {
        self.store.sync_is_immediate()
    }
}
