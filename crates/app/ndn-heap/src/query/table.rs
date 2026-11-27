//! What a node keeps of serving: the prefixes its heaps serve and the handlers behind them, and
//! the hints it has heard of which devices serve what (docs/specs/query.md, Several servers).
//!
//! Both are memory only and bounded; nothing here is persisted and a restart forgets it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ndn_foundation_types::Name;
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::types::{Handler, SERVE_PREFIX_MAX, SERVE_PREFIXES_MAX, ServeError};
use crate::rt::Instant;

/// One served prefix.
struct Served {
    token: u64,
    prefix: Name,
    handler: Arc<dyn Handler>,
}

/// The prefixes this node's heaps serve, per space.
#[derive(Default)]
pub(crate) struct ServeTable {
    state: Mutex<TableState>,
}

#[derive(Default)]
struct TableState {
    next: u64,
    spaces: HashMap<Name, Vec<Served>>,
}

/// The octets of a name's components, as a prefix is measured.
fn octets(name: &Name) -> usize {
    name.components().iter().map(|c| c.value.len()).sum()
}

impl ServeTable {
    /// Serve `prefix` of `space` with `handler`. Returns the token that removes it.
    ///
    /// # Errors
    ///
    /// [`ServeError::BadPrefix`] over 255 octets, [`ServeError::Overlap`] when the space serves
    /// exactly this prefix already (nested prefixes are allowed), [`ServeError::TooMany`] at 64
    /// prefixes in the space.
    pub(crate) fn add(
        &self,
        space: &Name,
        prefix: Name,
        handler: Arc<dyn Handler>,
    ) -> Result<u64, ServeError> {
        let size = octets(&prefix);
        if size > SERVE_PREFIX_MAX {
            return Err(ServeError::BadPrefix {
                size,
                max: SERVE_PREFIX_MAX,
            });
        }
        let mut st = self.state.lock();
        let token = st.next;
        let served = st.spaces.entry(space.clone()).or_default();
        if let Some(existing) = served.iter().find(|s| s.prefix == prefix) {
            return Err(ServeError::Overlap {
                existing: existing.prefix.clone(),
            });
        }
        if served.len() >= SERVE_PREFIXES_MAX {
            return Err(ServeError::TooMany {
                max: SERVE_PREFIXES_MAX,
            });
        }
        served.push(Served {
            token,
            prefix,
            handler,
        });
        st.next += 1;
        Ok(token)
    }

    /// Stop serving what `token` named.
    pub(crate) fn remove(&self, space: &Name, token: u64) {
        let mut st = self.state.lock();
        if let Some(served) = st.spaces.get_mut(space) {
            served.retain(|s| s.token != token);
            if served.is_empty() {
                st.spaces.remove(space);
            }
        }
    }

    /// The handler of the **longest** served prefix of `path` in `space`, with that prefix.
    pub(crate) fn lookup(&self, space: &Name, path: &Name) -> Option<(Name, Arc<dyn Handler>)> {
        let st = self.state.lock();
        st.spaces
            .get(space)?
            .iter()
            .filter(|s| path.has_prefix(&s.prefix))
            .max_by_key(|s| s.prefix.len())
            .map(|s| (s.prefix.clone(), Arc::clone(&s.handler)))
    }

    /// The prefixes `space` serves, in name order.
    pub(crate) fn prefixes(&self, space: &Name) -> Vec<Name> {
        let st = self.state.lock();
        let mut all: Vec<Name> = st
            .spaces
            .get(space)
            .map(|served| served.iter().map(|s| s.prefix.clone()).collect())
            .unwrap_or_default();
        all.sort();
        all
    }

    /// Every space with a served prefix.
    pub(crate) fn spaces(&self) -> Vec<Name> {
        self.state.lock().spaces.keys().cloned().collect()
    }
}

/// How long a heard announce counts as a hint: three of the announce's 30 s periods.
pub(crate) const HINT_TTL: Duration = Duration::from_secs(90);

/// The most devices one space keeps hints of: the ones heard last.
pub(crate) const HINTS_PER_SPACE: usize = 256;

/// What an announce said of one device.
struct Hint {
    device: Name,
    serves: Vec<Name>,
    heard: Instant,
}

/// The devices announces say serve queries, per space: **a hint**, as every announce is. The
/// asker still judges the device a writer offline before it asks, and the server's own judgement
/// of the query is the authority.
#[derive(Default)]
pub(crate) struct Hints {
    spaces: Mutex<HashMap<Name, Vec<Hint>>>,
    heard: Notify,
}

impl Hints {
    /// An announce of `device` over `space` was heard at `now`, listing `serves` (empty: the
    /// device serves nothing now, and its hint goes). A table past [`HINTS_PER_SPACE`] drops the
    /// device heard longest ago.
    pub(crate) fn record(&self, space: &Name, device: &Name, serves: &[Name], now: Instant) {
        {
            let mut spaces = self.spaces.lock();
            let hints = spaces.entry(space.clone()).or_default();
            hints.retain(|h| {
                h.device != *device && now.saturating_duration_since(h.heard) < HINT_TTL
            });
            if !serves.is_empty() {
                if hints.len() >= HINTS_PER_SPACE
                    && let Some(oldest) = hints
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, h)| h.heard)
                        .map(|(i, _)| i)
                {
                    hints.swap_remove(oldest);
                }
                hints.push(Hint {
                    device: device.clone(),
                    serves: serves.to_vec(),
                    heard: now,
                });
            }
            if hints.is_empty() {
                spaces.remove(space);
            }
        }
        self.heard.notify_waiters();
    }

    /// The devices of `space` heard to serve a prefix of `path` within [`HINT_TTL`] of `now`,
    /// the one heard last first.
    pub(crate) fn serving(&self, space: &Name, path: &Name, now: Instant) -> Vec<Name> {
        let spaces = self.spaces.lock();
        let mut found: Vec<&Hint> = spaces
            .get(space)
            .into_iter()
            .flatten()
            .filter(|h| now.saturating_duration_since(h.heard) < HINT_TTL)
            .filter(|h| h.serves.iter().any(|p| path.has_prefix(p)))
            .collect();
        found.sort_by_key(|h| std::cmp::Reverse(h.heard));
        found.into_iter().map(|h| h.device.clone()).collect()
    }

    /// Every device of `space` heard to serve something within [`HINT_TTL`] of `now`, the one
    /// heard last first: the announcing devices a `Targets::Person` query may add to the ones
    /// the record knows.
    pub(crate) fn devices(&self, space: &Name, now: Instant) -> Vec<Name> {
        let spaces = self.spaces.lock();
        let mut found: Vec<&Hint> = spaces
            .get(space)
            .into_iter()
            .flatten()
            .filter(|h| now.saturating_duration_since(h.heard) < HINT_TTL)
            .collect();
        found.sort_by_key(|h| std::cmp::Reverse(h.heard));
        found.into_iter().map(|h| h.device.clone()).collect()
    }

    /// Resolves at the next announce recorded: what an asker with no known server waits on.
    pub(crate) fn heard(&self) -> &Notify {
        &self.heard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{Query, Reply};

    fn n(uri: &str) -> Name {
        uri.parse().unwrap()
    }

    fn handler(tag: &'static str) -> Arc<dyn Handler> {
        Arc::new(move |_q: Query| async move {
            Reply::Answer(bytes::Bytes::from_static(tag.as_bytes()))
        })
    }

    #[test]
    fn the_longest_served_prefix_answers_and_a_prefix_that_is_not_one_does_not() {
        let table = ServeTable::default();
        let space = n("/alice/32=data/game");
        table.add(&space, n("/world"), handler("a")).unwrap();
        table.add(&space, n("/world/pickup"), handler("b")).unwrap();
        let (prefix, _) = table.lookup(&space, &n("/world/pickup/7")).unwrap();
        assert_eq!(prefix, n("/world/pickup"), "the longest wins");
        let (prefix, _) = table.lookup(&space, &n("/world/chat")).unwrap();
        assert_eq!(prefix, n("/world"));
        assert!(
            table.lookup(&space, &n("/worldwide")).is_none(),
            "a component prefix"
        );
        assert!(
            table
                .lookup(&n("/alice/32=data/other"), &n("/world"))
                .is_none()
        );
    }

    #[test]
    fn the_same_prefix_twice_is_overlap_and_the_limit_is_64() {
        let table = ServeTable::default();
        let space = n("/alice/32=data/game");
        let token = table.add(&space, n("/a"), handler("a")).unwrap();
        assert!(matches!(
            table.add(&space, n("/a"), handler("b")),
            Err(ServeError::Overlap { .. })
        ));
        table.remove(&space, token);
        table.add(&space, n("/a"), handler("b")).unwrap();
        for i in 1..SERVE_PREFIXES_MAX {
            table
                .add(&space, n(&format!("/p{i}")), handler("x"))
                .unwrap();
        }
        assert!(matches!(
            table.add(&space, n("/one-more"), handler("x")),
            Err(ServeError::TooMany { max: 64 })
        ));
    }

    #[test]
    fn a_prefix_over_255_octets_is_refused() {
        let table = ServeTable::default();
        let long = format!("/{}", "x".repeat(256));
        assert!(matches!(
            table.add(&n("/a/32=data/s"), n(&long), handler("a")),
            Err(ServeError::BadPrefix {
                size: 256,
                max: 255
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn hints_are_found_by_prefix_newest_first_and_lapse() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        hints.record(&space, &n("/alice/a"), &[n("/world")], t0);
        hints.record(
            &space,
            &n("/alice/b"),
            &[n("/world/pickup")],
            t0 + Duration::from_secs(1),
        );
        hints.record(
            &space,
            &n("/alice/c"),
            &[n("/other")],
            t0 + Duration::from_secs(2),
        );
        let now = t0 + Duration::from_secs(3);
        assert_eq!(
            hints.serving(&space, &n("/world/pickup/1"), now),
            vec![n("/alice/b"), n("/alice/a")]
        );
        assert!(hints.serving(&space, &n("/nothing"), now).is_empty());
        assert!(
            hints
                .serving(&space, &n("/world"), t0 + HINT_TTL + Duration::from_secs(1))
                .is_empty(),
            "a hint older than its TTL is not one"
        );
        hints.record(&space, &n("/alice/a"), &[], now);
        assert_eq!(
            hints.serving(&space, &n("/world/pickup/1"), now),
            vec![n("/alice/b")],
            "an announce that lists nothing takes the device's hint away"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_hints_kept_per_space_are_bounded_and_the_oldest_goes() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        for i in 0..(HINTS_PER_SPACE + 5) {
            hints.record(
                &space,
                &n(&format!("/alice/d{i}")),
                &[n("/w")],
                t0 + Duration::from_millis(i as u64),
            );
        }
        let now = t0 + Duration::from_secs(1);
        let found = hints.serving(&space, &n("/w"), now);
        assert_eq!(found.len(), HINTS_PER_SPACE);
        assert!(!found.contains(&n("/alice/d0")), "the first heard went");
        assert!(found.contains(&n(&format!("/alice/d{}", HINTS_PER_SPACE + 4))));
    }
}
