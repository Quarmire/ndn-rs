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

/// How long a heard prefix counts as a hint: three of the announce's 30 s periods.
pub(crate) const HINT_TTL: Duration = Duration::from_secs(90);

/// The most devices one space keeps hints of among those **vouched for**: the ones the record
/// holds an admitted entry of, or that answered a signed query. The record bounds the first
/// kind, an announce cannot make one; a table past it drops the device heard longest ago.
pub(crate) const HINTS_PER_SPACE: usize = 256;

/// The most vouched devices one person has hints of: a writer's devices are more than one
/// query asks ([`TARGETS_MAX`](super::types::TARGETS_MAX)), and no person may take the table.
pub(crate) const HINTS_PER_PERSON: usize = 32;

/// The most devices one space keeps hints of that nothing vouches for: an announce is unsigned,
/// so any name under a writer's namespace passes for one of her devices (a writer who has put
/// nothing has no entry, and is such a device too). This pool is its own, so that names a
/// stranger makes up cannot push a vouched device out.
pub(crate) const HINTS_UNVOUCHED_PER_SPACE: usize = 16;

/// The most unvouched devices of one person: names a stranger makes up under her namespace
/// fill her share and no more. A device already held is always refreshed; a new name is not
/// taken once the share is full (the first heard stay until they lapse).
pub(crate) const HINTS_UNVOUCHED_PER_PERSON: usize = 4;

/// The most devices per space remembered as having answered a signed query.
pub(crate) const PROVEN_PER_SPACE: usize = 64;

/// What an announce said of one device: the prefixes, each as of when it was last heard.
#[derive(Clone)]
struct Hint {
    device: Name,
    person: Name,
    /// The record held an admitted entry of the device when it was last heard.
    vouched: bool,
    serves: Vec<(Name, Instant)>,
}

impl Hint {
    fn lapsed(heard: Instant, now: Instant) -> bool {
        now.saturating_duration_since(heard) >= HINT_TTL
    }

    /// The moment the newest prefix not lapsed was heard, if any.
    fn heard(&self, now: Instant) -> Option<Instant> {
        self.serves
            .iter()
            .map(|(_, at)| *at)
            .filter(|at| !Self::lapsed(*at, now))
            .max()
    }

    /// The moment the newest prefix of `path` not lapsed was heard, if any.
    fn heard_for(&self, path: &Name, now: Instant) -> Option<Instant> {
        self.serves
            .iter()
            .filter(|(p, at)| path.has_prefix(p) && !Self::lapsed(*at, now))
            .map(|(_, at)| *at)
            .max()
    }

    /// Take `serves` as heard at `now`: a prefix held is refreshed, a new one is added unless
    /// the device holds [`SERVE_PREFIXES_MAX`] not lapsed (nothing is replaced: what is said of
    /// a device in the clear takes nothing away). The lapsed go.
    fn hear(&mut self, serves: &[Name], now: Instant) {
        self.serves.retain(|(_, at)| !Self::lapsed(*at, now));
        for prefix in serves {
            if let Some((_, at)) = self.serves.iter_mut().find(|(p, _)| p == prefix) {
                *at = now;
            } else if self.serves.len() < SERVE_PREFIXES_MAX {
                self.serves.push((prefix.clone(), now));
            }
        }
    }
}

#[derive(Default)]
struct SpaceHints {
    hints: Vec<Hint>,
    /// The devices whose signed answer to a query was judged good, and when.
    proven: HashMap<Name, Instant>,
}

impl SpaceHints {
    /// Vouched for: the record holds an entry of it, or it answered a signed query.
    fn protected(&self, hint: &Hint) -> bool {
        hint.vouched || self.proven.contains_key(&hint.device)
    }

    /// Order of trust: answered a signed query, then vouched by the record, then neither.
    fn rank(&self, hint: &Hint) -> u8 {
        if self.proven.contains_key(&hint.device) {
            2
        } else {
            u8::from(hint.vouched)
        }
    }

    /// The index of the hint heard longest ago among those `pick` takes that no signed answer
    /// vouched for.
    fn oldest(&self, now: Instant, pick: impl Fn(&Hint) -> bool) -> Option<usize> {
        self.hints
            .iter()
            .enumerate()
            .filter(|(_, h)| pick(h) && !self.proven.contains_key(&h.device))
            .min_by_key(|(_, h)| h.heard(now))
            .map(|(i, _)| i)
    }

    /// Make room for `hint` in its pool (a device that is not in the table). `false`: the pool is
    /// full of what must stay, and the hint is not taken.
    fn make_room(&mut self, hint: &Hint, now: Instant) -> bool {
        if self.protected(hint) {
            let held = |s: &Self, person: Option<&Name>| {
                s.hints
                    .iter()
                    .filter(|h| s.protected(h) && person.is_none_or(|p| h.person == *p))
                    .count()
            };
            while held(self, Some(&hint.person)) >= HINTS_PER_PERSON {
                let Some(i) = self.oldest(now, |h| h.person == hint.person) else {
                    return false;
                };
                self.hints.swap_remove(i);
            }
            while held(self, None) >= HINTS_PER_SPACE {
                let Some(i) = self.oldest(now, |_| true) else {
                    return false;
                };
                self.hints.swap_remove(i);
            }
            true
        } else {
            let held = |person: Option<&Name>| {
                self.hints
                    .iter()
                    .filter(|h| !self.protected(h) && person.is_none_or(|p| h.person == *p))
                    .count()
            };
            held(Some(&hint.person)) < HINTS_UNVOUCHED_PER_PERSON
                && held(None) < HINTS_UNVOUCHED_PER_SPACE
        }
    }
}

/// The devices announces say serve queries, per space: **a hint**, as every announce is. The
/// asker still judges the device a writer offline before it asks, and the server's own judgement
/// of the query is the authority.
///
/// An announce is unsigned and anyone may name a device, so a hint is trusted as far as it can
/// be vouched for:
/// - an announce never removes or replaces a hint, it only adds prefixes to a device and
///   refreshes the ones it lists: only the lapse ([`HINT_TTL`], per prefix) takes a prefix away;
/// - devices the record holds an admitted entry of, and devices that answered a signed query
///   ([`Self::proven`]), are kept in a pool names a stranger cannot reach, bounded per person
///   ([`HINTS_PER_PERSON`]) and per space ([`HINTS_PER_SPACE`]);
/// - every other device is kept in a small pool of its own ([`HINTS_UNVOUCHED_PER_SPACE`], per
///   person [`HINTS_UNVOUCHED_PER_PERSON`]) and a new name is refused when it is full;
/// - devices are returned best vouched first: answered a signed query, then vouched by the
///   record, then neither, and within each the one heard last first.
#[derive(Default)]
pub(crate) struct Hints {
    spaces: Mutex<HashMap<Name, SpaceHints>>,
    heard: Notify,
}

impl Hints {
    /// An announce of `device` (of `person`) over `space` was heard at `now`, listing `serves`;
    /// `vouched`: the record holds an admitted entry of the device. An announce that lists
    /// nothing is nothing to record: it takes no hint away, since it is unsigned.
    pub(crate) fn record(
        &self,
        space: &Name,
        device: &Name,
        person: &Name,
        vouched: bool,
        serves: &[Name],
        now: Instant,
    ) {
        if serves.is_empty() {
            return;
        }
        let taken = {
            let mut spaces = self.spaces.lock();
            let held = spaces.entry(space.clone()).or_default();
            held.hints.retain(|h| h.heard(now).is_some());
            let old = held
                .hints
                .iter()
                .position(|h| h.device == *device)
                .map(|i| held.hints.swap_remove(i));
            let mut hint = old.clone().unwrap_or_else(|| Hint {
                device: device.clone(),
                person: person.clone(),
                vouched,
                serves: Vec::new(),
            });
            hint.vouched = vouched;
            hint.person = person.clone();
            hint.hear(serves, now);
            let taken = !hint.serves.is_empty() && held.make_room(&hint, now);
            if taken {
                held.hints.push(hint);
            } else if let Some(old) = old {
                held.hints.push(old);
            }
            if held.hints.is_empty() && held.proven.is_empty() {
                spaces.remove(space);
            }
            taken
        };
        if taken {
            self.heard.notify_waiters();
        }
    }

    /// `device` answered a signed query over `space` and the answer was judged good (a signature
    /// by a key that stands as a writer): it is no name a stranger made up, so its hint is
    /// vouched for and outranks the ones heard later that are not. At most
    /// [`PROVEN_PER_SPACE`] are remembered, the one proven longest ago going first.
    pub(crate) fn proven(&self, space: &Name, device: &Name, now: Instant) {
        let mut spaces = self.spaces.lock();
        let held = spaces.entry(space.clone()).or_default();
        if held.proven.len() >= PROVEN_PER_SPACE
            && !held.proven.contains_key(device)
            && let Some(oldest) = held
                .proven
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(d, _)| d.clone())
        {
            held.proven.remove(&oldest);
        }
        held.proven.insert(device.clone(), now);
    }

    /// The devices of `space` heard to serve a prefix of `path` within [`HINT_TTL`] of `now`,
    /// the best vouched first and, among equals, the one heard last.
    pub(crate) fn serving(&self, space: &Name, path: &Name, now: Instant) -> Vec<Name> {
        let spaces = self.spaces.lock();
        let Some(held) = spaces.get(space) else {
            return Vec::new();
        };
        let mut found: Vec<(u8, Instant, &Name)> = held
            .hints
            .iter()
            .filter_map(|h| Some((held.rank(h), h.heard_for(path, now)?, &h.device)))
            .collect();
        found.sort_by_key(|(rank, at, _)| std::cmp::Reverse((*rank, *at)));
        found.into_iter().map(|(_, _, d)| d.clone()).collect()
    }

    /// Every device of `space` heard to serve something within [`HINT_TTL`] of `now`, in the
    /// order of [`Self::serving`]: the announcing devices a `Targets::Person` query may add to
    /// the ones the record knows.
    pub(crate) fn devices(&self, space: &Name, now: Instant) -> Vec<Name> {
        let spaces = self.spaces.lock();
        let Some(held) = spaces.get(space) else {
            return Vec::new();
        };
        let mut found: Vec<(u8, Instant, &Name)> = held
            .hints
            .iter()
            .filter_map(|h| Some((held.rank(h), h.heard(now)?, &h.device)))
            .collect();
        found.sort_by_key(|(rank, at, _)| std::cmp::Reverse((*rank, *at)));
        found.into_iter().map(|(_, _, d)| d.clone()).collect()
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

    /// The person of a test device: its first component (`/alice/a` is `/alice`'s).
    fn person(device: &str) -> Name {
        Name::from_components(n(device).components()[..1].iter().cloned())
    }

    fn record(
        hints: &Hints,
        space: &Name,
        device: &str,
        vouched: bool,
        serves: &[&str],
        at: Instant,
    ) {
        let serves: Vec<Name> = serves.iter().map(|s| n(s)).collect();
        hints.record(space, &n(device), &person(device), vouched, &serves, at);
    }

    #[tokio::test(start_paused = true)]
    async fn hints_are_found_by_prefix_newest_first_and_lapse() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        record(&hints, &space, "/alice/a", true, &["/world"], t0);
        record(
            &hints,
            &space,
            "/alice/b",
            true,
            &["/world/pickup"],
            t0 + Duration::from_secs(1),
        );
        record(
            &hints,
            &space,
            "/alice/c",
            true,
            &["/other"],
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
    }

    /// An announce is unsigned: what it says of a device adds to the hint and refreshes it, and
    /// nothing it says (no prefix, another prefix) takes a prefix away. Only the lapse does, a
    /// prefix at a time.
    #[tokio::test(start_paused = true)]
    async fn an_announce_takes_nothing_away_only_the_lapse_does() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        record(&hints, &space, "/alice/a", true, &["/world"], t0);
        let now = t0 + Duration::from_secs(1);
        record(&hints, &space, "/alice/a", true, &[], now);
        record(&hints, &space, "/alice/a", true, &["/other"], now);
        assert_eq!(
            hints.serving(&space, &n("/world/1"), now),
            vec![n("/alice/a")],
            "neither an empty announce nor another prefix removes /world"
        );
        assert_eq!(
            hints.serving(&space, &n("/other/1"), now),
            vec![n("/alice/a")]
        );
        // /world is said again at +60 s, /other is not: at +100 s /other lapsed and /world did
        // not.
        record(
            &hints,
            &space,
            "/alice/a",
            true,
            &["/world"],
            t0 + Duration::from_secs(60),
        );
        let later = t0 + Duration::from_secs(100);
        assert_eq!(
            hints.serving(&space, &n("/world/1"), later),
            vec![n("/alice/a")]
        );
        assert!(hints.serving(&space, &n("/other/1"), later).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_prefixes_of_a_device_are_bounded_and_the_first_stay() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        let many: Vec<String> = (0..SERVE_PREFIXES_MAX + 8)
            .map(|i| format!("/p{i}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        record(&hints, &space, "/alice/a", true, &many, t0);
        let now = t0 + Duration::from_secs(1);
        assert_eq!(
            hints.serving(&space, &n("/p0"), now),
            vec![n("/alice/a")],
            "the first heard stay"
        );
        assert!(
            hints
                .serving(&space, &n(&format!("/p{}", SERVE_PREFIXES_MAX + 7)), now)
                .is_empty(),
            "the ones over the bound are not kept"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_vouched_hints_per_space_are_bounded_and_the_oldest_goes() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        // Many persons, each under its own bound.
        for i in 0..(HINTS_PER_SPACE + 5) {
            record(
                &hints,
                &space,
                &format!("/p{}/d{i}", i % 16),
                true,
                &["/w"],
                t0 + Duration::from_millis(i as u64),
            );
        }
        let now = t0 + Duration::from_secs(1);
        let found = hints.serving(&space, &n("/w"), now);
        assert_eq!(found.len(), HINTS_PER_SPACE);
        assert!(!found.contains(&n("/p0/d0")), "the first heard went");
        assert!(found.contains(&n(&format!("/p4/d{}", HINTS_PER_SPACE + 4))));
    }

    #[tokio::test(start_paused = true)]
    async fn one_person_cannot_take_more_than_her_share_of_the_vouched_hints() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        for i in 0..(HINTS_PER_PERSON + 8) {
            record(
                &hints,
                &space,
                &format!("/alice/d{i}"),
                true,
                &["/w"],
                t0 + Duration::from_millis(i as u64),
            );
        }
        record(
            &hints,
            &space,
            "/bob/phone",
            true,
            &["/w"],
            t0 + Duration::from_secs(1),
        );
        let found = hints.serving(&space, &n("/w"), t0 + Duration::from_secs(2));
        assert_eq!(found.len(), HINTS_PER_PERSON + 1);
        assert!(
            found.contains(&n("/bob/phone")),
            "another person's hint is kept"
        );
        assert!(!found.contains(&n("/alice/d0")), "the oldest of hers went");
    }

    /// Names nothing vouches for fill a small pool of their own and cannot push out a device the
    /// record vouches for, nor one that was heard first and is not vouched: a new name is refused
    /// once the share of its person is full.
    #[tokio::test(start_paused = true)]
    async fn names_nothing_vouches_for_cannot_crowd_a_real_device_out() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        record(&hints, &space, "/alice/real", true, &["/w"], t0);
        record(&hints, &space, "/bob/real", false, &["/w"], t0);
        for i in 0..512 {
            record(
                &hints,
                &space,
                &format!("/{}/fake{i}", ["alice", "bob", "carol"][i % 3]),
                false,
                &["/w"],
                t0 + Duration::from_millis(1 + i as u64),
            );
        }
        let found = hints.serving(&space, &n("/w"), t0 + Duration::from_secs(2));
        assert_eq!(found[0], n("/alice/real"), "the vouched device comes first");
        assert!(
            found.contains(&n("/bob/real")),
            "so does the one heard first"
        );
        let fakes = |person: &str| {
            found
                .iter()
                .filter(|d| d.to_string().starts_with(&format!("/{person}/fake")))
                .count()
        };
        assert!(fakes("alice") <= HINTS_UNVOUCHED_PER_PERSON);
        assert!(
            fakes("bob") < HINTS_UNVOUCHED_PER_PERSON,
            "bob's share held bob/real"
        );
        assert!(
            found.len() - 1 <= HINTS_UNVOUCHED_PER_SPACE,
            "the pool of the space is {HINTS_UNVOUCHED_PER_SPACE}, found {}",
            found.len()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_device_that_answered_outranks_newer_hints_that_did_not() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        record(&hints, &space, "/alice/old", false, &["/w"], t0);
        record(
            &hints,
            &space,
            "/alice/vouched",
            true,
            &["/w"],
            t0 + Duration::from_secs(1),
        );
        record(
            &hints,
            &space,
            "/alice/new",
            false,
            &["/w"],
            t0 + Duration::from_secs(2),
        );
        let now = t0 + Duration::from_secs(3);
        assert_eq!(
            hints.serving(&space, &n("/w"), now),
            vec![n("/alice/vouched"), n("/alice/new"), n("/alice/old")],
            "vouched first, then the newest"
        );
        hints.proven(&space, &n("/alice/old"), now);
        assert_eq!(
            hints.serving(&space, &n("/w"), now)[0],
            n("/alice/old"),
            "a device that answered a signed query comes before every other"
        );
        // It is no longer held in the pool of the unvouched: the share of its person has room.
        record(&hints, &space, "/alice/more1", false, &["/w"], now);
        record(&hints, &space, "/alice/more2", false, &["/w"], now);
        record(&hints, &space, "/alice/more3", false, &["/w"], now);
        assert!(
            hints
                .serving(&space, &n("/w"), now)
                .contains(&n("/alice/more3"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_devices_remembered_as_answered_are_bounded_and_the_oldest_goes() {
        let hints = Hints::default();
        let space = n("/alice/32=data/game");
        let t0 = Instant::now();
        for i in 0..(PROVEN_PER_SPACE + 3) {
            hints.proven(
                &space,
                &n(&format!("/p{i}/d")),
                t0 + Duration::from_millis(i as u64),
            );
        }
        // The earliest forgotten answered no more outranks: both heard at once, the one that
        // is still proven is first.
        let now = t0 + Duration::from_secs(1);
        record(&hints, &space, "/p0/d", false, &["/w"], now);
        record(&hints, &space, "/p66/d", false, &["/w"], now);
        let found = hints.serving(&space, &n("/w"), now);
        assert_eq!(
            found[0],
            n("/p66/d"),
            "p66 is proven, p0 was forgotten: {found:?}"
        );
    }
}
