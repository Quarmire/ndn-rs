//! Round 9 (spec §19.8, the mirror grant): the joiner's end of a grant, kept
//! by [`Inner::keep_mirror`] where `join` ends, listed by `Device::grants`,
//! judged against the members record in force, and the folders it joined
//! ([`Device::joined_folders`], [`Device::joined_changes`]).
//!
//! `join` needs a forwarder between two devices; these cases drive what it
//! does at its end (`keep_mirror`, called with what the join verified) over a
//! joiner that was really answered by a real inviter and holds the inviter's
//! records. The cases over real links are the link layer's (`tests/joiner.rs`).

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::watch::Receiver;

use super::super::grants::MirrorNote;
use super::*;
use crate::intro::{JOINED_WRITERS_MAX, JoinedFolder};

/// The octets kept under `/localhost/ndn-data/intro/mirror/`.
fn mirror_notes(store: &dyn DataStore) -> Vec<(Name, Bytes)> {
    store.scan_under(&super::super::intro::local_name_base("mirror"), 0)
}

/// The members record that follows the one `of` holds in force for `folder`, as
/// a device of Alice's would sign it: the writers and the readers (persons) it
/// lists, a new epoch started by Alice's phone when it lists any reader.
fn listing(of: &Device, folder: &Name, writers: &[&str], readers: &[&str]) -> MembersBody {
    let m = of.inner.st.lock().folders[folder]
        .members
        .clone()
        .expect("a record is held");
    let (epoch, key_check) = if readers.is_empty() {
        (None, None)
    } else {
        let epoch = Epoch {
            creator: n("/alice/phone"),
            seq: Seq(1),
        };
        let check = seal::key_check(&ContentKey::generate(), folder, &epoch);
        (Some(epoch), Some(check))
    };
    MembersBody {
        collection: folder.clone(),
        folder: true,
        revision: m.revision.0 + 1,
        rule: m.rule.clone(),
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
        cuts: Vec::new(),
        epoch,
        key_check,
        since: None,
        parent: Some(m.as_parent()),
    }
}

/// `device` of `person`, started over `keys` and `store` the way a host starts it
/// after a join: the inviter's namespace adopted and its laptop's certificate
/// held before the device runs, so what it reads back at a start is judged.
async fn start_holding(
    person: &Person,
    device: &str,
    keys: &Arc<SecurityManager>,
    calls: &Arc<Calls>,
    store: &Arc<dyn DataStore>,
    inviter: &Inviter,
) -> Device {
    let device = n(device);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator.adopt_context(Arc::clone(&person.ctx)).unwrap();
    validator
        .adopt_context(Arc::clone(&inviter.alice.ctx))
        .unwrap();
    let laptop = key(inviter.laptop.name());
    let public = inviter
        .keys
        .get_signer_sync(&laptop)
        .unwrap()
        .public_key()
        .unwrap();
    validator
        .cert_cache()
        .insert(inviter.alice.certify(&laptop, &public).await);
    let host = Host {
        anchor: person.signed.clone(),
        validator: Arc::clone(&validator),
        refuses: Vec::new(),
        hold: None,
        calls: Arc::clone(calls),
    };
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        Arc::clone(keys),
        validator,
        Arc::clone(store),
        Config {
            first_look: Duration::from_millis(50),
            introducer: Some(Arc::new(host)),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// [`relay`] with the packets as `from` signed them, so that a restart reads
/// them back and judges them.
fn relay_signed(from: &Device, to: &Device, c: &Name) {
    let head = from.inner.st.lock().head;
    for seq in 1..=head {
        let name = log_name(from.name(), Some(c), seq);
        let Some(wire) = from.inner.store.get(&name) else {
            continue;
        };
        let content = Data::decode(wire.clone())
            .unwrap()
            .content()
            .unwrap()
            .clone();
        let record = wire::decode_record(content).unwrap();
        let mut st = to.inner.st.lock();
        to.inner.take(
            &mut st,
            name.clone(),
            wire,
            from.inner.writer.clone(),
            record,
            false,
        );
        assert_eq!(st.refused.get(&name), None, "the record was refused");
    }
}

/// Bob's phone and Alice's laptop, the way a join leaves them before it keeps
/// its note: Bob (of the namespace `ns`) was answered by Alice's offer of the
/// notebook and holds the records of it.
struct Joiner {
    alice: Inviter,
    person: Person,
    ns: String,
    keys: Arc<SecurityManager>,
    store: Arc<dyn DataStore>,
    bob: Device,
    calls: Arc<Calls>,
    folder: Name,
    /// The digest of the key that signed Alice's answer: the mirror's key.
    inviter: [u8; 32],
    delivered: AtomicUsize,
}

impl Joiner {
    async fn admitted(ns: &str) -> Joiner {
        Self::admitted_over(ns, Arc::new(MemoryStore::new())).await
    }

    async fn admitted_over(ns: &str, store: Arc<dyn DataStore>) -> Joiner {
        let alice = Inviter::new(Role::Writer, None, &[]).await;
        let folder = n("/alice/32=data/notebook");
        let person = Person::new(ns);
        let device = format!("{ns}/phone");
        let keys = keyed(&person, &device).await;
        let calls = Arc::new(Calls::default());
        let bob = start_holding(&person, &device, &keys, &calls, &store, &alice).await;
        let got = alice.answers(&bob).await;
        assert!(accepted(&got), "bob was answered {got:?}");
        relay_signed(&alice.laptop, &bob, &folder);
        // A joiner holds no use mark of its own (it made no offer): the judgement
        // of its mirror must not wait for one. The marks of Alice's the relay
        // brought are dropped, as a device that learned the records through the
        // inviter's summary holds none.
        bob.inner.st.lock().intro.used.clear();
        let inviter = alice.laptop.inner.own_key.unwrap();
        Joiner {
            alice,
            person,
            ns: ns.to_string(),
            keys,
            store,
            bob,
            calls,
            folder,
            inviter,
            delivered: AtomicUsize::new(0),
        }
    }

    /// Admitted, and the join's end kept the note.
    async fn joined(ns: &str) -> Joiner {
        let j = Self::admitted(ns).await;
        j.keep().await;
        j
    }

    /// What `join` does once the admitting record is held.
    async fn keep(&self) {
        self.bob
            .inner
            .keep_mirror(self.inviter, &n("/alice"), &self.folder)
            .await
            .unwrap();
    }

    /// The record after the one in force.
    fn listing(&self, writers: &[&str], readers: &[&str]) -> MembersBody {
        listing(&self.bob, &self.folder, writers, readers)
    }

    /// `body`, signed by one more device of Alice's, handed to Bob, and judged.
    async fn deliver(&self, body: MembersBody) {
        let at = self.delivered.fetch_add(1, Ordering::SeqCst);
        from_device(&self.bob, &format!("/alice/r{at}"), body);
        self.bob.inner.settle().await;
    }

    /// Bob's phone stopped and started again over its store and keys.
    async fn restart(&mut self) -> Arc<Calls> {
        self.bob.shutdown();
        let calls = Arc::new(Calls::default());
        self.bob = start_holding(
            &self.person,
            &format!("{}/phone", self.ns),
            &self.keys,
            &calls,
            &self.store,
            &self.alice,
        )
        .await;
        calls
    }

    /// What Bob's host is told for the mirror: Alice's key, her namespace, the
    /// folder, her role, no date.
    fn mirror_grant(&self, role: Role) -> Grant {
        Grant {
            key: self.inviter,
            namespaces: vec![n("/alice")],
            folder: self.folder.clone(),
            role,
            until: None,
        }
    }

    fn writers(&self) -> Vec<Name> {
        let joined = self.bob.joined_folders();
        assert_eq!(joined.len(), 1, "{joined:?}");
        joined[0].writers.clone()
    }
}

/// The watcher saw a change: the generation rose above `last`.
fn fired(rx: &mut Receiver<u64>, last: &mut u64, what: &str) {
    assert!(
        rx.has_changed().unwrap(),
        "{what}: joined_changes did not fire"
    );
    let now = *rx.borrow_and_update();
    assert!(
        now > *last,
        "{what}: the generation {now} did not rise above {last}"
    );
    *last = now;
}

fn quiet(rx: &Receiver<u64>, what: &str) {
    assert!(
        !rx.has_changed().unwrap(),
        "{what}: joined_changes fired though the list did not change"
    );
}

/// Spec §19.8: a join's end keeps the mirror note; the grant lists it with the
/// inviter's key, the inviter's namespace as the owner, the folder, the
/// inviter's role in the record in force and no date; the host is told once;
/// `joined_folders` lists the folder with this device's role; a restart keeps
/// both and tells the host nothing by itself.
#[tokio::test]
async fn a_join_keeps_the_mirror_grant_lists_it_and_tells_the_host_once() {
    let mut j = Joiner::admitted("/bob").await;
    assert_eq!(j.bob.grants(), Vec::new(), "a grant before the join's end");
    assert_eq!(j.bob.joined_folders(), Vec::new());
    j.keep().await;

    let grant = j.mirror_grant(Role::Writer);
    assert_eq!(j.bob.grants(), vec![grant.clone()]);
    assert_eq!(
        j.calls.granted(),
        vec![grant.clone()],
        "the host was not told of the mirror grant exactly once"
    );
    assert_eq!(
        j.bob.joined_folders(),
        vec![JoinedFolder {
            inviter: j.inviter,
            owner: n("/alice"),
            folder: j.folder.clone(),
            role: Role::Writer,
            writers: Vec::new(),
        }]
    );
    assert_eq!(
        mirror_notes(&*j.store).len(),
        1,
        "one join, one mirror note"
    );
    assert_eq!(j.calls.departed(), Vec::new());

    // A restart brings the entry back by itself, from the note and the records
    // it reads back (Alice's own, signed), and tells the host nothing (whoever
    // installs `grants()` does).
    let again = j.restart().await;
    assert_eq!(
        j.bob.grants(),
        vec![grant],
        "the entry did not survive a restart"
    );
    assert_eq!(j.bob.joined_folders().len(), 1);
    assert_eq!(again.granted(), Vec::new());
    assert_eq!(again.revoked_in(), Vec::new());
}

/// Spec §19.8: `joined_folders` lists the other writers' namespaces as
/// `writer_namespaces` derives them, minus this device's own namespace and every
/// namespace above or below it, only namespaces, sorted.
#[tokio::test]
async fn joined_folders_lists_the_other_writers_but_never_this_devices_own_names() {
    // Bob's namespace is /home/bob: /home lies above it, its phone below.
    let j = Joiner::joined("/home/bob").await;
    j.deliver(j.listing(
        &[
            "/alice",
            "/home/bob",
            "/home",
            "/home/bob/phone/member",
            "/dave",
            "/carol",
            "/erin/32=sync",
        ],
        &["/alice", "/home/bob"],
    ))
    .await;
    // "Sorted" is the canonical order of names (shorter components first).
    let mut expected = vec![n("/carol"), n("/dave")];
    expected.sort();
    assert_eq!(
        j.writers(),
        expected,
        "the writers are not the listed others', less this device's own names, the \
         inviter's, a name above or below Bob's namespace and a name that is no namespace"
    );
    let surface = j.bob.introductions();
    assert_eq!(surface.joined_folders(), j.bob.joined_folders());
}

/// Spec §19.8: at most `JOINED_WRITERS_MAX` writers, the first of the sorted
/// namespaces, however many the record lists.
#[tokio::test]
async fn joined_folders_lists_at_most_the_bound_of_writers_sorted() {
    let j = Joiner::joined("/bob").await;
    let many: Vec<String> = (1..=20).rev().map(|i| format!("/w{i:02}")).collect();
    let mut writers = vec!["/alice", "/bob"];
    writers.extend(many.iter().map(String::as_str));
    j.deliver(j.listing(&writers, &["/alice", "/bob"])).await;
    let listed = j.writers();
    assert_eq!(listed.len(), JOINED_WRITERS_MAX);
    let expected: Vec<Name> = (1..=JOINED_WRITERS_MAX)
        .map(|i| n(&format!("/w{i:02}")))
        .collect();
    assert_eq!(
        listed, expected,
        "the writers are not the first {JOINED_WRITERS_MAX} namespaces, in order"
    );
}

/// Spec §19.8: the grant's role is the inviter's in the record in force (a
/// writer when its namespace is listed as one, else a reader: never wider than
/// the record says), re-derived at every judgement and told to the host again
/// when it changes; the joined folder's role is this device's own.
#[tokio::test]
async fn the_role_is_the_inviters_in_the_record_and_the_host_is_told_again_when_it_changes() {
    let j = Joiner::joined("/bob").await;
    assert_eq!(j.bob.grants()[0].role, Role::Writer);

    // Alice not a writer any more (a reader, still), Bob one.
    j.deliver(j.listing(&["/bob"], &["/alice", "/bob"])).await;
    assert_eq!(
        j.bob.grants(),
        vec![j.mirror_grant(Role::Reader)],
        "an inviter the record lists as a reader was granted as a writer"
    );
    assert_eq!(j.bob.joined_folders()[0].role, Role::Writer);
    assert_eq!(
        j.calls.granted().last(),
        Some(&j.mirror_grant(Role::Reader)),
        "the host was not told of the inviter's new role"
    );
    let told = j.calls.granted().len();
    j.bob.inner.settle().await;
    assert_eq!(
        j.calls.granted().len(),
        told,
        "the same role was told again"
    );

    // Alice a writer again, Bob now a reader only.
    j.deliver(j.listing(&["/alice"], &["/alice", "/bob"])).await;
    assert_eq!(j.bob.grants(), vec![j.mirror_grant(Role::Writer)]);
    assert_eq!(j.bob.joined_folders()[0].role, Role::Reader);
    assert_eq!(
        j.calls.granted().last(),
        Some(&j.mirror_grant(Role::Writer))
    );
}

/// Spec §19.8: `joined_changes` fires on a join, on a record that adds a
/// writer, on one that removes a writer, on one that changes this device's
/// role, on an entry ending — and on nothing else.
#[tokio::test]
async fn joined_changes_fires_when_the_list_changes_and_only_then() {
    let j = Joiner::admitted("/bob").await;
    let mut rx = j.bob.joined_changes();
    let mut last = *rx.borrow_and_update();
    quiet(&rx, "a settle before the join");
    j.bob.inner.settle().await;
    quiet(&rx, "a settle with no entry");

    j.keep().await;
    fired(&mut rx, &mut last, "a join");
    j.bob.inner.settle().await;
    j.bob.inner.settle().await;
    quiet(&rx, "a settle with nothing new");

    j.deliver(j.listing(&["/alice", "/bob", "/carol"], &["/alice", "/bob", "/carol"]))
        .await;
    fired(&mut rx, &mut last, "a record that adds a writer");
    assert_eq!(j.writers(), vec![n("/carol")]);

    j.deliver(j.listing(&["/alice", "/bob"], &["/alice", "/bob"]))
        .await;
    fired(&mut rx, &mut last, "a record that removes a writer");
    assert_eq!(j.writers(), Vec::<Name>::new());

    j.deliver(j.listing(&["/alice"], &["/alice", "/bob"])).await;
    fired(
        &mut rx,
        &mut last,
        "a record that changes this device's role",
    );

    j.deliver(j.listing(&["/alice"], &["/alice"])).await;
    fired(&mut rx, &mut last, "a record that leaves this device out");
    assert_eq!(j.bob.joined_folders(), Vec::new());
    j.bob.inner.settle().await;
    quiet(&rx, "a settle after the entry ended");

    // The host's end of a fresh entry fires too.
    let j = Joiner::joined("/bob").await;
    let mut rx = j.bob.joined_changes();
    let mut last = *rx.borrow_and_update();
    assert!(j.bob.end_grant(&j.inviter).await.unwrap());
    fired(&mut rx, &mut last, "the host's end");
    assert!(!j.bob.end_grant(&j.inviter).await.unwrap());
    quiet(&rx, "an end of what had ended");
}

/// Spec §19.8: a held record that leaves this device out ends the entry: the
/// host is told in memory (`revoke_grant` with the key and the folder, once),
/// **never a departure**; `grants` and `joined_folders` drop it; the note is
/// marked ended durably, so a record that lists this device again does not
/// bring the entry back (a re-invitation does, by a join).
#[tokio::test]
async fn the_entry_ends_when_a_record_leaves_this_device_out_without_a_departure() {
    let mut j = Joiner::joined("/bob").await;
    let out = phone_leaves_out(&j.bob, &j.folder, &n("/bob"));
    from_device(&j.bob, "/alice/phone", out);
    j.bob.inner.settle().await;
    assert_eq!(
        j.calls.revoked_in(),
        vec![(j.inviter, j.folder.clone())],
        "a record that leaves bob out did not revoke exactly (the inviter's key, the folder)"
    );
    assert_eq!(
        j.calls.departed(),
        Vec::new(),
        "a mirror grant made a departure"
    );
    assert!(!j.calls.order().contains(&"departure"));
    assert_eq!(j.bob.grants(), Vec::new());
    assert_eq!(j.bob.joined_folders(), Vec::new());
    // Once, however often records are settled.
    j.bob.inner.settle().await;
    j.bob.inner.settle().await;
    assert_eq!(j.calls.revoked_in().len(), 1, "the end was told again");

    // A record that lists Bob again does not bring the ended entry back.
    j.deliver(j.listing(&["/alice", "/bob"], &["/alice", "/bob"]))
        .await;
    assert_eq!(
        j.bob.grants(),
        Vec::new(),
        "a record that readmitted bob resurrected an ended entry"
    );
    assert_eq!(j.bob.joined_folders(), Vec::new());

    // And after a restart.
    let again = j.restart().await;
    assert_eq!(j.bob.grants(), Vec::new());
    assert_eq!(again.revoked_in(), Vec::new());
    assert_eq!(again.departed(), Vec::new());
}

/// Spec §19.8: the host is told of an end in memory before it is durable: a
/// disk that has stopped answering does not delay the link layer's end.
#[tokio::test]
async fn the_host_is_told_of_a_mirrors_end_before_it_is_durable() {
    let store = Frozen::new();
    let j = Joiner::admitted_over("/bob", store.clone()).await;
    j.keep().await;
    let out = phone_leaves_out(&j.bob, &j.folder, &n("/bob"));
    from_device(&j.bob, "/alice/phone", out);
    // A failing assertion must not leave the disk frozen: the runtime would wait for it.
    struct Thaw(Arc<Frozen>);
    impl Drop for Thaw {
        fn drop(&mut self) {
            self.0.freeze(false);
        }
    }
    store.freeze(true);
    let _thaw = Thaw(store.clone());
    let stuck = tokio::time::timeout(Duration::from_millis(300), j.bob.inner.judge_grants()).await;
    assert!(stuck.is_err(), "the durable end finished on a frozen disk");
    assert_eq!(
        j.calls.revoked_in(),
        vec![(j.inviter, j.folder.clone())],
        "the host was not told of the end while the disk was stopped"
    );
}

/// Spec §19.8: the host ends the mirror: `end_grant(key)` ends the key's inviter
/// notes **and** mirror notes, `end_grant_in(key, folder)` those of the folder;
/// durable, no departure, the host is not told (it knows); the note stays ended
/// while the record still lists this device; a second join replaces the note, and
/// another inviter key is another entry.
#[tokio::test]
async fn the_host_ends_the_mirror_and_a_second_join_replaces_it() {
    let j = Joiner::joined("/bob").await;
    let other = n("/alice/32=data/other");
    assert!(
        !j.bob.end_grant_in(&j.inviter, &other).await.unwrap(),
        "an end of a folder that was not joined ended something"
    );
    assert!(!j.bob.end_grant(&[9; 32]).await.unwrap());
    assert_eq!(
        j.bob.grants().len(),
        1,
        "an end of another key or folder ended the entry"
    );

    assert!(j.bob.end_grant_in(&j.inviter, &j.folder).await.unwrap());
    assert_eq!(j.bob.grants(), Vec::new());
    assert_eq!(j.bob.joined_folders(), Vec::new());
    assert_eq!(
        j.calls.revoked_in(),
        Vec::new(),
        "the host was told of its own end"
    );
    assert_eq!(j.calls.departed(), Vec::new());
    assert!(
        !j.bob.end_grant(&j.inviter).await.unwrap(),
        "what had ended ended again"
    );
    // The record still lists Bob; the ended note does not come back by itself.
    j.bob.inner.settle().await;
    assert_eq!(j.bob.grants(), Vec::new());

    // A second join of the same folder by the same key replaces the note.
    j.keep().await;
    assert_eq!(j.bob.grants(), vec![j.mirror_grant(Role::Writer)]);
    assert_eq!(
        mirror_notes(&*j.store).len(),
        1,
        "the second join added a note"
    );
    assert_eq!(
        j.calls.granted().len(),
        2,
        "the second join did not tell the host"
    );

    // Another inviter key (a second device of Alice's) is another entry.
    j.bob
        .inner
        .keep_mirror([3; 32], &n("/alice"), &j.folder)
        .await
        .unwrap();
    assert_eq!(j.bob.grants().len(), 2);
    assert_eq!(j.bob.joined_folders().len(), 2);
    assert_eq!(mirror_notes(&*j.store).len(), 2);
    assert!(j.bob.end_grant(&[3; 32]).await.unwrap());
    assert_eq!(
        j.bob.grants(),
        vec![j.mirror_grant(Role::Writer)],
        "ending one key's entry ended the other's"
    );
    // end_grant(key) ends it whatever the folder.
    assert!(j.bob.end_grant(&j.inviter).await.unwrap());
    assert_eq!(j.bob.grants(), Vec::new());
}

/// Spec §19.8: the mirror has no date and `renew_grant` leaves it untouched.
#[tokio::test]
async fn renew_grant_leaves_a_mirror_undated() {
    let j = Joiner::joined("/bob").await;
    let later = Timestamp((j.bob.inner.config.clock)().0 + 3_600_000);
    assert_eq!(
        j.bob.renew_grant(&j.inviter, Some(later)).await.unwrap(),
        None
    );
    assert_eq!(j.bob.grants(), vec![j.mirror_grant(Role::Writer)]);
}

/// Spec §19.8: no record held for the folder, no entry (nothing to judge by);
/// and a folder that is not under the inviter's own namespace makes none (the
/// inviter would be granted a link into a folder it does not own).
#[tokio::test]
async fn no_note_is_kept_without_a_record_or_for_a_folder_the_inviter_does_not_own() {
    // The join's end before the admitting record is held keeps nothing.
    let j = Joiner::admitted("/bob").await;
    let bare = phone_of("/bob").await;
    bare.inner
        .keep_mirror(j.inviter, &n("/alice"), &j.folder)
        .await
        .unwrap();
    assert_eq!(bare.grants(), Vec::new());
    assert_eq!(bare.joined_folders(), Vec::new());
    assert_eq!(mirror_notes(&*bare.inner.store), Vec::new());

    // A folder of Bob's own, named by a hostile offer: Bob's own record lists
    // Bob, yet the inviter is granted nothing for it.
    let own = n("/bob/32=data/diary");
    j.bob
        .share_folder(
            &own,
            Share {
                rule: Rule::Log,
                writers: vec![n("/bob")],
                readers: vec![Audience::Person(n("/bob"))],
            }
            .into(),
        )
        .await
        .unwrap();
    j.bob
        .inner
        .keep_mirror(j.inviter, &n("/alice"), &own)
        .await
        .unwrap();
    assert_eq!(
        j.bob.grants(),
        Vec::new(),
        "a folder of Bob's own was granted to the inviter"
    );
    assert_eq!(j.bob.joined_folders(), Vec::new());
    assert_eq!(mirror_notes(&*j.store), Vec::new());
}

/// Spec §19.8: a mirror note whose MAC fails (made under another key, or changed
/// in the store, or a note the host ended with the flag cleared) grants nothing;
/// an inviter's note is no mirror note and the reverse.
#[tokio::test]
async fn a_mirror_note_that_fails_its_mac_or_is_of_the_other_kind_grants_nothing() {
    let rewrite = |j: &Joiner, edit: &dyn Fn(&Name, &Bytes) -> Bytes| {
        let mut notes = mirror_notes(&*j.store);
        assert_eq!(notes.len(), 1);
        let (name, value) = notes.pop().unwrap();
        j.store.insert(name.clone(), edit(&name, &value));
    };

    // Under another key.
    let j = Joiner::joined("/bob").await;
    rewrite(&j, &|_, _| {
        MirrorNote {
            key: j.inviter,
            owner: n("/alice"),
            folder: j.folder.clone(),
            role: Role::Writer,
            ended: false,
        }
        .encode(&[1; 32])
    });
    assert_eq!(
        j.bob.grants(),
        Vec::new(),
        "a note under another key was read"
    );
    assert_eq!(j.bob.joined_folders(), Vec::new());

    // Changed in place: the role octet flipped.
    let j = Joiner::joined("/bob").await;
    rewrite(&j, &|_, v| {
        let mut b = v.to_vec();
        b[2] ^= 1;
        Bytes::from(b)
    });
    assert_eq!(j.bob.grants(), Vec::new(), "a changed note was read");

    // Ended by the host, the flag cleared: the entry is not resurrected.
    let j = Joiner::joined("/bob").await;
    assert!(j.bob.end_grant(&j.inviter).await.unwrap());
    rewrite(&j, &|_, v| {
        let mut b = v.to_vec();
        b[1] = 0;
        Bytes::from(b)
    });
    assert_eq!(
        j.bob.grants(),
        Vec::new(),
        "an ended note came back with its flag cleared"
    );

    // Alice's inviter note put where Bob's mirror note stood, and the reverse.
    let j = Joiner::joined("/bob").await;
    let grant_base = super::super::intro::local_name_base("grant");
    let (_, inviters_note) = j.alice.store.scan_under(&grant_base, 0).pop().unwrap();
    let (_, mirror) = mirror_notes(&*j.store).pop().unwrap();
    assert_eq!(j.alice.laptop.grants().len(), 1);
    rewrite(&j, &|_, _| inviters_note.clone());
    assert_eq!(
        j.bob.grants(),
        Vec::new(),
        "an inviter's note read as a mirror note"
    );
    let (name, _) = j.alice.store.scan_under(&grant_base, 0).pop().unwrap();
    j.alice.store.insert(name, mirror);
    assert_eq!(
        j.alice.laptop.grants(),
        Vec::new(),
        "a mirror note read as an inviter's note"
    );
}

/// Spec §19.8: two folders of one inviter are two entries (per-entry ends): a
/// record that leaves this device out of one folder ends that entry alone
/// (`revoke_grant(key, folder)` once) and the other stands; the host's
/// `end_grant_in` ends one.
#[tokio::test]
async fn two_entries_of_one_inviter_end_one_by_one() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let notebook = n("/alice/32=data/notebook");
    let diary = n("/alice/32=data/diary");
    let person = Person::new("/bob");
    let calls = Arc::new(Calls::default());
    let bob = start_recording(
        &person,
        "/bob/phone",
        None,
        &[],
        None,
        None,
        Arc::clone(&calls),
    )
    .await;
    bob.inner
        .validator
        .adopt_context(Arc::clone(&alice.alice.ctx))
        .unwrap();
    assert!(accepted(&alice.answers(&bob).await));
    invite_to(&alice, &diary, Role::Writer, &bob).await;
    relay(&alice.laptop, &bob, &notebook);
    relay(&alice.laptop, &bob, &diary);
    bob.inner.st.lock().intro.used.clear();
    let key = alice.laptop.inner.own_key.unwrap();
    for folder in [&notebook, &diary] {
        bob.inner
            .keep_mirror(key, &n("/alice"), folder)
            .await
            .unwrap();
    }
    let folders = |d: &Device| -> Vec<Name> { d.grants().into_iter().map(|g| g.folder).collect() };
    assert_eq!(bob.grants().len(), 2, "{:?}", bob.grants());
    assert_eq!(
        bob.joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![diary.clone(), notebook.clone()],
        "joined_folders is not sorted by folder"
    );

    from_device(
        &bob,
        "/alice/phone",
        phone_leaves_out(&bob, &diary, &n("/bob")),
    );
    bob.inner.settle().await;
    assert_eq!(
        calls.revoked_in(),
        vec![(key, diary.clone())],
        "a record that leaves bob out of the diary did not revoke exactly (key, diary)"
    );
    assert_eq!(folders(&bob), vec![notebook.clone()]);
    assert_eq!(
        bob.joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![notebook.clone()]
    );
    bob.inner.settle().await;
    assert_eq!(calls.revoked_in().len(), 1);
    assert_eq!(calls.departed(), Vec::new());

    assert!(bob.end_grant_in(&key, &notebook).await.unwrap());
    assert_eq!(bob.grants(), Vec::new());
    assert_eq!(
        calls.revoked_in().len(),
        1,
        "the host's own end was told to the host"
    );
}

/// Spec §19.8 (mutual invitations): Ann invites Bob to A and Bob invites Ann to
/// B: each holds an inviter's note of one folder and a mirror note of the other
/// for the same peer key. They are entries of different folders, so neither
/// replaces the other, `end_grant_in` ends one, `end_grant(key)` ends both; the
/// inviter's note is no joined folder.
#[tokio::test]
async fn mutual_invitations_are_entries_of_different_folders() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let notebook = n("/alice/32=data/notebook");
    let journal = n("/bob/32=data/journal");
    let person = Person::new("/bob");
    let calls = Arc::new(Calls::default());
    let bob = start_recording(
        &person,
        "/bob/phone",
        None,
        &[],
        None,
        None,
        Arc::clone(&calls),
    )
    .await;
    bob.inner
        .validator
        .adopt_context(Arc::clone(&alice.alice.ctx))
        .unwrap();
    assert!(accepted(&alice.answers(&bob).await));
    relay(&alice.laptop, &bob, &notebook);

    // Bob invites Alice to his journal.
    bob.share_folder(
        &journal,
        Share {
            rule: Rule::Log,
            writers: vec![n("/bob")],
            readers: vec![Audience::Person(n("/bob"))],
        }
        .into(),
    )
    .await
    .unwrap();
    let code = bob
        .offer(
            &journal,
            Offer {
                role: Role::Writer,
                until: Timestamp((bob.inner.config.clock)().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let got = answer(
        &bob,
        ask(&alice.laptop, &bob, &code.offer, &secret_of(&code), &[]),
    )
    .await;
    assert!(accepted(&got), "alice was answered {got:?}");
    relay(&bob, &alice.laptop, &journal);

    let a = alice.laptop.inner.own_key.unwrap();
    let b = bob.inner.own_key.unwrap();
    bob.inner
        .keep_mirror(a, &n("/alice"), &notebook)
        .await
        .unwrap();
    alice
        .laptop
        .inner
        .keep_mirror(b, &n("/bob"), &journal)
        .await
        .unwrap();

    // Bob: the inviter's grant of the journal and the mirror of the notebook,
    // both for Alice's key.
    let mut bobs = bob.grants();
    bobs.sort_by(|x, y| x.folder.cmp(&y.folder));
    assert_eq!(bobs.len(), 2, "{bobs:?}");
    assert!(bobs.iter().all(|g| g.key == a), "{bobs:?}");
    assert_eq!(bobs.iter().map(|g| g.folder.clone()).collect::<Vec<_>>(), {
        let mut both = vec![notebook.clone(), journal.clone()];
        both.sort();
        both
    });
    assert_eq!(
        bob.joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![notebook.clone()],
        "the folder Bob invited to is no joined folder"
    );
    assert_eq!(alice.laptop.grants().len(), 2);
    assert_eq!(
        alice
            .laptop
            .joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![journal.clone()]
    );

    // end_grant_in ends one: the mirror of the notebook, the journal stands.
    assert!(bob.end_grant_in(&a, &notebook).await.unwrap());
    assert_eq!(
        bob.grants()
            .into_iter()
            .map(|g| g.folder)
            .collect::<Vec<_>>(),
        vec![journal.clone()],
        "ending the mirror ended the inviter's grant of the other folder"
    );
    // A second join of the notebook starts the mirror again beside it.
    bob.inner
        .keep_mirror(a, &n("/alice"), &notebook)
        .await
        .unwrap();
    assert_eq!(bob.grants().len(), 2);
    // The host ended the person: both go.
    assert!(bob.end_grant(&a).await.unwrap());
    assert_eq!(bob.grants(), Vec::new());
    assert_eq!(calls.departed(), Vec::new());
    assert_eq!(calls.revoked_in(), Vec::new());
}

/// Spec §19.8: the surface holds the device weakly and says what the device
/// says; once the device is gone it lists nothing and its watcher never sees a
/// change.
#[tokio::test]
async fn the_surface_says_what_the_device_says_and_nothing_once_it_is_gone() {
    let j = Joiner::admitted("/bob").await;
    let surface = j.bob.introductions();
    let mut rx = surface.joined_changes();
    assert_eq!(surface.joined_folders(), Vec::new());
    j.keep().await;
    assert!(
        rx.has_changed().unwrap(),
        "a join did not reach the surface's watcher"
    );
    assert_eq!(*rx.borrow_and_update(), *j.bob.joined_changes().borrow());
    assert_eq!(surface.joined_folders(), j.bob.joined_folders());
    assert_eq!(surface.joined_folders().len(), 1);

    let Joiner { bob, .. } = j;
    bob.shutdown();
    drop(bob);
    let mut gone = surface.joined_changes();
    for _ in 0..200 {
        if surface.joined_folders().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        surface.joined_folders(),
        Vec::new(),
        "the surface kept the device alive"
    );
    assert!(gone.changed().await.is_err());
}
