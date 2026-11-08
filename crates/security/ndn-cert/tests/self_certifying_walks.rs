//! Self-certifying `/user/<0xA1>` namespaces after a recovery
//! (trust-context.md §4.5): what a holder's by-name adoption admits, and
//! what an unauthenticated version pointer can cost a walk. Each test
//! guards one invariant:
//!
//! - adopting a held namespace by name again moves it on only as a refresh
//!   does — its forwarder expects a version signed by an anchor of the held
//!   version, never the genesis key the name hashes — so a thief holding
//!   the genesis key gets nothing admitted, and the holder reaches the
//!   recovered line's newest version;
//! - a walk fetches at most [`MAX_CATCH_UP_MISSES`] positions it cannot use,
//!   whatever version number the pointer names.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    AdoptError, CaExchange, CatchUpStop, CertError, GenesisKey, MAX_CATCH_UP_MISSES,
    NamespacePolicies, NewRootStore, OldRoot, RecoverySeed, RefreshError, RootStore, Unfetched,
    UpdateRefusal, VersionSource, add_recovery_anchor, adopt_by_name, follow_versions,
    init_self_certifying_in_pib_with, rdr_metadata_name, recover_namespace_in_pib, recovery_anchor,
    refresh_context,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{
    CertCache, FilePib, Keyring, SignedTrustContext, Signer, ValidationResult, Validator,
};

fn copy(data: &Data) -> Data {
    Data::decode(data.raw().clone()).unwrap()
}

/// A self-certifying namespace recovered after its genesis key was stolen:
/// the versions init makes (v1, the genesis, root A; v2), then A adds the
/// recovery anchor R, R installs the new root B, B re-issues. The thief
/// keeps A.
struct Recovered {
    _dirs: [tempfile::TempDir; 2],
    ns: Name,
    line: Vec<Data>,
    /// The stolen genesis root A.
    thief: Arc<dyn Signer>,
}

impl Recovered {
    async fn new() -> Self {
        let alice_dir = tempfile::tempdir().unwrap();
        let alice = FilePib::new(alice_dir.path()).unwrap();
        let out = init_self_certifying_in_pib_with(
            &alice,
            &GenesisKey::generate().unwrap(),
            "desk",
            &NewRootStore::File,
            &NamespacePolicies::default(),
        )
        .await
        .unwrap();
        let ns = out.init.context.namespace().clone();
        let mut line: Vec<Data> = out.init.genesis.iter().map(|g| copy(g.data())).collect();
        line.push(copy(&out.init.context_data));
        let thief = RootStore::open_for(&alice, &ns)
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
        let with_kit = add_recovery_anchor(thief.as_ref(), line.last().unwrap(), &kit)
            .await
            .unwrap()
            .data;

        let phone_dir = tempfile::tempdir().unwrap();
        let phone = FilePib::new(phone_dir.path()).unwrap();
        let recovered = recover_namespace_in_pib(
            &phone,
            &with_kit,
            &seed.signer(&ns),
            "phone",
            OldRoot::Compromised,
            &[],
            &[],
            &NewRootStore::File,
        )
        .await
        .unwrap();
        line.extend([
            with_kit,
            copy(&recovered.version.bump.data),
            copy(&recovered.root_version.data),
        ]);
        Self {
            _dirs: [alice_dir, phone_dir],
            ns,
            line,
            thief,
        }
    }

    /// The recovered line's newest version.
    fn newest(&self) -> u64 {
        self.line.len() as u64
    }

    /// The thief's version `version` of the namespace: the genesis's
    /// content (which lists A) signed by A.
    async fn forged(&self, version: u64) -> Data {
        SignedTrustContext::decode_content(self.line[0].content().unwrap(), version)
            .unwrap()
            .sign_into_data_async(self.thief.as_ref())
            .await
            .unwrap()
    }

    /// A node holding the namespace at version `held`, through a validating
    /// forwarder over its keyring (as a daemon's engine).
    async fn holder(&self, held: usize) -> (Arc<Keyring>, Validator) {
        let keyring = Arc::new(Keyring::new());
        let served: Vec<&Data> = self.line[..held].iter().collect();
        adopt_by_name(
            &keyring,
            None,
            &mut Upstream::serving(&self.ns, &served),
            &self.ns,
            None,
        )
        .await
        .unwrap();
        assert_eq!(keyring.version_of(&self.ns), Some(held as u64));
        let validator =
            Validator::with_keyring(Arc::clone(&keyring), Arc::new(CertCache::new()), None, 4);
        (keyring, validator)
    }
}

/// Every version of `ns` a node serves: RDR metadata naming the newest, and
/// each by its exact name; anything else is answered at once with nothing.
/// Counts the Interests it is sent.
struct Upstream {
    ns: Name,
    versions: Vec<Bytes>,
    interests: u64,
}

impl Upstream {
    fn serving(ns: &Name, versions: &[&Data]) -> Self {
        Self {
            ns: ns.clone(),
            versions: versions.iter().map(|d| d.raw().clone()).collect(),
            interests: 0,
        }
    }
}

impl CaExchange for Upstream {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        self.interests += 1;
        let interest = Interest::decode(interest).unwrap();
        let meta_name = rdr_metadata_name(&self.ns);
        if *interest.name == meta_name {
            let newest = Data::decode(self.versions.last().unwrap().clone()).unwrap();
            let version = newest
                .name
                .components()
                .last()
                .unwrap()
                .as_version()
                .unwrap();
            let wire = DataBuilder::new(
                meta_name.append_version(version).append_segment(0),
                &newest.name.encode_to_tlv(),
            )
            .build();
            return Ok(Data::decode(wire).unwrap());
        }
        self.versions
            .iter()
            .map(|wire| Data::decode(wire.clone()).unwrap())
            .find(|d| *d.name == *interest.name)
            .ok_or_else(|| CertError::Transport(format!("no reply for {}", interest.name)))
    }
}

/// `Upstream` through this node's validating forwarder, which drops what
/// its validator does not admit and records what it admits.
struct Forwarded<'a> {
    upstream: Upstream,
    forwarder: &'a Validator,
    admitted: Vec<Name>,
}

impl CaExchange for Forwarded<'_> {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let data = self.upstream.express(interest).await?;
        match self.forwarder.validate_chain_cached(&data).await.0 {
            ValidationResult::Valid(_) => {
                self.admitted.push((*data.name).clone());
                Ok(data)
            }
            other => Err(CertError::Transport(format!("dropped: {other:?}"))),
        }
    }
}

/// A holder on the recovered line adopts it by name again while the thief
/// serves its own newer version, signed by the stolen genesis key: its
/// forwarder admits nothing and nothing is adopted — the forwarder expects
/// a version signed by an anchor of the held one, not by the key the name
/// hashes. Adopted by name again at the newest, nothing changes.
#[tokio::test]
async fn a_held_namespace_adopted_by_name_again_admits_nothing_the_genesis_key_signs() {
    let alice = Recovered::new().await;
    let ns = &alice.ns;
    let line: Vec<&Data> = alice.line.iter().collect();
    let newest = alice.newest();
    let (keyring, forwarder) = alice.holder(line.len()).await;

    // The thief's next version, signed by the stolen genesis key A.
    let forged = alice.forged(newest + 1).await;
    let mut served = line.clone();
    served.push(&forged);
    let mut net = Forwarded {
        upstream: Upstream::serving(ns, &served),
        forwarder: &forwarder,
        admitted: Vec::new(),
    };
    let refused = adopt_by_name(&keyring, Some(&forwarder), &mut net, ns, None)
        .await
        .expect_err("a version signed by the stolen genesis key was adopted");
    assert!(
        !net.admitted.contains(&forged.name),
        "the forwarder admitted the thief's version: {refused}"
    );
    assert!(
        matches!(&refused, AdoptError::NotContinuous { held, offered, .. }
            if *held == newest && *offered == newest + 1),
        "{refused}"
    );
    assert_eq!(keyring.version_of(ns), Some(newest));

    let mut net = Forwarded {
        upstream: Upstream::serving(ns, &line),
        forwarder: &forwarder,
        admitted: Vec::new(),
    };
    let again = adopt_by_name(&keyring, Some(&forwarder), &mut net, ns, None)
        .await
        .unwrap();
    assert_eq!(again.context.version(), newest);
    assert_eq!(*again.data.name, *alice.line.last().unwrap().name);
    assert_eq!(keyring.version_of(ns), Some(newest));
}

/// A holder behind on a recovered line adopts it by name again: it reaches
/// the newest version, walking from the version it holds, through its
/// forwarder.
#[tokio::test]
async fn a_held_namespace_adopted_by_name_again_reaches_the_recovered_newest() {
    let alice = Recovered::new().await;
    let ns = &alice.ns;
    let line: Vec<&Data> = alice.line.iter().collect();
    let newest = alice.newest();
    // Holding the version with the recovery anchor, before the recovery.
    let (keyring, forwarder) = alice.holder(line.len() - 2).await;
    let mut net = Forwarded {
        upstream: Upstream::serving(ns, &line),
        forwarder: &forwarder,
        admitted: Vec::new(),
    };
    let adopted = adopt_by_name(&keyring, Some(&forwarder), &mut net, ns, None)
        .await
        .expect("the holder reaches the recovered line's newest version");
    assert_eq!(adopted.context.version(), newest);
    assert_eq!(keyring.version_of(ns), Some(newest));
    let walked: Vec<u64> = adopted
        .earlier
        .iter()
        .map(|s| s.context.version())
        .collect();
    assert_eq!(walked, [newest - 1]);
}

/// The thief names a version far beyond the recovered line's newest, and
/// the positions in between fail at once: the walk fetches at most
/// [`MAX_CATCH_UP_MISSES`] of them, then only the version named, and stops
/// saying why — not one Interest per position for its whole fetch time.
#[tokio::test]
async fn a_pointer_to_a_huge_version_costs_a_bounded_number_of_fetches() {
    let alice = Recovered::new().await;
    let ns = &alice.ns;
    let newest = alice.newest();
    let (keyring, _) = alice.holder(alice.line.len()).await;
    let forged = alice.forged(u64::MAX / 2).await;
    let mut served: Vec<&Data> = alice.line.iter().collect();
    served.push(&forged);
    let mut upstream = Upstream::serving(ns, &served);

    let started = std::time::Instant::now();
    let res = refresh_context(&keyring, None, &mut upstream, ns).await;
    let Err(RefreshError::Refused {
        refusal: UpdateRefusal::CatchUp { stop, .. },
        ..
    }) = &res
    else {
        panic!("{res:?}");
    };
    // The metadata, the version named, then the positions passed over (the
    // version named, the walk's last position, is not fetched again).
    assert!(
        upstream.interests <= MAX_CATCH_UP_MISSES + 2,
        "{} Interests in {:?}: {stop}",
        upstream.interests,
        started.elapsed()
    );
    assert!(
        matches!(stop, CatchUpStop::Missing { first, .. } if *first == newest + 1),
        "{stop}"
    );
    assert!(stop.to_string().contains("at most"), "{stop}");
    assert_eq!(keyring.version_of(ns), Some(newest));
}

/// A source whose every position fails at once — nothing there, or an old
/// version not newer than the one reached (a sync group's sequence numbers
/// carry any version) — except the last. Counts its fetches; past
/// `give_up` it passes over the rest (so the test ends).
struct InstantFailures {
    old: Data,
    first: u64,
    last: u64,
    fetches: u64,
    give_up: u64,
}

impl VersionSource for InstantFailures {
    async fn fetch(
        &mut self,
        position: u64,
        _from: &SignedTrustContext,
    ) -> Result<Data, Unfetched> {
        self.fetches += 1;
        if self.fetches > self.give_up && position < self.last {
            return Err(Unfetched::MissingUntil {
                next: u64::MAX,
                reason: "the test gave up".into(),
            });
        }
        if (position - self.first) % 2 == 1 || position == self.last {
            Ok(Data::decode(self.old.raw().clone()).unwrap())
        } else {
            Err(Unfetched::Missing("nothing there".into()))
        }
    }
}

/// The walk's own bound, whatever its source (a refresh's by name, a sync
/// group's by sequence number): positions that fail at once, missing or
/// not newer, are fetched [`MAX_CATCH_UP_MISSES`] times at most.
#[tokio::test]
async fn a_walk_fetches_a_bounded_number_of_positions_it_cannot_use() {
    let alice = Recovered::new().await;
    let first = alice.newest() + 1;
    let held = SignedTrustContext::open_signed(alice.line.last().unwrap())
        .await
        .unwrap()
        .0;
    let mut source = InstantFailures {
        old: copy(&alice.line[1]),
        first,
        last: u64::MAX,
        fetches: 0,
        give_up: 100 * MAX_CATCH_UP_MISSES,
    };
    let stop = follow_versions(&held, first..=u64::MAX, &mut source)
        .await
        .expect_err("nothing follows");
    assert!(
        source.fetches <= MAX_CATCH_UP_MISSES + 1,
        "{} fetches: {stop}",
        source.fetches
    );
    assert!(
        matches!(stop, CatchUpStop::Missing { first: f, .. } if f == first),
        "{stop}"
    );
}
