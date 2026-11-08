//! An inline version 1 of a self-certifying namespace not held
//! (trust-context.md §4.5.3, §4.5.6 note 1). Each test guards one
//! invariant:
//!
//! - while a network is bound, the namespace is adopted by name, and a link's
//!   inline version 1 only checked against the fetched one: a thief holding
//!   the stolen genesis key cannot hand a fresh adopter a second version 1
//!   of his own (a fork), whatever link carries it;
//! - the owner's inline version 1 leads to her newest version;
//! - an inline version 1 is taken alone only with no network bound, and the
//!   adoption says so.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    AdoptError, AnchorLink, CaExchange, CertError, NewRootStore, OldRoot, RecoverySeed,
    add_recovery_anchor, adopt_anchor_link, anchor_fingerprint, rdr_metadata_name,
    recover_namespace_in_pib, recovery_anchor,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::self_certifying::self_certifying_name;
use ndn_security::{Ed25519Signer, FilePib, Keyring, SignedTrustContext, Signer};
use ndn_trust_envelope::TrustEnvelope;

/// Alice's namespace, named from her genesis key A, and its line after A
/// was stolen: v1 (A), v2 adding her recovery anchor R (signed by A), v3
/// (signed by R, revoking A) and v4 (her new root's). Beside it, the thief's
/// own version 1, signed with the stolen A: it leaves R out (and names a CA
/// of his), so nothing Alice signs after it follows from it.
struct Line {
    ns: Name,
    /// The fingerprint of A, the anchor of either version 1.
    genesis_fingerprint: [u8; 32],
    versions: Vec<Data>,
    thief_v1: Data,
    _recovered: tempfile::TempDir,
}

impl Line {
    async fn new() -> Self {
        let seed = [41u8; 32];
        let public = Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
        let ns = self_certifying_name(&public);
        let a: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &seed,
            ns.clone().append("KEY").append("genesis"),
        ));
        let anchor = recovery_anchor(Arc::clone(&a)).await.unwrap();
        let genesis_fingerprint = anchor_fingerprint(&anchor);
        let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
        assert!(ctx.add_anchor(anchor));
        let v1 = ctx.sign_into_data_async(a.as_ref()).await.unwrap();

        let recovery = RecoverySeed::generate().unwrap();
        let kit = recovery_anchor(Arc::new(recovery.signer(&ns)))
            .await
            .unwrap();
        let v2 = add_recovery_anchor(a.as_ref(), &v1, &kit)
            .await
            .unwrap()
            .data;
        let dir = tempfile::tempdir().unwrap();
        let recovered = recover_namespace_in_pib(
            &FilePib::new(dir.path()).unwrap(),
            &v2,
            &recovery.signer(&ns),
            "phone",
            OldRoot::Compromised,
            &[],
            &[],
            &NewRootStore::File,
        )
        .await
        .unwrap();
        let v3 = recovered.version.bump.data;
        let v4 = recovered.root_version.data;

        let thief_v1 = SignedTrustContext::decode_content(v1.content().unwrap(), 1)
            .unwrap()
            .with_ca_endpoint(ns.clone().append("thief").append("CA"));
        let thief_v1 = thief_v1.sign_into_data_async(a.as_ref()).await.unwrap();
        Self {
            ns,
            genesis_fingerprint,
            versions: vec![v1, v2, v3, v4],
            thief_v1,
            _recovered: dir,
        }
    }

    /// The anchor link an introduction's credentials make of `v1`: the
    /// namespace, the fingerprint of its signer, its version, inline.
    fn inline(&self, v1: &Data) -> TrustEnvelope {
        TrustEnvelope::Anchor {
            namespace: Some(self.ns.to_string()),
            fingerprint: Some(self.genesis_fingerprint),
            version: Some(1),
            context_data: Some(v1.raw().clone()),
            context_content: None,
        }
    }

    /// What Bob's network serves of the namespace: Alice's line.
    fn network(&self) -> Upstream {
        Upstream {
            ns: self.ns.clone(),
            versions: self.versions.iter().map(|d| d.raw().clone()).collect(),
        }
    }
}

/// Every version of `ns` a node serves: RDR metadata naming the newest,
/// and each by its exact name.
struct Upstream {
    ns: Name,
    versions: Vec<Bytes>,
}

impl CaExchange for Upstream {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let interest = Interest::decode(interest).unwrap();
        let meta_name = rdr_metadata_name(&self.ns);
        let newest = self
            .versions
            .last()
            .map(|wire| Data::decode(wire.clone()).unwrap());
        if *interest.name == meta_name
            && let Some(newest) = newest
        {
            let version = newest.name.components().last().unwrap().as_version();
            let wire = DataBuilder::new(
                meta_name.append_version(version.unwrap()).append_segment(0),
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

/// The reviewer's scenario (M1): the thief offers Bob his version 1 inline
/// (an introduction's credentials, an anchor link) while Alice's recovered
/// line is reachable over Bob's network. Bob fetches her version 1, finds
/// the link's differs — two versions 1 signed by the key the name hashes,
/// evidence of a fork — and holds nothing of her namespace.
#[tokio::test]
async fn a_thiefs_inline_genesis_is_refused_as_a_fork_while_the_owners_line_is_reachable() {
    let line = Line::new().await;
    let link = AnchorLink::from_envelope(&line.inline(&line.thief_v1)).unwrap();
    let bob = Keyring::new();
    assert!(link.fetches(&bob), "an inline version 1 is adopted by name");
    let refused = adopt_anchor_link(&bob, None, &mut line.network(), &link)
        .await
        .expect_err("the thief's version 1 was adopted from an inline link");
    assert!(
        matches!(refused, AdoptError::GenesisFork { .. }),
        "{refused}"
    );
    assert!(refused.to_string().contains("fork"), "{refused}");
    assert!(bob.held(&line.ns).is_none(), "Bob holds the thief's line");
}

/// Alice's own version 1 inline, her line reachable: it matches the
/// fetched one, and Bob reaches her newest version from it, by name.
#[tokio::test]
async fn the_owners_inline_genesis_leads_to_her_newest_version_by_name() {
    let line = Line::new().await;
    let link = AnchorLink::from_envelope(&line.inline(&line.versions[0])).unwrap();
    let bob = Keyring::new();
    let adopted = adopt_anchor_link(&bob, None, &mut line.network(), &link)
        .await
        .unwrap();
    assert!(adopted.fetched && !adopted.offline_genesis);
    assert_eq!(adopted.context.version(), 4);
    let earlier: Vec<u64> = adopted
        .earlier
        .iter()
        .map(|s| s.context.version())
        .collect();
    assert_eq!(earlier, [1, 2, 3]);
    assert_eq!(bob.version_of(&line.ns), Some(4));
}

/// An inline version 1 alone is taken only with no network bound
/// (`adopt_anchor_envelope`), and the adoption says so. With a network
/// bound that reaches nobody, the link is refused, saying to retry once the
/// person's devices are reachable — never taken from its version 1.
#[tokio::test]
async fn an_inline_genesis_is_taken_alone_only_with_no_network_and_says_so() {
    let line = Line::new().await;
    let unreachable = AnchorLink::from_envelope(&line.inline(&line.versions[0])).unwrap();
    let bob = Keyring::new();
    let mut nobody = Upstream {
        ns: line.ns.clone(),
        versions: Vec::new(),
    };
    let refused = adopt_anchor_link(&bob, None, &mut nobody, &unreachable)
        .await
        .expect_err("an inline version 1 was taken alone with a network bound");
    assert!(
        matches!(refused, AdoptError::GenesisUnreachable { .. }),
        "{refused}"
    );
    assert!(refused.to_string().contains("Retry once"), "{refused}");
    assert!(bob.held(&line.ns).is_none());

    let offline = ndn_cert::adopt_anchor_envelope(&bob, &line.inline(&line.versions[0])).unwrap();
    assert!(offline.offline_genesis, "the adoption does not say so");
    assert!(!offline.fetched);
    assert_eq!(bob.version_of(&line.ns), Some(1));
    // Held now, a link moves it on only by continuity: the thief's version
    // 1 is a fork of it.
    let refused = ndn_cert::adopt_anchor_envelope(&bob, &line.inline(&line.thief_v1))
        .expect_err("a second version 1 replaced the held one");
    assert!(matches!(refused, AdoptError::Fork(1)), "{refused}");
}
