//! F1 Tier-1 witness — `did:ndn:*` resolution against the default
//! `UniversalResolver::with_cert_fetcher` path.
//!
//! Per the upstream roadmap doc
//! (internal)
//! Tier 1.3: spin up a fetcher that hands back a known cert when
//! asked for the right name; resolve `did:ndn:<base64url(name)>`;
//! assert the resulting `DidDocument` has the expected `id` and
//! at least one verification method.
//!
//! This test could not exist before T1.1+T1.2 because the resolver
//! had no way to consume the shared `CertFetcher` machinery.
//!
//! Application-side store-fallback resolution paths
//! (`Kind::Sovereignty { IdentityProof }` blocks) do not depend on
//! this test passing — but every cross-stack `did:ndn:*` URI consumer
//! does.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::{Name, NameComponent, SignatureType};
use ndn_security::cert_cache::{CertCache, Certificate};
use ndn_security::cert_fetcher::CertFetcher;
use ndn_security::did::{DidResolutionError, UniversalResolver, encoding::name_to_did};

/// Build an in-memory `CertFetcher` that hands back exactly one
/// cert for one name, panicking on any other request. Mirrors the
/// shape of `Validator`'s production fetcher closely enough that
/// the resolver path is the only thing under test.
fn fixture_fetcher(expected: Name, cert: Certificate) -> Arc<CertFetcher> {
    let cache = Arc::new(CertCache::new());
    let cell: std::sync::Mutex<Option<Certificate>> = std::sync::Mutex::new(Some(cert.clone()));
    let cell = Arc::new(cell);
    let fetch_fn: ndn_security::cert_fetcher::FetchFn = Arc::new(move |name: Name| {
        let cell = Arc::clone(&cell);
        let expected = expected.clone();
        Box::pin(async move {
            assert_eq!(
                name, expected,
                "fixture_fetcher only knows {expected}; got {name}",
            );
            // Build a minimal Data wire — enough for Certificate::decode
            // to round-trip when callers want it. The resolver's path
            // here uses `CertFetcher::fetch` which decodes Data into
            // Certificate; we sidestep that by going around through a
            // pre-baked Certificate. This works because CertFetcher
            // accepts a FetchFn returning Option<Data>, and we go
            // straight from Data → Certificate inside `do_fetch`. So
            // we need a Data wire that decodes back to our Certificate.
            //
            // A complete reconstruction is out of scope; the test
            // populates the cache directly below and the FetchFn never
            // actually fires. This closure is here in case the cache
            // misses unexpectedly.
            cell.lock().unwrap().take().map(|c| {
                // Produce a wire that re-decodes to our Certificate.
                // The simplest path is to use the cert's own
                // signed_region + sig_value if present; otherwise
                // panic loudly so the test author sees what's wrong.
                let signed = c.signed_region.expect("test cert needs signed_region");
                let sig = c.sig_value.expect("test cert needs sig_value");
                let mut buf = bytes::BytesMut::new();
                use ndn_tlv::TlvWriter;
                let mut w = TlvWriter::new();
                w.write_nested(ndn_packet::tlv_type::DATA, |w| {
                    w.write_raw(&signed);
                    w.write_tlv(ndn_packet::tlv_type::SIGNATURE_VALUE, &sig);
                });
                let wire = w.finish();
                buf.extend_from_slice(&wire);
                ndn_packet::Data::decode(buf.freeze()).expect("test wire decodes")
            })
        })
    });
    let fetcher = Arc::new(CertFetcher::new(
        Arc::clone(&cache),
        fetch_fn,
        Duration::from_secs(2),
    ));
    // Pre-warm the cache so the resolver path doesn't hit the
    // fetch_fn at all — this isolates the test to "does the
    // resolver consult the shared cache via CertFetcher?", which
    // is exactly T1.1's contract.
    cache.insert(cert);
    fetcher
}

fn fixture_cert(key_name: Name) -> Certificate {
    Certificate {
        name: Arc::new(key_name),
        // Ed25519 raw 32 bytes — `cert_to_did_document` reads this
        // and emits a verificationMethod entry.
        public_key: Bytes::from_static(&[7u8; 32]),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: SignatureType::SignatureEd25519,
    }
}

#[tokio::test]
async fn t1_resolves_did_ndn_via_cert_fetcher() {
    // Identity name = /test/alice; the resolver appends "KEY" to
    // build the cert name it asks the fetcher for.
    let identity: Name = Name::from_components([
        NameComponent::generic(Bytes::from_static(b"test")),
        NameComponent::generic(Bytes::from_static(b"alice")),
    ]);
    let key_name = identity.clone().append("KEY");
    let cert = fixture_cert(key_name.clone());
    let fetcher = fixture_fetcher(key_name, cert);

    let resolver = UniversalResolver::with_cert_fetcher(fetcher);
    let did = name_to_did(&identity);
    assert!(did.starts_with("did:ndn:"), "encoding produced {did}");

    let doc = resolver
        .resolve_document(&did)
        .await
        .expect("did:ndn must resolve through the default driver");

    // The document's id should round-trip back to the identity
    // we started with — that's the load-bearing contract: a
    // user who shares `did:ndn:<base64>(/test/alice)` gets back
    // a document identified by the same DID.
    assert_eq!(doc.id, did, "round-trip DID identity broke");
    assert!(
        !doc.verification_methods.is_empty(),
        "cert_to_did_document should have emitted at least one VM entry"
    );
}

#[tokio::test]
async fn t1_stub_mode_returns_internal_error() {
    // The default UniversalResolver::new() path keeps the stub
    // resolver. Confirm it's loud — any did:ndn:* request must
    // surface InternalError, not silently degrade to "method
    // not supported" or hang.
    let resolver = UniversalResolver::new();
    let identity: Name =
        Name::from_components([NameComponent::generic(Bytes::from_static(b"unwired"))]);
    let did = name_to_did(&identity);
    let result = resolver.resolve(&did).await;
    assert_eq!(
        result.did_resolution_metadata.error,
        Some(DidResolutionError::InternalError),
        "stub mode must return InternalError; got: {:?}",
        result.did_resolution_metadata.error
    );
}
