//! The decoder's limits (trust-envelope.md §6.5): an envelope is refused for its
//! size, its relay count or an over-long name before any work that scales with
//! it. Own test binary: a counting global allocator measures what a decode
//! allocates, per thread, so the other tests of this crate and parallel tests
//! here cannot disturb it.

use std::time::Duration;

use ndn_tlv::TlvWriter;
use ndn_trust_envelope::{
    ENVELOPE_MAX, EnvelopeError, HINT_RELAYS_MAX, LINK_HINT_MAX, NAME_WIRE_MAX, SCOPE_PATTERNS_MAX,
    TrustEnvelope,
};

use counting::measured;

/// A global allocator that counts, per thread, the bytes live and their peak.
/// `GlobalAlloc` is an unsafe trait; the workspace denies unsafe code, so the
/// allowance is scoped to this module, which only forwards to `System`.
#[allow(unsafe_code)]
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    thread_local! {
        // `const` initialisers, no destructor: touching them never allocates.
        static LIVE: Cell<usize> = const { Cell::new(0) };
        static PEAK: Cell<usize> = const { Cell::new(0) };
    }

    struct Counting;

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                grow(layout.size());
            }
            p
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let p = unsafe { System.alloc_zeroed(layout) };
            if !p.is_null() {
                grow(layout.size());
            }
            p
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
            let _ = LIVE.try_with(|l| l.set(l.get().saturating_sub(layout.size())));
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                let _ = LIVE.try_with(|l| l.set(l.get().saturating_sub(layout.size())));
                grow(new_size);
            }
            p
        }
    }

    fn grow(n: usize) {
        let _ = LIVE.try_with(|l| {
            let now = l.get() + n;
            l.set(now);
            let _ = PEAK.try_with(|p| p.set(p.get().max(now)));
        });
    }

    #[global_allocator]
    static ALLOC: Counting = Counting;

    /// What `f` returned, the most bytes it held at once, and how long it took.
    pub fn measured<T>(f: impl FnOnce() -> T) -> (T, usize, Duration) {
        let base = LIVE.with(Cell::get);
        PEAK.with(|p| p.set(base));
        let start = Instant::now();
        let out = f();
        (out, PEAK.with(Cell::get) - base, start.elapsed())
    }
}

const FINGERPRINT: u64 = 0x048E;
const SECRET: u64 = 0x0477;
const LINK_HINT: u64 = 0x0478;
const NAMESPACE_WIRE: u64 = 0x0490;
const OFFER_WIRE: u64 = 0x0492;
const RELAY_WIRE: u64 = 0x0494;

/// One generic name component of `octets` octets of 0xFF, as a Name's value.
fn component(octets: usize) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_tlv(0x08, &vec![0xFF; octets]);
    w.finish().to_vec()
}

/// A relative name: `shared` leading components of the namespace, then `rest`
/// (a Name's value).
fn relative(shared: u8, rest: &[u8]) -> Vec<u8> {
    let mut v = vec![shared];
    v.extend_from_slice(rest);
    v
}

/// An `intro` envelope with the given compact fields.
fn intro(namespace: Option<&[u8]>, offer: &[u8], relays: &[Vec<u8>]) -> Vec<u8> {
    let mut body = TlvWriter::new();
    if let Some(ns) = namespace {
        body.write_tlv(NAMESPACE_WIRE, ns);
    }
    body.write_tlv(FINGERPRINT, &[0xA5; 32]);
    body.write_tlv(OFFER_WIRE, offer);
    body.write_tlv(SECRET, &[0x3C; 16]);
    for r in relays {
        body.write_tlv(RELAY_WIRE, r);
    }
    envelope(7, &body.finish())
}

/// An `intro` as a hostile sender writes it: a namespace of one component of
/// `ns_octets` octets, and `relays` relays that each share that component and
/// add nothing (`[1]`: five octets on the wire).
fn hostile_intro(ns_octets: usize, relays: usize) -> Vec<u8> {
    intro(
        Some(&component(ns_octets)),
        &relative(1, &[]),
        &vec![relative(1, &[]); relays],
    )
}

fn envelope(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_nested(0x0470, |w| {
        w.write_tlv(0x0471, &[1]);
        w.write_tlv(0x0472, &[kind]);
        w.write_tlv(0x0473, body);
    });
    w.finish().to_vec()
}

/// A `recovery` envelope whose bundle is `octets` long.
fn recovery(octets: usize) -> Vec<u8> {
    let mut body = TlvWriter::new();
    body.write_tlv(0x0482, &vec![0x5A; octets]);
    envelope(4, &body.finish())
}

/// The `recovery` envelope that is exactly `total` octets long.
fn recovery_of(total: usize) -> Vec<u8> {
    let mut n = total;
    loop {
        let wire = recovery(n);
        if wire.len() <= total {
            assert_eq!(wire.len(), total, "no bundle makes exactly {total} octets");
            return wire;
        }
        n -= wire.len() - total;
    }
}

fn uri(kind: &str, wire: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "ndn-trust://{kind}/{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire)
    )
}

/// The refusal a decode must have given: more than a limit of `what`.
#[track_caller]
fn assert_too_many(got: Result<TrustEnvelope, EnvelopeError>, what: &str) {
    match got {
        Err(EnvelopeError::TooMany { what: w, .. }) if w == what => {}
        other => panic!("expected too many {what}, got {other:?}"),
    }
}

/// The refusal a decode must have given: a `what` over its size limit.
#[track_caller]
fn assert_too_large(got: Result<TrustEnvelope, EnvelopeError>, what: &str) {
    match got {
        Err(EnvelopeError::TooLarge { what: w, .. }) if w == what => {}
        other => panic!("expected {what} too large, got {other:?}"),
    }
}

/// The review's amplification: every relay copies the namespace's component
/// and writes it as escaped text, so a few thousand five-octet relays turn a
/// 40 KB link into hundreds of MB. It is refused for its relay count, within a
/// small fixed allocation, and fast.
#[test]
fn many_relays_sharing_a_long_namespace_are_refused_cheaply() {
    let wire = hostile_intro(8_000, 6_000);
    assert!(
        wire.len() < 40_000,
        "the hostile link is small: {}",
        wire.len()
    );
    let text = uri("intro", &wire);

    let (decoded, peak, took) = measured(|| TrustEnvelope::decode(&wire));
    println!("decode: {peak} peak bytes, {took:?}");
    assert_too_many(decoded, "relays");
    assert!(peak < 1 << 20, "allocated {peak} bytes at once");
    assert!(took < Duration::from_millis(500), "took {took:?}");

    let (parsed, peak, took) = measured(|| TrustEnvelope::from_uri(&text));
    println!("from_uri: {peak} peak bytes, {took:?}");
    assert_too_many(parsed, "relays");
    assert!(peak < 1 << 20, "allocated {peak} bytes at once");
    assert!(took < Duration::from_millis(500), "took {took:?}");
}

/// `HINT_RELAYS_MAX` relays decode, to the names they stand for; one more is
/// refused.
#[test]
fn the_relay_count_is_bounded() {
    let ns = component(5);
    let decode = |n| {
        TrustEnvelope::decode(&intro(
            Some(&ns),
            &relative(1, &[]),
            &vec![relative(1, &[]); n],
        ))
    };
    let Ok(TrustEnvelope::Intro(got)) = decode(HINT_RELAYS_MAX) else {
        panic!("{HINT_RELAYS_MAX} relays decode");
    };
    assert_eq!(got.relays.len(), HINT_RELAYS_MAX);
    assert!(got.relays.iter().all(|r| Some(r) == got.namespace.as_ref()));
    assert_too_many(decode(HINT_RELAYS_MAX + 1), "relays");
}

/// A namespace, or a relative name, whose wire form is over `NAME_WIRE_MAX`
/// is refused, whichever part makes it so; one at the limit decodes.
#[test]
fn a_name_over_the_packet_limit_is_refused() {
    // One generic component: type (1) + length (3, over 252) + value.
    let at_limit = NAME_WIRE_MAX - 4;
    let ok = |ns: &[u8], offer: &[u8]| TrustEnvelope::decode(&intro(Some(ns), offer, &[]));
    assert!(ok(&component(at_limit), &relative(1, &[])).is_ok());
    assert_too_large(
        ok(&component(at_limit + 1), &relative(1, &[])),
        "introduction namespace",
    );

    // A relative name's own components, with no namespace to share.
    let bare = |rest: &[u8]| TrustEnvelope::decode(&intro(None, &relative(0, rest), &[]));
    assert!(bare(&component(at_limit)).is_ok());
    assert_too_large(bare(&component(at_limit + 1)), "offer");

    // Each part within the limit, the name they make over it.
    let shared = component(5_000);
    assert_too_large(ok(&shared, &relative(1, &component(5_000))), "offer");
    let relay = TrustEnvelope::decode(&intro(
        Some(&shared),
        &relative(1, &[]),
        &[relative(1, &component(5_000))],
    ));
    assert_too_large(relay, "relay");
}

/// An envelope over `ENVELOPE_MAX` is refused before anything is allocated for
/// it: as bytes, as a link whose text is too long to be one, and in the legacy
/// form.
#[test]
fn an_oversized_envelope_is_refused_before_it_is_read() {
    let at_limit = recovery_of(ENVELOPE_MAX);
    assert!(TrustEnvelope::decode(&at_limit).is_ok());
    assert!(TrustEnvelope::from_uri(&uri("recovery", &at_limit)).is_ok());

    let over = recovery_of(ENVELOPE_MAX + 1);
    let (got, peak, _) = measured(|| TrustEnvelope::decode(&over));
    assert_too_large(got, "envelope");
    assert!(peak < 64 << 10, "allocated {peak} bytes at once");

    let text = uri("recovery", &over);
    let (got, peak, _) = measured(|| TrustEnvelope::from_uri(&text));
    assert_too_large(got, "link text");
    assert!(peak < 64 << 10, "allocated {peak} bytes at once");

    // Text that is far too long to be an envelope is not even decoded.
    let junk = format!("ndn-trust://recovery/{}", "A".repeat(2 * ENVELOPE_MAX));
    let (got, peak, _) = measured(|| TrustEnvelope::from_uri(&junk));
    assert_too_large(got, "link text");
    assert!(peak < 64 << 10, "allocated {peak} bytes at once");

    let legacy = format!("ndn-ctx:1:5:{}", "A".repeat(2 * ENVELOPE_MAX));
    let (got, peak, _) = measured(|| TrustEnvelope::from_uri(&legacy));
    assert_too_large(got, "link text");
    assert!(peak < 64 << 10, "allocated {peak} bytes at once");
}

/// The other things that repeat or ride opaque are bounded too: scope
/// patterns of a capability, and an introduction's link hint.
#[test]
fn scope_patterns_and_the_link_hint_are_bounded() {
    let capability = |patterns: usize| {
        let mut body = TlvWriter::new();
        body.write_tlv(0x048D, &[0]);
        body.write_tlv(0x0489, b"/home/alice");
        for _ in 0..patterns {
            body.write_tlv(0x048A, b"/work/<**rest>");
        }
        body.write_tlv(0x0486, &60u64.to_be_bytes());
        TrustEnvelope::decode(&envelope(6, &body.finish()))
    };
    assert!(capability(SCOPE_PATTERNS_MAX).is_ok());
    assert_too_many(capability(SCOPE_PATTERNS_MAX + 1), "scope patterns");

    let with_hint = |octets: usize| {
        let mut body = TlvWriter::new();
        body.write_tlv(FINGERPRINT, &[0xA5; 32]);
        body.write_tlv(OFFER_WIRE, &relative(0, &component(3)));
        body.write_tlv(SECRET, &[0x3C; 16]);
        body.write_tlv(LINK_HINT, &vec![0x5A; octets]);
        TrustEnvelope::decode(&envelope(7, &body.finish()))
    };
    assert!(with_hint(LINK_HINT_MAX).is_ok());
    assert_too_large(with_hint(LINK_HINT_MAX + 1), "link hint");
}
