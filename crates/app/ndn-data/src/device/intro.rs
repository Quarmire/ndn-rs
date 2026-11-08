//! The device's side of introductions (spec §19): offers and use marks in
//! the log, the asks it answers, and the joins it makes. Types, bytes and
//! proofs are [`crate::intro`]'s.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::cert_name::key_name_of;
use ndn_security::confidentiality::{ContentKey, Sealed, wrap_ck_to};
use ndn_security::safe_data::TrustPath;
use ndn_security::self_certifying::self_certifying_digest;
use ndn_security::{
    CertCache, Certificate, Keyring, SignedTrustContext, ValidationResult, Validator,
    anchor_fingerprint, public_key_digest,
};
use ndn_trust_envelope::{INTRO_WORDS_FINGERPRINT_LEN, IntroWords, Introduction, TrustEnvelope};

use super::{Device, Held, Inner, St, Subject, check_collection, local, open_grant, owner_signed};
use crate::error::DataError;
use crate::intro::{
    AnswerBody, AskBody, Code, IntroAsk, IntroRecord, IntroRefusal, Introducer, Joined, Offer,
    OfferBody, Outcome, Role, SECRET_LEN, UsedBody, answer_proof, answer_proves, ask_proof,
    ask_proves, commitment, intro_name, intro_prefix, proof_key,
};
use crate::layer::{ShareChange, Sharing};
use crate::version::{Audience, Writer};
use crate::wire::{self, LogName, Record, device_of, namespace_of, parse_log_name};

/// How many times a join sends its ask (the same parameters each time, so a
/// retry is answered from the answer the inviter device keeps for it) before
/// it says the inviter is not reachable. On a lossy path about half of the
/// exchanges fail (the faulty network of spec §18.1: a fifth of the packets
/// lost each way, some held past the Interest's lifetime); eight sends leave
/// about one join in two hundred unanswered, and an inviter really offline
/// is reported after eight lifetimes.
const ASK_TRIES: u32 = 8;

/// How many times a join asks for the offer record: as often as it asks.
const OFFER_TRIES: u32 = ASK_TRIES;

/// The longest certificate chain credentials carry, or are walked for.
const CHAIN_MAX: usize = 8;

/// What a device holds of introductions.
pub(super) struct Intros {
    /// Offers held, by the offer record's name: this device's own, and
    /// other devices' of its namespace.
    pub(super) offers: BTreeMap<Name, OfferBody>,
    /// Use marks naming a key held, by offer: the key it was used by and
    /// its digest. The first held of an offer stands.
    pub(super) used: BTreeMap<Name, (Name, [u8; 32])>,
    /// Offers a closing mark is held of: closed for good, used or not.
    pub(super) closed: BTreeSet<Name>,
    /// Asks are judged one at a time: a use, a wrong try counted, a
    /// closing mark each see what the one before wrote.
    serial: Arc<tokio::sync::Mutex<()>>,
    /// Asks held now, verifying or waiting for their turn
    /// ([`IntroPolicy::asks_queued`](crate::intro::IntroPolicy::asks_queued)).
    queued: usize,
}

impl Intros {
    pub(super) fn new() -> Self {
        Self {
            offers: BTreeMap::new(),
            used: BTreeMap::new(),
            closed: BTreeSet::new(),
            serial: Arc::new(tokio::sync::Mutex::new(())),
            queued: 0,
        }
    }
}

/// One ask held ([`Intros::queued`]), let go as it is dropped.
struct Queued<'a>(&'a Inner);

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        let mut st = self.0.st.lock();
        st.intro.queued = st.intro.queued.saturating_sub(1);
    }
}

/// `/localhost/ndn-data/intro/<what>/<offer's Name TLV>`: where the store
/// keeps what an own offer needs, under a local name no device serves.
fn local_name(what: &str, offer: &Name) -> Name {
    let base: Name = format!("/localhost/ndn-data/intro/{what}")
        .parse()
        .expect("a valid name");
    base.append_component(NameComponent::generic(offer.encode_to_tlv()))
}

/// Where the store keeps an own offer's proof key, wrapped to the device's
/// recipient key.
fn proof_key_name(offer: &Name) -> Name {
    local_name("key", offer)
}

/// Where the store keeps an own offer's wrong tries, all askers' together:
/// how many were counted toward the cap, then when the last one was (4 and
/// 8 octets, big-endian; the time by the device's clock).
fn tries_name(offer: &Name) -> Name {
    local_name("tries", offer)
}

/// Where the store keeps how many wrong tries one asker key, by its public
/// key's digest, asked an own offer with (4 octets, big-endian).
fn asker_tries_name(offer: &Name, digest: &[u8; 32]) -> Name {
    tries_name(offer).append_component(NameComponent::generic(Bytes::copy_from_slice(digest)))
}

/// Where the store keeps the use of an own offer under way: the asker key
/// and its digest (the key's Name TLV, then the digest), from before the
/// asker's anchor is adopted until the use mark is durable. A stop between
/// leaves it: the offer is that key's, whose retry finishes the use.
fn using_name(offer: &Name) -> Name {
    local_name("using", offer)
}

/// Where the store keeps the acceptance an own offer's use was answered
/// with: its user asking again gets it again (spec §19.4).
fn accepted_name(offer: &Name) -> Name {
    local_name("accepted", offer)
}

/// Credentials opened ([`AskBody::credentials`], an answer's): the signed
/// trust context they carry, checked against its own anchor only, and a
/// validator that holds that context alone and their certificates. Nothing
/// of them is trusted by this device until its host adopts the context.
struct Opened {
    ctx: Arc<SignedTrustContext>,
    anchor: Certificate,
    /// The trust context's signed Data, as the credentials carry it.
    context: Bytes,
    /// Their certificates.
    certs: Arc<CertCache>,
    validator: Validator,
}

/// Open `packets`: a signed trust context (its signature verified under
/// one of its own anchors, valid now), then certificates. `None` when they
/// are not that.
async fn open_credentials(packets: &[Bytes]) -> Option<Opened> {
    let (first, rest) = packets.split_first()?;
    if rest.len() > CHAIN_MAX {
        return None;
    }
    let data = Data::decode(first.clone()).ok()?;
    let (ctx, anchor) = SignedTrustContext::open_received(&data).await.ok()?;
    let ctx = Arc::new(ctx);
    let keyring = Keyring::of_claim(Arc::clone(&ctx)).ok()?;
    let certs = Arc::new(CertCache::new());
    for p in rest {
        certs.insert(Certificate::decode(&Data::decode(p.clone()).ok()?).ok()?);
    }
    let validator = Validator::with_keyring(Arc::new(keyring), Arc::clone(&certs), None, CHAIN_MAX)
        .refuse_without_anchors();
    Some(Opened {
        ctx,
        anchor,
        context: first.clone(),
        certs,
        validator,
    })
}

impl Opened {
    /// The key that signed `data` and its public key's digest, if `data`
    /// verifies by a chain of these certificates to this context's anchor
    /// (its schema obeyed, certificates valid now).
    async fn signer(&self, data: &Data) -> Option<(Name, [u8; 32])> {
        self.signer_by(&self.validator, data).await
    }

    /// [`Self::signer`], judged by `keyring` — this device's, once its host
    /// adopted the namespace: by a chain of these certificates to an anchor
    /// of the version it holds, under that version's schema and
    /// revocations. A proof that verifies only under the context the
    /// credentials carry (an older one, a key the held version revokes)
    /// does not count.
    async fn signer_held(&self, keyring: &Arc<Keyring>, data: &Data) -> Option<(Name, [u8; 32])> {
        let held = Validator::with_keyring(
            Arc::clone(keyring),
            Arc::clone(&self.certs),
            None,
            CHAIN_MAX,
        )
        .refuse_without_anchors();
        self.signer_by(&held, data).await
    }

    async fn signer_by(&self, validator: &Validator, data: &Data) -> Option<(Name, [u8; 32])> {
        match validator.validate_chain(data).await {
            ValidationResult::Valid(safe)
                if !matches!(safe.trust_path(), TrustPath::DigestSha256) => {}
            _ => return None,
        }
        let locator = data.sig_info()?.key_locator_name()?;
        let key = key_name_of(&locator);
        Some((key.clone(), self.claimed(&key)?))
    }

    /// The public key digest `key` has by these credentials, unverified: an
    /// anchor of the context (a key that is its own anchor shows no
    /// certificate), else the certificate of it a chain walk picks.
    fn claimed(&self, key: &Name) -> Option<[u8; 32]> {
        let cert = self
            .ctx
            .anchor_for(key)
            .or_else(|| self.validator.cert_cache().get_valid(key))?;
        Some(public_key_digest(&cert.public_key))
    }

    /// The certificates on the chain from `key` to the context's anchor,
    /// as a chain walk picks them, named under `ns`: what a validator
    /// adopting the context takes of these credentials, and nothing else
    /// they carry (a certificate on no chain, of another party's key, would
    /// only shadow that party's in the cache).
    fn chain(&self, key: &Name, ns: &Name) -> Vec<Certificate> {
        let mut out = Vec::new();
        let mut at = key.clone();
        for _ in 0..=CHAIN_MAX {
            if self.ctx.anchor_for(&at).is_some() {
                break;
            }
            let Some(cert) = self.validator.cert_cache().get_valid(&at) else {
                break;
            };
            let Some(issuer) = cert.issuer.as_deref().cloned() else {
                break;
            };
            if cert.key_name().has_prefix(ns) {
                out.push(cert);
            }
            at = issuer;
        }
        out
    }

    /// Whether what `keyring` now holds of this context's namespace vouches
    /// for every anchor these credentials carry (by public key). Checked
    /// once the host adopted the namespace: a self-certifying one is
    /// adopted from its genesis by name, not from these credentials, so a
    /// proof checked against them counts only if their anchors are the
    /// namespace's. A namespace of another kind is adopted from these very
    /// credentials, and holds.
    fn vouched_by(&self, keyring: &Keyring) -> bool {
        let ns = self.ctx.namespace();
        if !matches!(self_certifying_digest(ns), Ok(Some(_))) {
            return true;
        }
        keyring.held(ns).is_some_and(|held| {
            self.ctx.anchors().iter().all(|a| {
                held.anchors()
                    .iter()
                    .any(|h| h.value().public_key == a.value().public_key)
            })
        })
    }

    /// SHA-256 of the anchor's public key.
    fn fingerprint(&self) -> [u8; 32] {
        anchor_fingerprint(&self.anchor)
    }

    /// The inline anchor link of the context, for the host to adopt.
    fn link(&self) -> TrustEnvelope {
        TrustEnvelope::Anchor {
            namespace: Some(self.ctx.namespace().to_string()),
            fingerprint: Some(self.fingerprint()),
            version: Some(self.ctx.version()),
            context_data: Some(self.context.clone()),
            context_content: None,
        }
    }
}

/// The anchor fingerprint a code names: whole (its link), or its first
/// half (its words).
enum Fingerprint {
    Whole([u8; 32]),
    Half([u8; INTRO_WORDS_FINGERPRINT_LEN]),
}

impl Fingerprint {
    fn matches(&self, fp: &[u8; 32]) -> bool {
        match self {
            Fingerprint::Whole(w) => w == fp,
            Fingerprint::Half(h) => fp[..INTRO_WORDS_FINGERPRINT_LEN] == h[..],
        }
    }
}

/// What a code says.
struct Parsed {
    offer: Name,
    secret: [u8; SECRET_LEN],
    fingerprint: Fingerprint,
    namespace: Option<Name>,
    relays: Vec<String>,
}

/// Read a code: an `ndn-trust://intro/…` link (or its https mirror), or the
/// words form (an offer name, then the words).
fn parse_code(code: &str) -> Result<Parsed, DataError> {
    let bad = |name: Name, why: String| DataError::BadRequest { name, why };
    let code = code.trim();
    let offer_of = |s: &str| {
        s.parse::<Name>().map_err(|_| {
            bad(
                Name::root(),
                format!("the code names its offer as {s}, which is no name: check the code"),
            )
        })
    };
    if code.starts_with('/') {
        let w = IntroWords::parse(code).map_err(|e| {
            bad(
                Name::root(),
                format!("the code's words do not read ({e}): check each word"),
            )
        })?;
        return Ok(Parsed {
            offer: offer_of(&w.offer)?,
            secret: w.secret,
            fingerprint: Fingerprint::Half(w.fingerprint),
            namespace: None,
            relays: Vec::new(),
        });
    }
    match TrustEnvelope::from_uri(code) {
        Ok(TrustEnvelope::Intro(i)) => {
            let namespace = match &i.namespace {
                Some(ns) => Some(ns.parse::<Name>().map_err(|_| {
                    bad(
                        Name::root(),
                        format!("the code names the inviter as {ns}, which is no name"),
                    )
                })?),
                None => None,
            };
            Ok(Parsed {
                offer: offer_of(&i.offer)?,
                secret: i.secret,
                fingerprint: Fingerprint::Whole(i.fingerprint),
                namespace,
                relays: i.relays.clone(),
            })
        }
        Ok(other) => Err(bad(
            Name::root(),
            format!(
                "this is an ndn-trust {} link, not an introduction's code: give it to what \
                 takes that kind",
                other.kind().as_str()
            ),
        )),
        Err(e) => Err(bad(
            Name::root(),
            format!(
                "the code is neither an ndn-trust://intro link nor an offer name and words \
                 ({e}): check what was scanned or typed"
            ),
        )),
    }
}

/// The refusal of a join whose inviter device did not answer.
fn offline(offer: &Name, device: &Name) -> DataError {
    DataError::NotReady {
        name: offer.clone(),
        why: format!(
            "the inviter's device {device} does not answer (offline or unreachable): retry \
             later; the offer waits for you until it expires"
        ),
    }
}

impl Inner {
    /// Take an introduction record held as the log entry `name` (parsed as
    /// `log`), signed by `writer`: kept when a device of the folder's own
    /// namespace signed it (only an owner device offers a folder, and only
    /// the offering device marks its use) and noted.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn take_intro(
        &self,
        st: &mut St,
        name: Name,
        log: &LogName,
        wire: Bytes,
        writer: Writer,
        record: IntroRecord,
        digest: [u8; 32],
    ) {
        st.held.insert(
            name.clone(),
            Held::Record {
                writer: writer.clone(),
                digest,
            },
        );
        let Some(folder) = record.subject() else {
            return;
        };
        if !owner_signed(self.validator.keyring(), &name, &folder, &writer) {
            tracing::debug!(%name, "introduction record not signed by a device of the folder's namespace; ignored");
            return;
        }
        match record {
            IntroRecord::Offer(body) => {
                self.store.insert(name.clone(), wire);
                st.intro.offers.insert(name, body);
            }
            IntroRecord::Used(body) => {
                // Only the offering device marks its offer.
                let offering = parse_log_name(&body.offer).map(|l| l.device);
                if offering.as_ref() != Some(&log.device) {
                    tracing::debug!(%name, "a use mark of another device's offer; ignored");
                    return;
                }
                self.store.insert(name, wire);
                match body.by {
                    Some(by) => {
                        st.intro.used.entry(body.offer).or_insert(by);
                    }
                    None => {
                        st.intro.closed.insert(body.offer);
                    }
                }
            }
        }
    }

    /// The host's introducer, or why there is none.
    fn introducer(&self) -> Result<&Arc<dyn Introducer>, DataError> {
        self.config.introducer.as_ref().ok_or_else(|| {
            local(
                "introductions need the host's introducer (Config::introducer), which gives \
                 this device's anchor and adopts another person's: configure one and start \
                 the device again",
            )
        })
    }

    /// This device's credentials: its namespace's signed trust context, as
    /// the host gives it, then the certificates of its key up to the
    /// context's anchor.
    pub(super) fn credentials(&self) -> Result<Vec<Bytes>, DataError> {
        let context = self.introducer()?.anchor().ok_or_else(|| {
            local(
                "the host's introducer gives no anchor (this device's namespace's signed trust \
                 context): enroll the device in its namespace first",
            )
        })?;
        let ctx = self.validator.keyring().context_for(&self.device);
        let mut out = vec![context];
        let mut at = self.writer.key().clone();
        for _ in 0..CHAIN_MAX {
            if ctx.anchor_for(&at).is_some() {
                return Ok(out);
            }
            let cert = self
                .keys
                .cert_cache()
                .get_valid(&at)
                .or_else(|| self.validator.cert_cache().get_valid(&at))
                .ok_or_else(|| {
                    local(format!(
                        "no valid certificate of {at} is held, so this device cannot show the \
                         chain of its key to its namespace's anchor: renew the certificate"
                    ))
                })?;
            out.push(cert.data_wire().ok_or_else(|| {
                local(format!(
                    "the certificate {} held carries no signature",
                    cert.name
                ))
            })?);
            at =
                cert.issuer.as_deref().cloned().ok_or_else(|| {
                    local(format!("the certificate {} names no issuer", cert.name))
                })?;
        }
        Err(local(format!(
            "the chain of {} to its namespace's anchor is longer than {CHAIN_MAX} certificates",
            self.writer.key()
        )))
    }

    /// The forwarding hint a join's Interests carry: the relays the code
    /// names, else those this device's own namespace advertises. Hints only
    /// reach; nothing they say is trusted (spec §19.7).
    fn hints(&self, from_code: &[String]) -> Vec<Name> {
        let named: Vec<Name> = from_code.iter().filter_map(|s| s.parse().ok()).collect();
        if !named.is_empty() {
            return named;
        }
        self.validator
            .keyring()
            .context_for(&self.device)
            .relays()
            .iter()
            .map(|r| r.device.clone())
            .collect()
    }

    /// Fetch `name` with the forwarding hint `hints` (none: by name), and
    /// `params` as its ApplicationParameters (`name` then gains their
    /// digest).
    async fn fetch_hinted(
        &self,
        name: Name,
        hints: &[Name],
        params: Option<&Bytes>,
    ) -> Option<Data> {
        let _slot = self.slots.acquire().await.ok()?;
        let mut b = InterestBuilder::new(name).lifetime(self.config.lifetime);
        if !hints.is_empty() {
            b = b.forwarding_hint(hints.to_vec());
        }
        if let Some(p) = params {
            b = b.app_parameters(p.to_vec());
        }
        match Consumer::new(self.node.connection()).fetch_with(b).await {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::trace!(me = %self.device, "introduction fetch missed: {e}");
                None
            }
        }
    }

    /// The proof key of the own offer `offer`, from the store.
    fn proof_key_of(&self, st: &St, offer: &Name) -> Option<[u8; 32]> {
        let name = proof_key_name(offer);
        let wire = self.store.get(&name)?;
        open_grant(&st.keys.recipient, &name, wire).map(|k| *k.expose())
    }

    /// The own offer `offer`'s wrong tries counted toward
    /// [`IntroPolicy::wrong_tries_max`](crate::intro::IntroPolicy), and
    /// when the last one was counted.
    fn overall_tries(&self, offer: &Name) -> (u32, u64) {
        let Some(b) = self.store.get(&tries_name(offer)) else {
            return (0, 0);
        };
        let count = b
            .get(..4)
            .and_then(|c| <[u8; 4]>::try_from(c).ok())
            .map_or(0, u32::from_be_bytes);
        let at = b
            .get(4..12)
            .and_then(|t| <[u8; 8]>::try_from(t).ok())
            .map_or(0, u64::from_be_bytes);
        (count, at)
    }

    /// How many wrong tries the key of public key digest `digest` asked the
    /// own offer `offer` with.
    fn asker_tries(&self, offer: &Name, digest: &[u8; 32]) -> u32 {
        self.store
            .get(&asker_tries_name(offer, digest))
            .and_then(|b| <[u8; 4]>::try_from(b.as_ref()).ok())
            .map_or(0, u32::from_be_bytes)
    }

    /// Count a wrong try of `offer` by the key of digest `digest`, durably:
    /// against the asker always; toward the overall cap once the pause
    /// after the last one counted there passed (the policy's backoff,
    /// doubled by each counted). The asker's count and the overall one,
    /// once the store's barrier passed them; `None` if the device stopped
    /// first.
    async fn count_wrong(&self, offer: &Name, digest: &[u8; 32]) -> Option<(u32, u32)> {
        let mine = self.asker_tries(offer, digest).saturating_add(1);
        self.store.insert(
            asker_tries_name(offer, digest),
            Bytes::copy_from_slice(&mine.to_be_bytes()),
        );
        let (mut all, last) = self.overall_tries(offer);
        let now = (self.config.clock)().0;
        let pause = u64::try_from(self.config.intro.backoff.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_mul(1u64 << all.saturating_sub(1).min(32));
        if all == 0 || now >= last.saturating_add(pause) {
            all = all.saturating_add(1);
            let mut v = Vec::with_capacity(12);
            v.extend_from_slice(&all.to_be_bytes());
            v.extend_from_slice(&now.to_be_bytes());
            self.store.insert(tries_name(offer), Bytes::from(v));
        }
        self.barrier().await.then_some((mine, all))
    }

    /// The key a use of the own offer `offer` is under way for, if one is
    /// (a stop came between its start and its use mark).
    fn using(&self, offer: &Name) -> Option<(Name, [u8; 32])> {
        let b = self.store.get(&using_name(offer))?;
        let split = b.len().checked_sub(32)?;
        let key = Name::decode_from_tlv(b.slice(..split)).ok()?;
        Some((key, <[u8; 32]>::try_from(&b[split..]).ok()?))
    }

    /// Note durably that the own offer `offer` is being used by `by`,
    /// before anything of the use is done: whether the note is durable.
    async fn note_using(&self, offer: &Name, (key, digest): &(Name, [u8; 32])) -> bool {
        let mut v = key.encode_to_tlv().to_vec();
        v.extend_from_slice(digest);
        self.store.insert(using_name(offer), Bytes::from(v));
        self.barrier().await
    }

    /// Drop the note of a use of `offer` that did not happen (the host
    /// did not adopt the asker, or it was not added): the offer is not
    /// spent.
    async fn release(&self, offer: &Name) {
        self.store.remove(&using_name(offer));
        if !self.barrier().await {
            tracing::debug!(%offer, "the device stopped before an offer's use note was dropped durably");
        }
    }

    /// Sign the mark `body` of an own offer of `folder` into the own log —
    /// a use mark unless one naming a key is held, a closing mark unless
    /// one is held — and wait until it is durable. Whether such a mark of
    /// the offer is durable now.
    async fn mark(self: &Arc<Self>, folder: &Name, body: UsedBody) -> bool {
        let seq = {
            let mut st = self.st.lock();
            let held = match body.by {
                Some(_) => st.intro.used.contains_key(&body.offer),
                None => st.intro.closed.contains(&body.offer),
            };
            if held {
                // The device's own marks are restored at a start once
                // durable, and taken here as they are signed.
                st.head
            } else {
                match self.append(&mut st, Some(folder), IntroRecord::Used(body).encode()) {
                    Ok((_, seq)) => seq,
                    Err(e) => {
                        tracing::warn!(%folder, "a use mark was not signed: {e}");
                        return false;
                    }
                }
            }
        };
        if !self.published(seq).await {
            return false;
        }
        if let Err(e) = self.publish_about(folder, &[]).await {
            tracing::debug!(%folder, "a use mark is not announced: {e}");
        }
        true
    }

    /// Close every own offer of `folder` used — or being used — by a key
    /// under one of `dropped`, namespaces the folder's new members record
    /// removed (spec §19.7): a removed member never comes back by its code.
    pub(super) async fn close_used_by(self: &Arc<Self>, folder: &Name, dropped: &[Name]) {
        if dropped.is_empty() {
            return;
        }
        let offers: Vec<Name> = {
            let st = self.st.lock();
            st.intro
                .offers
                .iter()
                .filter(|(o, ob)| {
                    ob.folder == *folder
                        && !st.intro.closed.contains(*o)
                        && parse_log_name(o).is_some_and(|l| l.device == self.device)
                })
                .filter(|(o, _)| {
                    st.intro
                        .used
                        .get(*o)
                        .cloned()
                        .or_else(|| self.using(o))
                        .is_some_and(|(k, _)| dropped.iter().any(|d| k.has_prefix(d)))
                })
                .map(|(o, _)| o.clone())
                .collect()
        };
        for offer in offers {
            let closing = UsedBody {
                offer: offer.clone(),
                by: None,
            };
            if !self.mark(folder, closing).await {
                tracing::warn!(%offer, "the offer of a removed member is not closed: the device stopped first; close it with close_offer");
            }
        }
    }

    /// Why the namespace `ns`, which an introduction would bring under the
    /// anchor of `fingerprint`, may not be (spec §19.3, §19.4): "… <why>"
    /// completes "the namespace <ns> …". The policy's refusals
    /// ([`IntroPolicy::refuses`](crate::intro::IntroPolicy::refuses)); this
    /// device's own namespace or one over or under it; and every namespace
    /// it trusts — over or under one, or equal under another anchor. The
    /// same namespace under the same anchor is a party known already.
    fn overlap(&self, ns: &Name, fingerprint: &[u8; 32]) -> Option<String> {
        if let Some(why) = self.config.intro.refuses(ns) {
            return Some(why);
        }
        if *ns == self.ns || ns.has_prefix(&self.ns) || self.ns.has_prefix(ns) {
            return Some(format!("overlaps this device's own namespace {}", self.ns));
        }
        for ctx in self.validator.keyring().contexts() {
            let held = ctx.namespace();
            if held == ns {
                let same = ctx
                    .anchors()
                    .iter()
                    .any(|a| anchor_fingerprint(a.value()) == *fingerprint);
                if !same {
                    return Some("is trusted here already under another anchor".into());
                }
            } else if ns.has_prefix(held) {
                return Some(format!("lies under {held}, which this device trusts"));
            } else if held.has_prefix(ns) {
                return Some(format!("lies over {held}, which this device trusts"));
            }
        }
        None
    }

    /// Make `ns` a member of `folder` as `role` (spec §19.4): the next
    /// members record of the folder adds it as a writer (a writer's role)
    /// and as a reader (a sealed folder's), unless the record in force
    /// already admits it so. Signed as a change ([`ShareChange`]) to the
    /// record held when it is signed, so a let-go signed meanwhile stays,
    /// as an admission stays across a let-go (spec §15).
    async fn admit_joiner(
        self: &Arc<Self>,
        folder: &Name,
        role: Role,
        ns: &Name,
    ) -> Result<(), DataError> {
        let change = ShareChange {
            add_writers: match role {
                Role::Writer => vec![ns.clone()],
                _ => Vec::new(),
            },
            add_readers: vec![Audience::Person(ns.clone())],
            ..ShareChange::default()
        };
        Device {
            inner: Arc::clone(self),
        }
        .share_subject(
            Subject {
                name: folder.clone(),
                folder: true,
            },
            Sharing::Change(change),
        )
        .await
    }

    /// Answer an ask of this device (spec §19.4): open it, judge it in the
    /// order specified, and answer — admitting the asker, or refusing and
    /// saying why. One ask at a time; the same ask asked again gets the same
    /// answer while it is kept. `None` (a Nack) for what does not open or
    /// whose asker does not verify — a stranger's garbage costs a parse and
    /// one signature check — and for an ask past the ones held already
    /// ([`IntroPolicy::asks_queued`](crate::intro::IntroPolicy)): opening
    /// and verifying run at most [`Config::asks_verifying`](super::Config)
    /// at once.
    pub(super) async fn answer_intro(
        self: &Arc<Self>,
        name: &Name,
        params: Option<Bytes>,
    ) -> Option<Bytes> {
        if let Some(r) = self.st.lock().answers.get(name) {
            return Some(r.clone());
        }
        // The name's digest binds the parameters: an ask is its parameters.
        let params = params.filter(|p| intro_name(&self.device, p) == *name)?;
        let _held = {
            let mut st = self.st.lock();
            if st.intro.queued >= self.config.intro.asks_queued {
                tracing::warn!(
                    me = %self.device,
                    held = st.intro.queued,
                    "an introduction ask is not answered: as many asks as Config::intro.asks_queued allows are held already; its asker's retry is judged once they are done"
                );
                return None;
            }
            st.intro.queued += 1;
            Queued(self)
        };
        let (body, proof, asker, opened, claimed) = {
            let _verifying = self.verifying.acquire().await.ok()?;
            let ask = IntroAsk::decode(params).ok()?;
            let aad = intro_prefix(&self.device).encode_to_tlv();
            let plain = {
                let st = self.st.lock();
                let wrapped = Sealed::from_bytes(&ask.key).ok()?;
                let ck = st
                    .keys
                    .recipient
                    .unwrap_ck(&ask.ephemeral, &wrapped, &aad)
                    .ok()?;
                ck.open(&Sealed::from_bytes(&ask.sealed).ok()?, &aad).ok()?
            };
            let body = AskBody::decode(Bytes::from(plain)).ok()?;
            let (proof, asker) = Self::claimed_asker(&body.asker)?;
            let opened = open_credentials(&body.credentials).await?;
            // Who it claims to be, unverified: what a refusal before the
            // chain is checked is addressed to.
            let locator = proof.sig_info()?.key_locator_name()?;
            let claimed = key_name_of(&locator);
            let digest = opened.claimed(&claimed)?;
            (body, proof, asker, opened, (claimed, digest))
        };
        let serial = Arc::clone(&self.st.lock().intro.serial);
        let _turn = serial.lock().await;
        if let Some(r) = self.st.lock().answers.get(name) {
            return Some(r.clone());
        }
        let answer = self
            .judge_ask(&body, &proof, &asker, &opened, claimed)
            .await?;
        let reply = DataBuilder::new(name.clone(), &answer.encode()).sign_digest_sha256();
        self.st.lock().answers.insert(name.clone(), reply.clone());
        Some(reply)
    }

    /// Judge an opened ask, in order (spec §19.4): the offer is this
    /// device's and known; not closed; the asker's key chains to the anchor
    /// its credentials carry; not used by another key (its user is answered
    /// the acceptance it was given, and nothing more is done); not expired
    /// by this device's clock; the asker's own wrong tries not spent; the
    /// proof is right (a wrong one counted durably, against the asker and
    /// toward the overall cap); the asker's namespace is no other's. Then
    /// the use is noted, the asker's anchor adopted, the asker added to the
    /// folder, and the acceptance kept and the use mark signed, both
    /// durable before the answer; a failure before lets the use go.
    async fn judge_ask(
        self: &Arc<Self>,
        body: &AskBody,
        proof: &Data,
        asker: &Name,
        opened: &Opened,
        claimed: (Name, [u8; 32]),
    ) -> Option<AnswerBody> {
        let offer = &body.offer;
        let refuse = |(asker, digest): (Name, [u8; 32]), why| AnswerBody {
            offer: offer.clone(),
            asker,
            digest,
            outcome: Outcome::Refused(why),
            proof: None,
        };
        let own = parse_log_name(offer).is_some_and(|l| l.device == self.device);
        let held = {
            let st = self.st.lock();
            own.then(|| st.intro.offers.get(offer).cloned())
                .flatten()
                .and_then(|ob| Some((self.proof_key_of(&st, offer)?, ob)))
                .map(|(pk, ob)| {
                    let used = st.intro.used.get(offer).cloned();
                    (pk, ob, used, st.intro.closed.contains(offer))
                })
        };
        let Some((pk, ob, used, closed)) = held else {
            return Some(refuse(claimed, IntroRefusal::Unknown));
        };
        if closed || self.overall_tries(offer).0 >= self.config.intro.wrong_tries_max {
            return Some(refuse(claimed, IntroRefusal::Closed));
        }
        let (key, digest) = opened.signer(proof).await?;
        if *proof.name != wire::ask_name(asker, &body.binding(&self.device))
            || device_of(&key).as_ref() != Some(asker)
        {
            tracing::debug!(%offer, %asker, "an ask whose asker's proof does not verify; not answered");
            return None;
        }
        let by = (key, digest);
        // One use: a use mark, else a use a stop interrupted. Its user is
        // answered again — never admitted again: a later members record
        // may have removed it (spec §19.7).
        match used.clone().or_else(|| self.using(offer)) {
            Some(user) if user != by => return Some(refuse(by, IntroRefusal::Used)),
            Some(_) if used.is_some() => return self.accepted_again(offer, &ob, &pk, by),
            _ => {}
        }
        if ob.until <= (self.config.clock)() {
            return Some(refuse(by, IntroRefusal::Expired));
        }
        if self.asker_tries(offer, &by.1) >= ob.tries {
            return Some(refuse(by, IntroRefusal::Closed));
        }
        if !ask_proves(&pk, offer, &by.0, &by.1, &body.nonce, &body.proof) {
            let (mine, all) = self.count_wrong(offer, &by.1).await?;
            if all >= self.config.intro.wrong_tries_max {
                let closing = UsedBody {
                    offer: offer.clone(),
                    by: None,
                };
                if !self.mark(&ob.folder, closing).await {
                    return None;
                }
                return Some(refuse(by, IntroRefusal::Closed));
            }
            if mine >= ob.tries {
                return Some(refuse(by, IntroRefusal::Closed));
            }
            return Some(refuse(
                by,
                IntroRefusal::WrongProof {
                    left: ob.tries - mine,
                },
            ));
        }
        let theirs = opened.ctx.namespace().clone();
        let overlap = if asker.has_prefix(&theirs) {
            self.overlap(&theirs, &opened.fingerprint())
        } else {
            Some(format!("is not a prefix of the asking device {asker}"))
        };
        if let Some(why) = overlap {
            tracing::info!(%offer, namespace = %theirs, "an ask refused as a conflict: the namespace {why}");
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        // The use, noted before anything of it is done: a stop from here
        // on leaves the offer this key's, and its retry finishes the use.
        if !self.note_using(offer, &by).await {
            return None;
        }
        let introducer = self.introducer().ok()?;
        if let Err(why) = introducer.adopt(&opened.link()).await {
            tracing::warn!(%offer, namespace = %theirs, "the host did not adopt the asker's anchor: {why}; the offer is not spent and the asker's retry is judged again");
            self.release(offer).await;
            return None;
        }
        if !opened.vouched_by(self.validator.keyring()) {
            tracing::info!(%offer, namespace = %theirs, "an ask refused as a conflict: its credentials carry anchors the namespace adopted from its genesis does not hold");
            self.release(offer).await;
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        // The proof again, judged by what this device now holds of the
        // namespace: a key its held version revokes, shown with an older
        // version, does not ask for it.
        if opened
            .signer_held(self.validator.keyring(), proof)
            .await
            .as_ref()
            != Some(&by)
        {
            tracing::info!(%offer, namespace = %theirs, key = %by.0, "an ask refused as a conflict: its proof does not verify under the namespace as this device holds it (a key the held version revokes, or credentials older than it)");
            self.release(offer).await;
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        for c in opened.chain(&by.0, &theirs) {
            self.validator.cert_cache().insert(c);
        }
        if let Err(e) = self.admit_joiner(&ob.folder, ob.role, &theirs).await {
            tracing::warn!(%offer, namespace = %theirs, "the asker is not added to the folder: {e}; the offer is not spent and the asker's retry is judged again");
            self.release(offer).await;
            return None;
        }
        let answer = self.acceptance(offer, &ob, &pk, by.clone())?;
        // Kept with the use mark: the store's barrier under the mark makes
        // both durable before the answer.
        self.store.insert(accepted_name(offer), answer.encode());
        let mark = UsedBody {
            offer: offer.clone(),
            by: Some(by),
        };
        if !self.mark(&ob.folder, mark).await {
            return None;
        }
        self.store.remove(&using_name(offer));
        Some(answer)
    }

    /// The acceptance of `offer` for its asker key `by`: the folder, the
    /// role, this device's credentials and proof packet, the answer proof.
    fn acceptance(
        &self,
        offer: &Name,
        ob: &OfferBody,
        pk: &[u8; 32],
        (key, digest): (Name, [u8; 32]),
    ) -> Option<AnswerBody> {
        let credentials = self.credentials().ok()?;
        let mut answer = AnswerBody {
            offer: offer.clone(),
            asker: key,
            digest,
            outcome: Outcome::Accepted {
                folder: ob.folder.clone(),
                role: ob.role,
                credentials,
                inviter: Bytes::new(),
            },
            proof: None,
        };
        let signed = self.ask_proof(&answer.binding())?;
        if let Outcome::Accepted { inviter, .. } = &mut answer.outcome {
            *inviter = signed;
        }
        answer.proof = Some(answer_proof(pk, &answer));
        Some(answer)
    }

    /// The acceptance the used offer `offer` was answered with, for its
    /// user `by`, asking again: as kept. A use marked before acceptances
    /// were kept is answered the same acceptance signed afresh. Neither
    /// adopts nor admits anything.
    fn accepted_again(
        &self,
        offer: &Name,
        ob: &OfferBody,
        pk: &[u8; 32],
        by: (Name, [u8; 32]),
    ) -> Option<AnswerBody> {
        let kept = self
            .store
            .get(&accepted_name(offer))
            .and_then(|b| AnswerBody::decode(b).ok())
            .filter(|a| a.asker == by.0 && a.digest == by.1);
        match kept {
            Some(a) => Some(a),
            None => self.acceptance(offer, ob, pk, by),
        }
    }
}

impl Device {
    /// Make a one-use offer of `folder` (spec §19.2): a folder of this
    /// device's namespace whose members record is held here. Its record —
    /// the folder, the role, the expiry, the wrong tries that close it, a
    /// commitment to a fresh secret and this device's seal key — goes into
    /// the own log, the offer's proof key into the store wrapped to this
    /// device's recipient key; the code is returned once both are durable.
    /// Nothing secret is published.
    pub async fn offer(&self, folder: &Name, offer: Offer) -> Result<Code, DataError> {
        let inner = &self.inner;
        check_collection(folder)?;
        let ns = namespace_of(folder).expect("checked above");
        if ns != inner.ns {
            return Err(DataError::NotOwner {
                collection: folder.clone(),
            });
        }
        if offer.tries == 0 {
            return Err(DataError::BadRequest {
                name: folder.clone(),
                why: "an offer closes after one wrong try or more: give tries ≥ 1".into(),
            });
        }
        if offer.until <= (inner.config.clock)() {
            return Err(DataError::BadRequest {
                name: folder.clone(),
                why: "the offer's expiry has passed by this device's clock: give a later one"
                    .into(),
            });
        }
        let own = open_credentials(&inner.credentials()?)
            .await
            .filter(|o| *o.ctx.namespace() == inner.ns)
            .ok_or_else(|| {
                local(format!(
                    "the host's introducer gives an anchor that is not {}'s signed trust context \
                     with a chain to this device's key: fix the host's enrollment",
                    inner.ns
                ))
            })?;
        let mut secret = [0u8; SECRET_LEN];
        (inner.config.entropy)(&mut secret);
        let (name, seq) = {
            let mut st = inner.st.lock();
            if st
                .folders
                .get(folder)
                .and_then(|f| f.line.own.as_ref())
                .is_none()
            {
                return Err(DataError::BadRequest {
                    name: folder.clone(),
                    why: "no members record of this folder is held here: share the folder \
                          (share_folder) first, then offer it"
                        .into(),
                });
            }
            let seq = inner.next_seq(&st)?;
            let name = wire::log_name(&inner.device, Some(folder), seq);
            let key_name = proof_key_name(&name);
            let (ephemeral, wrapped) = wrap_ck_to(
                &st.keys.recipient.public(),
                &ContentKey::from_bytes(proof_key(&secret, &name)),
                &key_name.encode_to_tlv(),
            )
            .map_err(|e| local(format!("the offer's proof key could not be wrapped: {e}")))?;
            inner.store.insert(
                key_name,
                wire::encode_grant(&ephemeral, &wrapped.to_bytes()),
            );
            let record = IntroRecord::Offer(OfferBody {
                folder: folder.clone(),
                role: offer.role,
                until: offer.until,
                tries: offer.tries,
                commitment: commitment(&secret),
                seal_key: st.keys.recipient.public(),
            });
            let (signed, at) = inner.append(&mut st, Some(folder), record.encode())?;
            debug_assert_eq!((&signed, at), (&name, seq));
            (name, seq)
        };
        // Published, and its code shown, once durable (spec §4.2): before,
        // a power loss could take the record and give its seq to another.
        if !inner.published(seq).await {
            return Err(local(
                "the device stopped before the offer was durable: make a new offer",
            ));
        }
        inner.publish_about(folder, &[]).await?;
        let relays = inner
            .validator
            .keyring()
            .context_for(&inner.device)
            .relays()
            .iter()
            .map(|r| r.device.to_string())
            .collect();
        let intro = Introduction {
            namespace: Some(inner.ns.to_string()),
            fingerprint: own.fingerprint(),
            offer: name.to_string(),
            secret,
            relays,
        };
        let words = intro.to_words().to_string();
        let link = TrustEnvelope::Intro(intro).qr_uri().ok_or_else(|| {
            local(format!(
                "the offer's link does not fit one QR even without relay hints (the offer name \
                 {name} is too long): offer a folder of a shorter name"
            ))
        })?;
        Ok(Code {
            offer: name,
            link,
            words,
        })
    }

    /// Join the folder a code offers (spec §19.3): `code` is the link (or
    /// its https mirror) or the words form. Fetch the offer from the
    /// offering device, send it an ask sealed to its seal key, carrying this
    /// device's credentials and a proof of the secret bound to its key;
    /// check the answer against the code (bound to this key, proving the
    /// secret, signed by the offering device under the anchor the code
    /// names); have the host adopt the inviter's anchor; follow the folder.
    /// No answer: [`DataError::NotReady`], retry later — the offer waits.
    pub async fn join(&self, code: &str) -> Result<Joined, DataError> {
        let inner = &self.inner;
        let code = parse_code(code)?;
        let offer = code.offer.clone();
        let bad = |why: &str| DataError::BadRequest {
            name: offer.clone(),
            why: why.into(),
        };
        let forged = || DataError::Introduction {
            offer: offer.clone(),
            why: IntroRefusal::Forged,
        };
        let log = parse_log_name(&offer)
            .filter(|l| l.subject.is_some())
            .ok_or_else(|| bad("the code's offer is no log entry of a folder: check the code"))?;
        let device = log.device.clone();
        if device == inner.device || device.has_prefix(&inner.ns) {
            return Err(bad(
                "the code offers a folder of this device's own namespace: it is yours already",
            ));
        }
        // A namespace the code names is judged before anything is asked:
        // this device trusts none of it yet, and never one overlapping a
        // namespace it trusts (spec §19.3).
        if let (Some(ns), Fingerprint::Whole(fp)) = (&code.namespace, &code.fingerprint)
            && let Some(why) = inner.overlap(ns, fp)
        {
            return Err(DataError::Introduction {
                offer: offer.clone(),
                why: IntroRefusal::InviterConflict {
                    inviter: ns.clone(),
                    why,
                },
            });
        }
        let introducer = Arc::clone(inner.introducer()?);
        let credentials = inner.credentials()?;
        let own = open_credentials(&credentials).await.ok_or_else(|| {
            local(
                "the host's introducer gives an anchor that is no signed trust context: fix the \
                 host's enrollment",
            )
        })?;
        let me = inner.writer.key().clone();
        let digest = inner.own_key.ok_or_else(|| {
            local(format!(
                "the device key {me} gives no public key, so an answer cannot be bound to it"
            ))
        })?;
        let hints = inner.hints(&code.relays);
        let pk = proof_key(&code.secret, &offer);

        // The offer, as the offering device serves its own log entry.
        let held = wire::held_name(&device, &offer);
        let mut wrapped = None;
        for _ in 0..OFFER_TRIES {
            wrapped = inner.fetch_hinted(held.clone(), &hints, None).await;
            if wrapped.is_some() {
                break;
            }
        }
        let wrapped = wrapped.ok_or_else(|| offline(&offer, &device))?;
        let entry = wrapped
            .content()
            .and_then(|c| Data::decode(c.clone()).ok())
            .filter(|e| *wrapped.name == held && *e.name == offer)
            .ok_or_else(forged)?;
        let Some(Record::Intro(IntroRecord::Offer(ob))) = entry
            .content()
            .and_then(|c| wire::decode_record(c.clone()).ok())
        else {
            return Err(DataError::Introduction {
                offer: offer.clone(),
                why: IntroRefusal::Unknown,
            });
        };

        // The ask.
        let nonce = inner.nonce();
        let mut body = AskBody {
            offer: offer.clone(),
            nonce,
            proof: ask_proof(&pk, &offer, &me, &digest, &nonce),
            credentials,
            asker: Bytes::new(),
        };
        body.asker = inner
            .ask_proof(&body.binding(&device))
            .ok_or_else(|| local(format!("the device key {me} did not sign the ask")))?;
        let mine = Data::decode(body.asker.clone()).map_err(|e| local(e.to_string()))?;
        if own.signer(&mine).await != Some((me.clone(), digest)) {
            return Err(local(format!(
                "the anchor the host gives does not certify this device's key {me} (no chain \
                 of valid certificates to it): renew the certificate or fix the enrollment"
            )));
        }
        let aad = intro_prefix(&device).encode_to_tlv();
        let ck = ContentKey::generate();
        let (ephemeral, key) = wrap_ck_to(&ob.seal_key, &ck, &aad)
            .map_err(|e| local(format!("the ask could not be sealed: {e}")))?;
        let params = IntroAsk {
            ephemeral,
            key: key.to_bytes(),
            sealed: ck.seal(&body.encode(), &aad).to_bytes(),
        }
        .encode();
        let name = intro_name(&device, &params);
        let prefix = intro_prefix(&device);
        let mut answered = None;
        for _ in 0..ASK_TRIES {
            answered = inner
                .fetch_hinted(prefix.clone(), &hints, Some(&params))
                .await;
            if answered.is_some() {
                break;
            }
        }
        let data = answered.ok_or_else(|| offline(&offer, &device))?;

        // The answer, checked against the code.
        let answer = data
            .content()
            .filter(|_| *data.name == name)
            .and_then(|c| AnswerBody::decode(c.clone()).ok())
            .filter(|a| a.offer == offer && a.asker == me && a.digest == digest)
            .ok_or_else(forged)?;
        let (folder, role, credentials, signed) = match &answer.outcome {
            Outcome::Refused(why) => {
                return Err(DataError::Introduction {
                    offer: offer.clone(),
                    why: why.clone(),
                });
            }
            Outcome::Accepted {
                folder,
                role,
                credentials,
                inviter,
            } => (folder.clone(), *role, credentials, inviter),
        };
        if !answer_proves(&pk, &answer) {
            return Err(forged());
        }
        let theirs = open_credentials(credentials).await.ok_or_else(forged)?;
        let inviter = theirs.ctx.namespace().clone();
        let signed = Data::decode(signed.clone()).map_err(|_| forged())?;
        let by_device = |k: &Option<(Name, [u8; 32])>| {
            k.as_ref()
                .is_some_and(|(k, _)| device_of(k).as_ref() == Some(&device))
        };
        let signer = theirs.signer(&signed).await;
        if !code.fingerprint.matches(&theirs.fingerprint())
            || code.namespace.as_ref().is_some_and(|ns| *ns != inviter)
            || !device.has_prefix(&inviter)
            || *signed.name != wire::ask_name(&device, &answer.binding())
            || !by_device(&signer)
            || !by_device(&theirs.signer(&entry).await)
            || ob.commitment != commitment(&code.secret)
            || ob.folder != folder
            || ob.role != role
        {
            return Err(forged());
        }
        // The inviter proved the code: its namespace is judged as one the
        // code named would have been — the words name none.
        if let Some(why) = inner.overlap(&inviter, &theirs.fingerprint()) {
            return Err(DataError::Introduction {
                offer: offer.clone(),
                why: IntroRefusal::InviterConflict { inviter, why },
            });
        }
        introducer.adopt(&theirs.link()).await.map_err(|why| {
            local(format!(
                "this device's host did not adopt {inviter}'s anchor ({why}): fix that and join \
                 again with the same code (the offer is yours: asking again is answered again)"
            ))
        })?;
        if !theirs.vouched_by(inner.validator.keyring()) {
            return Err(DataError::Introduction {
                offer: offer.clone(),
                why: IntroRefusal::InviterConflict {
                    inviter,
                    why: "carries anchors its namespace, adopted from its genesis, does not \
                          hold"
                        .into(),
                },
            });
        }
        // Its signatures again, judged by what this device now holds of
        // the namespace: a key the held version revokes, shown with an
        // older version, does not answer for it.
        let keyring = inner.validator.keyring();
        if theirs.signer_held(keyring, &signed).await != signer
            || !by_device(&theirs.signer_held(keyring, &entry).await)
        {
            return Err(DataError::Introduction {
                offer: offer.clone(),
                why: IntroRefusal::InviterConflict {
                    inviter,
                    why: "answered with a key its namespace, as this device holds it, does not \
                          certify (a key the held version revokes, or credentials older than it)"
                        .into(),
                },
            });
        }
        if let Some((key, _)) = &signer {
            for c in theirs.chain(key, &inviter) {
                inner.validator.cert_cache().insert(c);
            }
        }
        inner.look(&folder).await?;
        Ok(Joined {
            folder,
            role,
            inviter,
        })
    }

    /// Close the offer `offer` this device made, for good (spec §19.2):
    /// a closing mark in the own log, signed and durable before this
    /// returns. Every ask of it is refused as closed from then on, its
    /// user's too; what the offer granted stays, until the folder's members
    /// record removes it. Closing a closed offer does nothing more.
    pub async fn close_offer(&self, offer: &Name) -> Result<(), DataError> {
        let inner = &self.inner;
        let maker = parse_log_name(offer).map(|l| l.device);
        if maker.as_ref() != Some(&inner.device) {
            return Err(DataError::BadRequest {
                name: offer.clone(),
                why: match maker {
                    Some(d) => format!(
                        "the offer was made by the device {d}, which alone answers and closes \
                         it: close it there"
                    ),
                    None => "this is no offer's name (a log entry \
                             <device>/32=log/<folder>/seq=<n>): give the name the offer printed"
                        .into(),
                },
            });
        }
        let folder = inner
            .st
            .lock()
            .intro
            .offers
            .get(offer)
            .map(|ob| ob.folder.clone())
            .ok_or_else(|| DataError::BadRequest {
                name: offer.clone(),
                why: "this device holds no offer of that name: give the name the offer printed"
                    .into(),
            })?;
        let closing = UsedBody {
            offer: offer.clone(),
            by: None,
        };
        if !inner.mark(&folder, closing).await {
            return Err(local(
                "the device stopped before the offer's closing mark was durable: close it again",
            ));
        }
        Ok(())
    }
}
