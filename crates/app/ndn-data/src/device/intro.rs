//! The device's side of introductions (spec §19): offers and use marks in
//! the log, the asks it answers, and the joins it makes. Types, bytes and
//! proofs are [`crate::intro`]'s.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::cert_name::key_name_of;
use ndn_security::confidentiality::{ContentKey, Sealed, wrap_ck_to};
use ndn_security::safe_data::TrustPath;
use ndn_security::{
    CertCache, Certificate, Keyring, SignedTrustContext, ValidationResult, Validator,
    anchor_fingerprint, public_key_digest,
};
use ndn_trust_envelope::{INTRO_WORDS_FINGERPRINT_LEN, IntroWords, Introduction, TrustEnvelope};

use super::{Device, Held, Inner, St, Subject, check_collection, local, open_grant, owner_signed};
use crate::collection;
use crate::error::DataError;
use crate::intro::{
    AnswerBody, AskBody, Code, IntroAsk, IntroRecord, IntroRefusal, Introducer, Joined, Offer,
    OfferBody, Outcome, Role, SECRET_LEN, UsedBody, answer_proof, answer_proves, ask_proof,
    ask_proves, commitment, intro_name, intro_prefix, proof_key,
};
use crate::layer::Share;
use crate::version::{Audience, Writer};
use crate::wire::{self, LogName, Record, device_of, namespace_of, parse_log_name};

/// How many times a join sends its ask (the same Interest each time, so a
/// retry is answered from the inviter device's cache) before it says the
/// inviter is not reachable.
const ASK_TRIES: u32 = 4;

/// How many times a join asks for the offer record.
const OFFER_TRIES: u32 = 2;

/// The longest certificate chain credentials carry, or are walked for.
const CHAIN_MAX: usize = 8;

/// What a device holds of introductions.
pub(super) struct Intros {
    /// Offers held, by the offer record's name: this device's own, and
    /// other devices' of its namespace.
    pub(super) offers: BTreeMap<Name, OfferBody>,
    /// Use marks held, by offer: the key it was used by and its digest, or
    /// `None` when closed. The first mark held of an offer stands.
    pub(super) used: BTreeMap<Name, Option<(Name, [u8; 32])>>,
    /// Asks are judged one at a time: a use mark, a wrong try counted, a
    /// closing mark each see what the one before wrote.
    serial: Arc<tokio::sync::Mutex<()>>,
}

impl Intros {
    pub(super) fn new() -> Self {
        Self {
            offers: BTreeMap::new(),
            used: BTreeMap::new(),
            serial: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

/// Where the store keeps an own offer's proof key, wrapped to the device's
/// recipient key: a local name no device serves.
fn proof_key_name(offer: &Name) -> Name {
    let base: Name = "/localhost/ndn-data/intro/key"
        .parse()
        .expect("a valid name");
    base.append_component(NameComponent::generic(offer.encode_to_tlv()))
}

/// Where the store keeps how many wrong tries an own offer was asked with.
fn tries_name(offer: &Name) -> Name {
    let base: Name = "/localhost/ndn-data/intro/tries"
        .parse()
        .expect("a valid name");
    base.append_component(NameComponent::generic(offer.encode_to_tlv()))
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
    certs: Vec<Certificate>,
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
    let keyring = Keyring::new();
    if !keyring.adopt(Arc::clone(&ctx)) {
        return None;
    }
    let cache = CertCache::new();
    let mut certs = Vec::with_capacity(rest.len());
    for p in rest {
        let cert = Certificate::decode(&Data::decode(p.clone()).ok()?).ok()?;
        cache.insert(cert.clone());
        certs.push(cert);
    }
    let validator = Validator::with_keyring(Arc::new(keyring), Arc::new(cache), None, CHAIN_MAX)
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
        match self.validator.validate_chain(data).await {
            ValidationResult::Valid(safe)
                if !matches!(safe.trust_path(), TrustPath::DigestSha256) => {}
            _ => return None,
        }
        let locator = data.sig_info()?.key_locator_name()?;
        let key = key_name_of(&locator);
        let cert = self
            .ctx
            .anchor_for(&key)
            .or_else(|| self.validator.cert_cache().get_valid(&key))?;
        Some((key, public_key_digest(&cert.public_key)))
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
                st.intro.used.entry(body.offer).or_insert(body.by);
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
    fn credentials(&self) -> Result<Vec<Bytes>, DataError> {
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

    /// Fetch `name` with the forwarding hint `hints` (none: by name).
    async fn fetch_hinted(&self, name: Name, hints: &[Name]) -> Option<Data> {
        let _slot = self.slots.acquire().await.ok()?;
        let mut b = InterestBuilder::new(name).lifetime(self.config.lifetime);
        if !hints.is_empty() {
            b = b.forwarding_hint(hints.to_vec());
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

    /// How many wrong tries the own offer `offer` was asked with.
    fn wrong_tries(&self, offer: &Name) -> u32 {
        self.store
            .get(&tries_name(offer))
            .and_then(|b| <[u8; 4]>::try_from(b.as_ref()).ok())
            .map_or(0, u32::from_be_bytes)
    }

    /// Count one more wrong try of `offer`, durably: the count, once the
    /// store's barrier passed it, or `None` if the device stopped first.
    async fn count_wrong(&self, offer: &Name) -> Option<u32> {
        let n = self.wrong_tries(offer).saturating_add(1);
        self.store
            .insert(tries_name(offer), Bytes::copy_from_slice(&n.to_be_bytes()));
        self.barrier().await.then_some(n)
    }

    /// Sign the use mark `body` of an offer of `folder` into the own log,
    /// unless a mark of it is held; wait until it is durable. Whether a
    /// mark of the offer is durable now.
    async fn mark(self: &Arc<Self>, folder: &Name, body: UsedBody) -> bool {
        let seq = {
            let mut st = self.st.lock();
            if st.intro.used.contains_key(&body.offer) {
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

    /// Make `ns` a member of `folder` as `role` (spec §19.4): the next
    /// members record of the folder adds it as a writer (a writer's role)
    /// and as a reader (a sealed folder's), unless the record in force
    /// already admits it so.
    async fn admit_joiner(
        self: &Arc<Self>,
        folder: &Name,
        role: Role,
        ns: &Name,
    ) -> Result<(), DataError> {
        let share = {
            let st = self.st.lock();
            let m = st
                .folders
                .get(folder)
                .and_then(|f| f.line.own.clone())
                .ok_or_else(|| DataError::NotReady {
                    name: folder.clone(),
                    why: "no members record of the folder is held here".into(),
                })?;
            let reader = Audience::Person(ns.clone());
            let writes = m.writers.iter().any(|w| ns.has_prefix(w));
            let reads = m.readers.is_empty() || collection::admitted(&reader, &m.readers);
            let mut writers = m.writers.clone();
            let mut readers = m.readers.clone();
            if role == Role::Writer && !writes {
                writers.push(ns.clone());
            }
            if !reads {
                readers.push(reader);
            }
            if writers.len() == m.writers.len() && readers.len() == m.readers.len() {
                return Ok(());
            }
            Share {
                rule: m.rule.clone(),
                writers,
                readers,
            }
        };
        Device {
            inner: Arc::clone(self),
        }
        .share_subject(
            Subject {
                name: folder.clone(),
                folder: true,
            },
            share,
        )
        .await
    }

    /// Answer an ask of this device (spec §19.4): open it, judge it in the
    /// order specified, and answer — admitting the asker, or refusing and
    /// saying why. One ask at a time; the same ask asked again gets the same
    /// answer while it is kept. `None` (a Nack) for what does not open or
    /// whose asker does not verify: a stranger's garbage costs a parse and
    /// one signature check.
    pub(super) async fn answer_intro(
        self: &Arc<Self>,
        name: &Name,
        ask: IntroAsk,
    ) -> Option<Bytes> {
        if let Some(r) = self.st.lock().answers.get(name) {
            return Some(r.clone());
        }
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
        // Who it claims to be, unverified: what a refusal before the chain
        // is checked is addressed to.
        let locator = proof.sig_info()?.key_locator_name()?;
        let claimed = key_name_of(&locator);
        let claimed_digest = opened
            .certs
            .iter()
            .find(|c| c.key_name() == claimed)
            .map(|c| public_key_digest(&c.public_key))?;
        let serial = Arc::clone(&self.st.lock().intro.serial);
        let _turn = serial.lock().await;
        if let Some(r) = self.st.lock().answers.get(name) {
            return Some(r.clone());
        }
        let answer = self
            .judge_ask(&body, &proof, &asker, &opened, (claimed, claimed_digest))
            .await?;
        let reply = DataBuilder::new(name.clone(), &answer.encode()).sign_digest_sha256();
        self.st.lock().answers.insert(name.clone(), reply.clone());
        Some(reply)
    }

    /// Judge an opened ask, in order (spec §19.4): the offer is this
    /// device's and known; not closed; not expired by this device's clock;
    /// the asker's key chains to the anchor its credentials carry; the
    /// proof is right (a wrong one counted durably, the offer closed for
    /// good at its tries); the asker's namespace is no other's; the offer
    /// is not used by another key. Then the use mark is made durable, the
    /// asker's anchor adopted, the asker added to the folder, and the answer
    /// signed.
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
                .map(|(pk, ob)| (pk, ob, st.intro.used.get(offer).cloned()))
        };
        let Some((pk, ob, used)) = held else {
            return Some(refuse(claimed, IntroRefusal::Unknown));
        };
        if matches!(used, Some(None)) || self.wrong_tries(offer) >= ob.tries {
            return Some(refuse(claimed, IntroRefusal::Closed));
        }
        if ob.until <= (self.config.clock)() {
            return Some(refuse(claimed, IntroRefusal::Expired));
        }
        let (key, digest) = opened.signer(proof).await?;
        if *proof.name != wire::ask_name(asker, &body.binding(&self.device))
            || device_of(&key).as_ref() != Some(asker)
        {
            tracing::debug!(%offer, %asker, "an ask whose asker's proof does not verify; not answered");
            return None;
        }
        let by = (key.clone(), digest);
        if !ask_proves(&pk, offer, &key, &digest, &body.nonce, &body.proof) {
            let n = self.count_wrong(offer).await?;
            if n >= ob.tries {
                let closing = UsedBody {
                    offer: offer.clone(),
                    by: None,
                };
                if !self.mark(&ob.folder, closing).await {
                    return None;
                }
                return Some(refuse(by, IntroRefusal::Closed));
            }
            return Some(refuse(by, IntroRefusal::WrongProof { left: ob.tries - n }));
        }
        let theirs = opened.ctx.namespace().clone();
        let fingerprint = opened.fingerprint();
        let shadowed = self
            .validator
            .keyring()
            .contexts()
            .into_iter()
            .find(|c| *c.namespace() == theirs)
            .is_some_and(|c| {
                !c.anchors()
                    .iter()
                    .any(|a| anchor_fingerprint(a.value()) == fingerprint)
            });
        if theirs.has_prefix(&self.ns)
            || self.ns.has_prefix(&theirs)
            || !asker.has_prefix(&theirs)
            || shadowed
        {
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        match &used {
            Some(Some(user)) if *user != by => return Some(refuse(by, IntroRefusal::Used)),
            Some(Some(_)) => {}
            _ => {
                let mark = UsedBody {
                    offer: offer.clone(),
                    by: Some(by.clone()),
                };
                if !self.mark(&ob.folder, mark).await {
                    return None;
                }
                // Concurrent asks are judged one at a time, so the mark held
                // is this one.
            }
        }
        let introducer = self.introducer().ok()?;
        if let Err(why) = introducer.adopt(&opened.link()).await {
            tracing::warn!(%offer, namespace = %theirs, "the host did not adopt the asker's anchor: {why}; the asker's retry is answered again");
            return None;
        }
        for c in &opened.certs {
            self.validator.cert_cache().insert(c.clone());
        }
        if let Err(e) = self.admit_joiner(&ob.folder, ob.role, &theirs).await {
            tracing::warn!(%offer, namespace = %theirs, "the asker is not added to the folder yet: {e}; its retry is answered again");
            return None;
        }
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
        answer.proof = Some(answer_proof(&pk, &answer));
        Some(answer)
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
            wrapped = inner.fetch_hinted(held.clone(), &hints).await;
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
        let ask = IntroAsk {
            ephemeral,
            key: key.to_bytes(),
            sealed: ck.seal(&body.encode(), &aad).to_bytes(),
        };
        let name = intro_name(&device, &ask);
        let mut answered = None;
        for _ in 0..ASK_TRIES {
            answered = inner.fetch_hinted(name.clone(), &hints).await;
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
        let by_device = |k: Option<(Name, [u8; 32])>| {
            k.is_some_and(|(k, _)| device_of(&k).as_ref() == Some(&device))
        };
        if !code.fingerprint.matches(&theirs.fingerprint())
            || code.namespace.as_ref().is_some_and(|ns| *ns != inviter)
            || !device.has_prefix(&inviter)
            || *signed.name != wire::ask_name(&device, &answer.binding())
            || !by_device(theirs.signer(&signed).await)
            || !by_device(theirs.signer(&entry).await)
            || ob.commitment != commitment(&code.secret)
            || ob.folder != folder
            || ob.role != role
        {
            return Err(forged());
        }
        introducer.adopt(&theirs.link()).await.map_err(|why| {
            local(format!(
                "this device's host did not adopt {inviter}'s anchor ({why}): fix that and join \
                 again with the same code (the offer is yours: asking again is answered again)"
            ))
        })?;
        for c in &theirs.certs {
            inner.validator.cert_cache().insert(c.clone());
        }
        inner.look(&folder).await?;
        Ok(Joined {
            folder,
            role,
            inviter,
        })
    }
}
