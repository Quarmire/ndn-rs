//! Recovery kits, and recovering a namespace whose root device is lost.
//!
//! A **recovery kit** holds a *recovery key*: a key of its own, never a copy
//! of the root. Its public key is added as an extra anchor of the
//! namespace's trust context, marked [`KeyRole::RECOVERY_ANCHOR`], in a
//! version the root signs ([`add_recovery_anchor`]). As every anchor, it can
//! sign the next version (the continuity rule: an update is signed by an
//! anchor of the held version), so when the root device is lost the
//! recovery key takes over without any other trust machinery
//! ([`recovery_version`], [`recover_namespace_in_pib`]). A recovery anchor is
//! root-equivalent by design and is kept offline.
//!
//! Why a separate key: a hardware root cannot be exported, and a copy of
//! the root written down as words would simply be the root. A separate key
//! can be revoked on its own ([`remove_recovery_anchor`]) and several kits
//! can coexist.
//!
//! A recovery key is named `<ns>/KEY/r<16 hex>`, the hex being the first 8
//! bytes of SHA-256 over its public key ([`recovery_key_name`]), so a word
//! list alone rebuilds the key and its name. Kit formats (the owner's
//! choice; equally supported):
//!
//! - **words**: an Ed25519 key from a 32-byte seed, shown once as 24 BIP39
//!   English words ([`RecoverySeed`]); the BIP39 checksum catches a mistyped
//!   word before anything is signed. Nothing about the seed is stored.
//! - **file**: an Ed25519 key in a passphrase-sealed SafeBag (PBES2, as the
//!   root store's) wrapped in an `ndn-trust://bag` envelope that also names
//!   the namespace and its expected fingerprint ([`seal_file_kit`],
//!   [`FileKit`]).
//! - **yubikey**: a P-256 key generated on a second YubiKey's PIV slot,
//!   never exportable (the `ndn-fwd` CLI drives it).
//!
//! **Recovering** ([`recover_namespace_in_pib`], on a replacement device that
//! holds the namespace's context): a new root (in the root store the
//! operator chooses), a new CA key and a new admin device identity, all
//! with fresh key ids; the recovery key signs version `N+1` whose anchors are
//! the new root and the recovery anchors kept, plus the old root when the
//! operator says it was **destroyed** ([`OldRoot`]; every recovery anchor
//! stays). When it was **compromised**, `N+1` also revokes the old root key
//! and the keys the old root device held ([`KeyRole::ROOT_DEVICE`]: its CA
//! key and admin key), so every certificate chaining through the old CA
//! stops validating, and it keeps only the recovery anchors the operator
//! vouches for (the signing kit and [`RecoveryPlan::kept_kits`]): whoever
//! held the old root could have added one of their own, and the rest are
//! removed and revoked. The new
//! root then signs `N+2`, the same content ([`reissue_version`]), so the
//! newest version is root-signed and the root's fingerprint is the expected
//! fingerprint of anchor links and invites again. Every node holding
//! version `N` adopts `N+1` and `N+2` by the continuity rule, one after the
//! other ([`crate::context_update::follow_versions`]).

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use ndn_packet::{Data, Name};
use ndn_security::cert_name::{DEFAULT_ISSUER, NDNCERT_ISSUER, key_name_of, new_key_name};
use ndn_security::safebag::SafeBag;
use ndn_security::{
    Certificate, Ed25519Signer, FilePib, KeyRole, OpenContextError, PibError, SecurityManager,
    SignedTrustContext, SignedTrustContextError, Signer, TrustError,
};
use ndn_trust_envelope::{ANCHOR_FINGERPRINT_LEN, TrustEnvelope};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ca::serialize_cert;
use crate::context_update::{ContextBump, UpdateRefusal, open_context_update};
use crate::namespace::{
    ANCHOR_CERT_FILE, CA_CERT_FILE, CA_CERT_VALIDITY_MS, DEVICE_CERT_FILE, DEVICE_CERT_VALIDITY_MS,
    NamespaceInitError, ca_dir, ca_key_name, certify_new_key,
};
use crate::roles::{Role, RoleError, device_identity, validate_namespace};
use crate::root_store::{
    NewRootStore, PendingRoot, RootSecret, RootStore, RootStoreError, SlotGuard, same_public_key,
};

/// Environment variable a CLI reads a file kit's passphrase from.
pub const KIT_PASSPHRASE_ENV: &str = "NDN_KIT_PASSPHRASE";
/// Environment variable a CLI reads a word kit's 24 words from (scripts,
/// tests) instead of asking.
pub const KIT_WORDS_ENV: &str = "NDN_KIT_WORDS";
/// Environment variable a CLI reads a YubiKey kit's PIV PIN from.
pub const KIT_PIN_ENV: &str = "NDN_KIT_PIN";
/// The PIV slot a YubiKey kit's key is generated in by default (`9d`, "Key
/// Management"). The kit goes on a token of its own: generating it on the
/// root's token is refused ([`SlotGuard`]).
pub const DEFAULT_KIT_SLOT: &str = "9d";
/// Words in a word kit: 256 bits of seed plus an 8-bit checksum.
pub const KIT_WORD_COUNT: usize = 24;

/// A kit format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KitFormat {
    Words,
    File,
    Yubikey,
}

impl KitFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            KitFormat::Words => "words",
            KitFormat::File => "file",
            KitFormat::Yubikey => "yubikey",
        }
    }
}

impl fmt::Display for KitFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KitFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "words" => Ok(KitFormat::Words),
            "file" => Ok(KitFormat::File),
            "yubikey" => Ok(KitFormat::Yubikey),
            _ => Err(format!("unknown kit format {s:?} (words, file, yubikey)")),
        }
    }
}

/// What happened to the lost root device — the operator must say, because
/// the two need opposite things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldRoot {
    /// Gone for good (broken, wiped, lost where nobody can use it): its
    /// root stays an anchor and every certificate it and its CA issued stays
    /// valid, so existing devices keep working and renew with the new CA.
    Destroyed,
    /// Possibly in someone else's hands: its root key, its CA key and its
    /// admin key are revoked, so every certificate chaining through the old
    /// CA stops validating and those devices enroll again; of the recovery
    /// anchors, only the kit that recovers and those the operator vouches
    /// for stay ([`RecoveryPlan::kept_kits`]).
    Compromised,
}

impl OldRoot {
    pub fn as_str(self) -> &'static str {
        match self {
            OldRoot::Destroyed => "destroyed",
            OldRoot::Compromised => "compromised",
        }
    }

    /// Why the choice exists, for a CLI that refuses to guess it.
    pub const CHOICE: &'static str = "`destroyed`: the old root device is gone for good — its \
         root stays an anchor, every certificate it and its CA issued stays valid, devices keep \
         working and renew with the new CA. `compromised`: someone else may hold it — its root \
         key, CA key and admin key are revoked, every device certificate issued through the old \
         CA stops validating, and those devices enroll again with new invites; every recovery \
         kit other than the one used and those you name to keep is revoked too (whoever held \
         the root could have added one). Keeping a compromised root valid would leave the \
         namespace in its holder's hands; revoking a destroyed one would cut off every device \
         for nothing";
}

impl fmt::Display for OldRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OldRoot {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "destroyed" => Ok(OldRoot::Destroyed),
            "compromised" => Ok(OldRoot::Compromised),
            _ => Err(format!("unknown --old-root {s:?} (destroyed, compromised)")),
        }
    }
}

/// Why a kit could not be made, opened or used, or a recovery not done.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("these recovery words are refused: {0}. Nothing was signed")]
    BadWords(String),
    #[error("{path} is not a recovery kit: {reason}")]
    NotAKit { path: String, reason: String },
    #[error("the kit passphrase does not open {path}: nothing was signed")]
    WrongKitPassphrase { path: String },
    #[error("the kit is for {kit}, not {requested}")]
    OtherNamespace { kit: String, requested: String },
    #[error(
        "the kit's key {key} is not a recovery anchor of the trust context of {namespace} held \
         here (v{version}){hint}, so it cannot recover the namespace; nothing was signed"
    )]
    NotARecoveryAnchor {
        key: String,
        namespace: String,
        version: u64,
        hint: String,
    },
    #[error(
        "{key} is not an anchor of {namespace} v{version}, so it cannot sign its next version: \
         run this on the root device (or recover with a kit, `ndn-fwd recover`)"
    )]
    SignerNotAnAnchor {
        key: String,
        namespace: String,
        version: u64,
    },
    #[error("{0} is already an anchor of this trust context")]
    AlreadyAnAnchor(String),
    #[error("the recovery anchor certificate {0} is not valid now")]
    AnchorNotValid(String),
    #[error("{0} signs this version, so it cannot remove itself from the anchors")]
    RemovesSigner(String),
    #[error(
        "kits to keep are named only when the old root is compromised: with it destroyed, every \
         recovery anchor stays (nothing it could have added is distrusted). Name no kits to keep, \
         or recover with the old root compromised"
    )]
    KeptKitsNeedCompromised,
    #[error(
        "{pib} holds the root of {namespace} ({kind} root store): this already is a root \
         device of the namespace. Recover on a replacement device whose PIB holds no root of \
         {namespace} (the roots of other trusted prefixes may stay)"
    )]
    AlreadyRootDevice {
        pib: String,
        namespace: String,
        kind: String,
    },
    #[error(
        "{path} exists: this PIB already holds a CA identity of the namespace. Recover into the \
         PIB of a device that runs no CA of it"
    )]
    CaPresent { path: PathBuf },
    #[error("refusing to revoke {name}: it covers the anchor {anchor} of the new version")]
    CoversAnchor { name: String, anchor: String },
    #[error("context version {0} cannot be bumped")]
    VersionExhausted(u64),
    #[error("the held context is not a valid signed trust context: {0}")]
    Unreadable(#[from] OpenContextError),
    #[error("trust context: {0}")]
    Context(#[from] SignedTrustContextError),
    #[error("the new version would not be adopted by holders of the current one: {0}")]
    Continuity(#[from] UpdateRefusal),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error(transparent)]
    RootStore(#[from] RootStoreError),
    #[error(transparent)]
    Pib(#[from] PibError),
    #[error(transparent)]
    Role(#[from] RoleError),
    #[error(transparent)]
    Init(#[from] NamespaceInitError),
    #[error("YubiKey: {0}")]
    Yubikey(String),
    #[error(
        "this YubiKey's firmware is {firmware}: a recovery kit made on it could never be opened, \
         as reading its key back needs the PIV slot metadata of firmware 5.3 or later. Use a \
         YubiKey with firmware 5.3 or later, or a words or file kit; nothing was generated"
    )]
    KitFirmwareTooOld { firmware: String },
    #[error("I/O on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An Ed25519 key is carried raw by in-memory signers and as SPKI by some
/// certificates; a recovery key's name is derived from the raw form.
fn canonical_public_key(public_key: &[u8]) -> &[u8] {
    if ndn_security::spki::is_ed25519_spki(public_key) {
        // An Ed25519 SPKI ends with the raw 32-byte key.
        return &public_key[public_key.len() - 32..];
    }
    public_key
}

/// The name of the recovery key with `public_key` in `namespace`:
/// `<ns>/KEY/r<hex of the first 8 bytes of SHA-256(public key)>`.
pub fn recovery_key_name(namespace: &Name, public_key: &[u8]) -> Name {
    let digest = Sha256::digest(canonical_public_key(public_key));
    namespace
        .clone()
        .append("KEY")
        .append(format!("r{}", hex(&digest[..8])))
}

// ── Word kits ──────────────────────────────────────────────────────────────

/// The 32-byte seed of a word kit's Ed25519 recovery key. Zeroed on drop.
pub struct RecoverySeed(Zeroizing<[u8; 32]>);

impl RecoverySeed {
    /// A fresh seed from the system RNG.
    pub fn generate() -> Result<Self, RecoveryError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..])
            .map_err(|_| TrustError::KeyStore("system RNG unavailable".into()))?;
        Ok(Self(seed))
    }

    /// The seed the 24 BIP39 English `words` encode. Case and spacing do
    /// not matter; a word outside the list, a wrong count or a checksum
    /// mismatch (a mistyped or swapped word) is refused.
    pub fn from_words(words: &str) -> Result<Self, RecoveryError> {
        let mut normalized = Zeroizing::new(String::with_capacity(words.len()));
        let mut count = 0;
        for word in words.split_whitespace() {
            if count > 0 {
                normalized.push(' ');
            }
            normalized.extend(word.chars().flat_map(char::to_lowercase));
            count += 1;
        }
        if count != KIT_WORD_COUNT {
            return Err(RecoveryError::BadWords(format!(
                "{count} words; a recovery kit has {KIT_WORD_COUNT}"
            )));
        }
        // A refusal names the position only: a mistyped word is usually one
        // edit from the real one, and the error reaches terminals and logs.
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
            .map_err(|e| {
                RecoveryError::BadWords(match e {
                    bip39::Error::UnknownWord(i) => {
                        format!("word {} is not a BIP39 English word", i + 1)
                    }
                    bip39::Error::InvalidChecksum => {
                        "the checksum does not match: a word is mistyped, or two are swapped".into()
                    }
                    other => other.to_string(),
                })
            })?;
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let mut seed = Zeroizing::new([0u8; 32]);
        let ok = len == 32;
        if ok {
            seed.copy_from_slice(&entropy[..32]);
        }
        zeroize::Zeroize::zeroize(&mut entropy);
        if !ok {
            return Err(RecoveryError::BadWords(format!(
                "{len} bytes of seed, not 32"
            )));
        }
        Ok(Self(seed))
    }

    /// The seed as 24 BIP39 English words, space-separated.
    pub fn to_words(&self) -> Zeroizing<String> {
        use std::fmt::Write as _;
        let mnemonic =
            bip39::Mnemonic::from_entropy(&self.0[..]).expect("32 bytes of entropy always encode");
        // Room for 24 of the longest (8-letter) words and their spaces, so
        // the string never reallocates and leaves no unwiped copy behind.
        let mut words = Zeroizing::new(String::with_capacity(KIT_WORD_COUNT * 9));
        write!(words, "{mnemonic}").expect("writing to a String cannot fail");
        words
    }

    /// The recovery key of `namespace` this seed makes, named
    /// [`recovery_key_name`].
    pub fn signer(&self, namespace: &Name) -> Ed25519Signer {
        let probe = Ed25519Signer::from_seed(&self.0, Name::root());
        let name = recovery_key_name(namespace, &probe.public_key_bytes());
        Ed25519Signer::from_seed(&self.0, name)
    }

    fn pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
        ndn_security::safebag::ed25519_seed_to_pkcs8(&self.0)
            .map(Zeroizing::new)
            .map_err(|e| TrustError::KeyStore(e.to_string()).into())
    }
}

/// The recovery key's self-signed anchor certificate
/// (`<key>/self/<version>`, never expiring like the root's), signed through
/// the signer's async path (a hardware kit signs on the token).
pub async fn recovery_anchor(signer: Arc<dyn Signer>) -> Result<Certificate, RecoveryError> {
    let key = signer.key_name().clone();
    let public_key = signer
        .public_key()
        .ok_or_else(|| TrustError::KeyStore(format!("{key} reports no public key")))?;
    let mgr = SecurityManager::new();
    mgr.register_signer(key.clone(), signer);
    Ok(mgr
        .issue_self_signed_async(&key, public_key, u64::MAX)
        .await?)
}

// ── File kits ──────────────────────────────────────────────────────────────

/// The NFC form of a UTF-8 kit passphrase, when it differs from the bytes
/// given: a file kit is sealed with it, so the same text typed through an
/// input method that produces another normalization still opens the kit.
/// `None` for a passphrase already in NFC or not UTF-8 (used as given).
fn nfc_passphrase(passphrase: &[u8]) -> Option<Zeroizing<String>> {
    use unicode_normalization::{UnicodeNormalization, is_nfc};
    let text = std::str::from_utf8(passphrase).ok()?;
    (!is_nfc(text)).then(|| Zeroizing::new(text.nfc().collect()))
}

/// A file kit's content: the `ndn-trust://bag` URI of an envelope carrying
/// the recovery key's SafeBag — its anchor certificate and the key sealed
/// with `passphrase` (in Unicode NFC when it is UTF-8) — plus the
/// namespace and its expected fingerprint (`fingerprint`: the root's, when
/// the kit was made).
pub fn seal_file_kit(
    seed: &RecoverySeed,
    anchor: &Certificate,
    namespace: &Name,
    fingerprint: Option<[u8; ANCHOR_FINGERPRINT_LEN]>,
    passphrase: &RootSecret,
) -> Result<String, RecoveryError> {
    if passphrase.expose().is_empty() {
        return Err(RootStoreError::Secret("refusing an empty kit passphrase".into()).into());
    }
    let wire = anchor
        .data_wire()
        .ok_or_else(|| TrustError::KeyStore("the recovery anchor has no signed wire".into()))?;
    let pkcs8 = seed.pkcs8()?;
    let nfc = nfc_passphrase(passphrase.expose());
    let password = nfc
        .as_ref()
        .map_or(passphrase.expose(), |nfc| nfc.as_bytes());
    let bag = SafeBag::encrypt(wire, &pkcs8, password)
        .map_err(|e| TrustError::KeyStore(e.to_string()))?;
    Ok(TrustEnvelope::Bag {
        key_name: anchor.key_name().to_string(),
        safebag: bag.encode(),
        namespace: Some(namespace.to_string()),
        fingerprint,
    }
    .to_uri())
}

/// A file kit read from disk, still sealed.
#[derive(Debug)]
pub struct FileKit {
    path: PathBuf,
    /// The namespace the kit recovers.
    pub namespace: Name,
    /// The recovery key's name.
    pub key_name: Name,
    /// The recovery key's public key (from its anchor certificate).
    pub public_key: bytes::Bytes,
    /// The namespace's expected fingerprint when the kit was made.
    pub fingerprint: Option<[u8; ANCHOR_FINGERPRINT_LEN]>,
    bag: SafeBag,
}

impl FileKit {
    /// Read the kit at `path` (its `ndn-trust://bag` URI).
    pub fn read(path: &Path) -> Result<FileKit, RecoveryError> {
        let shown = path.display().to_string();
        let not_a_kit = |reason: String| RecoveryError::NotAKit {
            path: shown.clone(),
            reason,
        };
        let text = std::fs::read_to_string(path).map_err(|source| RecoveryError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let envelope =
            TrustEnvelope::from_uri(text.trim()).map_err(|e| not_a_kit(e.to_string()))?;
        let TrustEnvelope::Bag {
            key_name,
            safebag,
            namespace: Some(namespace),
            fingerprint,
        } = envelope
        else {
            return Err(not_a_kit(
                "not an ndn-trust://bag envelope naming a namespace".into(),
            ));
        };
        let namespace: Name = namespace
            .parse()
            .map_err(|e| not_a_kit(format!("namespace {namespace:?}: {e}")))?;
        let key_name: Name = key_name
            .parse()
            .map_err(|e| not_a_kit(format!("key name {key_name:?}: {e}")))?;
        let bag = SafeBag::decode(&safebag).map_err(|e| not_a_kit(format!("SafeBag: {e}")))?;
        let anchor = Data::decode(bag.certificate.clone())
            .ok()
            .and_then(|d| Certificate::decode(&d).ok())
            .ok_or_else(|| not_a_kit("its SafeBag carries no certificate".into()))?;
        if anchor.key_name() != key_name
            || recovery_key_name(&namespace, &anchor.public_key) != key_name
        {
            return Err(not_a_kit(format!(
                "its certificate {} is not the recovery key {key_name} of {namespace}",
                anchor.name
            )));
        }
        // Before any passphrase is asked for: a crafted kit asking for
        // billions of PBKDF2 iterations would take hours to open.
        bag.check_kdf_cost().map_err(|e| not_a_kit(e.to_string()))?;
        Ok(FileKit {
            path: path.to_path_buf(),
            namespace,
            key_name,
            public_key: anchor.public_key.clone(),
            fingerprint,
            bag,
        })
    }

    /// Unseal the recovery key with the kit passphrase: as given, then (a
    /// kit is sealed with it) its Unicode NFC form.
    pub fn open(&self, passphrase: &RootSecret) -> Result<Ed25519Signer, RecoveryError> {
        let nfc = nfc_passphrase(passphrase.expose());
        let signer = std::iter::once(passphrase.expose())
            .chain(nfc.as_ref().map(|nfc| nfc.as_bytes()))
            .find_map(|password| {
                let pkcs8 = Zeroizing::new(self.bag.decrypt_pkcs8(password).ok()?);
                Ed25519Signer::from_pkcs8_der(&pkcs8, self.key_name.clone()).ok()
            })
            .ok_or_else(|| RecoveryError::WrongKitPassphrase {
                path: self.path.display().to_string(),
            })?;
        if !same_public_key(&signer.public_key_bytes(), &self.public_key) {
            return Err(RecoveryError::NotAKit {
                path: self.path.display().to_string(),
                reason: "the sealed key is not the key of its certificate".into(),
            });
        }
        Ok(signer)
    }
}

// ── YubiKey kits ───────────────────────────────────────────────────────────

/// A YubiKey kit: a P-256 recovery key generated on a PIV slot of a second
/// token (PIN policy `always`, so the PIN is verified before each signature;
/// the touch policy as chosen), never exportable. Built with the
/// `yubikey-piv` feature; without it every operation says so.
#[derive(Clone, Debug)]
pub struct YubikeyKit {
    /// The token, when several are connected.
    pub serial: Option<u32>,
    /// `9a`, `9c`, `9d` (default, [`DEFAULT_KIT_SLOT`]), `9e`.
    pub slot: String,
    /// `always` (default), `cached`, `never`.
    pub touch_policy: String,
}

/// The oldest YubiKey firmware a kit is made on: opening a kit reads the
/// slot's public key from its PIV metadata (GET METADATA), which firmware
/// 5.3 introduced.
pub const KIT_MIN_FIRMWARE: [u8; 3] = [5, 3, 0];

/// Refuse a token whose `firmware` ([major, minor, patch]) is older than
/// [`KIT_MIN_FIRMWARE`]: a kit generated there could never be opened.
pub fn check_kit_firmware(firmware: [u8; 3]) -> Result<(), RecoveryError> {
    if firmware < KIT_MIN_FIRMWARE {
        let [major, minor, patch] = firmware;
        return Err(RecoveryError::KitFirmwareTooOld {
            firmware: format!("{major}.{minor}.{patch}"),
        });
    }
    Ok(())
}

#[cfg(feature = "yubikey-piv")]
impl YubikeyKit {
    fn token(
        &self,
    ) -> Result<(ndn_security::YubikeyPiv, ndn_security::YubikeySlot), RecoveryError> {
        let slot: ndn_security::YubikeySlot = self.slot.parse().map_err(RecoveryError::Yubikey)?;
        let token = match self.serial {
            Some(s) => ndn_security::YubikeyPiv::open_by_serial(s),
            None => ndn_security::YubikeyPiv::open(),
        }
        .map_err(|e| RecoveryError::Yubikey(format!("{e}; plug in the recovery kit's YubiKey")))?;
        Ok((token, slot))
    }

    /// Generate the recovery key of `namespace` on the token. `guard` keeps
    /// it off a token it must not go on (the root's) and off an occupied
    /// slot unless replacing is allowed. Returns its signer (named
    /// [`recovery_key_name`]; the PIN is verified before each signature) and
    /// the token's serial.
    pub async fn generate(
        &self,
        namespace: &Name,
        pin: &RootSecret,
        guard: &SlotGuard,
    ) -> Result<(Arc<dyn Signer>, u32), RecoveryError> {
        use ndn_security::{YubikeyPinPolicy, YubikeyTouchPolicy};
        let (token, slot) = self.token()?;
        check_kit_firmware(token.firmware())?;
        crate::root_store::check_generation_target(&token, slot, guard).await?;
        let touch: YubikeyTouchPolicy =
            self.touch_policy.parse().map_err(RecoveryError::Yubikey)?;
        let (_unnamed, spki) = token
            .generate_with_policy(
                Name::root(),
                slot,
                YubikeyPinPolicy::Always,
                touch,
                Zeroizing::new(pin.expose().to_vec()),
            )
            .await
            .map_err(|e| RecoveryError::Yubikey(e.to_string()))?;
        let signer = token.signer_with(
            recovery_key_name(namespace, &spki),
            slot,
            spki,
            Some(Zeroizing::new(pin.expose().to_vec())),
        );
        Ok((signer, token.serial()))
    }

    /// The public key in the slot, from its metadata (firmware 5.3+): no
    /// PIN, nothing signed.
    pub async fn public_key(&self) -> Result<bytes::Bytes, RecoveryError> {
        let (token, slot) = self.token()?;
        token.slot_public_key(slot).await.map_err(|e| {
            RecoveryError::Yubikey(format!(
                "{e} (reading a slot's public key needs firmware 5.3+)"
            ))
        })
    }

    /// A signer for the slot's key as the recovery key of `namespace`, and
    /// the token's serial: the PIN is verified now and before each
    /// signature.
    pub async fn signer(
        &self,
        namespace: &Name,
        pin: &RootSecret,
    ) -> Result<(Arc<dyn Signer>, u32), RecoveryError> {
        let (token, slot) = self.token()?;
        token
            .verify_pin(pin.expose())
            .await
            .map_err(|e| RecoveryError::Yubikey(e.to_string()))?;
        let spki = token
            .slot_public_key(slot)
            .await
            .map_err(|e| RecoveryError::Yubikey(e.to_string()))?;
        let signer = token.signer_with(
            recovery_key_name(namespace, &spki),
            slot,
            spki,
            Some(Zeroizing::new(pin.expose().to_vec())),
        );
        Ok((signer, token.serial()))
    }
}

#[cfg(not(feature = "yubikey-piv"))]
impl YubikeyKit {
    fn not_built() -> RecoveryError {
        RecoveryError::Yubikey(
            "this build has no YubiKey support (build with the cargo feature `yubikey-piv`)".into(),
        )
    }

    /// See the `yubikey-piv` build.
    pub async fn generate(
        &self,
        _namespace: &Name,
        _pin: &RootSecret,
        _guard: &SlotGuard,
    ) -> Result<(Arc<dyn Signer>, u32), RecoveryError> {
        Err(Self::not_built())
    }

    /// See the `yubikey-piv` build.
    pub async fn public_key(&self) -> Result<bytes::Bytes, RecoveryError> {
        Err(Self::not_built())
    }

    /// See the `yubikey-piv` build.
    pub async fn signer(
        &self,
        _namespace: &Name,
        _pin: &RootSecret,
    ) -> Result<(Arc<dyn Signer>, u32), RecoveryError> {
        Err(Self::not_built())
    }
}

// ── Context versions ───────────────────────────────────────────────────────

/// Whether `public_key` is the key of an anchor of `ctx`.
fn is_anchor_key(ctx: &SignedTrustContext, public_key: &[u8]) -> bool {
    ctx.anchors()
        .iter()
        .any(|a| same_public_key(&a.value().public_key, public_key))
}

/// The recovery anchor of `ctx` whose key is `public_key`: a kit recovers
/// only when its key is an anchor of the held context marked
/// [`KeyRole::RECOVERY_ANCHOR`]. Returns the anchor's key name.
pub fn kit_anchor(ctx: &SignedTrustContext, public_key: &[u8]) -> Result<Name, RecoveryError> {
    let anchor = ctx
        .anchors()
        .iter()
        .find(|a| same_public_key(&a.value().public_key, public_key))
        .map(|a| key_name_of(a.key()));
    let refuse = |key: &Name, hint: &str| RecoveryError::NotARecoveryAnchor {
        key: key.to_string(),
        namespace: ctx.namespace().to_string(),
        version: ctx.version(),
        hint: hint.to_string(),
    };
    match anchor {
        Some(key) if ctx.has_key_role(&key, KeyRole::RECOVERY_ANCHOR) => Ok(key),
        Some(key) => Err(refuse(&key, " (it is an anchor, but not a recovery key)")),
        None => Err(refuse(
            &recovery_key_name(ctx.namespace(), public_key),
            " (never added, revoked since, or a kit of another namespace)",
        )),
    }
}

/// The held context and version `N+1` made from its content, after checking
/// that `signer` holds an anchor of it.
async fn open_next(
    signer: &dyn Signer,
    held: &Data,
) -> Result<(SignedTrustContext, SignedTrustContext), RecoveryError> {
    let (ctx, _) = SignedTrustContext::open_signed(held).await?;
    if !signer
        .public_key()
        .is_some_and(|pk| is_anchor_key(&ctx, &pk))
    {
        return Err(RecoveryError::SignerNotAnAnchor {
            key: signer.key_name().to_string(),
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
        });
    }
    let version = ctx
        .version()
        .checked_add(1)
        .ok_or(RecoveryError::VersionExhausted(ctx.version()))?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let next = SignedTrustContext::decode_content(content, version)?;
    Ok((ctx, next))
}

/// Sign `next` with `signer` and check that every holder of `held` adopts it
/// (continuity, newer).
async fn finish(
    signer: &dyn Signer,
    held: &SignedTrustContext,
    next: SignedTrustContext,
) -> Result<ContextBump, RecoveryError> {
    let data = next.sign_into_data_async(signer).await?;
    open_context_update(held, &data).await?;
    let added = next
        .revocations()
        .iter()
        .filter(|r| !held.revocations().contains(r))
        .cloned()
        .collect();
    Ok(ContextBump {
        context: next,
        data,
        added,
    })
}

/// Version `N+1` of the held context `held` with the recovery key of
/// `anchor` (its self-signed certificate) added as an anchor marked
/// [`KeyRole::RECOVERY_ANCHOR`], signed by `signer` — an anchor key of
/// `held` (the root, unlocked from its root store). Everything else is
/// carried over. Pure: nothing is adopted, stored or published.
pub async fn add_recovery_anchor(
    signer: &dyn Signer,
    held: &Data,
    anchor: &Certificate,
) -> Result<ContextBump, RecoveryError> {
    let (ctx, next) = open_next(signer, held).await?;
    if is_anchor_key(&ctx, &anchor.public_key) {
        return Err(RecoveryError::AlreadyAnAnchor(
            anchor.key_name().to_string(),
        ));
    }
    let next = next.with_key_role(KeyRole::RECOVERY_ANCHOR, anchor.key_name());
    if !next.add_anchor(anchor.clone()) {
        return Err(RecoveryError::AnchorNotValid(anchor.name.to_string()));
    }
    finish(signer, &ctx, next).await
}

/// Version `N+1` of `held` without the recovery anchor `key`: its
/// certificates leave the anchor set, its role goes, and the key is revoked
/// (a kit that leaked can sign nothing anyone accepts afterwards). Signed by
/// `signer`, an anchor key of `held` other than `key`.
pub async fn remove_recovery_anchor(
    signer: &dyn Signer,
    held: &Data,
    key: &Name,
) -> Result<ContextBump, RecoveryError> {
    let (ctx, next) = open_next(signer, held).await?;
    if !ctx.has_key_role(key, KeyRole::RECOVERY_ANCHOR) {
        return Err(RecoveryError::NotARecoveryAnchor {
            key: key.to_string(),
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
            hint: " (`ndn-fwd recovery-kit list` shows them)".into(),
        });
    }
    let signs_with_it = signer.public_key().is_some_and(|pk| {
        ctx.anchors()
            .iter()
            .any(|a| key_name_of(a.key()) == *key && same_public_key(&a.value().public_key, &pk))
    });
    if signs_with_it {
        return Err(RecoveryError::RemovesSigner(key.to_string()));
    }
    next.anchors().retain(|name, _| key_name_of(name) != *key);
    let mut next = next.without_key_roles(|_, k| k == key);
    if !next.is_revoked(key) {
        next = next.with_revocation(key.clone());
    }
    finish(signer, &ctx, next).await
}

/// Version `N+1` of `held` with exactly its content, signed by `signer` —
/// an anchor key of `held`. After a recovery, the new root reissues the
/// version the recovery key signed ([`recover_namespace_in_pib`]), so the
/// newest version is signed by the root: an anchor link or invite naming
/// the root's fingerprint as the expected fingerprint authenticates it. A
/// node holding a version before the recovery follows both by the
/// continuity rule (`N` → the recovery key's `N+1` → the root's `N+2`,
/// [`crate::context_update::follow_versions`]). Pure.
pub async fn reissue_version(
    signer: &dyn Signer,
    held: &Data,
) -> Result<ContextBump, RecoveryError> {
    let (ctx, next) = open_next(signer, held).await?;
    finish(signer, &ctx, next).await
}

/// What a recovery puts in version `N+1`.
#[derive(Debug)]
pub struct RecoveryPlan<'a> {
    /// The new root's self-signed anchor certificate.
    pub new_root: &'a Certificate,
    /// The keys of the new root device (its CA key and admin key), marked
    /// [`KeyRole::ROOT_DEVICE`] in place of the old ones.
    pub new_root_device_keys: &'a [Name],
    pub old_root: OldRoot,
    /// [`OldRoot::Compromised`] only: the recovery anchors of `N`, besides
    /// the kit that signs, the operator vouches for — kits they made and
    /// still hold. Whoever held the old root could have added a recovery
    /// anchor of their own, and a recovery anchor is root-equivalent, so
    /// every other one is removed and revoked. Must be empty for
    /// [`OldRoot::Destroyed`], which keeps every recovery anchor.
    pub kept_kits: &'a [Name],
}

/// Version `N+1` made by a recovery key.
#[derive(Debug)]
pub struct RecoveryVersion {
    pub bump: ContextBump,
    /// The kit's key (a recovery anchor of `N`, and of `N+1`).
    pub recovery_key: Name,
    /// The old root's anchor keys: still anchors (`destroyed`) or removed
    /// and revoked (`compromised`).
    pub old_root_keys: Vec<Name>,
    /// `compromised`: the keys the old root device held, revoked.
    pub old_root_device_keys: Vec<Name>,
    /// `compromised`, and the held context recorded no root-device keys (a
    /// namespace made before they were recorded): the CA key `ndn-fwd init`
    /// names (`<ns>/CA/KEY/ca`) was revoked; the old admin key is unknown.
    pub root_device_keys_unrecorded: bool,
    /// The recovery anchors of `N+1`: the kit that signed, and every other
    /// recovery anchor of `N` (`destroyed`) or those in
    /// [`RecoveryPlan::kept_kits`] (`compromised`).
    pub kept_kits: Vec<Name>,
    /// `compromised`: the recovery anchors of `N` nobody vouched for,
    /// removed and revoked.
    pub removed_kits: Vec<Name>,
}

/// The anchors of `N` a recovery sorts: the old root's, the recovery
/// anchors kept and those removed.
struct AnchorSplit {
    old_root_keys: Vec<Name>,
    kept_kits: Vec<Name>,
    removed_kits: Vec<Name>,
}

/// Sort the anchors of `ctx` for a recovery by the kit `recovery_key`,
/// refusing a kit to keep that is no recovery anchor of `ctx` (listing
/// them), or any kit to keep when the old root was destroyed.
fn split_anchors(
    ctx: &SignedTrustContext,
    recovery_key: &Name,
    old_root: OldRoot,
    kept: &[Name],
) -> Result<AnchorSplit, RecoveryError> {
    let mut old_root_keys: Vec<Name> = Vec::new();
    let mut kits: Vec<Name> = Vec::new();
    for anchor in ctx.anchors().iter() {
        let key = key_name_of(anchor.key());
        let set = if ctx.has_key_role(&key, KeyRole::RECOVERY_ANCHOR) {
            &mut kits
        } else {
            &mut old_root_keys
        };
        if !set.contains(&key) {
            set.push(key);
        }
    }
    kits.sort();
    if old_root == OldRoot::Destroyed && !kept.is_empty() {
        return Err(RecoveryError::KeptKitsNeedCompromised);
    }
    if let Some(unknown) = kept.iter().find(|k| !kits.contains(k)) {
        return Err(RecoveryError::NotARecoveryAnchor {
            key: unknown.to_string(),
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
            hint: format!(
                " (its recovery anchors: {})",
                kits.iter()
                    .map(Name::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }
    let (kept_kits, removed_kits) = match old_root {
        OldRoot::Destroyed => (kits, Vec::new()),
        OldRoot::Compromised => kits
            .into_iter()
            .partition(|k| k == recovery_key || kept.contains(k)),
    };
    Ok(AnchorSplit {
        old_root_keys,
        kept_kits,
        removed_kits,
    })
}

/// Version `N+1` of `held`, signed by the recovery key `recovery` (a
/// recovery anchor of `held`, else refused before anything is signed):
/// anchors = the new root + the recovery anchors kept (+ the old root
/// when [`OldRoot::Destroyed`]); the new root device's keys replace the
/// old ones' [`KeyRole::ROOT_DEVICE`] entries. When
/// [`OldRoot::Compromised`], the old root, the old root device's keys and
/// every recovery anchor other than the signing kit and
/// [`RecoveryPlan::kept_kits`] are removed and revoked — nothing the old
/// root could have installed keeps the power to sign the next version.
/// Schema, CA endpoints and earlier revocations are carried over. Pure.
pub async fn recovery_version(
    recovery: &dyn Signer,
    held: &Data,
    plan: &RecoveryPlan<'_>,
) -> Result<RecoveryVersion, RecoveryError> {
    let (ctx, _) = SignedTrustContext::open_signed(held).await?;
    let recovery_pk = recovery.public_key().unwrap_or_default();
    let recovery_key = kit_anchor(&ctx, &recovery_pk)?;
    let (ctx, next) = open_next(recovery, held).await?;

    let AnchorSplit {
        old_root_keys,
        kept_kits,
        removed_kits,
    } = split_anchors(&ctx, &recovery_key, plan.old_root, plan.kept_kits)?;

    let mut next = next.without_key_roles(|role, key| {
        role == KeyRole::ROOT_DEVICE
            || (role == KeyRole::RECOVERY_ANCHOR && removed_kits.contains(key))
    });
    for key in plan.new_root_device_keys {
        next = next.with_key_role(KeyRole::ROOT_DEVICE, key.clone());
    }
    if !next.add_anchor(plan.new_root.clone()) {
        return Err(RecoveryError::AnchorNotValid(
            plan.new_root.name.to_string(),
        ));
    }

    let mut old_root_device_keys = Vec::new();
    let mut root_device_keys_unrecorded = false;
    if plan.old_root == OldRoot::Compromised {
        next.anchors().retain(|name, _| {
            let key = key_name_of(name);
            !old_root_keys.contains(&key) && !removed_kits.contains(&key)
        });
        old_root_device_keys = ctx.keys_with_role(KeyRole::ROOT_DEVICE).cloned().collect();
        if old_root_device_keys.is_empty() {
            root_device_keys_unrecorded = true;
            old_root_device_keys.push(ca_key_name(ctx.namespace()));
        }
        for key in old_root_keys
            .iter()
            .chain(&old_root_device_keys)
            .chain(&removed_kits)
        {
            if let Some(anchor) = next.anchors().iter().find(|a| a.key().has_prefix(key)) {
                return Err(RecoveryError::CoversAnchor {
                    name: key.to_string(),
                    anchor: anchor.key().to_string(),
                });
            }
            if !next.is_revoked(key) {
                next = next.with_revocation(key.clone());
            }
        }
    }
    let bump = finish(recovery, &ctx, next).await?;
    Ok(RecoveryVersion {
        bump,
        recovery_key,
        old_root_keys,
        old_root_device_keys,
        root_device_keys_unrecorded,
        kept_kits,
        removed_kits,
    })
}

// ── Recovering into a replacement device's PIB ─────────────────────────────

/// A namespace recovered into a replacement device's PIB by
/// [`recover_namespace_in_pib`]: this device is its root device now.
#[derive(Debug)]
pub struct RecoveredNamespace {
    pub namespace: Name,
    /// The version recovered from.
    pub previous_version: u64,
    /// Version `N+1`, signed by the recovery key — to hand to the daemon,
    /// which adopts, stores and publishes it.
    pub version: RecoveryVersion,
    /// Version `N+2`: `N+1`'s content signed by the new root
    /// ([`reissue_version`]) — handed over after `N+1`. The newest version
    /// is then signed by the root, so the root's fingerprint is the
    /// namespace's expected fingerprint again: anchor links and invites
    /// minted from now on name it, and a device holding no context adopts
    /// with them.
    pub root_version: ContextBump,
    /// Where the new root key lives.
    pub root_store: RootStore,
    /// The new root's self-signed anchor certificate.
    pub anchor: Certificate,
    pub ca_key: Name,
    /// The new CA certificate, issued by the new root.
    pub ca_cert: Certificate,
    /// This device's new admin identity `<ns>/admin/<device>`.
    pub device_identity: Name,
    pub device_key: Name,
    /// Its certificate, issued by the new CA.
    pub device_cert: Certificate,
    pub ca_cert_path: PathBuf,
    pub anchor_cert_path: PathBuf,
    pub device_cert_path: PathBuf,
}

impl RecoveredNamespace {
    /// Take everything [`recover_namespace_in_pib`] wrote out of the PIB
    /// again (the daemon refused the new version): the root store, the new
    /// keys, the PIB trust anchor and the certificate files.
    pub fn undo(&self, pib: &FilePib) {
        let ca_dir = self
            .ca_cert_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| ca_dir(pib.root(), &self.namespace));
        remove_recovered(
            pib,
            &self.namespace,
            Some(&self.root_store),
            &[
                self.anchor.key_name(),
                self.ca_key.clone(),
                self.device_key.clone(),
            ],
            &ca_dir,
        );
    }
}

/// Best effort: remove what a recovery of `namespace` wrote (its root
/// store, `keys`, the certificate files in its CA directory `ca_dir`); the
/// roots and CAs of other namespaces stay.
fn remove_recovered(
    pib: &FilePib,
    namespace: &Name,
    store: Option<&RootStore>,
    keys: &[Name],
    ca_dir: &Path,
) {
    let store = store
        .cloned()
        .or_else(|| RootStore::open_for(pib, namespace).ok().flatten());
    if let Some(store) = store
        && let Err(e) = store.destroy(pib)
    {
        tracing::warn!(target: "security", error = %e, "could not remove the new root store");
    }
    for key in keys {
        if pib.has_private_key(key) {
            let _ = pib.delete_key(key);
        }
        let _ = pib.remove_trust_anchor(key);
    }
    for file in [CA_CERT_FILE, ANCHOR_CERT_FILE, DEVICE_CERT_FILE] {
        let _ = std::fs::remove_file(ca_dir.join(file));
    }
}

/// Recover the namespace of the held context `held` (its signed Data,
/// version `N`, as this device holds it) into this device's PIB with the
/// recovery key `recovery`:
///
/// 1. the kit's key must be a recovery anchor of `N` ([`kit_anchor`]), every
///    kit in `kept_kits` too (with the old root compromised; see
///    [`RecoveryPlan::kept_kits`]), and the PIB must hold no root and no CA
///    identity of the namespace (those of other namespaces may stay) —
///    checked before anything is written or signed;
/// 2. a new root `<ns>/KEY/<id>` in the root store `root` (as `ndn-fwd
///    init` creates one), self-signed; a new CA key `<ns>/CA/KEY/<id>` with
///    a certificate by the new root; a new admin identity
///    `<ns>/admin/<device>` with a key `…/KEY/<id>` certified by the new CA
///    — fresh key ids, so nothing collides with (or is revoked with) the
///    old keys;
/// 3. version `N+1` signed by the recovery key ([`recovery_version`]), and
///    version `N+2` — the same content — signed by the new root
///    ([`reissue_version`]), so the newest version names the root as its
///    signer and the root's fingerprint is the expected fingerprint of the
///    namespace's anchor links and invites from now on;
/// 4. the root store (`<pib>/root/<hex of ns>/`), the PIB trust anchor and
///    the CA's `{ca-cert,anchor-cert,device-cert}.data` in the namespace's
///    [`ca_dir`] written (the CA endpoint stays
///    `<ns>/CA`).
///
/// `N+1` and `N+2` are returned, not stored: the caller hands them, in that
/// order, to the running daemon (`security/context-update`), which adopts
/// each by the continuity rule, stores and publishes it; if the daemon
/// answers that it did not adopt `N+1`, [`RecoveredNamespace::undo`] (not
/// when no answer came: the daemon may still adopt it). A node that held
/// `N` follows both (it keeps them and serves them by name, so the nodes
/// behind it do too). A failure here removes whatever was written.
pub async fn recover_namespace_in_pib(
    pib: &FilePib,
    held: &Data,
    recovery: &dyn Signer,
    device: &str,
    old_root: OldRoot,
    kept_kits: &[Name],
    root: &NewRootStore,
) -> Result<RecoveredNamespace, RecoveryError> {
    let (ctx, _) = SignedTrustContext::open_signed(held).await?;
    let namespace = ctx.namespace().clone();
    validate_namespace(&namespace)?;
    let recovery_key = kit_anchor(&ctx, &recovery.public_key().unwrap_or_default())?;
    split_anchors(&ctx, &recovery_key, old_root, kept_kits)?;
    if let Some(store) = RootStore::open_for(pib, &namespace)? {
        return Err(RecoveryError::AlreadyRootDevice {
            pib: pib.root().display().to_string(),
            namespace: namespace.to_string(),
            kind: store.kind().to_string(),
        });
    }
    let ca_dir = ca_dir(pib.root(), &namespace);
    for file in [CA_CERT_FILE, ANCHOR_CERT_FILE, DEVICE_CERT_FILE] {
        let path = ca_dir.join(file);
        if path.exists() {
            return Err(RecoveryError::CaPresent { path });
        }
    }
    let device_identity = device_identity(&namespace, Role::Admin, device)?;
    let root_key = new_key_name(&namespace)?;
    let ca_key = new_key_name(&namespace.clone().append("CA"))?;
    let device_key = new_key_name(&device_identity)?;

    let built: Result<_, RecoveryError> = async {
        let pending = PendingRoot::create(pib, &root_key, root).await?;
        let mgr = SecurityManager::new();
        let root_signer = pending.signer();
        let public_key = root_signer.public_key().unwrap_or_default();
        mgr.register_signer(root_key.clone(), Arc::clone(&root_signer));
        let anchor = mgr
            .issue_self_signed_async(&root_key, public_key, u64::MAX)
            .await?;
        let ca_cert = certify_new_key(
            pib,
            &mgr,
            &ca_key,
            &root_key,
            CA_CERT_VALIDITY_MS,
            DEFAULT_ISSUER,
        )
        .await?;
        mgr.register_signer(ca_key.clone(), pib.get_signer(&ca_key)?);
        let device_cert = certify_new_key(
            pib,
            &mgr,
            &device_key,
            &ca_key,
            DEVICE_CERT_VALIDITY_MS,
            NDNCERT_ISSUER,
        )
        .await?;
        let version = recovery_version(
            recovery,
            held,
            &RecoveryPlan {
                new_root: &anchor,
                new_root_device_keys: &[ca_key.clone(), device_key.clone()],
                old_root,
                kept_kits,
            },
        )
        .await?;
        let root_version = reissue_version(root_signer.as_ref(), &version.bump.data).await?;

        let root_store = pending.commit(pib, &namespace, &anchor)?;
        pib.add_trust_anchor(&root_key, &anchor)?;
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| RecoveryError::Io { path, source }
        };
        ndn_security::secure_fs::create_private_dir_all(&ca_dir).map_err(io(&ca_dir))?;
        let mut paths = Vec::new();
        for (file, cert) in [
            (CA_CERT_FILE, &ca_cert),
            (ANCHOR_CERT_FILE, &anchor),
            (DEVICE_CERT_FILE, &device_cert),
        ] {
            let path = ca_dir.join(file);
            ndn_security::secure_fs::write_private(&path, serialize_cert(cert))
                .map_err(io(&path))?;
            paths.push(path);
        }
        Ok((
            version,
            root_version,
            root_store,
            anchor,
            ca_cert,
            device_cert,
            paths,
        ))
    }
    .await;

    match built {
        Ok((version, root_version, root_store, anchor, ca_cert, device_cert, paths)) => {
            let [ca_cert_path, anchor_cert_path, device_cert_path]: [PathBuf; 3] =
                paths.try_into().expect("three certificate files");
            Ok(RecoveredNamespace {
                namespace,
                previous_version: ctx.version(),
                version,
                root_version,
                root_store,
                anchor,
                ca_key,
                ca_cert,
                device_identity,
                device_key,
                device_cert,
                ca_cert_path,
                anchor_cert_path,
                device_cert_path,
            })
        }
        Err(e) => {
            remove_recovered(
                pib,
                &namespace,
                None,
                &[root_key, ca_key, device_key],
                &ca_dir,
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_yubikey_kit_is_refused_on_firmware_before_5_3() {
        for old in [[4, 3, 7], [5, 1, 2], [5, 2, 7]] {
            let refused = check_kit_firmware(old).unwrap_err();
            let [major, minor, patch] = old;
            let text = refused.to_string();
            assert!(
                text.contains(&format!("firmware is {major}.{minor}.{patch}")),
                "{text}"
            );
            assert!(text.contains("could never be opened"), "{text}");
        }
        for new in [[5, 3, 0], [5, 4, 3], [5, 7, 1], [6, 0, 0]] {
            assert!(check_kit_firmware(new).is_ok(), "{new:?}");
        }
    }

    async fn kit_anchor_of(seed: &RecoverySeed) -> Certificate {
        recovery_anchor(Arc::new(seed.signer(&"/home/bob".parse().unwrap())))
            .await
            .unwrap()
    }

    /// Write a kit file carrying `bag` for `anchor`.
    fn write_kit(dir: &Path, file: &str, anchor: &Certificate, bag: &SafeBag) -> PathBuf {
        let uri = TrustEnvelope::Bag {
            key_name: anchor.key_name().to_string(),
            safebag: bag.encode(),
            namespace: Some("/home/bob".into()),
            fingerprint: None,
        }
        .to_uri();
        let path = dir.join(file);
        std::fs::write(&path, uri).unwrap();
        path
    }

    #[tokio::test]
    async fn a_file_kit_opens_with_its_passphrase_in_either_unicode_normalization() {
        let dir = tempfile::tempdir().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let anchor = kit_anchor_of(&seed).await;
        let nfc = RootSecret::new("caf\u{e9} cr\u{e8}me".as_bytes().to_vec());
        let nfd = RootSecret::new("cafe\u{301} cre\u{300}me".as_bytes().to_vec());
        let public_key = seed.signer(&Name::root()).public_key_bytes();

        // Sealed from NFD input: sealed in NFC, opens with either.
        let uri = seal_file_kit(&seed, &anchor, &"/home/bob".parse().unwrap(), None, &nfd).unwrap();
        let path = dir.path().join("new.kit");
        std::fs::write(&path, uri).unwrap();
        let kit = FileKit::read(&path).unwrap();
        for passphrase in [&nfc, &nfd] {
            assert_eq!(kit.open(passphrase).unwrap().public_key_bytes(), public_key);
        }
        assert!(matches!(
            kit.open(&RootSecret::new(b"cafe creme".to_vec())),
            Err(RecoveryError::WrongKitPassphrase { .. })
        ));

        // A kit sealed before with the NFD bytes as given still opens with them.
        let wire = anchor.data_wire().unwrap();
        let raw = SafeBag::encrypt(wire, &seed.pkcs8().unwrap(), nfd.expose()).unwrap();
        let kit = FileKit::read(&write_kit(dir.path(), "old.kit", &anchor, &raw)).unwrap();
        assert_eq!(kit.open(&nfd).unwrap().public_key_bytes(), public_key);
    }

    /// An EncryptedPrivateKeyInfo (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC)
    /// whose iterationCount INTEGER holds `iterations`.
    fn sealed_key_with_iterations(iterations: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() >= 0x80 {
                out.push(0x81);
            }
            out.push(content.len() as u8);
            out.extend_from_slice(content);
            out
        }
        let oid = |bytes: &[u8]| tlv(0x06, bytes);
        let prf = tlv(
            0x30,
            &[
                oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09]),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let pbkdf2 = tlv(
            0x30,
            &[
                oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c]),
                tlv(
                    0x30,
                    &[tlv(0x04, &[1; 16]), tlv(0x02, iterations), prf].concat(),
                ),
            ]
            .concat(),
        );
        let aes = tlv(
            0x30,
            &[
                oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]),
                tlv(0x04, &[2; 16]),
            ]
            .concat(),
        );
        let pbes2 = tlv(
            0x30,
            &[
                oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d]),
                tlv(0x30, &[pbkdf2, aes].concat()),
            ]
            .concat(),
        );
        tlv(0x30, &[pbes2, tlv(0x04, &[0; 16])].concat())
    }

    #[tokio::test]
    async fn a_file_kit_asking_for_too_many_iterations_is_refused_before_its_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let anchor = kit_anchor_of(&seed).await;
        let bag = |iterations: &[u8]| SafeBag {
            certificate: anchor.data_wire().unwrap(),
            encrypted_key: sealed_key_with_iterations(iterations).into(),
        };
        // 600 000, as kits are sealed: read (the key itself is junk).
        let usual = bag(&[0x09, 0x27, 0xc0]);
        assert!(FileKit::read(&write_kit(dir.path(), "usual.kit", &anchor, &usual)).is_ok());
        // 10 000 001 and u32::MAX: refused when read.
        for (file, iterations) in [
            ("over.kit", &[0x00, 0x98, 0x96, 0x81][..]),
            ("max.kit", &[0x00, 0xff, 0xff, 0xff, 0xff][..]),
        ] {
            let path = write_kit(dir.path(), file, &anchor, &bag(iterations));
            match FileKit::read(&path) {
                Err(RecoveryError::NotAKit { reason, .. }) => {
                    assert!(reason.contains("too costly"), "{reason}")
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }
}
