//! An ask sealed to the offering device's seal key (spec §19.4), and the notes the
//! inviter keeps wrapped to its own recipient key: a fresh content key wrapped to
//! the key with a fresh ephemeral X25519 key, and the plaintext sealed under it, both
//! bound to associated data.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::{
    ConfidentialityError, ContentKey, RecipientKey, Sealed, wrap_ck_to,
};

/// An ask sealed to a device's seal key: a fresh content key wrapped to that key with a
/// fresh ephemeral X25519 key, and the ask's plaintext sealed under the content key,
/// both bound to `aad`, the Interest's name without its parameters digest.
pub(crate) struct SealedAsk {
    /// The asker's ephemeral X25519 public key.
    pub(crate) ephemeral: [u8; 32],
    /// The content key, wrapped to the seal key.
    pub(crate) key: Bytes,
    /// The plaintext, sealed under the content key.
    pub(crate) sealed: Bytes,
}

/// A content key wrapped to a seal key, before the plaintext is sealed under it: an ask
/// whose proof binds the ephemeral key needs the key to make its plaintext.
pub(crate) struct AskKey {
    ck: ContentKey,
    /// The asker's ephemeral X25519 public key.
    pub(crate) ephemeral: [u8; 32],
    key: Bytes,
}

impl AskKey {
    /// Make a content key and wrap it to `seal_key`, bound to `aad`.
    pub(crate) fn to(seal_key: &[u8; 32], aad: &[u8]) -> Result<Self, ConfidentialityError> {
        let ck = ContentKey::generate();
        let (ephemeral, wrapped) = wrap_ck_to(seal_key, &ck, aad)?;
        Ok(AskKey {
            ck,
            ephemeral,
            key: wrapped.to_bytes(),
        })
    }

    /// Seal `plain` under the content key, bound to `aad`.
    pub(crate) fn seal(self, plain: &[u8], aad: &[u8]) -> SealedAsk {
        SealedAsk {
            ephemeral: self.ephemeral,
            key: self.key,
            sealed: self.ck.seal(plain, aad).to_bytes(),
        }
    }
}

/// Seal an ask's `plain` to the seal key `to`, bound to `aad`.
pub(crate) fn seal_ask(
    to: &[u8; 32],
    aad: &[u8],
    plain: &[u8],
) -> Result<SealedAsk, ConfidentialityError> {
    Ok(AskKey::to(to, aad)?.seal(plain, aad))
}

/// Open an ask sealed to `recipient`: the plaintext, or `None` if the key does not
/// unwrap, the ciphertext does not open, or either is not bound to `aad`.
pub(crate) fn open_ask(
    recipient: &RecipientKey,
    aad: &[u8],
    ephemeral: &[u8; 32],
    key: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    let ck = recipient
        .unwrap_ck(ephemeral, &Sealed::from_bytes(key).ok()?, aad)
        .ok()?;
    ck.open(&Sealed::from_bytes(sealed).ok()?, aad).ok()
}

/// `secret` (32 octets) wrapped to the device's own recipient key under the note's
/// key `name`, so a writer of the store cannot read it: the ephemeral public key,
/// then the wrapped content key.
pub(crate) fn wrap_note(
    recipient: &RecipientKey,
    name: &Name,
    secret: [u8; 32],
) -> Result<Bytes, ConfidentialityError> {
    let (ephemeral, wrapped) = wrap_ck_to(
        &recipient.public(),
        &ContentKey::from_bytes(secret),
        &name.encode_to_tlv(),
    )?;
    let mut out = ephemeral.to_vec();
    out.extend_from_slice(&wrapped.to_bytes());
    Ok(Bytes::from(out))
}

/// The 32 octets [`wrap_note`] wrapped under `name`; `None` for a note that is not
/// wrapped to this device's key under that name.
pub(crate) fn open_note(recipient: &RecipientKey, name: &Name, note: &[u8]) -> Option<[u8; 32]> {
    let (ephemeral, wrapped) = note.split_first_chunk::<32>()?;
    let key = recipient
        .unwrap_ck(
            ephemeral,
            &Sealed::from_bytes(wrapped).ok()?,
            &name.encode_to_tlv(),
        )
        .ok()?;
    Some(*key.expose())
}
