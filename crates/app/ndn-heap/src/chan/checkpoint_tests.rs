//! The checkpoint record: its octets (golden vectors for docs/specs/channel.md), what its signature
//! binds, and what a reader refuses.

use super::*;
use crate::chan::aead::{Aead, FrameCipher};
use crate::chan::frame::{Header, open, seal};
use crate::chan::key::ChannelKey;
use crate::chan::message::PAD;
use ndn_foundation_types::Name;
use ndn_security::Ed25519Signer;
use ndn_transport::{SideClass, SideKind};

const CHANNEL: u64 = 0x0102_0304_0506_0708;
/// The full epoch; the header carries its low octet, 0x02.
const EPOCH: u32 = 0x0102;
const SEQ0: u64 = 0x1122_3344_5566_7788;
const LO: u64 = 5;
const HI: u64 = 40;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The device key of the vectors: the seed is 32 octets of 0x42 (its public key is
/// `2152f8d1...db12`, computed with `openssl pkey`).
fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0x42; 32], "/bob/phone/KEY/1".parse::<Name>().unwrap())
}

fn public_octets() -> [u8; 32] {
    <[u8; 32]>::try_from(&signer().public_key().unwrap()[..]).unwrap()
}

fn public() -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(&public_octets()).unwrap()
}

/// Three frames: `seq0` 5, 9 and 30, whose hashes are runs of 16 octets from 0x10, 0x20, 0x30.
fn entries() -> Vec<(u64, [u8; HASH_LEN])> {
    [(5u64, 0x10u8), (9, 0x20), (30, 0x30)]
        .into_iter()
        .map(|(seq0, first)| (seq0, std::array::from_fn(|i| first + i as u8)))
        .collect()
}

fn record() -> Bytes {
    sign(&signer(), CHANNEL, EPOCH, LO, HI, &entries()).unwrap()
}

/// `K` = octets 0x00 to 0x1f (as in frame.rs's vectors).
fn cipher(aead: Aead) -> FrameCipher {
    let key = ChannelKey::from_bytes(std::array::from_fn(|i| i as u8)).frame_key(CHANNEL, EPOCH);
    FrameCipher::new(&key, aead)
}

fn frame(aead: Aead) -> Bytes {
    let header = Header::new(
        SideClass::Stream,
        SideKind::Checkpoint,
        CHANNEL,
        EPOCH as u8,
        SEQ0,
        0,
    )
    .unwrap();
    seal(&cipher(aead), &header, &record()).unwrap()
}

/// The vectors of channel.md. The record was computed with Python and `openssl pkeyutl -sign
/// -rawin` (Ed25519) from the layout in the spec, independently of this code: a wrong label, a
/// missing field, a wrong byte order or a different list digest fails here.
#[test]
fn the_golden_record_is_these_octets() {
    assert_eq!(
        hex(&public_octets()),
        "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
    );
    assert_eq!(
        hex(&record()),
        concat!(
            // lo 5, hi 40, n 3
            "052803",
            // seq0 5 (delta 0), h
            "00101112131415161718191a1b1c1d1e1f",
            // seq0 9 (delta 4), h
            "04202122232425262728292a2b2c2d2e2f",
            // seq0 30 (delta 21), h
            "15303132333435363738393a3b3c3d3e3f",
            // the signature
            "1e4039039753d79a846efebc1432d95ca2e74c5144a0cfa066f4849aef5fa2f5",
            "ff672d55a3ecd789bd39d1fbefc80b8da11741956099501db2eefcc459776506",
        )
    );
}

/// The checkpoint frame of the vectors: AES-256-GCM, stream class, `count` 0, under `K` = 0x00 to
/// 0x1f at channel `0102030405060708`, epoch 0x0102, `seq0` `1122334455667788`. It opens, in
/// RustCrypto and in `ring`, to the record above.
#[test]
fn the_golden_checkpoint_frame_is_these_octets() {
    let f = frame(Aead::Aes256Gcm);
    assert_eq!(f[..2], [0x00, 0x31]);
    assert_eq!(f[2..10], CHANNEL.to_be_bytes());
    assert_eq!(f[10], 0x02);
    assert_eq!(f[11..19], SEQ0.to_be_bytes());
    assert_eq!(f[19], 0);
    assert_eq!(hex(&f), GOLDEN_FRAME);
    let opened = open(&cipher(Aead::Aes256Gcm), f.clone(), 4_096).unwrap();
    assert_eq!(opened.plaintext(), &record());
    // RustCrypto agrees with what `ring` sealed.
    use aes_gcm::aead::{Aead as _, KeyInit, Payload};
    let key = ChannelKey::from_bytes(std::array::from_fn(|i| i as u8)).frame_key(CHANNEL, EPOCH);
    let gcm = aes_gcm::Aes256Gcm::new_from_slice(key.expose()).unwrap();
    let mut nonce = [0u8; 12];
    nonce[0] = EPOCH as u8;
    nonce[4..].copy_from_slice(&SEQ0.to_be_bytes());
    let plain = gcm
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &f[20..],
                aad: &f[..20],
            },
        )
        .unwrap();
    assert_eq!(plain, record().to_vec());
}

const GOLDEN_FRAME: &str = "00310102030405060708021122334455667788007f587c27c5dce02dcb3fd9b8344ca7fcef4f2aeec00cf775253a142c60d2f6041ecc423b0010cb806ef7bee93e3424843e6f4bdba790fd51c5e356718e6ea52a48b62e32ef535e8dca5142d0b55f30765ec9caceefe196969c401d5b9ba2d67f908216f4ba7c0147f0834f65b98700fe03b5927b24adc0d747f104795a4c82527091e4ed14e2";

#[test]
fn a_record_reads_back_and_verifies_only_for_its_channel_epoch_and_range() {
    let plain = record();
    let read = Record::decode(&plain).unwrap();
    assert_eq!((read.lo, read.hi), (LO, HI));
    assert_eq!(read.entries, entries());
    assert!(read.verify(CHANNEL, EPOCH, &public()));
    assert!(
        !read.verify(CHANNEL + 1, EPOCH, &public()),
        "another channel"
    );
    assert!(!read.verify(CHANNEL, EPOCH + 1, &public()), "another epoch");
    assert!(
        !read.verify(CHANNEL, EPOCH + 256, &public()),
        "epochs 256 apart"
    );
    let another = Ed25519Signer::from_seed(&[7; 32], "/eve/phone/KEY/1".parse::<Name>().unwrap());
    let another = Ed25519PublicKey::from_bytes(&another.public_key().unwrap()).unwrap();
    assert!(!read.verify(CHANNEL, EPOCH, &another), "another key");
    // Another range with the same list: the range is signed too.
    let mut shifted = plain.to_vec();
    shifted[1] += 1; // hi 41
    let moved = Record::decode(&shifted).unwrap();
    assert!(!moved.verify(CHANNEL, EPOCH, &public()), "another range");
    // Another hash in the list.
    let mut other = plain.to_vec();
    other[5] ^= 1;
    assert!(
        !Record::decode(&other)
            .unwrap()
            .verify(CHANNEL, EPOCH, &public())
    );
    assert_eq!(
        read.listed(9).collect::<Vec<_>>(),
        [&entries()[1].1],
        "a listed sequence yields its hash"
    );
    assert_eq!(read.listed(10).count(), 0);
}

#[test]
fn a_padded_record_reads_and_junk_after_it_does_not() {
    let mut padded = record().to_vec();
    padded.push(PAD);
    padded.extend_from_slice(&[0; 7]);
    assert!(Record::decode(&padded).is_ok());
    let mut junk = record().to_vec();
    junk.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(
        Record::decode(&junk),
        Err(CheckpointError::Padding(_))
    ));
}

#[test]
fn an_empty_checkpoint_is_a_range_and_a_signature() {
    let plain = sign(&signer(), CHANNEL, EPOCH, 10, 10, &[]).unwrap();
    assert_eq!(plain.len(), 3 + SIG_LEN);
    let read = Record::decode(&plain).unwrap();
    assert!(read.entries.is_empty());
    assert!(read.verify(CHANNEL, EPOCH, &public()));
}

#[test]
fn a_reader_refuses_what_no_sender_writes() {
    // A longer varint than the value needs: the digest of the list would not be canonical.
    let mut long = vec![0x40, 0x05];
    long.extend_from_slice(&record()[1..]);
    assert!(matches!(
        Record::decode(&long),
        Err(CheckpointError::NotMinimal { .. })
    ));
    // hi below lo.
    let mut backwards = record().to_vec();
    backwards[0] = 41;
    assert!(matches!(
        Record::decode(&backwards),
        Err(CheckpointError::Range { .. })
    ));
    // An entry outside [lo, hi): the last delta pushes it to hi.
    let mut outside = record().to_vec();
    outside[0] = 6; // lo 6: the first entry (5 + 0 from lo = 6) moves, the last stays below
    outside[1] = 31; // hi 31: the entry at 6 + 4 + 21 = 31 is outside
    assert!(matches!(
        Record::decode(&outside),
        Err(CheckpointError::Outside { .. })
    ));
    // More frames than a ring holds.
    let mut many = vec![0x00, 0x3f];
    many.extend_from_slice(&varint_bytes(4_097));
    assert!(matches!(
        Record::decode(&many),
        Err(CheckpointError::TooMany { n: 4_097 })
    ));
    // Cut short.
    for cut in [0, 1, 2, 3, 10, record().len() - 1] {
        assert!(Record::decode(&record()[..cut]).is_err(), "{cut}");
    }
    // The writer refuses a list that does not rise and a signer that does not sign.
    let mut down = entries();
    down.swap(0, 1);
    assert!(sign(&signer(), CHANNEL, EPOCH, LO, HI, &down).is_err());
    assert!(matches!(
        sign_with(|_| None, CHANNEL, EPOCH, LO, HI, &entries()),
        Err(CheckpointError::Unwritable { .. })
    ));
    assert!(matches!(
        sign(&signer(), CHANNEL, EPOCH, HI, LO, &[]),
        Err(CheckpointError::Range { .. })
    ));
    assert!(matches!(
        sign(&signer(), CHANNEL, EPOCH, LO, 8, &entries()),
        Err(CheckpointError::Outside { .. })
    ));
}

fn varint_bytes(v: u64) -> Vec<u8> {
    let mut out = BytesMut::new();
    varint::write(&mut out, v).unwrap();
    out.to_vec()
}
