//! A sealed answer's packet is padded to a size bucket (answers.md §13.3): two answers whose read
//! sets differ in size, inside one bucket, are packets of one size, so a relay does not learn the
//! number of reads, only the bucket. A body that is not padded exactly as the spec says is refused.

use ndn_packet::encode::DataBuilder;
use ndn_tlv::{TlvReader, TlvWriter};

use super::*;
use crate::answer::{Body, tlv as answer_tlv};

/// The folder of `plan()` and `budget()`.
fn trip() -> Name {
    n("/alice/32=data/trip")
}

/// A collection of the folder, for `i`.
fn input(i: usize) -> Name {
    n(&format!("/alice/32=data/trip/in{i}"))
}

/// Alice's laptop, the folder `trip` sealed to Alice alone (so every collection under it is in
/// the folder's one epoch, and every answer over them lists the same epochs), holding `inputs`
/// collections of one number each.
async fn folder_alice(w: &mut World, inputs: usize) -> Device {
    let laptop = w.start("/alice/laptop", knowing(vec![sum(1)])).await;
    laptop
        .share_folder(&trip(), sealed_share(&["/alice"]).into())
        .await
        .unwrap();
    for i in 0..inputs {
        put_n(&laptop, &input(i), i as i64).await;
    }
    laptop
}

/// A sealed answer over the first `k` inputs: its name, its packet and the plaintext's size (the
/// ciphertext without its nonce and tag).
async fn answer_over(laptop: &Device, k: usize) -> (Name, Bytes, usize, usize) {
    let inputs: Vec<Name> = (0..k).map(input).collect();
    put_def(laptop, &plan(), &inputs.iter().collect::<Vec<_>>()).await;
    let q = pure_question(newest(laptop, &plan()).await, &sum_v(1));
    let name = laptop.publish_answer(&q).await.unwrap();
    let wire = laptop.inner.stored_answer(&name).unwrap();
    let rec = AnswerRecord::decode(
        Data::decode(wire.clone())
            .unwrap()
            .content()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let RecordContent::Sealed { ciphertext, .. } = rec.content else {
        panic!("a sealed answer")
    };
    let reads = ask(laptop, &q).await.unwrap().reads.reads().len();
    (name, wire, ciphertext.len() - 28, reads)
}

#[tokio::test]
async fn sealed_answers_of_one_size_bucket_are_packets_of_one_size() {
    let mut w = World::new();
    let laptop = folder_alice(&mut w, 8).await;
    let mut all = Vec::new();
    for k in 1..=8 {
        all.push(answer_over(&laptop, k).await);
    }
    let mut same_bucket_different_reads = 0;
    for (a, x) in all.iter().enumerate() {
        for y in &all[a + 1..] {
            let (reads_x, reads_y) = (x.3, y.3);
            assert_ne!(reads_x, reads_y);
            // Whatever the bucket, the packet's size is a function of it and of the epochs (the
            // same here) and nothing else: equal buckets, equal packets; unequal, unequal.
            assert_eq!(
                x.2 == y.2,
                x.1.len() == y.1.len(),
                "answers over {reads_x} and {reads_y} reads: plaintexts of {} and {} octets, \
                 packets of {} and {} octets",
                x.2,
                y.2,
                x.1.len(),
                y.1.len()
            );
            if x.2 == y.2 {
                same_bucket_different_reads += 1;
            }
        }
    }
    assert!(
        same_bucket_different_reads > 0,
        "no two sealed answers with different numbers of reads have packets of one size: {:?}",
        all.iter()
            .map(|(_, wire, plain, reads)| (*reads, *plain, wire.len()))
            .collect::<Vec<_>>()
    );
    // A different bucket is a different size, and every plaintext is padded to its bucket.
    let sizes: std::collections::BTreeSet<usize> = all.iter().map(|x| x.2).collect();
    assert!(sizes.len() > 1, "the reads span more than one bucket");
    for plain in &sizes {
        assert_eq!(
            *plain,
            crate::answer::padded_len(*plain),
            "{plain} octets are a bucket"
        );
    }
    // The answers still open and read back whole.
    for (name, ..) in &all {
        let got = ask(&laptop, name).await.unwrap();
        assert_eq!(got.binding.kind, AnswerKind::Pure);
    }
}

#[tokio::test]
async fn an_unsealed_answer_is_not_padded() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let name = laptop.publish_answer(&q).await.unwrap();
    let wire = laptop.inner.stored_answer(&name).unwrap();
    let rec = AnswerRecord::decode(Data::decode(wire).unwrap().content().unwrap().clone()).unwrap();
    let RecordContent::Plain(body) = rec.content else {
        panic!("an unsealed answer is its body in the clear")
    };
    let mut r = TlvReader::new(body.clone());
    let (typ, _) = r.read_tlv().unwrap();
    assert_eq!(typ, answer_tlv::ANSWER_BODY);
    assert!(r.is_empty(), "nothing follows the AnswerBody");
    assert_eq!(Body::decode(body.clone()).unwrap().encode(), body);
}

/// The plaintext `name`'s sealed answer opens to, the keys and epochs it is sealed under.
fn plaintext_of(
    laptop: &Device,
    name: &Name,
    wire: &Bytes,
) -> (Bytes, crate::seal::AudienceKeys, Vec<Epoch>, AnswerKind) {
    let rec = AnswerRecord::decode(
        Data::decode(wire.clone())
            .unwrap()
            .content()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let RecordContent::Sealed { epochs, ciphertext } = rec.content else {
        panic!("a sealed answer")
    };
    let keys = laptop.inner.audience(&epochs, name).unwrap().unwrap();
    let plain = seal::open_answer(&keys, name, rec.kind, &epochs, &ciphertext).unwrap();
    (plain, keys, epochs, rec.kind)
}

/// `plain` sealed, with the same key schedule the code uses, as the answer at `name`, signed by
/// the laptop, and what any reader says of the packet.
async fn open_forged(
    laptop: &Device,
    name: &Name,
    wire: &Bytes,
    plain: &[u8],
) -> Result<(), DataError> {
    let (_, keys, epochs, kind) = plaintext_of(laptop, name, wire);
    let record = AnswerRecord {
        kind,
        content: RecordContent::Sealed {
            ciphertext: seal::seal_answer(&keys, name, kind, &epochs, plain),
            epochs,
        },
    };
    let forged = laptop
        .inner
        .sign(DataBuilder::new(name.clone(), &record.encode()))
        .unwrap();
    laptop
        .inner
        .open_packet(Data::decode(forged).unwrap(), None, &[])
        .await
        .map(|_| ())
}

fn padding_of(zeros: usize) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_tlv(answer_tlv::ANSWER_PADDING, &vec![0u8; zeros]);
    w.finish().to_vec()
}

#[tokio::test]
async fn padding_that_is_not_zero_or_not_canonical_is_refused_and_says_why() {
    let mut w = World::new();
    let laptop = folder_alice(&mut w, 3).await;
    let (name, wire, _, _) = answer_over(&laptop, 3).await;
    let (padded, ..) = plaintext_of(&laptop, &name, &wire);
    // The body and the padding the code made.
    let mut r = TlvReader::new(padded.clone());
    r.read_tlv().unwrap();
    let body = padded.slice(..r.position());
    let padding = padded.slice(r.position()..);
    assert!(!padding.is_empty(), "this body is not a whole bucket");

    // The packet the code made opens.
    open_forged(&laptop, &name, &wire, &padded).await.unwrap();

    let refused = |why: &str, got: Result<(), DataError>| {
        let err = got.expect_err(why);
        let DataError::Answer {
            why: AnswerRefusal::Malformed(said),
            ..
        } = &err
        else {
            panic!("{why}: not a malformed answer: {err:?}")
        };
        assert!(said.to_lowercase().contains("padding"), "{why}: {said}");
        said.clone()
    };

    // A non-zero octet in the padding.
    let mut dirty = padded.to_vec();
    let last = dirty.len() - 1;
    dirty[last] = 1;
    refused(
        "non-zero padding",
        open_forged(&laptop, &name, &wire, &dirty).await,
    );
    // No padding at all, the body not being a whole bucket.
    refused(
        "padding missing",
        open_forged(&laptop, &name, &wire, &body).await,
    );
    // Padding of another length: one octet shorter, one octet longer, a whole bucket longer.
    let z = padding.len() - 4;
    assert!(
        (2..253).contains(&z),
        "a padding with a one-octet length: {z}"
    );
    for other in [z - 1, z + 1, z + 128] {
        let mut plain = body.to_vec();
        plain.extend_from_slice(&padding_of(other));
        refused(
            "padding of the wrong length",
            open_forged(&laptop, &name, &wire, &plain).await,
        );
    }
    // The padding twice.
    let mut twice = padded.to_vec();
    twice.extend_from_slice(&padding_of(0));
    refused(
        "duplicated padding",
        open_forged(&laptop, &name, &wire, &twice).await,
    );
    // The padding before the body.
    let mut first = padding.to_vec();
    first.extend_from_slice(&body);
    refused(
        "padding first",
        open_forged(&laptop, &name, &wire, &first).await,
    );
    // The right padding with its length in the three-octet form.
    let mut long = body.to_vec();
    let mut w = TlvWriter::new();
    w.write_varu64(answer_tlv::ANSWER_PADDING);
    long.extend_from_slice(&w.finish());
    long.extend_from_slice(&[0xFD, 0x00, (z - 2) as u8]);
    long.extend_from_slice(&vec![0u8; z - 2]);
    refused(
        "a non-minimal length",
        open_forged(&laptop, &name, &wire, &long).await,
    );
}
