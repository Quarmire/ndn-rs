//! The receiver's compact [`Message`] reads exactly what the message reader read before it was
//! made small (REPLY-26 §3.2): the same messages, the same refusals, in the same places. `Old` is
//! that reader as it was (the owned 120-octet message, each field a `Name`-like value of its own),
//! kept here as the reference; the cases run it and the production reader over the golden frame
//! vectors, the malformed-plaintext table of `message::tests`, and a fixed-seed fuzz corpus of
//! valid frames mutated and random octets.

use std::collections::BTreeSet;

use bytes::Bytes;

use super::tests::malformed_vectors;
use super::*;
use crate::chan::limits::{MESSAGE_DEFAULT, SEQUENCE_LIMIT};

/// The message reader before the change, verbatim but for the type it yields.
struct Old {
    data: Bytes,
    pos: usize,
    seq: u64,
    count: usize,
    seen: usize,
    max_message: usize,
    done: bool,
}

impl Old {
    fn new(plaintext: Bytes, seq0: u64, count: usize, max_message: usize) -> Self {
        Self {
            data: plaintext,
            pos: 0,
            seq: seq0,
            count,
            seen: 0,
            max_message: max_message.min(MESSAGE_MAX),
            done: false,
        }
    }

    fn varint(&mut self, what: &'static str) -> Result<u64, MessageError> {
        let (value, n) =
            varint::read(&self.data[self.pos..]).ok_or(MessageError::Truncated { what })?;
        self.pos += n;
        Ok(value)
    }

    fn take(&mut self, len: usize, what: &'static str) -> Result<Bytes, MessageError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or(MessageError::Truncated { what })?;
        let out = self.data.slice(self.pos..end);
        self.pos = end;
        Ok(out)
    }

    fn take_payload(&mut self, len: usize) -> Result<(Bytes, usize), MessageError> {
        let whole = self.data.len();
        let shared = whole <= SHARE_FRAME_MAX || len.saturating_mul(2) >= whole;
        let slice = self.take(len, "payload")?;
        if shared {
            let share = whole.div_ceil(self.count.max(1));
            Ok((slice, len.max(share)))
        } else {
            Ok((Bytes::copy_from_slice(&slice), len))
        }
    }

    fn message(&mut self) -> Result<ReadMessage, MessageError> {
        let flags = *self
            .data
            .get(self.pos)
            .ok_or(MessageError::Truncated { what: "flags" })?;
        if flags & PAD != 0 {
            if flags != PAD {
                return Err(MessageError::Flags { flags });
            }
            return Err(MessageError::Count {
                expected: self.count,
                found: self.seen,
            });
        }
        if flags & RESERVED != 0 || flags & (STANDING | REPLAYED) == (STANDING | REPLAYED) {
            return Err(MessageError::Flags { flags });
        }
        self.pos += 1;
        let origin = if flags & STANDING != 0 {
            Some(Origin::Standing(self.varint("original sequence")?))
        } else if flags & REPLAYED != 0 {
            Some(Origin::Replayed(self.varint("original sequence")?))
        } else {
            None
        };
        if let Some(origin) = origin
            && origin.sequence() >= self.seq
        {
            return Err(MessageError::OriginalSequence {
                original: origin.sequence(),
                seq: self.seq,
            });
        }
        let name_id = self.varint("name id")?;
        if !(1..=NAMES_PER_CHANNEL).contains(&name_id) {
            return Err(MessageError::NameId { id: name_id });
        }
        let name = if flags & NAMED != 0 {
            let len = self.varint("name length")?;
            if len > NAME_MAX as u64 {
                return Err(MessageError::NameTooLong { len: len as usize });
            }
            Some(self.take(len as usize, "name")?)
        } else {
            None
        };
        let stand_secs = if flags & STAND != 0 {
            let secs = self.varint("stand seconds")?;
            if secs > STAND_SECS_MAX {
                return Err(MessageError::StandSeconds {
                    secs,
                    max: STAND_SECS_MAX,
                });
            }
            Some(secs)
        } else {
            None
        };
        let len = self.varint("payload length")?;
        if len > self.max_message as u64 {
            return Err(MessageError::TooLarge {
                len: usize::try_from(len).unwrap_or(usize::MAX),
                max: self.max_message,
            });
        }
        let (payload, pinned) = self.take_payload(len as usize)?;
        Ok(ReadMessage {
            seq: self.seq,
            name_id,
            name,
            stand_secs,
            origin,
            payload,
            pinned,
        })
    }

    /// The messages the iterator gave, and the error it ended with, if any.
    fn run(mut self) -> (Vec<ReadMessage>, Option<MessageError>) {
        let mut got = Vec::new();
        loop {
            if self.done {
                return (got, None);
            }
            if self.seen == self.count {
                self.done = true;
                return (got, check_padding(&self.data[self.pos..]).err());
            }
            match self.message() {
                Ok(m) => {
                    self.seen += 1;
                    self.seq += 1;
                    got.push(m);
                }
                Err(e) => return (got, Some(e)),
            }
        }
    }
}

/// What a frame is given to the readers as: its plaintext, the sequence of its first message, the
/// count its header says and the limit of a payload.
#[derive(Clone, Debug)]
struct Input {
    plain: Vec<u8>,
    seq0: u64,
    count: usize,
    max_message: usize,
}

/// The production reader through the iterator: the messages and the error it ended with.
fn by_iterator(input: &Input) -> (Vec<ReadMessage>, Option<MessageError>) {
    let mut got = Vec::new();
    for next in Messages::new(
        Bytes::from(input.plain.clone()),
        input.seq0,
        input.count,
        input.max_message,
    ) {
        match next {
            Ok(m) => got.push(m),
            Err(e) => return (got, Some(e)),
        }
    }
    (got, None)
}

/// The production reader as the receiver uses it: `parse_into`, then each message with its name.
fn by_parse_into(input: &Input) -> (Vec<ReadMessage>, Option<MessageError>) {
    let (mut messages, mut names) = (Vec::new(), Vec::new());
    let result = Messages::new(
        Bytes::from(input.plain.clone()),
        input.seq0,
        input.count,
        input.max_message,
    )
    .parse_into(&mut messages, &mut names);
    let got = messages
        .iter()
        .map(|m| ReadMessage::of(m, &names))
        .collect();
    (got, result.err())
}

/// Whether a payload is a slice of the frame (a copy is not): what the sharing rule decides.
fn sharing(plain: &[u8], payload: &Bytes) -> bool {
    !payload.is_empty() && plain.as_ptr_range().contains(&payload.as_ptr())
}

fn variant(e: &MessageError) -> &'static str {
    match e {
        MessageError::Truncated { .. } => "Truncated",
        MessageError::Flags { .. } => "Flags",
        MessageError::NameId { .. } => "NameId",
        MessageError::NameTooLong { .. } => "NameTooLong",
        MessageError::TooLarge { .. } => "TooLarge",
        MessageError::Overflow { .. } => "Overflow",
        MessageError::Count { .. } => "Count",
        MessageError::Trailing { .. } => "Trailing",
        MessageError::Padding { .. } => "Padding",
        MessageError::OriginalSequence { .. } => "OriginalSequence",
        MessageError::StandSeconds { .. } => "StandSeconds",
    }
}

/// Runs the reference and both production entries on `input` and requires them to agree on the
/// messages, their charges, whether each payload shares the frame, and the refusal.
fn agree(input: &Input, seen: &mut BTreeSet<&'static str>) {
    let (old, old_err) = Old::new(
        Bytes::from(input.plain.clone()),
        input.seq0,
        input.count,
        input.max_message,
    )
    .run();
    for (what, (got, err)) in [
        ("iterator", by_iterator(input)),
        ("parse_into", by_parse_into(input)),
    ] {
        assert_eq!(err, old_err, "{what}: the refusal of {input:02x?}");
        assert_eq!(got, old, "{what}: the messages of {input:02x?}");
        for (a, b) in got.iter().zip(&old) {
            assert_eq!(
                sharing(&input.plain, &a.payload),
                sharing(&input.plain, &b.payload),
                "{what}: a payload is shared or copied as it was: {input:02x?}"
            );
        }
    }
    seen.insert(old_err.as_ref().map_or("Ok", variant));
}

/// A fixed-seed generator (xorshift64*): the corpus is the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, of: &[T]) -> T {
        of[self.below(of.len() as u64) as usize]
    }
}

/// A valid message of random fields, written by the writer.
fn random_message(rng: &mut Rng, seq: u64, buf: &mut Vec<u8>) {
    let payload: Vec<u8> = (0..rng.pick(&[0u64, 1, 5, 64, 300, 2_000, 5_000]))
        .map(|_| rng.next() as u8)
        .collect();
    let name: Vec<u8> = (0..rng.pick(&[0u64, 3, 40, 255]))
        .map(|_| rng.next() as u8)
        .collect();
    let mut m = OutMessage::new(1 + rng.below(NAMES_PER_CHANNEL), &payload);
    if rng.below(3) == 0 {
        m.name = Some(&name);
    }
    if rng.below(4) == 0 {
        m.stand_secs = Some(rng.below(STAND_SECS_MAX + 1));
    }
    if seq > 0 {
        // An original sequence is below the message's own and a varint holds at most 2^62 - 1.
        let below = seq.min(varint::MAX);
        match rng.below(6) {
            0 => m.origin = Some(Origin::Standing(rng.below(below))),
            1 => m.origin = Some(Origin::Replayed(rng.below(below))),
            _ => {}
        }
    }
    m.write(buf).expect("a valid message writes");
}

/// A frame of valid messages, then mutated by what a key holder, a bug or a bit error could do.
fn mutated(rng: &mut Rng) -> Input {
    let seq0 = rng.pick(&[0u64, 1, 5, 40, 1 << 41, SEQUENCE_LIMIT - 300]);
    let n = 1 + rng.below(12) as usize;
    let mut plain = Vec::new();
    for i in 0..n {
        random_message(rng, seq0 + i as u64, &mut plain);
    }
    let mut count = n;
    for _ in 0..rng.below(4) {
        match rng.below(9) {
            0 if !plain.is_empty() => {
                let at = rng.below(plain.len() as u64) as usize;
                plain[at] ^= 1 << rng.below(8);
            }
            1 if !plain.is_empty() => {
                let at = rng.below(plain.len() as u64) as usize;
                plain[at] = rng.next() as u8;
            }
            2 => {
                let to = rng.below(plain.len() as u64 + 1) as usize;
                plain.truncate(to);
            }
            3 => plain.extend((0..rng.below(8)).map(|_| rng.next() as u8)),
            4 => {
                plain.push(PAD);
                plain.extend(std::iter::repeat_n(0u8, rng.below(40) as usize));
            }
            5 => {
                plain.push(PAD);
                plain.extend((0..rng.below(8)).map(|_| rng.next() as u8));
            }
            6 => count = count.saturating_sub(1),
            7 => count += 1,
            _ => {
                let at = rng.below(plain.len() as u64 + 1) as usize;
                plain.insert(at, rng.next() as u8);
            }
        }
    }
    Input {
        plain,
        seq0,
        count,
        max_message: rng.pick(&[64, 300, 3_000, MESSAGE_DEFAULT]),
    }
}

/// Random octets, weighted towards the flag octets and small varints a parser meets.
fn random_octets(rng: &mut Rng) -> Input {
    let len = rng.below(48) as usize;
    let plain = (0..len)
        .map(|_| match rng.below(4) {
            0 => rng.pick(&[0x00u8, 0x01, 0x02, 0x04, 0x08, 0x03, 0x05, 0x0a, 0x0f, 0x80]),
            1 => rng.below(8) as u8,
            _ => rng.next() as u8,
        })
        .collect();
    Input {
        plain,
        seq0: rng.pick(&[0u64, 1, 9, 1 << 41]),
        count: rng.below(4) as usize,
        max_message: rng.pick(&[8, 64, MESSAGE_DEFAULT]),
    }
}

/// The frame vectors the wire format is pinned by (`frame::tests`) and the table of refusals of
/// `message::tests`.
#[test]
fn the_compact_reader_reads_the_golden_vectors_and_the_malformed_table_as_the_old_one_did() {
    let mut seen = BTreeSet::new();
    // The golden DATA frame's plaintext (a bare message and a NAMED one), and the padded one.
    let golden = [
        (
            hex_octets("00010568656c6c6f01020308016106776f726c6421"),
            0x1122_3344_5566_7788u64,
            2usize,
        ),
        (vec![0, 1, 0, PAD, 0, 0, 0, 0, 0, 0], 7, 1),
    ];
    for (plain, seq0, count) in golden {
        for max_message in [MESSAGE_DEFAULT, 64, 3] {
            agree(
                &Input {
                    plain: plain.clone(),
                    seq0,
                    count,
                    max_message,
                },
                &mut seen,
            );
        }
    }
    for (plain, count, _) in malformed_vectors() {
        for seq0 in [0, 1, 40] {
            agree(
                &Input {
                    plain: plain.to_vec(),
                    seq0,
                    count: *count,
                    max_message: 64,
                },
                &mut seen,
            );
        }
    }
    assert!(seen.contains("Ok"), "{seen:?}");
}

fn hex_octets(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// A corpus of 60,000 frames: valid ones the writer made (every flag, name, stand time and origin),
/// each mutated by bit flips, truncation, insertion, padding that is and is not zeros, a count one
/// off and a payload limit below the payload; and 20,000 strings of random octets. The reader
/// must agree with the old one on every message and every refusal, and the corpus must have
/// reached each refusal the reader has.
#[test]
fn the_compact_reader_refuses_and_reads_a_fuzz_corpus_as_the_old_one_did() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut seen = BTreeSet::new();
    for _ in 0..40_000 {
        agree(&mutated(&mut rng), &mut seen);
    }
    for _ in 0..20_000 {
        agree(&random_octets(&mut rng), &mut seen);
    }
    for want in [
        "Ok",
        "Truncated",
        "Flags",
        "NameId",
        "NameTooLong",
        "TooLarge",
        "Count",
        "Trailing",
        "Padding",
        "OriginalSequence",
        "StandSeconds",
    ] {
        assert!(
            seen.contains(want),
            "the corpus never reached {want}: {seen:?}"
        );
    }
}

/// A frame over [`SHARE_FRAME_MAX`] copies the payload that is less than half of it: the copy
/// and the charge are the old reader's, and a NAMED message of such a frame is read the same.
#[test]
fn a_large_frame_copies_what_it_copied_and_charges_what_it_charged() {
    let mut seen = BTreeSet::new();
    let mut plain = Vec::new();
    let mut named = OutMessage::new(7, &[0x11; 200]);
    named.name = Some(b"\x08\x01a\x08\x01b");
    named.write(&mut plain).unwrap();
    for i in 0..60u8 {
        OutMessage::new(1 + u64::from(i), &[i; 200])
            .write(&mut plain)
            .unwrap();
    }
    OutMessage::new(2, &vec![0x22; 12_000])
        .write(&mut plain)
        .unwrap();
    assert!(plain.len() > SHARE_FRAME_MAX);
    for count in [62usize, 61, 63] {
        agree(
            &Input {
                plain: plain.clone(),
                seq0: 5,
                count,
                max_message: MESSAGE_DEFAULT,
            },
            &mut seen,
        );
    }
}
