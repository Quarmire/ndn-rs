//! The receiver's compact [`Message`] reads exactly what the message reader read before it was
//! made small (REPLY-26 §3.2): the same messages, the same refusals, in the same places. `Old` is
//! that reader as it was (the owned 120-octet message, each field a `Name`-like value of its own),
//! kept here as the reference; the cases run it and the production reader over the golden frame
//! vectors, the malformed-plaintext table of `message::tests`, a fixed-seed fuzz corpus of valid
//! frames mutated and random octets, and a deterministic table of every boundary of the format
//! (`every_boundary_of_the_format_reads_and_refuses_as_the_old_reader_did`).
//!
//! One difference from the reference is by design and is not hidden: production copies a **name**
//! out of a frame over [`SHARE_FRAME_MAX`] where the reference shares it. Names are compared by
//! value; the share-or-copy rule is compared with the reference for payloads and checked against
//! its own rule for names (see `agree`, and
//! `a_name_shares_a_small_frame_and_is_copied_out_of_a_large_one`).

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

    /// Takes `len` octets as a slice of the frame, whatever the frame's size. The reader read names
    /// so (and payloads through `take_payload`); production copies a name out of a frame over
    /// [`SHARE_FRAME_MAX`], the one place it differs from this reference by design (`agree`).
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

/// The production reader through the iterator: the messages and the error it ended with. The
/// frame is the `Bytes` the payloads and names are slices of, or copies out of.
fn by_iterator(input: &Input, frame: &Bytes) -> (Vec<ReadMessage>, Option<MessageError>) {
    let mut got = Vec::new();
    for next in Messages::new(frame.clone(), input.seq0, input.count, input.max_message) {
        match next {
            Ok(m) => got.push(m),
            Err(e) => return (got, Some(e)),
        }
    }
    (got, None)
}

/// The production reader as the receiver uses it: `parse_into`, then each message with its name.
fn by_parse_into(input: &Input, frame: &Bytes) -> (Vec<ReadMessage>, Option<MessageError>) {
    let (mut messages, mut names) = (Vec::new(), Vec::new());
    let result = Messages::new(frame.clone(), input.seq0, input.count, input.max_message)
        .parse_into(&mut messages, &mut names);
    let got = messages
        .iter()
        .map(|m| ReadMessage::of(m, &names))
        .collect();
    (got, result.err())
}

/// Whether `part` is a slice of `frame` (a copy is not): what a sharing rule decides. An empty
/// part has no octets to point at and is neither.
fn sharing(frame: &Bytes, part: &Bytes) -> bool {
    !part.is_empty() && frame.as_ptr_range().contains(&part.as_ptr())
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
        MessageError::NamesNotEmpty { .. } => "NamesNotEmpty",
    }
}

/// The outcome of a frame as a label: `Ok`, the refusal's variant, and for a truncation the
/// field the frame ended in (`Truncated:payload length`).
fn label(error: Option<&MessageError>) -> String {
    match error {
        None => "Ok".to_owned(),
        Some(MessageError::Truncated { what }) => format!("Truncated:{what}"),
        Some(e) => variant(e).to_owned(),
    }
}

/// What the cases reached: the refusals (`variants`, and `labels` which tell the truncations
/// apart), and the payloads and names compared as shared and as copied.
#[derive(Debug, Default)]
struct Seen {
    variants: BTreeSet<&'static str>,
    labels: BTreeSet<String>,
    shared: usize,
    copied: usize,
    names_shared: usize,
    names_copied: usize,
}

/// Runs the reference and both production entries on `input` and requires them to agree on the
/// messages, their charges, whether each payload shares the frame, and the refusal.
///
/// What is compared, exactly: messages (sequence, name id, **name by value**, stand seconds,
/// origin, **payload by value**, charge) and the refusal, between the reference and each
/// production entry; whether a payload is a slice of the frame, against the reference. What is
/// **not** compared with the reference: whether a *name* is a slice of the frame. The reference
/// reads names with `take`, which always shares, as the reader did before; production copies a
/// name out of a frame over [`SHARE_FRAME_MAX`] (a name is held by the receiver's name table
/// for as long as it is bound, and must not keep a large frame alive). A name's sharing is
/// instead checked against that rule here (shared when the frame is at most `SHARE_FRAME_MAX`,
/// copied otherwise) and pinned in `a_name_shares_a_small_frame_and_is_copied_out_of_a_large_one`.
fn agree(input: &Input, seen: &mut Seen) {
    let frame = Bytes::from(input.plain.clone());
    let (old, old_err) = Old::new(frame.clone(), input.seq0, input.count, input.max_message).run();
    for (what, (got, err)) in [
        ("iterator", by_iterator(input, &frame)),
        ("parse_into", by_parse_into(input, &frame)),
    ] {
        assert_eq!(err, old_err, "{what}: the refusal of {input:02x?}");
        assert_eq!(got, old, "{what}: the messages of {input:02x?}");
        for (a, b) in got.iter().zip(&old) {
            let shared = sharing(&frame, &a.payload);
            assert_eq!(
                shared,
                sharing(&frame, &b.payload),
                "{what}: a payload is shared or copied as it was: {input:02x?}"
            );
            if shared {
                seen.shared += 1;
            } else if !a.payload.is_empty() {
                seen.copied += 1;
            }
            if let Some(name) = a.name.as_ref().filter(|n| !n.is_empty()) {
                let shared = sharing(&frame, name);
                assert_eq!(
                    shared,
                    frame.len() <= SHARE_FRAME_MAX,
                    "{what}: a name is shared by a frame of at most {SHARE_FRAME_MAX} octets and \
                     copied out of a larger one: {input:02x?}"
                );
                if shared {
                    seen.names_shared += 1;
                } else {
                    seen.names_copied += 1;
                }
            }
        }
    }
    seen.variants.insert(old_err.as_ref().map_or("Ok", variant));
    seen.labels.insert(label(old_err.as_ref()));
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
    let mut seen = Seen::default();
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
    assert!(seen.variants.contains("Ok"), "{seen:?}");
    assert!(
        seen.shared > 0,
        "no payload was compared as shared: {seen:?}"
    );
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
    let mut seen = Seen::default();
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
            seen.variants.contains(want),
            "the corpus never reached {want}: {seen:?}"
        );
    }
}

/// A frame over [`SHARE_FRAME_MAX`] copies the payload that is less than half of it: the copy
/// and the charge are the old reader's, and a NAMED message of such a frame is read the same.
#[test]
fn a_large_frame_copies_what_it_copied_and_charges_what_it_charged() {
    let mut seen = Seen::default();
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
    assert!(seen.copied > 0, "no payload was copied out: {seen:?}");
    assert!(seen.names_copied > 0, "no name was copied out: {seen:?}");
}

// -- The boundaries, one by one ------------------------------------------------------------------

/// A varint's value and the octets it is written in (1, 2, 4 or 8). The writer writes the
/// shortest; the reader accepts any (RFC 9000 §16).
#[derive(Clone, Copy)]
struct V(u64, usize);

/// `value` in the shortest form.
fn v(value: u64) -> V {
    V(value, varint::len(value).expect("a varint's value"))
}

/// `value` in exactly `width` octets (it must fit).
fn wide(value: u64, width: usize) -> V {
    assert!(
        varint::len(value).is_some_and(|shortest| shortest <= width),
        "{value} does not fit {width} octets"
    );
    V(value, width)
}

fn put(buf: &mut Vec<u8>, V(value, width): V) {
    match width {
        1 => buf.push(value as u8),
        2 => buf.extend_from_slice(&(0x4000 | value as u16).to_be_bytes()),
        4 => buf.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes()),
        8 => buf.extend_from_slice(&(0xc000_0000_0000_0000 | value).to_be_bytes()),
        _ => unreachable!("a varint is 1, 2, 4 or 8 octets"),
    }
}

/// The fields of a message that are varints.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Original,
    NameId,
    NameLen,
    Stand,
    Len,
}

impl Field {
    /// What a truncation inside the field is called by the reader.
    fn what(self) -> &'static str {
        match self {
            Field::Original => "original sequence",
            Field::NameId => "name id",
            Field::NameLen => "name length",
            Field::Stand => "stand seconds",
            Field::Len => "payload length",
        }
    }
}

/// One message written field by field, each varint in the form the case names and each length as
/// the case says it, whether or not the octets are there: what a writer would not write and a key
/// holder or a bit error can.
#[derive(Clone)]
struct Raw {
    flags: u8,
    original: V,
    name_id: V,
    name_len: V,
    name: Vec<u8>,
    stand: V,
    len: V,
    payload: Vec<u8>,
}

impl Raw {
    /// A valid bare message of name id 1 and an empty payload.
    fn new() -> Raw {
        Raw {
            flags: 0,
            original: v(0),
            name_id: v(1),
            name_len: v(0),
            name: Vec::new(),
            stand: v(0),
            len: v(0),
            payload: Vec::new(),
        }
    }

    /// A payload of `n` octets, said and present.
    fn payload(mut self, n: usize) -> Raw {
        self.len = v(n as u64);
        self.payload = vec![0x5a; n];
        self
    }

    /// A payload of `n` octets said, none present.
    fn says(mut self, n: u64) -> Raw {
        self.len = v(n);
        self.payload = Vec::new();
        self
    }

    /// A name of `n` octets, said and present.
    fn named(mut self, n: usize) -> Raw {
        self.flags |= NAMED;
        self.name_len = v(n as u64);
        self.name = vec![0x41; n];
        self
    }

    fn stand(mut self, secs: V) -> Raw {
        self.flags |= STAND;
        self.stand = secs;
        self
    }

    fn standing(mut self, original: V) -> Raw {
        self.flags |= STANDING;
        self.original = original;
        self
    }

    fn replayed(mut self, original: V) -> Raw {
        self.flags |= REPLAYED;
        self.original = original;
        self
    }

    fn id(mut self, id: V) -> Raw {
        self.name_id = id;
        self
    }

    fn with_name_len(mut self, len: V) -> Raw {
        self.name_len = len;
        self
    }

    fn with_len(mut self, len: V) -> Raw {
        self.len = len;
        self
    }

    /// The message, in the wire order. With `cut` the message ends one octet short of the end of
    /// that field's varint (so the field is cut inside its own octets) and nothing follows.
    fn write_cut(&self, buf: &mut Vec<u8>, cut: Option<Field>) {
        buf.push(self.flags);
        let field = |buf: &mut Vec<u8>, which: Field, value: V| {
            put(buf, value);
            if cut == Some(which) {
                buf.pop();
                true
            } else {
                false
            }
        };
        if self.flags & (STANDING | REPLAYED) != 0 && field(buf, Field::Original, self.original) {
            return;
        }
        if field(buf, Field::NameId, self.name_id) {
            return;
        }
        if self.flags & NAMED != 0 {
            if field(buf, Field::NameLen, self.name_len) {
                return;
            }
            buf.extend_from_slice(&self.name);
        }
        if self.flags & STAND != 0 && field(buf, Field::Stand, self.stand) {
            return;
        }
        if field(buf, Field::Len, self.len) {
            return;
        }
        buf.extend_from_slice(&self.payload);
    }

    fn write(&self, buf: &mut Vec<u8>) {
        self.write_cut(buf, None);
    }
}

fn frame(messages: &[Raw]) -> Vec<u8> {
    let mut buf = Vec::new();
    for m in messages {
        m.write(&mut buf);
    }
    buf
}

/// `plain` padded with PAD and zeros to exactly `total` octets.
fn padded_to(mut plain: Vec<u8>, total: usize) -> Vec<u8> {
    assert!(
        plain.len() < total,
        "{} octets leave no room to pad to {total}",
        plain.len()
    );
    plain.push(PAD);
    plain.resize(total, 0);
    plain
}

/// The table: each case is run through the reference and both production entries (`agree`), and
/// the reference's outcome must be the one the case names (`want`: `Ok`, a refusal's variant, or
/// `Truncated:<field>`; `*` for a case whose outcome is not stated), so a boundary is pinned on
/// both sides and the table cannot pass by reaching none of them.
struct Table {
    seen: Seen,
    cases: usize,
}

const SEQ0: u64 = 10;

impl Table {
    fn new() -> Self {
        Table {
            seen: Seen::default(),
            cases: 0,
        }
    }

    fn case(&mut self, what: &str, plain: Vec<u8>, seq0: u64, count: usize, mm: usize, want: &str) {
        let input = Input {
            plain,
            seq0,
            count,
            max_message: mm,
        };
        let (_, error) = Old::new(Bytes::from(input.plain.clone()), seq0, count, mm).run();
        let got = label(error.as_ref());
        if want != "*" {
            assert_eq!(
                got, want,
                "{what}: the reference reads {:02x?} (seq0 {seq0}, count {count}, limit {mm}) as {got}",
                input.plain
            );
        }
        agree(&input, &mut self.seen);
        self.cases += 1;
    }

    /// `messages` as one frame at `SEQ0`, one message counted, limit `mm`.
    fn one(&mut self, what: &str, m: Raw, mm: usize, want: &str) {
        self.case(what, frame(&[m]), SEQ0, 1, mm, want);
    }
}

/// The wire order of the golden frame's second message, for the prefix expectations: octet by
/// octet, what a frame cut after `p` octets ends in. The first message is `00 01 05 'hello'`, the
/// second `01 02 03 <name of 3> 06 'world!'`.
fn golden_prefix_want(p: usize) -> &'static str {
    match p {
        0 | 8 => "Truncated:flags",
        1 | 9 => "Truncated:name id",
        2 | 14 => "Truncated:payload length",
        10 => "Truncated:name length",
        11..=13 => "Truncated:name",
        3..=7 | 15..=20 => "Truncated:payload",
        21 => "Ok",
        _ => unreachable!("the golden frame has 21 octets"),
    }
}

/// Every boundary of the format, deterministically: what the fuzz corpus meets only by chance.
/// The reference and both production entries must read each case alike (messages, charges,
/// whether each payload is a slice of the frame, names by value, the exact refusal), and each case
/// states the outcome the format gives it. The table must reach every refusal the reader has, and
/// every field a frame can end in.
#[test]
fn every_boundary_of_the_format_reads_and_refuses_as_the_old_reader_did() {
    let mut t = Table::new();
    let mm = 64;

    // 1. Every prefix of each golden plaintext (the frame's header count stays what it was, so a
    //    frame cut short is a frame that ends inside a message, or lacks one it counts).
    let g1 = hex_octets("00010568656c6c6f01020308016106776f726c6421");
    assert_eq!(g1.len(), 21);
    for p in 0..=g1.len() {
        t.case(
            &format!("golden 1 cut at {p}"),
            g1[..p].to_vec(),
            0x1122_3344_5566_7788,
            2,
            MESSAGE_DEFAULT,
            golden_prefix_want(p),
        );
    }
    let g2 = vec![0, 1, 0, PAD, 0, 0, 0, 0, 0, 0];
    for p in 0..=g2.len() {
        let want = match p {
            0 => "Truncated:flags",
            1 => "Truncated:name id",
            2 => "Truncated:payload length",
            _ => "Ok",
        };
        t.case(
            &format!("golden 2 cut at {p}"),
            g2[..p].to_vec(),
            7,
            1,
            MESSAGE_DEFAULT,
            want,
        );
    }

    // 2. The count of the header against the messages held: n - 1, n and n + 1, with and without
    //    padding after the last.
    let three = frame(&[
        Raw::new().payload(3),
        Raw::new().named(5).payload(0),
        Raw::new().id(v(9)).payload(60),
    ]);
    let padded = {
        let mut p = three.clone();
        p.extend_from_slice(&[PAD, 0, 0, 0, 0]);
        p
    };
    for (plain, count, want) in [
        (&three, 2, "Trailing"),
        (&three, 3, "Ok"),
        (&three, 4, "Truncated:flags"),
        (&padded, 2, "Trailing"),
        (&padded, 3, "Ok"),
        (&padded, 4, "Count"),
        (&padded, 5, "Count"),
    ] {
        t.case(
            &format!(
                "{} octets, padded {}, count {count}",
                plain.len(),
                plain.len() == padded.len()
            ),
            plain.clone(),
            SEQ0,
            count,
            MESSAGE_DEFAULT,
            want,
        );
    }
    t.case("no messages, none counted", Vec::new(), SEQ0, 0, mm, "Ok");
    t.case(
        "no messages, one counted",
        Vec::new(),
        SEQ0,
        1,
        mm,
        "Truncated:flags",
    );
    t.case(
        "a message, none counted",
        frame(&[Raw::new()]),
        SEQ0,
        0,
        mm,
        "Trailing",
    );
    let mut bad_pad = three.clone();
    bad_pad.extend_from_slice(&[PAD, 0, 1, 0]);
    t.case(
        "padding with a non-zero octet",
        bad_pad,
        SEQ0,
        3,
        mm,
        "Padding",
    );
    let mut other_bits = three.clone();
    other_bits.push(PAD | 1);
    t.case(
        "PAD with another bit after the last",
        other_bits.clone(),
        SEQ0,
        3,
        mm,
        "Trailing",
    );
    t.case(
        "PAD with another bit where a message is due",
        other_bits,
        SEQ0,
        4,
        mm,
        "Flags",
    );

    // 3. A payload at the limit: limit - 1, limit and limit + 1, whether its octets are there or
    //    not (the limit is judged before the octets are looked for).
    for (len, want) in [
        (0, "Ok"),
        (63, "Ok"),
        (64, "Ok"),
        (65, "TooLarge"),
        (66, "TooLarge"),
    ] {
        t.one(
            &format!("payload {len}, limit {mm}"),
            Raw::new().payload(len),
            mm,
            want,
        );
    }
    t.one("65 said, none there", Raw::new().says(65), mm, "TooLarge");
    t.one(
        "64 said, 63 there",
        Raw::new().payload(63).with_len(v(64)),
        mm,
        "Truncated:payload",
    );
    t.one("0 limit, 0 payload", Raw::new(), 0, "Ok");
    t.one("0 limit, 1 payload", Raw::new().payload(1), 0, "TooLarge");
    t.one(
        "2^62 - 1 said",
        Raw::new().says(varint::MAX),
        mm,
        "TooLarge",
    );
    // The limit is clamped to MESSAGE_MAX, whatever the caller gave.
    let max = MESSAGE_MAX as u64;
    for limit in [MESSAGE_MAX, MESSAGE_MAX + 1, usize::MAX] {
        t.one(
            "MESSAGE_MAX said, none there",
            Raw::new().says(max),
            limit,
            "Truncated:payload",
        );
        t.one(
            "MESSAGE_MAX + 1 said",
            Raw::new().says(max + 1),
            limit,
            "TooLarge",
        );
    }

    // 4. A name of 254, 255 and 256 octets (and its octets cut, and 0).
    for (len, want) in [
        (0, "Ok"),
        (1, "Ok"),
        (254, "Ok"),
        (255, "Ok"),
        (256, "NameTooLong"),
        (257, "NameTooLong"),
    ] {
        t.one(
            &format!("name of {len}"),
            Raw::new().named(len).payload(2),
            mm,
            want,
        );
    }
    let mut said_256 = Raw::new().named(255);
    said_256.name_len = v(256);
    t.one("256 said, 255 there", said_256, mm, "NameTooLong");
    // The name's last octet is the frame's: 254 of 255 are there.
    let mut short_name = frame(&[Raw::new().named(255)]);
    short_name.truncate(short_name.len() - 2);
    t.case(
        "255 said, 254 there",
        short_name,
        SEQ0,
        1,
        mm,
        "Truncated:name",
    );
    let mut huge_name = Raw::new().named(3);
    huge_name.name_len = v(varint::MAX);
    t.one("a name of 2^62 - 1 said", huge_name, mm, "NameTooLong");

    // 5. Stand seconds: 3599, 3600 and 3601 (and 0, and the largest a varint holds).
    for (secs, want) in [
        (0, "Ok"),
        (3599, "Ok"),
        (3600, "Ok"),
        (3601, "StandSeconds"),
        (varint::MAX, "StandSeconds"),
    ] {
        t.one(
            &format!("stands {secs} s"),
            Raw::new().stand(v(secs)).payload(1),
            mm,
            want,
        );
        t.one(
            &format!("named, stands {secs} s"),
            Raw::new().named(4).stand(v(secs)).payload(1),
            mm,
            want,
        );
    }

    // 6. Name ids 0, 1, 4096 and 4097 (and 2^62 - 1); the id is judged before the name length is
    //    read.
    for (id, want) in [
        (0, "NameId"),
        (1, "Ok"),
        (2, "Ok"),
        (4095, "Ok"),
        (4096, "Ok"),
        (4097, "NameId"),
        (varint::MAX, "NameId"),
    ] {
        t.one(
            &format!("name id {id}"),
            Raw::new().id(v(id)).payload(1),
            mm,
            want,
        );
    }
    t.case(
        "an id of 0, the frame ends there",
        vec![NAMED, 0],
        SEQ0,
        1,
        mm,
        "NameId",
    );
    t.case(
        "an id of 4097, the frame ends there",
        vec![NAMED, 0x50, 0x01],
        SEQ0,
        1,
        mm,
        "NameId",
    );

    // 7. The original sequence against the message's own (seq - 1, seq, seq + 1), in each of the
    //    two flavours, in the first message of a frame and the second, and judged before what
    //    follows it is read.
    type Make = fn(Raw, V) -> Raw;
    let flavours: [(&str, Make); 2] = [("standing", Raw::standing), ("replayed", Raw::replayed)];
    for (flavour, make) in flavours {
        for (seq0, original, want) in [
            (SEQ0, SEQ0 - 1, "Ok"),
            (SEQ0, SEQ0, "OriginalSequence"),
            (SEQ0, SEQ0 + 1, "OriginalSequence"),
            (SEQ0, 0, "Ok"),
            (SEQ0, varint::MAX, "OriginalSequence"),
            (0, 0, "OriginalSequence"),
            (1, 0, "Ok"),
            (1, 1, "OriginalSequence"),
        ] {
            t.case(
                &format!("{flavour} {original} at seq {seq0}"),
                frame(&[make(Raw::new().payload(1), v(original))]),
                seq0,
                1,
                mm,
                want,
            );
        }
        // The second message of a frame has the sequence after the first's.
        for (original, want) in [
            (SEQ0 - 1, "Ok"),
            (SEQ0, "Ok"),
            (SEQ0 + 1, "OriginalSequence"),
            (SEQ0 + 2, "OriginalSequence"),
        ] {
            t.case(
                &format!("second message, {flavour} {original}"),
                frame(&[
                    Raw::new().payload(1),
                    make(Raw::new().payload(1), v(original)),
                ]),
                SEQ0,
                2,
                mm,
                want,
            );
        }
        // Judged before the name id, and after the original is read in full.
        t.one(
            &format!("{flavour} at seq, and name id 0"),
            make(Raw::new().id(v(0)), v(SEQ0)),
            mm,
            "OriginalSequence",
        );
        t.one(
            &format!("{flavour} below seq, and name id 0"),
            make(Raw::new().id(v(0)), v(SEQ0 - 1)),
            mm,
            "NameId",
        );
        let mut cut_after = Vec::new();
        cut_after.push(make(Raw::new(), v(SEQ0 - 1)).flags);
        put(&mut cut_after, v(SEQ0 - 1));
        t.case(
            &format!("{flavour} below seq, the frame ends there"),
            cut_after,
            SEQ0,
            1,
            mm,
            "Truncated:name id",
        );
        let mut cut_at = Vec::new();
        cut_at.push(make(Raw::new(), v(SEQ0)).flags);
        put(&mut cut_at, v(SEQ0));
        t.case(
            &format!("{flavour} at seq, the frame ends there"),
            cut_at,
            SEQ0,
            1,
            mm,
            "OriginalSequence",
        );
    }

    // 8. Every flags octet, followed by the fields it says.
    for flags in 0..=255u8 {
        let want = if flags == PAD {
            "Count"
        } else if flags & PAD != 0
            || flags & RESERVED != 0
            || flags & (STANDING | REPLAYED) == (STANDING | REPLAYED)
        {
            "Flags"
        } else {
            "Ok"
        };
        let raw = Raw {
            flags,
            original: v(SEQ0 - 1),
            name_len: v(2),
            name: vec![b'a', b'b'],
            stand: v(5),
            ..Raw::new().payload(1)
        };
        t.one(&format!("flags {flags:#04x}"), raw, mm, want);
    }

    // 9. Non-minimal varints (2, 4 and 8 octets for a value that fits fewer) in every length
    //    field: read as the same value, with the same refusal at each boundary.
    for width in [1usize, 2, 4, 8] {
        let small = |value: u64| wide(value, width);
        t.one(
            &format!("original in {width}"),
            Raw::new().standing(small(3)).payload(1),
            mm,
            "Ok",
        );
        t.one(
            &format!("original = seq in {width}"),
            Raw::new().replayed(small(SEQ0)).payload(1),
            mm,
            "OriginalSequence",
        );
        t.one(
            &format!("name id in {width}"),
            Raw::new().id(small(7)).payload(1),
            mm,
            "Ok",
        );
        t.one(
            &format!("name length in {width}"),
            Raw::new().named(3).payload(1).with_name_len(small(3)),
            mm,
            "Ok",
        );
        t.one(
            &format!("stand in {width}"),
            Raw::new().stand(small(5)).payload(1),
            mm,
            "Ok",
        );
        t.one(
            &format!("payload length in {width}"),
            Raw::new().payload(4).with_len(small(4)),
            mm,
            "Ok",
        );
        t.one(
            &format!("payload length 63 in {width}"),
            Raw::new().payload(63).with_len(small(63)),
            mm,
            "Ok",
        );
        if width >= 2 {
            t.one(
                &format!("name id 4096 in {width}"),
                Raw::new().id(small(4096)).payload(1),
                mm,
                "Ok",
            );
            t.one(
                &format!("name id 4097 in {width}"),
                Raw::new().id(small(4097)).payload(1),
                mm,
                "NameId",
            );
            t.one(
                &format!("name id 0 in {width}"),
                Raw::new().id(small(0)).payload(1),
                mm,
                "NameId",
            );
            t.one(
                &format!("name length 255 in {width}"),
                Raw::new().named(255).with_name_len(small(255)),
                mm,
                "Ok",
            );
            t.one(
                &format!("name length 256 in {width}"),
                Raw::new().named(255).with_name_len(small(256)),
                mm,
                "NameTooLong",
            );
            t.one(
                &format!("stand 3600 in {width}"),
                Raw::new().stand(small(3600)).payload(1),
                mm,
                "Ok",
            );
            t.one(
                &format!("stand 3601 in {width}"),
                Raw::new().stand(small(3601)).payload(1),
                mm,
                "StandSeconds",
            );
            t.one(
                &format!("payload length 64 in {width}"),
                Raw::new().payload(64).with_len(small(64)),
                mm,
                "Ok",
            );
            t.one(
                &format!("payload length 65 in {width}"),
                Raw::new().payload(65).with_len(small(65)),
                mm,
                "TooLarge",
            );
            t.one(
                &format!("original seq - 1 in {width}"),
                Raw::new().standing(small(SEQ0 - 1)).payload(1),
                mm,
                "Ok",
            );
        }
        // The largest value a varint holds, in 8 octets, in each field.
        if width == 8 {
            t.one(
                "original 2^62 - 1",
                Raw::new().standing(small(varint::MAX)),
                mm,
                "OriginalSequence",
            );
            t.one(
                "name id 2^62 - 1",
                Raw::new().id(small(varint::MAX)),
                mm,
                "NameId",
            );
            t.one(
                "stand 2^62 - 1",
                Raw::new().stand(small(varint::MAX)),
                mm,
                "StandSeconds",
            );
            t.one(
                "length 2^62 - 1",
                Raw::new().with_len(small(varint::MAX)),
                mm,
                "TooLarge",
            );
            let mut huge = Raw::new().named(3);
            huge.name_len = small(varint::MAX);
            t.one("name length 2^62 - 1", huge, mm, "NameTooLong");
        }
    }
    // Cut inside the varint itself: each field, each width, the frame ends one octet short.
    let everything = || Raw::new().named(3).stand(v(5)).standing(v(1)).payload(2);
    for width in [2usize, 4, 8] {
        for field in [
            Field::Original,
            Field::NameId,
            Field::NameLen,
            Field::Stand,
            Field::Len,
        ] {
            let mut raw = everything();
            match field {
                Field::Original => raw.original = wide(1, width),
                Field::NameId => raw.name_id = wide(1, width),
                Field::NameLen => raw.name_len = wide(3, width),
                Field::Stand => raw.stand = wide(5, width),
                Field::Len => raw.len = wide(2, width),
            }
            let mut plain = Vec::new();
            raw.write_cut(&mut plain, Some(field));
            t.case(
                &format!("{} cut inside {width} octets", field.what()),
                plain,
                SEQ0,
                1,
                mm,
                &format!("Truncated:{}", field.what()),
            );
        }
    }

    // 10. Lengths nested in the frame: a length that says more than the frame holds, one that
    //     swallows the next message, and the same in a frame over the share limit.
    for (said, want) in [
        (3u64, "Trailing"),
        (4, "Ok"),
        (5, "Truncated:payload"),
        (60, "Truncated:payload"),
    ] {
        let mut plain = frame(&[Raw::new().says(said)]);
        plain.extend_from_slice(&[7; 4]);
        t.case(&format!("{said} said, 4 there"), plain, SEQ0, 1, mm, want);
    }
    let mut swallowed = frame(&[Raw::new().says(4)]);
    swallowed.extend_from_slice(&frame(&[Raw::new().payload(1)]));
    t.case(
        "a payload that takes the second message",
        swallowed.clone(),
        SEQ0,
        2,
        mm,
        "Truncated:flags",
    );
    t.case("and counted once", swallowed, SEQ0, 1, mm, "Ok");
    let mut name_over = frame(&[Raw::new().named(255)]);
    name_over.truncate(40);
    t.case(
        "a name of 255 said, 36 there",
        name_over,
        SEQ0,
        1,
        mm,
        "Truncated:name",
    );
    for total in [SHARE_FRAME_MAX, SHARE_FRAME_MAX + 1] {
        let head = frame(&[Raw::new().named(40).with_len(wide(1000, 2))]);
        let rest = total - head.len();
        for (said, want) in [
            (rest as u64, "Ok"),
            (rest as u64 + 1, "Truncated:payload"),
            (rest as u64 - 1, "Trailing"),
            (16_000, "Truncated:payload"),
        ] {
            let mut plain = frame(&[Raw::new().named(40).with_len(wide(said, 2))]);
            plain.resize(total, 7);
            t.case(
                &format!("{said} said, {rest} there, in a frame of {total}"),
                plain,
                SEQ0,
                1,
                MESSAGE_DEFAULT,
                want,
            );
        }
    }

    // 11. Frames of 9000 and 9001 octets (and the octets about them) that carry a named message:
    //     what is shared and what is copied, and what each message is charged, at the share limit
    //     and at half of the frame.
    for total in [
        SHARE_FRAME_MAX - 1,
        SHARE_FRAME_MAX,
        SHARE_FRAME_MAX + 1,
        SHARE_FRAME_MAX + 2,
    ] {
        // One named message, padded to the exact size; and three, one counted each way.
        t.case(
            &format!("one named message in {total}"),
            padded_to(frame(&[Raw::new().named(40).payload(100)]), total),
            SEQ0,
            1,
            MESSAGE_DEFAULT,
            "Ok",
        );
        let three = frame(&[
            Raw::new().named(40).payload(100),
            Raw::new().id(v(2)).payload(300),
            Raw::new().named(255).id(v(3)).payload(0),
        ]);
        for count in [2usize, 3, 4] {
            let want = match count {
                2 => "Trailing",
                3 => "Ok",
                _ => "Count",
            };
            t.case(
                &format!("three messages in {total}, count {count}"),
                padded_to(three.clone(), total),
                SEQ0,
                count,
                MESSAGE_DEFAULT,
                want,
            );
        }
        // No padding at all: the message is the frame, to the octet (the 4 octets of the other
        // fields, the 40 of the name and a 2-octet length make 45 more than the payload).
        let snug = frame(&[Raw::new().named(40).payload(total - 45)]);
        assert_eq!(snug.len(), total);
        t.case(
            &format!("one named message that is all of {total}"),
            snug,
            SEQ0,
            1,
            MESSAGE_DEFAULT,
            "Ok",
        );
        // A payload at half of the frame: copied below it, shared at and above it, and always
        // shared by a frame of at most SHARE_FRAME_MAX. Both production entries and the
        // reference are compared, so each case counts twice (once for each production entry).
        for payload in [total / 2 - 1, total / 2, total / 2 + 1] {
            let plain = padded_to(frame(&[Raw::new().named(40).payload(payload)]), total);
            let before = (t.seen.shared, t.seen.copied);
            t.case(
                &format!("a payload of {payload} in {total}"),
                plain,
                SEQ0,
                1,
                MESSAGE_DEFAULT,
                "Ok",
            );
            let counted = (t.seen.shared - before.0, t.seen.copied - before.1);
            let shared = total <= SHARE_FRAME_MAX || payload * 2 >= total;
            assert_eq!(
                counted,
                if shared { (2, 0) } else { (0, 2) },
                "a payload of {payload} in a frame of {total}: shared or copied by the rule"
            );
        }
    }

    // Every refusal the reader has was reached, and every field a frame can end in; each
    // boundary above named its outcome, so a refusal the table did not mean to reach would have
    // failed its case.
    for want in [
        "Ok",
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
            t.seen.variants.contains(want),
            "the table never reached {want}: {:?}",
            t.seen
        );
    }
    for field in [
        "flags",
        "original sequence",
        "name id",
        "name length",
        "name",
        "stand seconds",
        "payload length",
        "payload",
    ] {
        let label = format!("Truncated:{field}");
        assert!(
            t.seen.labels.contains(&label),
            "the table never ended a frame in the {field}: {:?}",
            t.seen
        );
    }
    assert!(t.seen.shared > 0 && t.seen.copied > 0, "{:?}", t.seen);
    assert!(
        t.seen.names_shared > 0 && t.seen.names_copied > 0,
        "{:?}",
        t.seen
    );
    assert!(t.cases >= 400, "{} cases", t.cases);
}

/// The rule for a **name**, which the reference does not share (it shares every name; production
/// does not, and that is intended): a name is a slice of the frame when the frame is at most
/// [`SHARE_FRAME_MAX`] octets, and a copy of its own when the frame is larger, whatever the
/// name's size and whatever the payload does. A name is held by the receiver's name table for as
/// long as it stays bound, so one that shared a large frame would keep up to
/// `STREAM_FRAME_MAX` octets alive for 255; a payload is judged by its own size against the
/// frame's (`take_payload`), a name is too small to be most of any large frame. The name is the
/// same octets either way, which is what the equivalence cases compare.
#[test]
fn a_name_shares_a_small_frame_and_is_copied_out_of_a_large_one() {
    for total in [
        100usize,
        SHARE_FRAME_MAX - 1,
        SHARE_FRAME_MAX,
        SHARE_FRAME_MAX + 1,
        SHARE_FRAME_MAX + 2,
        40_000,
    ] {
        for (name_len, payload) in [(1usize, 20usize), (40, 20), (255, 20), (3, total / 2 + 10)] {
            if payload + name_len + 8 >= total {
                continue;
            }
            let plain = padded_to(frame(&[Raw::new().named(name_len).payload(payload)]), total);
            let frame = Bytes::from(plain.clone());
            let input = Input {
                plain,
                seq0: SEQ0,
                count: 1,
                max_message: MESSAGE_DEFAULT,
            };
            for (what, (got, err)) in [
                ("iterator", by_iterator(&input, &frame)),
                ("parse_into", by_parse_into(&input, &frame)),
            ] {
                assert_eq!(err, None, "{what}: a frame of {total}");
                let message = &got[0];
                let name = message.name.as_ref().expect("a named message");
                assert_eq!(
                    name.as_ref(),
                    vec![0x41; name_len].as_slice(),
                    "{what}: the name's octets, a frame of {total}"
                );
                assert_eq!(
                    sharing(&frame, name),
                    total <= SHARE_FRAME_MAX,
                    "{what}: a name of {name_len} in a frame of {total} (a payload of {payload})"
                );
                // The payload is judged by its own rule beside it.
                assert_eq!(
                    sharing(&frame, &message.payload),
                    total <= SHARE_FRAME_MAX || payload * 2 >= total,
                    "{what}: a payload of {payload} in a frame of {total}"
                );
            }
        }
    }
}
