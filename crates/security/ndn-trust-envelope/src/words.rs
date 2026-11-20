//! Octets as English words (trust-envelope.md §5.8): the BIP39 English list,
//! whose checksum catches a mistyped or swapped word. A recovery kit shows
//! its seed so, and an introduction code its secret and anchor fingerprint
//! (data-layer.md §19); both use this one list.
//!
//! Two codecs share it. [`encode`] / [`decode`]: exactly 32 octets as 24
//! words, BIP39's own 8-bit checksum (recovery kits, the words form of an
//! introduction). [`encode_checked`] / [`decode_checked`]: any payload of
//! 4 mod 11 octets, with a 12-bit checksum that also covers a **bound
//! text** (the short introduction code binds the inviter's device name and
//! address, so a typo in them is caught like one in a word).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How many words carry 32 octets.
pub const WORD_COUNT: usize = 24;

/// Bits one word carries.
const WORD_BITS: usize = 11;

/// Bits of a checked code's checksum.
const CHECK_BITS: usize = 12;

/// The domain label a checked code's checksum is made under.
const CHECK_LABEL: &[u8] = b"ndn-trust/intro-short/1";

/// Why words were refused. A refusal names a position only: a mistyped
/// word is usually one edit from the real one, and the error reaches
/// terminals and logs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WordsError {
    /// Not [`WORD_COUNT`] words.
    #[error("{0} words, not {WORD_COUNT}")]
    Count(usize),
    /// The word at this position (from 1) is not on the list.
    #[error("word {0} is not a BIP39 English word")]
    UnknownWord(usize),
    /// Every word is on the list, but the checksum does not match. For a
    /// checked code the text it is bound to is part of the checksum.
    #[error("the checksum does not match: a word is mistyped, or two are swapped")]
    Checksum,
    /// A number of words that fills no whole number of octets with a
    /// 12-bit checksum: a checked code has 4, 12, 20, 28, 36, … words.
    #[error("{0} words do not make a checked code (4 plus a multiple of 8 words)")]
    BadCount(usize),
    /// A payload that fills no whole number of words with a 12-bit
    /// checksum: its length must be 4 mod 11 octets (4, 15, 26, 37, 48, …).
    #[error("a payload of {0} octets does not fill whole words (4 mod 11 octets do)")]
    PayloadLength(usize),
}

/// The first 12 bits of the checksum of `payload` bound to `bound`.
fn checksum(payload: &[u8], bound: &str) -> u32 {
    let mut hash = Sha256::new();
    hash.update(CHECK_LABEL);
    hash.update(bound.as_bytes());
    hash.update([0u8]);
    hash.update(payload);
    let digest = hash.finalize();
    (u32::from(digest[0]) << 4) | (u32::from(digest[1]) >> 4)
}

/// `payload` followed by a 12-bit checksum bound to `bound`, as BIP39
/// English words, space-separated: `(8 · len + 12) / 11` of them (20 for
/// 26 octets, 36 for 48). The checksum is the first 12 bits of
/// `SHA-256("ndn-trust/intro-short/1" ‖ bound ‖ 0x00 ‖ payload)`, so
/// [`decode_checked`] only accepts the words with the same `bound`. A
/// payload whose length is not 4 mod 11 octets is refused.
pub fn encode_checked(payload: &[u8], bound: &str) -> Result<Zeroizing<String>, WordsError> {
    if payload.len() % WORD_BITS != 4 {
        return Err(WordsError::PayloadLength(payload.len()));
    }
    let list = bip39::Language::English.word_list();
    let count = (8 * payload.len() + CHECK_BITS) / WORD_BITS;
    // Room for the longest (8-letter) words and their spaces, so the string
    // never reallocates and leaves no unwiped copy behind.
    let mut words = Zeroizing::new(String::with_capacity(count * 9));
    // At most 10 bits wait in `acc` between words, 8 more come in.
    let (mut acc, mut bits) = (0u32, 0usize);
    let word = |acc: &mut u32, bits: &mut usize, words: &mut String| {
        while *bits >= WORD_BITS {
            *bits -= WORD_BITS;
            if !words.is_empty() {
                words.push(' ');
            }
            words.push_str(list[(*acc >> *bits) as usize & 0x7ff]);
            *acc &= (1 << *bits) - 1;
        }
    };
    for &b in payload {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        word(&mut acc, &mut bits, &mut words);
    }
    acc = (acc << CHECK_BITS) | checksum(payload, bound);
    bits += CHECK_BITS;
    word(&mut acc, &mut bits, &mut words);
    debug_assert_eq!(bits, 0, "a payload of 4 mod 11 octets fills whole words");
    Ok(words)
}

/// The payload `words` encode, if they carry a checksum bound to `bound`
/// ([`encode_checked`]). Case and spacing do not matter. Refused, in this
/// order: a word count that cannot be a checked code
/// ([`WordsError::BadCount`]), a word off the list (its position, from 1),
/// a checksum that does not match `bound` and the payload.
pub fn decode_checked(words: &str, bound: &str) -> Result<Zeroizing<Vec<u8>>, WordsError> {
    let count = words.split_whitespace().count();
    if count % 8 != 4 {
        return Err(WordsError::BadCount(count));
    }
    let payload_len = (WORD_BITS * count - CHECK_BITS) / 8;
    let mut payload = Zeroizing::new(Vec::with_capacity(payload_len));
    let mut lower = Zeroizing::new(String::with_capacity(16));
    let (mut acc, mut bits) = (0u32, 0usize);
    for (i, word) in words.split_whitespace().enumerate() {
        lower.clear();
        lower.extend(word.chars().flat_map(char::to_lowercase));
        let index = bip39::Language::English
            .find_word(&lower)
            .ok_or(WordsError::UnknownWord(i + 1))?;
        acc = (acc << WORD_BITS) | u32::from(index);
        bits += WORD_BITS;
        while bits >= 8 && payload.len() < payload_len {
            bits -= 8;
            payload.push((acc >> bits) as u8);
        }
        // Keep what is waiting: at most 8 + 11 bits before the checksum.
        acc &= (1 << bits) - 1;
    }
    debug_assert_eq!(bits, CHECK_BITS);
    if acc != checksum(&payload, bound) {
        return Err(WordsError::Checksum);
    }
    Ok(payload)
}

/// `octets` as [`WORD_COUNT`] BIP39 English words, space-separated.
pub fn encode(octets: &[u8; 32]) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mnemonic =
        bip39::Mnemonic::from_entropy(&octets[..]).expect("32 octets of entropy always encode");
    // Room for 24 of the longest (8-letter) words and their spaces, so the
    // string never reallocates and leaves no unwiped copy behind.
    let mut words = Zeroizing::new(String::with_capacity(WORD_COUNT * 9));
    write!(words, "{mnemonic}").expect("writing to a String cannot fail");
    words
}

/// The 32 octets `words` encode ([`encode`]). Case and spacing do not
/// matter; a word outside the list, a wrong count or a checksum mismatch is
/// refused.
pub fn decode(words: &str) -> Result<Zeroizing<[u8; 32]>, WordsError> {
    let mut normalized = Zeroizing::new(String::with_capacity(words.len()));
    let mut count = 0;
    for word in words.split_whitespace() {
        if count > 0 {
            normalized.push(' ');
        }
        normalized.extend(word.chars().flat_map(char::to_lowercase));
        count += 1;
    }
    if count != WORD_COUNT {
        return Err(WordsError::Count(count));
    }
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
        .map_err(|e| match e {
            bip39::Error::UnknownWord(i) => WordsError::UnknownWord(i + 1),
            // Twenty-four words always carry 32 octets: what is left is
            // the checksum.
            _ => WordsError::Checksum,
        })?;
    let (mut entropy, len) = mnemonic.to_entropy_array();
    let mut octets = Zeroizing::new([0u8; 32]);
    octets.copy_from_slice(&entropy[..len.min(32)]);
    zeroize::Zeroize::zeroize(&mut entropy);
    Ok(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Words round-trip; case and spacing do not matter.
    #[test]
    fn words_round_trip_whatever_their_case_and_spacing() {
        let octets = [0x7f; 32];
        let words = encode(&octets);
        assert_eq!(words.split_whitespace().count(), WORD_COUNT);
        assert_eq!(*decode(&words).unwrap(), octets);
        let shouted = format!("  {}  ", words.to_uppercase().replace(' ', "\n "));
        assert_eq!(*decode(&shouted).unwrap(), octets);
    }

    /// A word off the list, a missing word and a swapped pair are refused.
    #[test]
    fn mistyped_missing_and_swapped_words_are_refused() {
        let words: Vec<String> = encode(&[0x11; 32]).split(' ').map(str::to_owned).collect();
        let mut typo = words.clone();
        typo[4] = "zzzz".into();
        assert_eq!(decode(&typo.join(" ")), Err(WordsError::UnknownWord(5)));
        assert_eq!(
            decode(&words[1..].join(" ")),
            Err(WordsError::Count(WORD_COUNT - 1))
        );
        let mut swapped = words.clone();
        let i = (0..WORD_COUNT - 1)
            .find(|&i| swapped[i] != swapped[i + 1])
            .unwrap();
        swapped.swap(i, i + 1);
        assert!(decode(&swapped.join(" ")).is_err());
    }
}

#[cfg(test)]
mod checked_tests {
    use super::*;

    const BOUND: &str = "/alice/member/laptop 192.0.2.7:4433";

    fn payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect()
    }

    fn split(words: &str) -> Vec<String> {
        words.split(' ').map(str::to_owned).collect()
    }

    /// 26 octets are 20 words and 48 octets 36; the words read back to the
    /// payload whatever their case and spacing.
    #[test]
    fn checked_words_round_trip_at_twenty_and_thirty_six() {
        for (len, count) in [(26, 20), (48, 36)] {
            let payload = payload(len);
            let words = encode_checked(&payload, BOUND).unwrap();
            assert_eq!(words.split(' ').count(), count);
            assert_eq!(*decode_checked(&words, BOUND).unwrap(), payload);
            let shouted = format!(" {}\n", words.to_uppercase().replace(' ', "  \n"));
            assert_eq!(*decode_checked(&shouted, BOUND).unwrap(), payload);
        }
    }

    /// Only payloads of 4 mod 11 octets fill whole words: others are refused
    /// on the way in, and a word count that does not fill whole octets on
    /// the way out.
    #[test]
    fn checked_words_refuse_lengths_that_do_not_fill_words() {
        assert_eq!(
            encode_checked(&payload(16), BOUND).unwrap_err(),
            WordsError::PayloadLength(16)
        );
        let words = encode_checked(&payload(26), BOUND).unwrap();
        let all = split(&words);
        for n in [0, 1, 3, 19, 21, 24, 35, 37] {
            let cut = all.iter().cycle().take(n).cloned().collect::<Vec<_>>();
            assert_eq!(
                decode_checked(&cut.join(" "), BOUND).unwrap_err(),
                WordsError::BadCount(n),
                "{n} words"
            );
        }
    }

    /// The first word off the list is named by its position (from 1), before
    /// the checksum is judged.
    #[test]
    fn checked_words_name_the_position_of_a_word_off_the_list() {
        let mut all = split(&encode_checked(&payload(26), BOUND).unwrap());
        all[6] = "zzzz".into();
        all[9] = "qqqq".into();
        assert_eq!(
            decode_checked(&all.join(" "), BOUND).unwrap_err(),
            WordsError::UnknownWord(7)
        );
    }

    /// The checksum covers the text it is bound to: any other text is
    /// refused, a typo in it included.
    #[test]
    fn checked_words_are_bound_to_their_text() {
        let words = encode_checked(&payload(26), BOUND).unwrap();
        for other in [
            "/alice/member/laptoq 192.0.2.7:4433",
            "/alice/member/laptop 192.0.2.7:4434",
            "/alice/member/laptop 192.0.2.8:4433",
            "/alice/member/laptop",
            "",
        ] {
            assert_eq!(
                decode_checked(&words, other).unwrap_err(),
                WordsError::Checksum,
                "{other:?}"
            );
        }
    }

    /// Every other word of the whole list put in any place of a code, and
    /// every adjacent pair swapped, is refused but for the 2^-12 of checksums
    /// that agree by chance: `(substitutions tried, undetected, swaps tried,
    /// undetected)`.
    fn corpus(len: usize) -> (usize, usize, usize, usize) {
        let words = split(&encode_checked(&payload(len), BOUND).unwrap());
        let list = bip39::Language::English.word_list();
        let (mut tried, mut undetected) = (0, 0);
        for at in 0..words.len() {
            for &w in list.iter().filter(|&&w| w != words[at]) {
                let mut typo = words.clone();
                typo[at] = w.to_owned();
                tried += 1;
                undetected += usize::from(decode_checked(&typo.join(" "), BOUND).is_ok());
            }
        }
        let (mut swaps, mut swaps_undetected) = (0, 0);
        for at in 0..words.len() - 1 {
            if words[at] == words[at + 1] {
                continue;
            }
            let mut swap = words.clone();
            swap.swap(at, at + 1);
            swaps += 1;
            swaps_undetected += usize::from(decode_checked(&swap.join(" "), BOUND).is_ok());
        }
        (tried, undetected, swaps, swaps_undetected)
    }

    /// The count of undetected edits is deterministic for the fixed corpus;
    /// the bound is three times what chance (2^-12 each) expects, and the
    /// exact figures are printed for the record.
    #[test]
    fn checked_words_catch_substitutions_and_swaps_but_chance() {
        for len in [26, 48] {
            let (tried, undetected, swaps, swaps_undetected) = corpus(len);
            println!(
                "{len} octets: {undetected} of {tried} substitutions and {swaps_undetected} of \
                 {swaps} adjacent swaps undetected"
            );
            assert!(
                undetected <= 3 * (tried / 4096),
                "{undetected} of {tried} substitutions undetected, chance expects {}",
                tried / 4096
            );
            assert!(
                swaps_undetected <= 1,
                "{swaps_undetected} of {swaps} swaps undetected"
            );
        }
    }
}
