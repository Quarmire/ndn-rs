//! Thirty-two octets as 24 English words (trust-envelope.md §5.8): the
//! BIP39 English list, whose checksum catches a mistyped or swapped word.
//! A recovery kit shows its seed so, and an introduction code its secret
//! and anchor fingerprint (data-layer.md §19); both use this one codec.

use zeroize::Zeroizing;

/// How many words carry 32 octets.
pub const WORD_COUNT: usize = 24;

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
    /// Every word is on the list, but the checksum does not match.
    #[error("the checksum does not match: a word is mistyped, or two are swapped")]
    Checksum,
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
