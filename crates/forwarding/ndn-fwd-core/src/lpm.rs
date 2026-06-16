//! FIB longest-prefix-match selection rule.
//!
//! This owns *only* the selection policy, not the matching or the storage.
//! Callers iterate their own table (a trie on the native side, a linear hash
//! scan on the constrained side), confirm which entries are a prefix of the
//! queried name, and hand the matches here as `(prefix_len, value)` pairs. The
//! entry with the longest prefix wins; on a length tie the first match is kept
//! (callers dedupe one entry per prefix, so ties only arise across equal-length
//! distinct prefixes, which cannot both match the same name).
//!
//! Keeping this rule in one place is what lets the two container types stay
//! behaviourally identical — pinned by the unit tests below and, ultimately, by
//! the cross-impl conformance vectors.

/// Reduce already-confirmed prefix matches to the longest one.
///
/// `name_len` is the queried name's component count; candidates whose
/// `prefix_len` exceeds it are rejected (a prefix cannot be longer than the
/// name). A `prefix_len` of 0 is the default route and matches any name.
///
/// Runs in one pass, holds one candidate, allocates nothing.
#[inline]
pub fn longest_match<T>(
    name_len: usize,
    candidates: impl IntoIterator<Item = (usize, T)>,
) -> Option<T> {
    let mut best: Option<(usize, T)> = None;
    for (prefix_len, value) in candidates {
        if prefix_len > name_len {
            continue;
        }
        // Strictly-longer replaces; equal or shorter keeps the incumbent
        // (first-match-wins on ties).
        if best.as_ref().is_none_or(|(b, _)| prefix_len > *b) {
            best = Some((prefix_len, value));
        }
    }
    best.map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_wins() {
        let candidates = [(1usize, 'a'), (3, 'c'), (2, 'b')];
        assert_eq!(longest_match(4, candidates), Some('c'));
    }

    #[test]
    fn default_route_matches_anything() {
        assert_eq!(longest_match(5, [(0usize, 'd')]), Some('d'));
        assert_eq!(longest_match(0, [(0usize, 'd')]), Some('d'));
    }

    #[test]
    fn overlong_prefix_rejected() {
        // A 3-component prefix cannot match a 2-component name.
        assert_eq!(longest_match(2, [(3usize, 'x')]), None);
    }

    #[test]
    fn no_candidates_is_none() {
        assert_eq!(longest_match::<char>(3, []), None);
    }

    #[test]
    fn tie_keeps_first() {
        // Equal-length matches: the first candidate is retained.
        assert_eq!(longest_match(2, [(2usize, 1u8), (2, 2u8)]), Some(1));
    }
}
