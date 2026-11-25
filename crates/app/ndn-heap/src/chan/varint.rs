//! The QUIC variable-length integer (RFC 9000 §16): the two high bits of the
//! first octet give the length (1, 2, 4 or 8 octets), the rest is the value,
//! big-endian, at most 2^62 - 1.
//!
//! The encoder is minimal. The decoder accepts a longer encoding than the
//! value needs (RFC 9000 allows it) and never reads past the slice.

use bytes::BufMut;

/// The largest value a varint holds: 2^62 - 1.
pub(crate) const MAX: u64 = (1 << 62) - 1;

/// A value above [`MAX`], which no varint holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0} does not fit a variable-length integer (at most 2^62 - 1)")]
pub(crate) struct Overflow(pub u64);

/// The octets `value` takes, or `None` above [`MAX`].
pub(crate) const fn len(value: u64) -> Option<usize> {
    match value {
        0..=0x3f => Some(1),
        0x40..=0x3fff => Some(2),
        0x4000..=0x3fff_ffff => Some(4),
        0x4000_0000..=MAX => Some(8),
        _ => None,
    }
}

/// Appends `value` in the shortest form.
pub(crate) fn write(buf: &mut impl BufMut, value: u64) -> Result<(), Overflow> {
    match len(value).ok_or(Overflow(value))? {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
    Ok(())
}

/// Reads one varint from the start of `data`: the value and the octets it
/// took, or `None` when `data` ends inside it.
pub(crate) fn read(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let n = 1usize << (first >> 6);
    let bytes = data.get(..n)?;
    let mut value = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn enc(v: u64) -> Vec<u8> {
        let mut b = BytesMut::new();
        write(&mut b, v).unwrap();
        b.to_vec()
    }

    /// RFC 9000 Appendix A.1's four examples, and the boundary of every length.
    #[test]
    fn the_rfc_examples_and_every_length_boundary_encode_and_decode() {
        assert_eq!(
            enc(151_288_809_941_952_652),
            [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]
        );
        assert_eq!(enc(494_878_333), [0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(enc(15_293), [0x7b, 0xbd]);
        assert_eq!(enc(37), [0x25]);
        for (value, n) in [
            (0u64, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX, 8),
        ] {
            let wire = enc(value);
            assert_eq!(wire.len(), n, "{value}");
            assert_eq!(read(&wire), Some((value, n)), "{value}");
            assert_eq!(len(value), Some(n));
        }
    }

    #[test]
    fn a_value_above_2_pow_62_minus_1_is_refused() {
        assert_eq!(len(MAX + 1), None);
        let mut b = BytesMut::new();
        assert_eq!(write(&mut b, MAX + 1), Err(Overflow(MAX + 1)));
        assert_eq!(write(&mut b, u64::MAX), Err(Overflow(u64::MAX)));
        assert!(b.is_empty(), "nothing is written for a refused value");
    }

    #[test]
    fn a_varint_cut_short_is_not_read_and_a_longer_form_than_needed_is() {
        for wire in [&[0x40u8][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0, 0, 0, 0], &[]] {
            assert_eq!(read(wire), None);
        }
        // 5 in two octets, and in eight: allowed, and the octets read are reported.
        assert_eq!(read(&[0x40, 0x05, 0xff]), Some((5, 2)));
        assert_eq!(read(&[0xc0, 0, 0, 0, 0, 0, 0, 5]), Some((5, 8)));
    }
}
