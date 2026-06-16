//! Minimal ISO-8601 time formatter / parser for NDN certificate
//! `ValidityPeriod` per ndn-cxx `security/validity-period.cpp:29`
//! (`ISO_DATETIME_SIZE = 15`) and `util/time.cpp::toIsoString` (Boost
//! `to_iso_string` form: `YYYYMMDDTHHMMSS`, UTC, no separators).

/// Length in bytes of the canonical NDN ISO-8601 datetime form.
pub const ISO_DATETIME_LEN: usize = 15;

/// Format a UNIX-epoch nanosecond timestamp as the 15-byte
/// `YYYYMMDDTHHMMSS` ASCII string used by ndn-cxx / NFD certificate
/// `ValidityPeriod` fields.
pub fn format_iso_basic(unix_ns: u64) -> [u8; ISO_DATETIME_LEN] {
    let secs = unix_ns / 1_000_000_000;
    let (y, mo, d, h, mi, s) = unix_secs_to_ymdhms(secs);
    let mut out = [b'0'; ISO_DATETIME_LEN];
    write_u32(&mut out[0..4], y);
    write_u32(&mut out[4..6], mo);
    write_u32(&mut out[6..8], d);
    out[8] = b'T';
    write_u32(&mut out[9..11], h);
    write_u32(&mut out[11..13], mi);
    write_u32(&mut out[13..15], s);
    out
}

/// Parse a 15-byte `YYYYMMDDTHHMMSS` ASCII string back into nanoseconds
/// since the UNIX epoch. Returns `None` if `bytes` is not exactly 15
/// ASCII characters in the expected shape.
pub fn parse_iso_basic(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != ISO_DATETIME_LEN || bytes[8] != b'T' {
        return None;
    }
    let y = read_u32(&bytes[0..4])?;
    let mo = read_u32(&bytes[4..6])?;
    let d = read_u32(&bytes[6..8])?;
    let h = read_u32(&bytes[9..11])?;
    let mi = read_u32(&bytes[11..13])?;
    let s = read_u32(&bytes[13..15])?;
    let secs = ymdhms_to_unix_secs(y, mo, d, h, mi, s)?;
    Some(secs * 1_000_000_000)
}

fn write_u32(slot: &mut [u8], mut v: u32) {
    for i in (0..slot.len()).rev() {
        slot[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
}

fn read_u32(slot: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    for &b in slot {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u32;
    }
    Some(v)
}

/// Convert UNIX epoch seconds to (year, month, day, hour, minute, second)
/// using the proleptic Gregorian calendar. Days-from-epoch math follows
/// Howard Hinnant's `civil_from_days`.
fn unix_secs_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let secs_in_day = (secs % 86_400) as u32;
    let h = secs_in_day / 3600;
    let mi = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, h, mi, s)
}

fn ymdhms_to_unix_secs(y: u32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<u64> {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + h as u64 * 3600 + mi as u64 * 60 + s as u64)
}

/// Howard Hinnant `civil_from_days` (CC0). Returns (year, month, day)
/// for `days` since 1970-01-01.
fn civil_from_days(z: i64) -> (u32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

fn days_from_civil(y: u32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as u64 + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_roundtrip() {
        let s = format_iso_basic(0);
        assert_eq!(&s, b"19700101T000000");
        assert_eq!(parse_iso_basic(&s), Some(0));
    }

    #[test]
    fn year_2000_known_date() {
        // 2000-01-01T00:00:00 UTC = 946_684_800 sec since epoch.
        let ns = 946_684_800u64 * 1_000_000_000;
        let s = format_iso_basic(ns);
        assert_eq!(&s, b"20000101T000000");
        assert_eq!(parse_iso_basic(&s), Some(ns));
    }

    #[test]
    fn modern_date_roundtrip() {
        // Encode a fixed string, verify parse gives a u64, re-encode
        // matches. Avoids hard-coding a UNIX-epoch literal whose value
        // must be computed externally.
        let original = b"20260501T123456";
        let ns = parse_iso_basic(original).expect("must parse");
        assert_eq!(&format_iso_basic(ns), original);
    }

    #[test]
    fn parse_then_format_roundtrip_far_future() {
        let original = b"20990228T235959";
        let ns = parse_iso_basic(original).expect("must parse");
        assert_eq!(&format_iso_basic(ns), original);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_iso_basic(b"19700101T00000").is_none());
        assert!(parse_iso_basic(b"19700101T0000000").is_none());
    }

    #[test]
    fn parse_rejects_missing_t_separator() {
        assert!(parse_iso_basic(b"19700101_000000").is_none());
    }

    #[test]
    fn parse_rejects_non_digits() {
        assert!(parse_iso_basic(b"abcd0101T000000").is_none());
    }
}
