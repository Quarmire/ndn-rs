//! GF(2^8) arithmetic for systematic FEC.
//!
//! Polynomial `x^8 + x^4 + x^3 + x^2 + 1` (`0x11d`) with generator `α = 2` —
//! the Reed–Solomon convention. `2` is primitive over this polynomial (AES's
//! `0x11b` does not share that property); `build_tables` asserts primitivity
//! so a wrong polynomial fails loudly.
//!
//! `mul` and `mul_add` use a peasant inner loop and rely on
//! autovectorisation; the log/antilog tables back `inv` and `pow` only. The
//! `simd` feature additionally enables explicit NEON / SSSE3 / AVX2 shuffle
//! paths. `tests::bench_mul_add` records throughput and gates regressions.

use std::sync::OnceLock;

/// Low byte of the reduction polynomial `x^8 + x^4 + x^3 + x^2 + 1`; the
/// bit-8 term is absorbed by the overflow check.
const REDUCE: u8 = 0x1d;

/// Peasant multiplication: eight `if-shift-xor` iterations, register-resident
/// so LLVM can vectorise the surrounding byte loop. Exposed for fuzz/baseline.
#[inline]
pub fn mul_peasant(a: u8, b: u8) -> u8 {
    let mut r: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= REDUCE;
        }
        b >>= 1;
    }
    r
}

struct Tables {
    /// `log[x] = i` such that `2^i = x` (for `x != 0`).
    log: [u8; 256],
    /// `exp[i] = 2^i mod poly`, doubled to `[0, 510)` to avoid `i % 255`.
    exp: [u8; 510],
}

static TABLES: OnceLock<Tables> = OnceLock::new();

fn tables() -> &'static Tables {
    TABLES.get_or_init(build_tables)
}

fn build_tables() -> Tables {
    let mut log = [0u8; 256];
    let mut exp = [0u8; 510];
    let mut x: u8 = 1;
    for (i, slot) in exp.iter_mut().take(255).enumerate() {
        *slot = x;
        log[x as usize] = i as u8;
        x = mul_peasant(x, 2);
    }
    assert_eq!(x, 1, "GF(2^8) generator 2 must cycle in 255 steps; got {x}",);
    let mut seen = [false; 256];
    seen[0] = true;
    for &v in &exp[..255] {
        assert!(
            !seen[v as usize],
            "GF(2^8) generator 2 is not primitive: {v} repeats — check polynomial"
        );
        seen[v as usize] = true;
    }
    let (head, tail) = exp.split_at_mut(255);
    tail.copy_from_slice(&head[..255]);
    Tables { log, exp }
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    mul_peasant(a, b)
}

pub fn inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

/// `base^exp` in GF(2^8). `0^0 = 1`; `0^n = 0` for `n > 0`.
pub fn pow(base: u8, exp: u32) -> u8 {
    if exp == 0 {
        return 1;
    }
    if base == 0 {
        return 0;
    }
    let t = tables();
    let log_b = t.log[base as usize] as u64;
    let idx = (log_b * exp as u64) % 255;
    t.exp[idx as usize]
}

/// In-place `dst[i] ^= mul(coeff, src[i])`. Routes through SIMD shuffle
/// (NEON / SSSE3 / AVX2) with `feature = "simd"`, otherwise the peasant
/// byte loop.
pub fn mul_add(dst: &mut [u8], src: &[u8], coeff: u8) {
    debug_assert_eq!(dst.len(), src.len());
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
        return;
    }
    mul_add_simd_or_peasant(dst, src, coeff);
}

#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[inline]
fn mul_add_simd_or_peasant(dst: &mut [u8], src: &[u8], coeff: u8) {
    mul_add_neon(dst, src, coeff);
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[inline]
fn mul_add_simd_or_peasant(dst: &mut [u8], src: &[u8], coeff: u8) {
    x86::dispatch(dst, src, coeff);
}

#[cfg(not(any(
    all(feature = "simd", target_arch = "aarch64"),
    all(feature = "simd", target_arch = "x86_64"),
)))]
#[inline]
fn mul_add_simd_or_peasant(dst: &mut [u8], src: &[u8], coeff: u8) {
    mul_add_peasant_buf(dst, src, coeff);
}

/// Pure-peasant byte loop; public so benches and property tests can call
/// it directly even when `simd` is enabled.
pub fn mul_add_peasant_buf(dst: &mut [u8], src: &[u8], coeff: u8) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= mul_peasant(coeff, *s);
    }
}

// SIMD path: split each byte into a low/high nibble and precompute two
// 16-entry tables (`mul(coeff, x)` and `mul(coeff, x << 4)` for x in 0..16).
// One shuffle per nibble + XOR recovers all 16 products per chunk.
#[cfg(all(feature = "simd", any(target_arch = "aarch64", target_arch = "x86_64")))]
fn build_nibble_tables(coeff: u8) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    for x in 0u8..16 {
        lo[x as usize] = mul_peasant(coeff, x);
        hi[x as usize] = mul_peasant(coeff, x << 4);
    }
    (lo, hi)
}

#[cfg(all(feature = "simd", target_arch = "aarch64"))]
fn mul_add_neon(dst: &mut [u8], src: &[u8], coeff: u8) {
    use std::arch::aarch64::*;
    let (lo, hi) = build_nibble_tables(coeff);
    // SAFETY: NEON is baseline on aarch64-64; the 16-byte chunk loop guards `len >= 16`.
    unsafe {
        let v_lo = vld1q_u8(lo.as_ptr());
        let v_hi = vld1q_u8(hi.as_ptr());
        let lo_mask = vdupq_n_u8(0x0F);
        let mut i = 0usize;
        let end = src.len() & !15;
        while i < end {
            let s = vld1q_u8(src.as_ptr().add(i));
            let s_lo_idx = vandq_u8(s, lo_mask);
            let s_hi_idx = vshrq_n_u8::<4>(s);
            let r_lo = vqtbl1q_u8(v_lo, s_lo_idx);
            let r_hi = vqtbl1q_u8(v_hi, s_hi_idx);
            let r = veorq_u8(r_lo, r_hi);
            let d = vld1q_u8(dst.as_ptr().add(i));
            vst1q_u8(dst.as_mut_ptr().add(i), veorq_u8(d, r));
            i += 16;
        }
        for j in i..src.len() {
            dst[j] ^= mul_peasant(coeff, src[j]);
        }
    }
}

// AVX2's `_mm256_shuffle_epi8` is two independent 128-bit shuffles, so the
// nibble table must be broadcast into both halves of the YMM register.
// Path selection is memoised in a static fn pointer to amortise feature
// detection.
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
mod x86 {
    use super::{build_nibble_tables, mul_add_peasant_buf, mul_peasant};
    use std::sync::OnceLock;

    type AddFn = fn(&mut [u8], &[u8], u8);

    static DISPATCH: OnceLock<AddFn> = OnceLock::new();

    pub(super) fn dispatch(dst: &mut [u8], src: &[u8], coeff: u8) {
        let f = *DISPATCH.get_or_init(select);
        f(dst, src, coeff);
    }

    fn select() -> AddFn {
        if is_x86_feature_detected!("avx2") {
            avx2_entry
        } else if is_x86_feature_detected!("ssse3") {
            ssse3_entry
        } else {
            mul_add_peasant_buf
        }
    }

    fn ssse3_entry(dst: &mut [u8], src: &[u8], coeff: u8) {
        // SAFETY: gated by runtime feature detection in `select`.
        unsafe { ssse3_inner(dst, src, coeff) }
    }

    fn avx2_entry(dst: &mut [u8], src: &[u8], coeff: u8) {
        // SAFETY: gated by runtime feature detection in `select`.
        unsafe { avx2_inner(dst, src, coeff) }
    }

    #[target_feature(enable = "ssse3")]
    unsafe fn ssse3_inner(dst: &mut [u8], src: &[u8], coeff: u8) {
        use std::arch::x86_64::*;
        let (lo, hi) = build_nibble_tables(coeff);
        let v_lo = _mm_loadu_si128(lo.as_ptr() as *const __m128i);
        let v_hi = _mm_loadu_si128(hi.as_ptr() as *const __m128i);
        let lo_mask = _mm_set1_epi8(0x0F);
        let mut i = 0usize;
        let end = src.len() & !15;
        while i < end {
            let s = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
            let s_lo = _mm_and_si128(s, lo_mask);
            // `_mm_srli_epi16` shifts 16-bit lanes; mask off neighbour-byte bleed.
            let s_hi = _mm_and_si128(_mm_srli_epi16(s, 4), lo_mask);
            let r_lo = _mm_shuffle_epi8(v_lo, s_lo);
            let r_hi = _mm_shuffle_epi8(v_hi, s_hi);
            let r = _mm_xor_si128(r_lo, r_hi);
            let d = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
            _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, _mm_xor_si128(d, r));
            i += 16;
        }
        for j in i..src.len() {
            dst[j] ^= mul_peasant(coeff, src[j]);
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn avx2_inner(dst: &mut [u8], src: &[u8], coeff: u8) {
        use std::arch::x86_64::*;
        let (lo, hi) = build_nibble_tables(coeff);
        let v_lo = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr() as *const __m128i));
        let v_hi = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr() as *const __m128i));
        let lo_mask = _mm256_set1_epi8(0x0F);
        let mut i = 0usize;
        let end = src.len() & !31;
        while i < end {
            let s = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
            let s_lo = _mm256_and_si256(s, lo_mask);
            let s_hi = _mm256_and_si256(_mm256_srli_epi16(s, 4), lo_mask);
            let r_lo = _mm256_shuffle_epi8(v_lo, s_lo);
            let r_hi = _mm256_shuffle_epi8(v_hi, s_hi);
            let r = _mm256_xor_si256(r_lo, r_hi);
            let d = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_xor_si256(d, r),
            );
            i += 32;
        }
        // SSSE3 is implied by AVX2, so the 16-byte residue path is safe.
        if src.len() - i >= 16 {
            super::x86::ssse3_inner(&mut dst[i..], &src[i..], coeff);
            return;
        }
        for j in i..src.len() {
            dst[j] ^= mul_peasant(coeff, src[j]);
        }
    }

    #[cfg(test)]
    pub(crate) fn ssse3_for_test() -> Option<AddFn> {
        is_x86_feature_detected!("ssse3").then_some(ssse3_entry)
    }
    #[cfg(test)]
    pub(crate) fn avx2_for_test() -> Option<AddFn> {
        is_x86_feature_detected!("avx2").then_some(avx2_entry)
    }
}

/// In-place scalar multiply: `dst[i] *= coeff`.
pub fn scale(dst: &mut [u8], coeff: u8) {
    if coeff == 1 {
        return;
    }
    if coeff == 0 {
        for d in dst.iter_mut() {
            *d = 0;
        }
        return;
    }
    for d in dst.iter_mut() {
        *d = mul_peasant(coeff, *d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_zero() {
        for a in 0u16..256 {
            let a = a as u8;
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(0, a), 0);
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(1, a), a);
        }
    }

    #[test]
    fn inverse_round_trip() {
        for a in 1u16..256 {
            let a = a as u8;
            let inv_a = inv(a);
            assert_ne!(inv_a, 0, "inv({a}) should not be 0");
            assert_eq!(mul(a, inv_a), 1, "a * inv(a) != 1 for a={a}");
        }
    }

    /// Table inverse must agree with Fermat's `a^254`. Guards primitivity.
    #[test]
    fn table_inv_matches_fermat() {
        for a in 1u16..256 {
            let a = a as u8;
            let mut fermat = 1u8;
            for _ in 0..254 {
                fermat = mul_peasant(fermat, a);
            }
            assert_eq!(inv(a), fermat, "inv mismatch at a={a}");
        }
    }

    #[test]
    fn associativity_sample() {
        for a in [1u8, 2, 3, 7, 13, 255] {
            for b in [1u8, 2, 5, 11, 127, 200] {
                for c in [1u8, 2, 4, 8, 16, 250] {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                }
            }
        }
    }

    #[test]
    fn pow_basics() {
        assert_eq!(pow(0, 0), 1);
        assert_eq!(pow(0, 5), 0);
        assert_eq!(pow(7, 0), 1);
        assert_eq!(pow(2, 1), 2);
        for base in [1u8, 2, 3, 5, 17, 200] {
            let mut acc = 1u8;
            for e in 0u32..10 {
                assert_eq!(pow(base, e), acc, "base={base} e={e}");
                acc = mul(acc, base);
            }
        }
    }

    #[test]
    fn mul_matches_peasant() {
        for a in 0u16..256 {
            for b in 0u16..256 {
                let (a, b) = (a as u8, b as u8);
                assert_eq!(mul(a, b), mul_peasant(a, b));
            }
        }
    }

    #[test]
    fn mul_add_matches_naive() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
        for coeff in [0u8, 1, 2, 7, 100, 255] {
            let mut dst = [10u8, 20, 30, 40, 50, 60, 70, 80];
            let mut naive = dst;
            mul_add(&mut dst, &src, coeff);
            for i in 0..src.len() {
                naive[i] ^= mul_peasant(coeff, src[i]);
            }
            assert_eq!(dst, naive, "coeff={coeff}");
        }
    }

    /// Dispatched SIMD path must agree with peasant byte-for-byte across
    /// coeffs and lengths covering AVX2 chunks, SSSE3 chunks, and tails.
    #[cfg(all(feature = "simd", any(target_arch = "aarch64", target_arch = "x86_64"),))]
    #[test]
    fn simd_matches_peasant() {
        let max_len = 257;
        let src: Vec<u8> = (0..max_len).map(|i| ((i * 19) ^ 0x37) as u8).collect();
        for coeff in [0u8, 1, 2, 3, 17, 100, 200, 255] {
            for len in [0, 1, 15, 16, 17, 31, 32, 33, 48, 64, 128, 200, 257] {
                let mut dst_simd = vec![0xAAu8; len];
                let mut dst_ref = vec![0xAAu8; len];
                mul_add(&mut dst_simd, &src[..len], coeff);
                mul_add_peasant_buf(&mut dst_ref, &src[..len], coeff);
                assert_eq!(
                    dst_simd, dst_ref,
                    "dispatched vs peasant mismatch at coeff={coeff} len={len}"
                );
            }
        }
    }

    /// Exercise SSSE3 and AVX2 each in isolation so a regression in the
    /// path the local CPU doesn't dispatch to still fails the test.
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    #[test]
    fn x86_explicit_paths_match_peasant() {
        let max_len = 257;
        let src: Vec<u8> = (0..max_len).map(|i| ((i * 23) ^ 0x5A) as u8).collect();
        let mut paths: Vec<(&'static str, fn(&mut [u8], &[u8], u8))> = Vec::new();
        if let Some(f) = x86::ssse3_for_test() {
            paths.push(("ssse3", f));
        }
        if let Some(f) = x86::avx2_for_test() {
            paths.push(("avx2", f));
        }
        for (label, f) in paths {
            for coeff in [0u8, 1, 2, 3, 17, 100, 255] {
                for len in [0, 1, 15, 16, 17, 31, 32, 33, 64, 200, 257] {
                    let mut dst_simd = vec![0xAAu8; len];
                    let mut dst_ref = vec![0xAAu8; len];
                    f(&mut dst_simd, &src[..len], coeff);
                    mul_add_peasant_buf(&mut dst_ref, &src[..len], coeff);
                    assert_eq!(
                        dst_simd, dst_ref,
                        "{label}: mismatch at coeff={coeff} len={len}"
                    );
                }
            }
        }
    }

    /// Microbench every mul_add path; asserts the dispatched path beats
    /// peasant. Run with
    /// `cargo test -p ndn-coding --release bench_mul_add -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_mul_add() {
        const LEN: usize = 4096;
        const ITERS: usize = 4096;
        let src: Vec<u8> = (0..LEN).map(|i| ((i * 17) ^ 0xa5) as u8).collect();
        let _ = tables();
        let mb = (LEN as f64 * ITERS as f64) / (1024.0 * 1024.0);

        let coeffs: Vec<u8> = (0..ITERS).map(|i| ((i & 0xff) | 1) as u8).collect();

        type AddFn = Box<dyn FnMut(&mut [u8], &[u8], u8)>;
        let bench = |label: &str, mut f: AddFn| {
            let mut dst = vec![0u8; LEN];
            let t0 = std::time::Instant::now();
            for &c in &coeffs {
                f(&mut dst, &src, c);
            }
            let elapsed = t0.elapsed();
            std::hint::black_box(&dst);
            let mbs = mb / elapsed.as_secs_f64();
            println!("  {label:<24}: {elapsed:?} ({mbs:.1} MiB/s)");
            elapsed
        };

        println!("\nmul_add microbench (len={LEN}, iters={ITERS}, total={mb:.1} MiB):");

        let peasant = bench("peasant", Box::new(mul_add_peasant_buf));

        let table_path = {
            let t = tables();
            bench(
                "per-coeff table",
                Box::new(move |d, s, c| {
                    let log_c = t.log[c as usize] as usize;
                    let mut tbl = [0u8; 256];
                    for (x, slot) in tbl.iter_mut().enumerate().skip(1) {
                        *slot = t.exp[log_c + t.log[x] as usize];
                    }
                    for (dd, ss) in d.iter_mut().zip(s.iter()) {
                        *dd ^= tbl[*ss as usize];
                    }
                }),
            )
        };

        #[cfg(all(feature = "simd", target_arch = "aarch64"))]
        let neon = Some(bench("NEON vtbl", Box::new(mul_add_neon)));
        #[cfg(not(all(feature = "simd", target_arch = "aarch64")))]
        let neon: Option<std::time::Duration> = None;

        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        let ssse3 = x86::ssse3_for_test().map(|f| bench("SSSE3 shuffle", Box::new(f)));
        #[cfg(not(all(feature = "simd", target_arch = "x86_64")))]
        let ssse3: Option<std::time::Duration> = None;

        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        let avx2 = x86::avx2_for_test().map(|f| bench("AVX2 shuffle", Box::new(f)));
        #[cfg(not(all(feature = "simd", target_arch = "x86_64")))]
        let avx2: Option<std::time::Duration> = None;

        let dispatched = bench("dispatched (mul_add)", Box::new(mul_add));
        assert!(
            dispatched <= peasant + std::time::Duration::from_micros(200),
            "dispatched path slower than peasant: dispatched={dispatched:?} peasant={peasant:?}"
        );

        let speedup = |t: std::time::Duration| peasant.as_secs_f64() / t.as_secs_f64();
        let mut summary = format!(
            "  speedup vs peasant   : table={:.2}x, dispatched={:.2}x",
            speedup(table_path),
            speedup(dispatched)
        );
        if let Some(t) = neon {
            summary += &format!(", neon={:.2}x", speedup(t));
        }
        if let Some(t) = ssse3 {
            summary += &format!(", ssse3={:.2}x", speedup(t));
        }
        if let Some(t) = avx2 {
            summary += &format!(", avx2={:.2}x", speedup(t));
        }
        println!("{summary}");
    }
}
