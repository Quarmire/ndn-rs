//! SHA-256, in-crate (FIPS 180-4).
//!
//! Why not the workspace `sha2`: this crate is a `[scope]="spec"` calculus
//! with obligation C7 — zero ndf-* dependencies, `--no-default-features`
//! builds — and the corpus fixed the hash constitutionally (ndf-the-landing
//! Act III: "the document hash is SHA-256 over exactly those bytes";
//! ndf-decision-atlas: D-3/D-10 removed algorithm agility). Baking the ~120
//! lines here makes the spec crate literally dependency-free and immune to
//! rustcrypto release-wave churn. Ruling recorded as docs/keel/DECISIONS.md
//! D-K2, with FIPS known-answer tests below.

/// A content hash: 32 raw bytes of SHA-256 (wire rule R7).
pub type Hash = [u8; 32];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Incremental SHA-256 state. `no_std`, allocation-free.
pub struct Sha256 {
    state: [u32; 8],
    /// Total message length in bytes.
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Fresh state.
    pub const fn new() -> Self {
        Self { state: H0, len: 0, buf: [0u8; 64], buf_len: 0 }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        let mut data = data;
        if self.buf_len > 0 {
            let take = core::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finish and produce the digest.
    pub fn finalize(mut self) -> Hash {
        let bit_len = self.len.wrapping_mul(8);
        // Padding: 0x80, zeros, 64-bit big-endian bit length.
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        // Manual absorb of the length so `self.len` bookkeeping can't recurse.
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Render a hash as lowercase hex (64 chars) into a fixed buffer; returns the
/// `&str`. Allocation-free display helper for logs and FREEZE.md content.
pub fn hex<'a>(hash: &Hash, out: &'a mut [u8; 64]) -> &'a str {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in hash.iter().enumerate() {
        out[2 * i] = DIGITS[(byte >> 4) as usize];
        out[2 * i + 1] = DIGITS[(byte & 0x0f) as usize];
    }
    // SAFETY-free: DIGITS is ASCII, so the buffer is valid UTF-8.
    core::str::from_utf8(out).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn hexs(h: &Hash) -> alloc::string::String {
        let mut buf = [0u8; 64];
        alloc::string::String::from(hex(h, &mut buf))
    }

    // FIPS 180-4 / NIST CAVP known answers.
    #[test]
    fn kat_empty() {
        assert_eq!(
            hexs(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn kat_abc() {
        assert_eq!(
            hexs(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn kat_two_blocks() {
        assert_eq!(
            hexs(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn kat_million_a() {
        let m = vec![b'a'; 1_000_000];
        assert_eq!(
            hexs(&sha256(&m)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn incremental_equals_oneshot() {
        let data = b"the keel is the layer the suite stands on";
        let mut inc = Sha256::new();
        for chunk in data.chunks(7) {
            inc.update(chunk);
        }
        assert_eq!(inc.finalize(), sha256(data));
    }
}
