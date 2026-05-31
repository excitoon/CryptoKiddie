//! GOST 28147-89 block cipher (param-Z S-box) with the CNT encryption mode,
//! IMIT message-authentication mode, and GOST key meshing.
//!
//! These are the symmetric primitives behind the TLS GOST cipher suite
//! `TLS_GOSTR341112_256_WITH_28147_CNT_IMIT` (the suite `lkulgost.nalog.ru`
//! negotiated). References:
//!
//! * RFC 5830 — GOST 28147-89 cipher, CNT (gammirovanie) and IMIT modes.
//! * RFC 4357 — GOST key meshing (§2.3.2) and parameters.
//! * RFC 8891 — Magma (GOST R 34.12-2015): states that Magma is *the same
//!   algorithm* as GOST 28147-89 with the param-Z S-box fixed, differing only
//!   in that the key and data are parsed big-endian instead of little-endian.
//!   This module therefore implements one shared Feistel core and verifies it
//!   against RFC 8891 Appendix A's official Magma known-answer test, then
//!   exposes the little-endian GOST 28147-89 parsing used by the TLS modes.
//!
//! Validation status: the block-cipher core is anchored by the RFC 8891 Magma
//! KAT (cryptographically exact). The CNT/IMIT/key-meshing modes are
//! implemented to the RFC 4357/5830 specifications with structural tests; their
//! final confirmation is an on-wire interop check against the server, which is
//! the staged next step.

/// param-Z S-box (`id-tc26-gost-28147-param-Z`), as `Pi'_0 .. Pi'_7`
/// (RFC 8891 §4.1 / RFC 7836 Appendix C). `SBOX[i]` substitutes the nibble at
/// bit positions `4*i .. 4*i+3`.
const SBOX_Z: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

/// GOST key-meshing constant `C` (RFC 4357 §2.3.2).
const KEY_MESHING_C: [u8; 32] = [
    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23, 0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12, 0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
];

/// The `g` round function: `t(a [+] k) <<< 11`, where `t` is the param-Z
/// nibble substitution and `[+]` is addition mod 2^32 (RFC 8891 §4.2).
#[inline]
fn g(k: u32, a: u32) -> u32 {
    let s = a.wrapping_add(k);
    let mut out = 0u32;
    let mut i = 0;
    while i < 8 {
        let nibble = ((s >> (4 * i)) & 0xF) as usize;
        out |= (SBOX_Z[i][nibble] as u32) << (4 * i);
        i += 1;
    }
    out.rotate_left(11)
}

/// Expand the eight 32-bit key words into the 32-round subkey schedule:
/// words `0..8` for rounds 1-24, then words `7..0` for rounds 25-32
/// (RFC 8891 §4.3).
fn schedule(words: &[u32; 8]) -> [u32; 32] {
    let mut ks = [0u32; 32];
    for i in 0..24 {
        ks[i] = words[i % 8];
    }
    for i in 0..8 {
        ks[24 + i] = words[7 - i];
    }
    ks
}

/// Core Feistel network shared by Magma and GOST 28147-89. `a1` is the high
/// 32-bit half, `a0` the low half. Encryption runs the schedule forward.
fn feistel(ks: &[u32; 32], mut a1: u32, mut a0: u32) -> (u32, u32) {
    for round in ks.iter().take(31) {
        let t = a1 ^ g(*round, a0);
        a1 = a0;
        a0 = t;
    }
    // Final round (G*): no half-swap.
    let t = a1 ^ g(ks[31], a0);
    (t, a0)
}

/// A prepared GOST 28147-89 / Magma key (the 32-round subkey schedule).
#[derive(Clone)]
pub struct Gost28147 {
    enc: [u32; 32],
}

impl Gost28147 {
    /// Build a key in GOST 28147-89 (little-endian) parsing — the form used by
    /// the TLS CNT/IMIT modes.
    pub fn new_gost(key: &[u8; 32]) -> Self {
        Self::from_words(key_words(key, false))
    }

    /// Build a key in Magma (big-endian) parsing — used only to exercise the
    /// RFC 8891 known-answer test.
    pub fn new_magma(key: &[u8; 32]) -> Self {
        Self::from_words(key_words(key, true))
    }

    fn from_words(words: [u32; 8]) -> Self {
        Self {
            enc: schedule(&words),
        }
    }

    /// Encrypt a 64-bit block in GOST 28147-89 little-endian byte order.
    pub fn encrypt_block_le(&self, block: &[u8; 8]) -> [u8; 8] {
        let a0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let a1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let (r1, r0) = feistel(&self.enc, a1, a0);
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&r0.to_le_bytes());
        out[4..8].copy_from_slice(&r1.to_le_bytes());
        out
    }

    /// Decrypt a 64-bit block in GOST 28147-89 little-endian byte order.
    pub fn decrypt_block_le(&self, block: &[u8; 8]) -> [u8; 8] {
        let a0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let a1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let mut dec = self.enc;
        dec.reverse();
        let (r1, r0) = feistel(&dec, a1, a0);
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&r0.to_le_bytes());
        out[4..8].copy_from_slice(&r1.to_le_bytes());
        out
    }

    /// Encrypt a 64-bit block in Magma big-endian byte order (KAT helper).
    pub fn encrypt_block_be(&self, block: &[u8; 8]) -> [u8; 8] {
        let a1 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let a0 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let (r1, r0) = feistel(&self.enc, a1, a0);
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&r1.to_be_bytes());
        out[4..8].copy_from_slice(&r0.to_be_bytes());
        out
    }

    /// Run the first 16 rounds only (used by the IMIT MAC), little-endian I/O,
    /// returning the two halves without the final no-swap round.
    fn imit_step(&self, a1: u32, a0: u32) -> (u32, u32) {
        let (mut a1, mut a0) = (a1, a0);
        for round in self.enc.iter().take(16) {
            let t = a1 ^ g(*round, a0);
            a1 = a0;
            a0 = t;
        }
        (a1, a0)
    }
}

fn key_words(key: &[u8; 32], big_endian: bool) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (j, word) in words.iter_mut().enumerate() {
        let chunk = [key[4 * j], key[4 * j + 1], key[4 * j + 2], key[4 * j + 3]];
        *word = if big_endian {
            u32::from_be_bytes(chunk)
        } else {
            u32::from_le_bytes(chunk)
        };
    }
    words
}

/// GOST 28147-89 CNT (gammirovanie / counter) keystream generator with optional
/// GOST key meshing every 1024 bytes (RFC 5830 §6, RFC 4357 §2.3.2).
pub struct CntKeystream {
    key: Gost28147,
    raw_key: [u8; 32],
    n1: u32,
    n2: u32,
    /// Buffered keystream bytes not yet consumed.
    buf: Vec<u8>,
    buf_pos: usize,
    /// Bytes produced since the last key meshing.
    since_mesh: usize,
    meshing: bool,
}

const CNT_C1: u32 = 0x0101_0104;
const CNT_C2: u32 = 0x0101_0101;

impl CntKeystream {
    /// Initialise the keystream from a 32-byte key and 8-byte IV (sync). The IV
    /// is first ECB-encrypted to seed the counters (RFC 5830 §6).
    pub fn new(key: &[u8; 32], iv: &[u8; 8], meshing: bool) -> Self {
        let cipher = Gost28147::new_gost(key);
        let seed = cipher.encrypt_block_le(iv);
        let n1 = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]);
        let n2 = u32::from_le_bytes([seed[4], seed[5], seed[6], seed[7]]);
        Self {
            key: cipher,
            raw_key: *key,
            n1,
            n2,
            buf: Vec::new(),
            buf_pos: 0,
            since_mesh: 0,
            meshing,
        }
    }

    /// Produce the next 8-byte gamma block by advancing the counters and
    /// encrypting them.
    fn next_block(&mut self) -> [u8; 8] {
        if self.meshing && self.since_mesh == 1024 {
            self.mesh();
            self.since_mesh = 0;
        }
        // N1 += C2 mod 2^32
        self.n1 = self.n1.wrapping_add(CNT_C2);
        // N2 += C1 mod (2^32 - 1). Mirrors gost-engine `gost_cnt_next` exactly:
        // on unsigned overflow add 1, otherwise leave the sum untouched. The
        // value 0xFFFFFFFF is a valid intermediate state and must NOT be
        // normalised to 0, or the keystream would diverge from the reference at
        // the counter boundary by one block.
        let (sum, carry) = self.n2.overflowing_add(CNT_C1);
        self.n2 = if carry { sum.wrapping_add(1) } else { sum };
        let mut block = [0u8; 8];
        block[0..4].copy_from_slice(&self.n1.to_le_bytes());
        block[4..8].copy_from_slice(&self.n2.to_le_bytes());
        let gamma = self.key.encrypt_block_le(&block);
        self.since_mesh += 8;
        gamma
    }

    /// Apply GOST key meshing: refresh the key and re-encrypt the counter
    /// state (RFC 4357 §2.3.2).
    fn mesh(&mut self) {
        // K[i+1] = decryptECB(K[i], C)
        let old = Gost28147::new_gost(&self.raw_key);
        let mut new_key = [0u8; 32];
        for (i, chunk) in KEY_MESHING_C.chunks_exact(8).enumerate() {
            let block: [u8; 8] = chunk.try_into().expect("8-byte chunk");
            let dec = old.decrypt_block_le(&block);
            new_key[i * 8..i * 8 + 8].copy_from_slice(&dec);
        }
        self.raw_key = new_key;
        self.key = Gost28147::new_gost(&new_key);
        // IV0[i+1] = encryptECB(K[i+1], IVn[i])
        let mut iv = [0u8; 8];
        iv[0..4].copy_from_slice(&self.n1.to_le_bytes());
        iv[4..8].copy_from_slice(&self.n2.to_le_bytes());
        let enc = self.key.encrypt_block_le(&iv);
        self.n1 = u32::from_le_bytes([enc[0], enc[1], enc[2], enc[3]]);
        self.n2 = u32::from_le_bytes([enc[4], enc[5], enc[6], enc[7]]);
    }

    /// XOR `data` in place with the keystream (encrypt or decrypt — CNT is
    /// symmetric).
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.buf_pos == self.buf.len() {
                self.buf = self.next_block().to_vec();
                self.buf_pos = 0;
            }
            *byte ^= self.buf[self.buf_pos];
            self.buf_pos += 1;
        }
    }
}

/// Compute the GOST 28147-89 IMIT MAC (imitovstavka) over `data` with `key` and
/// the given IV (RFC 5830 §8). Returns the 4-byte tag. `data` is zero-padded to
/// an 8-byte boundary.
pub fn imit(key: &[u8; 32], iv: &[u8; 8], data: &[u8]) -> [u8; 4] {
    let cipher = Gost28147::new_gost(key);
    let mut n1 = u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]);
    let mut n2 = u32::from_le_bytes([iv[4], iv[5], iv[6], iv[7]]);

    let mut block;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        block = [
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ];
        (n1, n2) = imit_mix(&cipher, n1, n2, &block);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        block = [0u8; 8];
        block[..rem.len()].copy_from_slice(rem);
        (n1, _) = imit_mix(&cipher, n1, n2, &block);
    }
    // The 4-byte MAC is taken from the low word.
    n1.to_le_bytes()
}

fn imit_mix(cipher: &Gost28147, n1: u32, n2: u32, block: &[u8; 8]) -> (u32, u32) {
    let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let b1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    // `imit_step` returns the two halves as (high, low); the MAC state keeps
    // them as (n1 = low, n2 = high) so the next block XORs each half correctly
    // and the 4-byte tag is taken from the low word `n1` (matches gost-engine
    // `gost_mac_iv`/`mac_block`).
    let (hi, lo) = cipher.imit_step(n2 ^ b1, n1 ^ b0);
    (lo, hi)
}

/// Streaming GOST 28147-89 IMIT (imitovstavka) MAC with optional GOST key
/// meshing every 1024 processed bytes (RFC 5830 §8, RFC 4357 §2.3.2).
///
/// Unlike the one-shot [`imit`], this context accumulates input across many
/// `update` calls and produces a tag with a *non-destructive* [`finalize`], so
/// the same running state can keep absorbing data afterwards. This matches the
/// legacy GOST TLS suites, whose record MAC is computed over the
/// concatenation of every record's `MACed_data` seen so far
/// (the Chudov GOST TLS draft §2.3) — the IMIT context is never reset
/// between records.
#[derive(Clone)]
pub struct ImitContext {
    key: Gost28147,
    raw_key: [u8; 32],
    n1: u32,
    n2: u32,
    /// Partial (< 8 byte) tail awaiting more input.
    tail: [u8; 8],
    tail_len: usize,
    /// Bytes absorbed (in whole blocks) since the last meshing.
    since_mesh: usize,
    meshing: bool,
}

impl ImitContext {
    /// Create a context keyed with `key`, seeded from the 8-byte `iv`.
    pub fn new(key: &[u8; 32], iv: &[u8; 8], meshing: bool) -> Self {
        Self {
            key: Gost28147::new_gost(key),
            raw_key: *key,
            n1: u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]]),
            n2: u32::from_le_bytes([iv[4], iv[5], iv[6], iv[7]]),
            tail: [0u8; 8],
            tail_len: 0,
            meshing,
            since_mesh: 0,
        }
    }

    fn absorb_block(&mut self, block: &[u8; 8]) {
        if self.meshing && self.since_mesh == 1024 {
            self.mesh();
            self.since_mesh = 0;
        }
        let (n1, n2) = imit_mix(&self.key, self.n1, self.n2, block);
        self.n1 = n1;
        self.n2 = n2;
        self.since_mesh += 8;
    }

    /// GOST key meshing for the MAC key (mirrors [`CntKeystream::mesh`]).
    fn mesh(&mut self) {
        let old = Gost28147::new_gost(&self.raw_key);
        let mut new_key = [0u8; 32];
        for (i, chunk) in KEY_MESHING_C.chunks_exact(8).enumerate() {
            let block: [u8; 8] = chunk.try_into().expect("8-byte chunk");
            let dec = old.decrypt_block_le(&block);
            new_key[i * 8..i * 8 + 8].copy_from_slice(&dec);
        }
        self.raw_key = new_key;
        self.key = Gost28147::new_gost(&new_key);
    }

    /// Absorb more data into the running MAC.
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        // Top up an existing partial tail first.
        if self.tail_len > 0 {
            let need = 8 - self.tail_len;
            let take = need.min(data.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&data[..take]);
            self.tail_len += take;
            data = &data[take..];
            if self.tail_len == 8 {
                let block = self.tail;
                self.absorb_block(&block);
                self.tail_len = 0;
            }
        }
        // Absorb whole blocks directly.
        let mut chunks = data.chunks_exact(8);
        for chunk in &mut chunks {
            let block: [u8; 8] = chunk.try_into().expect("8-byte chunk");
            self.absorb_block(&block);
        }
        // Stash the remainder.
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.tail[..rem.len()].copy_from_slice(rem);
            self.tail_len = rem.len();
        }
    }

    /// Produce the current 4-byte MAC without disturbing the running state.
    /// Any buffered partial block is zero-padded for this computation only.
    pub fn finalize(&self) -> [u8; 4] {
        let mut n1 = self.n1;
        if self.tail_len > 0 {
            let mut block = [0u8; 8];
            block[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
            // A pending mesh would also apply to this trailing block.
            let mut key = self.key.clone();
            if self.meshing && self.since_mesh == 1024 {
                let old = Gost28147::new_gost(&self.raw_key);
                let mut new_key = [0u8; 32];
                for (i, chunk) in KEY_MESHING_C.chunks_exact(8).enumerate() {
                    let c: [u8; 8] = chunk.try_into().expect("8-byte chunk");
                    let dec = old.decrypt_block_le(&c);
                    new_key[i * 8..i * 8 + 8].copy_from_slice(&dec);
                }
                key = Gost28147::new_gost(&new_key);
            }
            let (r1, _) = imit_mix(&key, self.n1, self.n2, &block);
            n1 = r1;
        }
        n1.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex8(v: &[u8; 8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn magma_known_answer_rfc8891() {
        // RFC 8891 Appendix A.4.
        let key: [u8; 32] = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
            0xfc, 0xfd, 0xfe, 0xff,
        ];
        let plaintext: [u8; 8] = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let cipher = Gost28147::new_magma(&key);
        let ct = cipher.encrypt_block_be(&plaintext);
        assert_eq!(hex8(&ct), "4ee901e5c2d8ca3d");
    }

    #[test]
    fn magma_subkey_g_intermediates_rfc8891() {
        // RFC 8891 Appendix A.2 transformation g spot-checks.
        assert_eq!(g(0x8765_4321, 0xfedc_ba98), 0xfdcb_c20c);
        assert_eq!(g(0xfdcb_c20c, 0x8765_4321), 0x7e79_1a4b);
    }

    #[test]
    fn imit_known_answer_gost_engine_reference() {
        // Cross-implementation KAT vs gost-engine `gost_mac_iv` (param-Z S-box):
        // key=01..20, iv=01..08, data=0xa0..0xaf (two blocks). Anchors the IMIT
        // primitive and its IV seeding / half-word handling independently of the
        // key-wrap composition.
        let key: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let iv = [1, 2, 3, 4, 5, 6, 7, 8];
        let data: [u8; 16] = core::array::from_fn(|i| (0xa0 + i) as u8);
        assert_eq!(imit(&key, &iv, &data), [0x93, 0x41, 0xba, 0x1c]);
    }

    #[test]
    fn gost_ecb_round_trips() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let cipher = Gost28147::new_gost(&key);
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let ct = cipher.encrypt_block_le(&pt);
        let back = cipher.decrypt_block_le(&ct);
        assert_eq!(back, pt);
        assert_ne!(ct, pt);
    }

    #[test]
    fn cnt_is_symmetric() {
        let key: [u8; 32] = core::array::from_fn(|i| (255 - i) as u8);
        let iv = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let plaintext = b"GOST 28147-89 CNT mode round-trip test payload!!".to_vec();

        let mut ct = plaintext.clone();
        CntKeystream::new(&key, &iv, true).apply(&mut ct);
        assert_ne!(ct, plaintext);

        let mut pt = ct.clone();
        CntKeystream::new(&key, &iv, true).apply(&mut pt);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn cnt_known_answer_gost_engine_reference() {
        // Cross-implementation KAT vs gost-engine `gost_cnt_next` (param-Z, no
        // meshing): key[i]=i*5+1, iv=0a..11. Anchors the CNT seed (ECB of IV),
        // the counter constants/half assignment (low += 0x01010101 plain wrap,
        // high += 0x01010104 mod 2^32-1 with the `if(go>g) g++` carry rule) and
        // the keystream byte order.
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
        let iv = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11];
        let mut ks = [0u8; 32];
        CntKeystream::new(&key, &iv, false).apply(&mut ks);
        let expected: [u8; 32] = [
            0x7c, 0x6b, 0xc1, 0x5d, 0xfc, 0xec, 0xcb, 0x00, 0x50, 0x5f, 0xdd, 0x96, 0xa5, 0x43,
            0xce, 0xf9, 0x9f, 0x5a, 0x7e, 0x60, 0xac, 0xc3, 0x9e, 0xa8, 0x1f, 0x9b, 0xb0, 0x62,
            0x34, 0xff, 0xb3, 0x44,
        ];
        assert_eq!(ks, expected);
    }

    #[test]
    fn cnt_keystream_survives_meshing_boundary() {
        // Cross the 1024-byte meshing boundary and confirm decrypt matches.
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let iv = [1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext: Vec<u8> = (0..2500).map(|i| (i % 256) as u8).collect();

        let mut ct = plaintext.clone();
        CntKeystream::new(&key, &iv, true).apply(&mut ct);
        let mut pt = ct.clone();
        CntKeystream::new(&key, &iv, true).apply(&mut pt);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn imit_is_deterministic_and_sensitive() {
        let key: [u8; 32] = core::array::from_fn(|i| (i + 3) as u8);
        let iv = [0u8; 8];
        let a = imit(&key, &iv, b"the quick brown fox");
        let b = imit(&key, &iv, b"the quick brown fox");
        let c = imit(&key, &iv, b"the quick brown fOx");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn imit_context_matches_one_shot() {
        // Streaming IMIT (no meshing) must equal the one-shot `imit` over the
        // same data, regardless of how the input is chunked.
        let key: [u8; 32] = core::array::from_fn(|i| (i * 5 + 1) as u8);
        let iv = [9, 8, 7, 6, 5, 4, 3, 2];
        let data = b"streaming imit equals one-shot over identical input bytes";

        let one_shot = imit(&key, &iv, data);

        let mut ctx = ImitContext::new(&key, &iv, false);
        // Feed in awkward chunk sizes to exercise the partial-tail buffer.
        for chunk in data.chunks(3) {
            ctx.update(chunk);
        }
        assert_eq!(ctx.finalize(), one_shot);
    }

    #[test]
    fn imit_context_finalize_is_non_destructive() {
        // Finalizing mid-stream must not disturb the running state: a later
        // finalize over more data must match a fresh single computation.
        let key: [u8; 32] = core::array::from_fn(|i| (200 - i) as u8);
        let iv = [0u8; 8];

        let mut ctx = ImitContext::new(&key, &iv, false);
        ctx.update(b"first record payload");
        let _mid = ctx.finalize();
        ctx.update(b"second record payload");
        let cumulative = ctx.finalize();

        let mut combined = Vec::new();
        combined.extend_from_slice(b"first record payload");
        combined.extend_from_slice(b"second record payload");
        assert_eq!(cumulative, imit(&key, &iv, &combined));
    }

    #[test]
    fn imit_context_is_order_sensitive() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let iv = [1u8; 8];
        let mut a = ImitContext::new(&key, &iv, false);
        a.update(b"AAAAAAAA");
        a.update(b"BBBBBBBB");
        let mut b = ImitContext::new(&key, &iv, false);
        b.update(b"BBBBBBBB");
        b.update(b"AAAAAAAA");
        assert_ne!(a.finalize(), b.finalize());
    }
}
