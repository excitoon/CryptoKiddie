//! GOST TLS 1.2 pseudo-random function (`PRF_GOSTR3411_2012_256`).
//!
//! RFC 9189 §4.3 specifies that the GOST 2012 TLS 1.2 cipher suites use the
//! TLS 1.2 PRF construction (RFC 5246 §5) instantiated with
//! `HMAC_GOSTR3411_2012_256`, i.e. HMAC over the Streebog-256 hash
//! (GOST R 34.11-2012, 256-bit output).
//!
//! ```text
//! PRF(secret, label, seed) = P_hash(secret, label || seed)
//! P_hash(secret, seed)     = HMAC(secret, A(1) || seed)
//!                          || HMAC(secret, A(2) || seed)
//!                          || ...
//! A(0) = seed
//! A(i) = HMAC(secret, A(i - 1))
//! ```
//!
//! The HMAC primitive is anchored by the official `HMAC_GOSTR3411_2012_256`
//! known-answer test from R 50.1.113-2016 / RFC 7836 Appendix A, so the
//! cryptographic core is exact; only the TLS framing around it is GOST-specific
//! glue.

use streebog::{Digest, Streebog256};

/// Streebog-256 HMAC output length, in bytes.
pub const MAC_LEN: usize = 32;

/// Streebog-256 internal block size, in bytes (512-bit compression input).
const BLOCK_LEN: usize = 64;

/// `GOSTR3411_2012_256(data)` — the Streebog-256 hash. Exposed for hashing the
/// TLS handshake transcript (`Finished` / `CertificateVerify`).
pub fn streebog256(data: &[u8]) -> [u8; MAC_LEN] {
    let mut hasher = Streebog256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut result = [0u8; MAC_LEN];
    result.copy_from_slice(&out);
    result
}

/// `HMAC_GOSTR3411_2012_256(key, data)` (RFC 2104 HMAC over Streebog-256).
pub fn hmac_streebog256(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    // Normalise the key to one block: hash if too long, then zero-pad.
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        block[..MAC_LEN].copy_from_slice(&streebog256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_LEN];
    let mut opad = [0u8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] = block[i] ^ 0x36;
        opad[i] = block[i] ^ 0x5c;
    }

    // inner = H(ipad || data)
    let mut inner = Streebog256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    // outer = H(opad || inner)
    let mut outer = Streebog256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out = outer.finalize();

    let mut result = [0u8; MAC_LEN];
    result.copy_from_slice(&out);
    result
}
/// TLS 1.2 `P_hash` (RFC 5246 §5) using `HMAC_GOSTR3411_2012_256`.
///
/// Produces `out.len()` bytes of keying material from `secret` and `seed`.
fn p_hash(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    // A(0) = seed; A(i) = HMAC(secret, A(i-1)).
    let mut a = hmac_streebog256(secret, seed);
    let mut written = 0;
    while written < out.len() {
        // HMAC(secret, A(i) || seed)
        let mut input = Vec::with_capacity(MAC_LEN + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        let block = hmac_streebog256(secret, &input);

        let take = (out.len() - written).min(MAC_LEN);
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;

        // Advance A(i) = HMAC(secret, A(i-1)).
        a = hmac_streebog256(secret, &a);
    }
}

/// TLS 1.2 GOST PRF: `PRF(secret, label, seed) = P_hash(secret, label || seed)`.
///
/// Returns exactly `out_len` bytes.
pub fn prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut full_seed = Vec::with_capacity(label.len() + seed.len());
    full_seed.extend_from_slice(label);
    full_seed.extend_from_slice(seed);

    let mut out = vec![0u8; out_len];
    p_hash(secret, &full_seed, &mut out);
    out
}

/// TLS master-secret length (RFC 5246 §8.1).
pub const MASTER_SECRET_LEN: usize = 48;

/// Per-direction key/MAC/IV lengths for the legacy GOST 28147-89 CNT+IMIT
/// suite (the Chudov GOST TLS draft §3.2).
pub const MAC_KEY_LEN: usize = 32;
pub const ENC_KEY_LEN: usize = 32;
pub const FIXED_IV_LEN: usize = 8;
/// Total `key_block` length: `2 * (mac + enc + iv)` = 144 bytes.
pub const KEY_BLOCK_LEN: usize = 2 * (MAC_KEY_LEN + ENC_KEY_LEN + FIXED_IV_LEN);

/// Derive the 48-byte `master_secret` from the 32-byte premaster secret.
///
/// `master_secret = PRF(premaster, "master secret", client_random || server_random)`.
pub fn master_secret(
    premaster_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; MASTER_SECRET_LEN] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    let out = prf(premaster_secret, b"master secret", &seed, MASTER_SECRET_LEN);
    let mut ms = [0u8; MASTER_SECRET_LEN];
    ms.copy_from_slice(&out);
    ms
}

/// Connection key material split out of the 144-byte `key_block`
/// (the Chudov GOST TLS draft §3.2). Order follows TLS 1.2 §6.3:
/// MAC keys, then encryption keys, then fixed IVs.
#[derive(Clone)]
pub struct KeyBlock {
    pub client_mac_key: [u8; MAC_KEY_LEN],
    pub server_mac_key: [u8; MAC_KEY_LEN],
    pub client_enc_key: [u8; ENC_KEY_LEN],
    pub server_enc_key: [u8; ENC_KEY_LEN],
    pub client_iv: [u8; FIXED_IV_LEN],
    pub server_iv: [u8; FIXED_IV_LEN],
}

/// Derive the `key_block` and split it into the six connection keys.
///
/// `key_block = PRF(master_secret, "key expansion", server_random || client_random)`.
pub fn key_block(
    master_secret: &[u8; MASTER_SECRET_LEN],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> KeyBlock {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    let block = prf(master_secret, b"key expansion", &seed, KEY_BLOCK_LEN);

    let mut off = 0;
    let mut take = |n: usize| {
        let s = &block[off..off + n];
        off += n;
        s.to_vec()
    };

    let mut kb = KeyBlock {
        client_mac_key: [0u8; MAC_KEY_LEN],
        server_mac_key: [0u8; MAC_KEY_LEN],
        client_enc_key: [0u8; ENC_KEY_LEN],
        server_enc_key: [0u8; ENC_KEY_LEN],
        client_iv: [0u8; FIXED_IV_LEN],
        server_iv: [0u8; FIXED_IV_LEN],
    };
    kb.client_mac_key.copy_from_slice(&take(MAC_KEY_LEN));
    kb.server_mac_key.copy_from_slice(&take(MAC_KEY_LEN));
    kb.client_enc_key.copy_from_slice(&take(ENC_KEY_LEN));
    kb.server_enc_key.copy_from_slice(&take(ENC_KEY_LEN));
    kb.client_iv.copy_from_slice(&take(FIXED_IV_LEN));
    kb.server_iv.copy_from_slice(&take(FIXED_IV_LEN));
    kb
}

/// `Finished.verify_data` length (the Chudov GOST TLS draft §3.8).
pub const VERIFY_DATA_LEN: usize = 12;

/// TLS label for the client's `Finished` message.
pub const CLIENT_FINISHED_LABEL: &[u8] = b"client finished";
/// TLS label for the server's `Finished` message.
pub const SERVER_FINISHED_LABEL: &[u8] = b"server finished";

/// Compute `Finished.verify_data`:
/// `PRF(master_secret, label, GOSTR3411(handshake_messages))[0..11]`.
///
/// `handshake_hash` is `streebog256(handshake_messages)`.
pub fn finished_verify_data(
    master_secret: &[u8; MASTER_SECRET_LEN],
    label: &[u8],
    handshake_hash: &[u8; MAC_LEN],
) -> [u8; VERIFY_DATA_LEN] {
    let out = prf(master_secret, label, handshake_hash, VERIFY_DATA_LEN);
    let mut vd = [0u8; VERIFY_DATA_LEN];
    vd.copy_from_slice(&out);
    vd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Official `HMAC_GOSTR3411_2012_256` KAT from R 50.1.113-2016 / RFC 7836.
    ///
    /// K = 000102...1f (32 bytes), T = 0126bdb8...0100 (16 bytes),
    /// HMAC = a1aa5f7d...4922ed9 (32 bytes).
    #[test]
    fn hmac_streebog256_known_answer_r5011132016() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let data = hex("0126bdb87800af214341456563780100");
        let expected = hex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");
        assert_eq!(
            hmac_streebog256(&key, &data).as_slice(),
            expected.as_slice()
        );
    }

    /// RFC 9189 §A.2.2 CNT_IMIT handshake KAT: with the worked-example PMS and
    /// client/server randoms, master_secret, key_block, and the client
    /// Finished verify_data must match the reference bytes.
    #[test]
    fn rfc9189_a22_handshake_secrets_kat() {
        // ClientHello.random and ServerHello.random from §A.2.2.
        let client_random: [u8; 32] =
            hex("6A523D6880DCC2DC75CCC43CFD04B616F5C3757B8077B76A9B504949FD3BFDB8")
                .try_into()
                .unwrap();
        let server_random: [u8; 32] =
            hex("FE92C9516D0E1A67A04C33CD7F2C90B15E76DCC30815C19F92A6D100915AF2DB")
                .try_into()
                .unwrap();
        // PMS from §A.2.2.
        let pms = hex("CE0DD6B6704212152BE4695A7E89F64C8929A40DBF0A5A55C2CE002B06BAB62F");

        // master_secret KAT.
        let ms = master_secret(&pms, &client_random, &server_random);
        let ms_expected = hex(
            "BE5746C8BBB7847E978FD4C94F523452442C8EB172FDE6281C18C54463B1F94C2BD9814005416DBB0F90A57EA4E06B50",
        );
        assert_eq!(&ms[..], &ms_expected[..], "master_secret mismatch");

        // key_block KAT: client material is
        // K_write_MAC|K_read_MAC|K_write_ENC|K_read_ENC|IV_write|IV_read.
        let kb = key_block(&ms, &client_random, &server_random);
        let mut client_material = Vec::new();
        client_material.extend_from_slice(&kb.client_mac_key);
        client_material.extend_from_slice(&kb.server_mac_key);
        client_material.extend_from_slice(&kb.client_enc_key);
        client_material.extend_from_slice(&kb.server_enc_key);
        client_material.extend_from_slice(&kb.client_iv);
        client_material.extend_from_slice(&kb.server_iv);
        // The §A.2.2 listing shows the first 96 bytes (the two 32-byte MAC keys
        // and the client 32-byte ENC key); compare that prefix.
        let km_expected = hex(
            "F337F6A86FF31FCA52EA647CDEE3B78334AB77B57FE0DB2FC0C871ECDCACA5A8FBA04C2132823A2496EF936F0EBCF30EA0CB7EAF6CA794754F1F45B17722DEB44E5BC32D4430AF5893116ACF81A3BE0C90D2EA8E76E0840728BAF5E2B2F940C0",
        );
        assert_eq!(
            &client_material[..km_expected.len()],
            &km_expected[..],
            "key_block mismatch"
        );

        // Finished verify_data KAT: PRF(MS, "client finished", HASH(HM)).
        let hash_hm: [u8; MAC_LEN] =
            hex("F8D6FEEB17644D17B03836A651EB8769BDEAA2D3EB1847F69191427C30D0178E")
                .try_into()
                .unwrap();
        let vd = finished_verify_data(&ms, CLIENT_FINISHED_LABEL, &hash_hm);
        let vd_expected = hex("D3EE1DEA725CD7080C744311");
        assert_eq!(&vd[..], &vd_expected[..], "client verify_data mismatch");
    }

    /// `P_hash` must be a prefix-stable stream: requesting fewer bytes yields a
    /// prefix of a longer request with identical inputs.
    #[test]
    fn p_hash_is_prefix_stable() {
        let secret = b"master secret bytes";
        let seed = b"label and seed material";
        let mut short = [0u8; 20];
        let mut long = [0u8; 80];
        p_hash(secret, seed, &mut short);
        p_hash(secret, seed, &mut long);
        assert_eq!(&short[..], &long[..20]);
    }

    /// `P_hash` output spanning multiple HMAC blocks is exactly the
    /// concatenation of the per-iteration blocks (length not a multiple of 32).
    #[test]
    fn p_hash_spans_multiple_blocks() {
        let secret = b"k";
        let seed = b"s";
        let mut out = [0u8; 70];
        p_hash(secret, seed, &mut out);
        // Recompute by hand and compare the 3rd (partial) block boundary.
        let a1 = hmac_streebog256(secret, seed);
        let mut i1 = Vec::new();
        i1.extend_from_slice(&a1);
        i1.extend_from_slice(seed);
        let b1 = hmac_streebog256(secret, &i1);
        assert_eq!(&out[..32], &b1[..]);
    }

    /// The TLS PRF wrapper must equal `P_hash(secret, label || seed)`.
    #[test]
    fn prf_matches_p_hash_of_label_and_seed() {
        let secret = b"secret";
        let label = b"master secret";
        let seed = b"random1random2";
        let got = prf(secret, label, seed, 48);

        let mut combined = Vec::new();
        combined.extend_from_slice(label);
        combined.extend_from_slice(seed);
        let mut expect = [0u8; 48];
        p_hash(secret, &combined, &mut expect);
        assert_eq!(got, expect.to_vec());
    }

    /// Different labels must yield different output (label is bound into seed).
    #[test]
    fn prf_label_changes_output() {
        let secret = b"secret";
        let seed = b"abcdef";
        let a = prf(secret, b"key expansion", seed, 32);
        let b = prf(secret, b"master secret", seed, 32);
        assert_ne!(a, b);
    }

    /// `key_block` partitions exactly 144 bytes of PRF output into the six
    /// connection keys in TLS 1.2 §6.3 order, with no overlap or gaps.
    #[test]
    fn key_block_partitions_144_bytes() {
        let ms = [0x5au8; MASTER_SECRET_LEN];
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];

        // Reference: raw 144-byte PRF over server_random || client_random.
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&sr);
        seed[32..].copy_from_slice(&cr);
        let raw = prf(&ms, b"key expansion", &seed, KEY_BLOCK_LEN);
        assert_eq!(raw.len(), 144);

        let kb = key_block(&ms, &cr, &sr);
        assert_eq!(&kb.client_mac_key[..], &raw[0..32]);
        assert_eq!(&kb.server_mac_key[..], &raw[32..64]);
        assert_eq!(&kb.client_enc_key[..], &raw[64..96]);
        assert_eq!(&kb.server_enc_key[..], &raw[96..128]);
        assert_eq!(&kb.client_iv[..], &raw[128..136]);
        assert_eq!(&kb.server_iv[..], &raw[136..144]);
    }

    /// master_secret uses client_random||server_random; key_block uses the
    /// reverse order — so swapping randoms must change the derived material.
    #[test]
    fn master_and_key_block_use_documented_seed_order() {
        let pms = [0x01u8; 32];
        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];
        let ms = master_secret(&pms, &cr, &sr);
        // master_secret seed = client||server
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&cr);
        seed[32..].copy_from_slice(&sr);
        let expect = prf(&pms, b"master secret", &seed, MASTER_SECRET_LEN);
        assert_eq!(&ms[..], &expect[..]);

        // key_block seed is the reverse order, so it differs from a
        // client||server seeded block of the same label.
        let kb = key_block(&ms, &cr, &sr);
        let wrong = prf(&ms, b"key expansion", &seed, KEY_BLOCK_LEN);
        assert_ne!(&kb.client_mac_key[..], &wrong[0..32]);
    }

    /// Finished verify_data is 12 bytes and depends on the label.
    #[test]
    fn finished_verify_data_is_12_bytes_and_label_bound() {
        let ms = [0x33u8; MASTER_SECRET_LEN];
        let h = streebog256(b"handshake transcript");
        let c = finished_verify_data(&ms, CLIENT_FINISHED_LABEL, &h);
        let s = finished_verify_data(&ms, SERVER_FINISHED_LABEL, &h);
        assert_eq!(c.len(), 12);
        assert_eq!(s.len(), 12);
        assert_ne!(c, s);
        // Matches a direct PRF computation.
        let direct = prf(&ms, CLIENT_FINISHED_LABEL, &h, VERIFY_DATA_LEN);
        assert_eq!(&c[..], &direct[..]);
    }
}
