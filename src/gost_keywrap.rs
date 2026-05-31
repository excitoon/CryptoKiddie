//! GOST key wrap and KEK diversification (RFC 4357 §6.3, §6.5).
//!
//! These algorithms wrap a 32-byte GOST 28147-89 content-encryption key (CEK)
//! — in the TLS case, the 32-byte premaster secret — under a key-encryption key
//! (KEK) derived by VKO from the token. The wrapped blob `UKM | CEK_ENC |
//! CEK_MAC` is what the GOST `ClientKeyExchange` carries inside its
//! `TLSGostKeyTransportBlob` (the Chudov GOST TLS draft §3.6).
//!
//! All keys and IVs are interpreted little-endian (RFC 4357 §1.1). The
//! underlying ECB / CFB / IMIT operations come from [`crate::gost28147`], whose
//! block core is anchored by the RFC 8891 Magma KAT.
//!
//! VALIDATION NOTE: the GOST 28147-89 primitives are KAT-anchored, but this
//! *composition* (the diversification bit-order, the `S[i]` construction, the
//! CFB feedback direction and the wrap field order) is currently verified only
//! by wrap→unwrap round-trips and tamper detection. An independent reference
//! vector (e.g. an RFC 4490 CMS example) or a live exchange is needed to fully
//! confirm interoperability.

use crate::gost28147::{Gost28147, imit};

/// Length of the wrapped key blob: `UKM(8) | CEK_ENC(32) | CEK_MAC(4)`.
pub const WRAPPED_KEY_LEN: usize = 8 + 32 + 4;

/// Encrypt `data` (a multiple of 8 bytes) in ECB mode under `cipher`.
fn encrypt_ecb(cipher: &Gost28147, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let block: [u8; 8] = chunk.try_into().expect("8-byte block");
        out.extend_from_slice(&cipher.encrypt_block_le(&block));
    }
    out
}

/// Decrypt `data` (a multiple of 8 bytes) in ECB mode under `cipher`.
fn decrypt_ecb(cipher: &Gost28147, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let block: [u8; 8] = chunk.try_into().expect("8-byte block");
        out.extend_from_slice(&cipher.decrypt_block_le(&block));
    }
    out
}

/// Encrypt `data` (a multiple of 8 bytes) in 64-bit CFB mode under `cipher`
/// with the given 8-byte IV (RFC 4357 §1.1 `encryptCFB`).
fn encrypt_cfb(cipher: &Gost28147, iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut feedback = *iv;
    for chunk in data.chunks_exact(8) {
        let gamma = cipher.encrypt_block_le(&feedback);
        let mut cblock = [0u8; 8];
        for i in 0..8 {
            cblock[i] = chunk[i] ^ gamma[i];
        }
        out.extend_from_slice(&cblock);
        feedback = cblock;
    }
    out
}

/// KEK diversification (RFC 4357 §6.5): derive `K(UKM)` from a
/// 32-byte key and an 8-byte UKM.
pub fn kek_diversify(kek: &[u8; 32], ukm: &[u8; 8]) -> [u8; 32] {
    let mut k = *kek;
    for &ukm_byte in ukm.iter() {
        // Split K[i] into eight little-endian 32-bit words and accumulate the
        // two sums selected by the bits of this UKM byte.
        let mut s1: u32 = 0;
        let mut s2: u32 = 0;
        for j in 0..8 {
            let word = u32::from_le_bytes([k[4 * j], k[4 * j + 1], k[4 * j + 2], k[4 * j + 3]]);
            if (ukm_byte >> j) & 1 == 1 {
                s1 = s1.wrapping_add(word);
            } else {
                s2 = s2.wrapping_add(word);
            }
        }
        let mut s = [0u8; 8];
        s[0..4].copy_from_slice(&s1.to_le_bytes());
        s[4..8].copy_from_slice(&s2.to_le_bytes());

        // K[i+1] = encryptCFB(S[i], K[i], K[i]).
        let cipher = Gost28147::new_gost(&k);
        let next = encrypt_cfb(&cipher, &s, &k);
        k.copy_from_slice(&next);
    }
    k
}

/// A GOST-wrapped content-encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    pub ukm: [u8; 8],
    pub cek_enc: [u8; 32],
    pub cek_mac: [u8; 4],
}

impl WrappedKey {
    /// Serialize as `UKM | CEK_ENC | CEK_MAC` (44 bytes).
    pub fn to_bytes(&self) -> [u8; WRAPPED_KEY_LEN] {
        let mut out = [0u8; WRAPPED_KEY_LEN];
        out[0..8].copy_from_slice(&self.ukm);
        out[8..40].copy_from_slice(&self.cek_enc);
        out[40..44].copy_from_slice(&self.cek_mac);
        out
    }

    /// Parse from the 44-byte `UKM | CEK_ENC | CEK_MAC` layout.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyWrapError> {
        if bytes.len() != WRAPPED_KEY_LEN {
            return Err(KeyWrapError::BadLength);
        }
        let mut ukm = [0u8; 8];
        let mut cek_enc = [0u8; 32];
        let mut cek_mac = [0u8; 4];
        ukm.copy_from_slice(&bytes[0..8]);
        cek_enc.copy_from_slice(&bytes[8..40]);
        cek_mac.copy_from_slice(&bytes[40..44]);
        Ok(Self {
            ukm,
            cek_enc,
            cek_mac,
        })
    }
}

/// GOST key wrap (RFC 4357 §6.3): wrap a 32-byte `cek` under `kek` using
/// the 8-byte `ukm` (the shared UKM from VKO).
pub fn gost_key_wrap(kek: &[u8; 32], ukm: &[u8; 8], cek: &[u8; 32]) -> WrappedKey {
    let kek_ukm = kek_diversify(kek, ukm);
    // CEK_MAC = gost28147IMIT(UKM, KEK(UKM), CEK).
    let cek_mac = imit(&kek_ukm, ukm, cek);
    // CEK_ENC = encryptECB(KEK(UKM), CEK).
    let cipher = Gost28147::new_gost(&kek_ukm);
    let enc = encrypt_ecb(&cipher, cek);
    let mut cek_enc = [0u8; 32];
    cek_enc.copy_from_slice(&enc);
    WrappedKey {
        ukm: *ukm,
        cek_enc,
        cek_mac,
    }
}

/// GOST key unwrap (RFC 4357 §6.4): recover the 32-byte CEK, verifying the
/// MAC.
pub fn gost_key_unwrap(kek: &[u8; 32], wrapped: &WrappedKey) -> Result<[u8; 32], KeyWrapError> {
    let kek_ukm = kek_diversify(kek, &wrapped.ukm);
    let cipher = Gost28147::new_gost(&kek_ukm);
    let dec = decrypt_ecb(&cipher, &wrapped.cek_enc);
    let mut cek = [0u8; 32];
    cek.copy_from_slice(&dec);

    let expected = imit(&kek_ukm, &wrapped.ukm, &cek);
    if !constant_time_eq(&expected, &wrapped.cek_mac) {
        return Err(KeyWrapError::BadMac);
    }
    Ok(cek)
}

fn constant_time_eq(a: &[u8; 4], b: &[u8; 4]) -> bool {
    let mut diff = 0u8;
    for i in 0..4 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Errors from key wrapping/unwrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapError {
    /// Wrapped blob is not 44 bytes.
    BadLength,
    /// CEK_MAC verification failed.
    BadMac,
}

impl core::fmt::Display for KeyWrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyWrapError::BadLength => write!(f, "wrapped key not 44 bytes"),
            KeyWrapError::BadMac => write!(f, "CEK_MAC verification failed"),
        }
    }
}

impl std::error::Error for KeyWrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
    }

    /// Cross-implementation KAT against the gost-engine C reference
    /// (`gost89.c` + `gost_keywrap.c`, S-box `Gost28147_TC26ParamSetZ`).
    /// Inputs: `kek[i]=i*7+3`, `ukm=0x11*(i+1)`, `cek=200-i`. The expected
    /// values were produced by compiling and running that reference; they pin
    /// the little-endian GOST 28147-89 block core, the §6.5 diversification and
    /// the full §6.3 wrap byte-for-byte to the canonical reference behaviour.
    #[test]
    fn key_wrap_kat_matches_gost_engine_reference() {
        let kek = kek();
        let ukm = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let cek: [u8; 32] = core::array::from_fn(|i| (200 - i) as u8);

        // Block core: ECB of 00..07 under KEK.
        let cipher = Gost28147::new_gost(&kek);
        assert_eq!(
            cipher.encrypt_block_le(&[0, 1, 2, 3, 4, 5, 6, 7]),
            [0x62, 0x06, 0xb7, 0xa1, 0x4b, 0xd1, 0x4f, 0xc5]
        );

        // KEK diversification (§6.5).
        let div = kek_diversify(&kek, &ukm);
        let expected_div: [u8; 32] = [
            0xc8, 0x04, 0xd4, 0x10, 0x4f, 0x36, 0xbb, 0xc6, 0x07, 0xfb, 0x6a, 0x0c, 0x8f, 0xcc,
            0x35, 0xf4, 0x13, 0x4e, 0x7d, 0x35, 0x95, 0x09, 0x35, 0x1b, 0xdd, 0x64, 0xa8, 0x57,
            0xa7, 0x53, 0x32, 0x61,
        ];
        assert_eq!(div, expected_div);

        // Full GOST key wrap (§6.3): UKM | CEK_ENC | CEK_MAC.
        let wrapped = gost_key_wrap(&kek, &ukm, &cek).to_bytes();
        let expected_wrap: [u8; 44] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // UKM
            0x45, 0xff, 0xfb, 0x70, 0xed, 0x51, 0x9f, 0xee, 0x6d, 0x07, 0xa0, 0x37, 0x08, 0xdb,
            0xd0, 0x8d, 0x1e, 0x37, 0x24, 0x42, 0xfa, 0x12, 0x63, 0xcb, 0x24, 0xbe, 0x02, 0x5f,
            0x7a, 0x64, 0xee, 0x1e, // CEK_ENC
            0x9e, 0x47, 0x1c, 0xae, // CEK_MAC
        ];
        assert_eq!(wrapped, expected_wrap);
    }

    /// Wrap then unwrap recovers the original CEK.
    #[test]
    fn wrap_unwrap_round_trip() {
        let kek = kek();
        let ukm = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let cek: [u8; 32] = core::array::from_fn(|i| (200 - i) as u8);

        let wrapped = gost_key_wrap(&kek, &ukm, &cek);
        let recovered = gost_key_unwrap(&kek, &wrapped).expect("valid MAC");
        assert_eq!(recovered, cek);
        // CEK_ENC must not equal the plaintext CEK.
        assert_ne!(&wrapped.cek_enc[..], &cek[..]);
    }

    /// Serialization round-trips through the 44-byte wire layout.
    #[test]
    fn wrapped_key_bytes_round_trip() {
        let kek = kek();
        let ukm = [1, 2, 3, 4, 5, 6, 7, 8];
        let cek = [0x42u8; 32];
        let wrapped = gost_key_wrap(&kek, &ukm, &cek);

        let bytes = wrapped.to_bytes();
        assert_eq!(bytes.len(), 44);
        let parsed = WrappedKey::from_bytes(&bytes).expect("valid length");
        assert_eq!(parsed, wrapped);
    }

    /// Tampering with CEK_ENC must fail the MAC check.
    #[test]
    fn tampered_cek_enc_fails_mac() {
        let kek = kek();
        let ukm = [9, 8, 7, 6, 5, 4, 3, 2];
        let cek = [0x55u8; 32];
        let mut wrapped = gost_key_wrap(&kek, &ukm, &cek);
        wrapped.cek_enc[0] ^= 0x01;
        assert_eq!(
            gost_key_unwrap(&kek, &wrapped).unwrap_err(),
            KeyWrapError::BadMac
        );
    }

    /// A different UKM diversifies the KEK differently, so the wrap differs and
    /// unwrapping under the wrong UKM fails the MAC.
    #[test]
    fn ukm_diversifies_the_wrap() {
        let kek = kek();
        let cek = [0x77u8; 32];
        let w1 = gost_key_wrap(&kek, &[1; 8], &cek);
        let w2 = gost_key_wrap(&kek, &[2; 8], &cek);
        assert_ne!(w1.cek_enc, w2.cek_enc);

        // Swap in the wrong UKM: MAC fails.
        let forged = WrappedKey {
            ukm: [2; 8],
            ..w1.clone()
        };
        assert_eq!(
            gost_key_unwrap(&kek, &forged).unwrap_err(),
            KeyWrapError::BadMac
        );
    }

    /// Diversification is deterministic and UKM-sensitive.
    #[test]
    fn kek_diversify_is_deterministic_and_sensitive() {
        let kek = kek();
        let a = kek_diversify(&kek, &[0x0F; 8]);
        let b = kek_diversify(&kek, &[0x0F; 8]);
        let c = kek_diversify(&kek, &[0xF0; 8]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // A diversified key must differ from the input key.
        assert_ne!(a, kek);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert_eq!(
            WrappedKey::from_bytes(&[0u8; 40]).unwrap_err(),
            KeyWrapError::BadLength
        );
    }
}
