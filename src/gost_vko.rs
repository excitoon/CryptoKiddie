//! VKO_GOSTR3410_2012_256 key agreement (RFC 7836 §4.3.1) and the RFC 9189
//! CNT_IMIT ephemeral key-transport export key (KEG_28147).
//!
//! Per RFC 9189 §4.2.4.2, the TLS_GOSTR341112_256_WITH_28147_CNT_IMIT suite
//! (0xFF85) does **not** use the client certificate key for key agreement. The
//! client generates an *ephemeral* key pair `(d_eph, Q_eph)` on the server's
//! curve and derives the export key from `VKO_256(d_eph, Q_s, UKM)`; the client
//! certificate key is used only to sign `CertificateVerify`.
//!
//! VKO_256: `KEK = Streebog256(K)`, `K = (UKM * x mod q) * Q`, where the shared
//! point is serialized `X_le ‖ Y_le` (RFC 7836 §3: x then y, little-endian).
//! The GOST curves used here have cofactor 1, so `m/q` is omitted.

use crate::gost_ec::{Curve, Point};
use crate::gost_prf::streebog256;
use num_bigint::BigUint;
use num_traits::Zero;

/// Compute `VKO_GOSTR3410_2012_256(own_private, peer_public, ukm)` → 32-byte KEK.
///
/// `ukm` is interpreted as a little-endian integer (the GOST/TC26
/// convention; the same value carried in the key-transport blob's `ukm` field).
pub fn vko_256(curve: &Curve, own_private: &BigUint, peer_public: &Point, ukm: &[u8]) -> [u8; 32] {
    let ukm_int = BigUint::from_bytes_le(ukm);
    // scalar = UKM * x mod q  (cofactor m/q == 1)
    let scalar = (&ukm_int * own_private) % &curve.q;
    let shared = curve.scalar_mul(&scalar, peer_public);
    let ser = curve
        .encode_point_le(&shared)
        .expect("shared point is not at infinity for valid inputs");
    streebog256(&ser)
}

/// Compute the public point `Q = d * P` for a private scalar `d`.
pub fn public_point(curve: &Curve, private: &BigUint) -> Point {
    curve.scalar_mul(private, &curve.generator())
}

/// A freshly generated ephemeral key pair on a given curve.
pub struct Ephemeral {
    /// Private scalar `d_eph` in `[1, q-1]`.
    pub private: BigUint,
    /// Public point `Q_eph = d_eph * P`.
    pub public: Point,
}

/// Generate an ephemeral key pair on `curve` using `fill` for entropy.
///
/// `fill` must populate the slice with cryptographically secure random bytes
/// (e.g. `getrandom::getrandom`). The scalar is reduced into `[1, q-1]`.
pub fn ephemeral_keypair<F>(curve: &Curve, mut fill: F) -> Result<Ephemeral, String>
where
    F: FnMut(&mut [u8]) -> Result<(), String>,
{
    // Draw an extra 16 bytes of entropy before reduction to keep the modular
    // bias negligible (RFC 6979 §3.3 style oversampling).
    let mut buf = vec![0u8; curve.field_bytes + 16];
    fill(&mut buf)?;
    let mut d = BigUint::from_bytes_be(&buf) % &curve.q;
    if d.is_zero() {
        d = BigUint::from(1u32);
    }
    let public = public_point(curve, &d);
    Ok(Ephemeral { private: d, public })
}

/// The export key material for the RFC 9189 CNT_IMIT ClientKeyExchange.
pub struct ExportKey {
    /// The 32-byte VKO output `R = VKO_256(d_eph, Q_s, UKM)` — feed this to
    /// [`crate::gost_keywrap::gost_key_wrap`] as the KEK (it applies CPDivers
    /// internally to obtain `K_EXP`).
    pub kek: [u8; 32],
    /// The ephemeral public point `Q_eph` to carry in the blob.
    pub ephemeral_public: Point,
}

/// Derive the export key by generating an ephemeral key pair and running VKO
/// against the server's public point.
pub fn derive_export_key<F>(
    curve: &Curve,
    server_public: &Point,
    ukm: &[u8],
    fill: F,
) -> Result<ExportKey, String>
where
    F: FnMut(&mut [u8]) -> Result<(), String>,
{
    let eph = ephemeral_keypair(curve, fill)?;
    let kek = vko_256(curve, &eph.private, server_public, ukm);
    Ok(ExportKey {
        kek,
        ephemeral_public: eph.public,
    })
}

/// The result of preparing an RFC 9189 CNT_IMIT ClientKeyExchange key transport.
pub struct KeyTransport {
    /// `R = VKO_256(d_eph, Q_s, UKM)` — pass as the KEK to `gost_key_wrap`.
    pub kek: [u8; 32],
    /// The DER *content* of the ephemeral `SubjectPublicKeyInfo` (algorithm
    /// identifier + `subjectPublicKey` BIT STRING), ready to be re-tagged
    /// `[0] IMPLICIT` inside `transportParameters.ephemeralPublicKey`.
    pub ephemeral_spki_content: Vec<u8>,
}

/// Prepare the software ephemeral key transport for the 0xFF85 handshake.
///
/// * `server_point` — the server leaf cert's raw public point (`X_le ‖ Y_le`).
/// * `server_spki_algorithm` — the server SPKI's `algorithm` AlgorithmIdentifier
///   DER (tag `0x30…`); reused verbatim for the ephemeral key so the
///   `publicKeyParamSet` exactly matches the server's curve.
/// * `ukm` — the 8-byte shared UKM.
/// * `fill` — CSPRNG entropy source for the ephemeral private key.
///
/// The server's curve is identified by trying each known 256-bit TC26 set
/// and checking which one the server point lies on.
pub fn software_key_transport<F>(
    server_point: &[u8],
    server_spki_algorithm: &[u8],
    ukm: &[u8],
    fill: F,
) -> Result<KeyTransport, String>
where
    F: FnMut(&mut [u8]) -> Result<(), String>,
{
    let (curve, server_public) = detect_curve_and_point(server_point)
        .ok_or_else(|| "server public point is not on any known 256-bit GOST curve".to_string())?;

    let export = derive_export_key(&curve, &server_public, ukm, fill)?;
    let q_eph = curve
        .encode_point_le(&export.ephemeral_public)
        .ok_or_else(|| "ephemeral public key is the point at infinity".to_string())?;

    // subjectPublicKey BIT STRING = 0x00 unused-bits || OCTET STRING(X_le ‖ Y_le).
    let octet = der_tlv(0x04, &q_eph);
    let mut bitstr_content = vec![0x00];
    bitstr_content.extend_from_slice(&octet);
    let bitstring = der_tlv(0x03, &bitstr_content);

    let mut spki_content = server_spki_algorithm.to_vec();
    spki_content.extend_from_slice(&bitstring);

    Ok(KeyTransport {
        kek: export.kek,
        ephemeral_spki_content: spki_content,
    })
}

/// Try each known 256-bit curve and return the one the raw point lies on.
fn detect_curve_and_point(server_point: &[u8]) -> Option<(Curve, Point)> {
    use crate::gost_ec::{tc26_256_paramset_b, tc26_256_paramset_c, tc26_256_paramset_d};
    for curve in [
        tc26_256_paramset_b(),
        tc26_256_paramset_c(),
        tc26_256_paramset_d(),
    ] {
        if let Some(point) = curve.decode_point_le(server_point) {
            return Some((curve, point));
        }
    }
    None
}

/// Minimal DER TLV with definite short/long length.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut n = len;
        let mut bytes = Vec::new();
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gost_ec::tests_support::paramset_a_512;

    /// RFC 7836 Appendix B, example 7: VKO_GOSTR3410_2012_256 with 256-bit
    /// output on the 512-bit `paramSetA` keys.
    #[test]
    fn vko_256_rfc7836_example7() {
        let c = paramset_a_512();

        // Private keys are stored little-endian (GOST/pyGOST convention).
        let x_a = BigUint::from_bytes_le(&hx_bytes(
            "c9 90 ec d9 72 fc e8 4e c4 db 02 27 78 f5 0f ca
             c7 26 f4 67 08 38 4b 8d 45 83 04 96 2d 71 47 f8
             c2 db 41 ce f2 2c 90 b1 02 f2 96 84 04 f9 b9 be
             6d 47 c7 96 92 d8 18 26 b3 2b 8d ac a4 3c b6 67",
        ));

        // Public key x*P of A (curve point, X_le ‖ Y_le as stored).
        let qa_bytes = hx_bytes(
            "aa b0 ed a4 ab ff 21 20 8d 18 79 9f b9 a8 55 66
             54 ba 78 30 70 eb a1 0c b9 ab b2 53 ec 56 dc f5
             d3 cc ba 61 92 e4 64 e6 e5 bc b6 de a1 37 79 2f
             24 31 f6 c8 97 eb 1b 3c 0c c1 43 27 b1 ad c0 a7
             91 46 13 a3 07 4e 36 3a ed b2 04 d3 8d 35 63 97
             1b d8 75 8e 87 8c 9d b1 14 03 72 1b 48 00 2d 38
             46 1f 92 47 2d 40 ea 92 f9 95 8c 0f fa 4c 93 75
             64 01 b9 7f 89 fd be 0b 5e 46 e4 a4 63 1c db 5a",
        );

        let qb_bytes = hx_bytes(
            "19 2f e1 83 b9 71 3a 07 72 53 c7 2c 87 35 de 2e
             a4 2a 3d bc 66 ea 31 78 38 b6 5f a3 25 23 cd 5e
             fc a9 74 ed a7 c8 63 f4 95 4d 11 47 f1 f2 b2 5c
             39 5f ce 1c 12 91 75 e8 76 d1 32 e9 4e d5 a6 51
             04 88 3b 41 4c 9b 59 2e c4 dc 84 82 6f 07 d0 b6
             d9 00 6d da 17 6c e4 8c 39 1e 3f 97 d1 02 e0 3b
             b5 98 bf 13 2a 22 8a 45 f7 20 1a ba 08 fc 52 4a
             2d 77 e4 3a 36 2a b0 22 ad 40 28 f7 5b de 3b 79",
        );

        let ukm = hx_bytes("1d 80 60 3c 85 44 c7 27");

        let expected_kek = hx_bytes(
            "c9 a9 a7 73 20 e2 cc 55 9e d7 2d ce 6f 47 e2 19
             2c ce a9 5f a6 48 67 05 82 c0 54 c0 ef 36 c2 21",
        );

        // 1) Confirm scalar / public-key byte order: x_A * P == stored Q_A.
        let qa = public_point(&c, &x_a);
        assert_eq!(
            c.encode_point_le(&qa).unwrap(),
            qa_bytes,
            "private-key byte order or scalar-mul is wrong"
        );

        // 2) Q_B parses on-curve as little-endian halves.
        let qb = c
            .decode_point_le(&qb_bytes)
            .expect("Q_B should be a valid little-endian point on the curve");

        // 3) VKO(x_A, Q_B, UKM) matches the published KEK.
        let kek = vko_256(&c, &x_a, &qb, &ukm);
        assert_eq!(kek.to_vec(), expected_kek, "VKO_256 KEK mismatch");
    }

    fn hx_bytes(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
        (0..cleaned.len() / 2)
            .map(|i| u8::from_str_radix(&cleaned[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Ephemeral DH agreement on the 256-bit paramSetB curve: both parties
    /// derive the same KEK from their own private and the peer's public point.
    #[test]
    fn ephemeral_agreement_is_symmetric_256() {
        use crate::gost_ec::tc26_256_paramset_b;
        let c = tc26_256_paramset_b();
        let ukm = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        // Deterministic pseudo-entropy for the test (NOT for production).
        let mut seed_a = 0x1234_5678u64;
        let fill_a = |buf: &mut [u8]| -> Result<(), String> {
            for b in buf.iter_mut() {
                seed_a = seed_a.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed_a >> 33) as u8;
            }
            Ok(())
        };
        let mut seed_b = 0x9E37_79B9u64;
        let fill_b = |buf: &mut [u8]| -> Result<(), String> {
            for b in buf.iter_mut() {
                seed_b = seed_b.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed_b >> 33) as u8;
            }
            Ok(())
        };

        let a = ephemeral_keypair(&c, fill_a).unwrap();
        let b = ephemeral_keypair(&c, fill_b).unwrap();
        assert!(c.is_on_curve(&a.public));
        assert!(c.is_on_curve(&b.public));

        let kek_ab = vko_256(&c, &a.private, &b.public, &ukm);
        let kek_ba = vko_256(&c, &b.private, &a.public, &ukm);
        assert_eq!(kek_ab, kek_ba, "ephemeral VKO must be symmetric");
    }
}
