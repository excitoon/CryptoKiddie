//! DER encoding of the GOST `ClientKeyExchange` key-transport blob
//! (`GostR3410-KeyTransport`, RFC 4490 §2.2), used by the 0xFF85 suite.
//!
//! ASN.1 (RFC 4490):
//! ```text
//! GostR3410-KeyTransport ::= SEQUENCE {
//!     sessionEncryptedKey   Gost28147-89-EncryptedKey,
//!     transportParameters
//!       [0] IMPLICIT GostR3410-TransportParameters OPTIONAL }
//!
//! Gost28147-89-EncryptedKey ::= SEQUENCE {
//!     encryptedKey          OCTET STRING,            -- CEK_ENC (32)
//!     maskKey           [0] IMPLICIT OCTET STRING OPTIONAL,
//!     macKey                OCTET STRING }           -- CEK_MAC (4)
//!
//! GostR3410-TransportParameters ::= SEQUENCE {
//!     encryptionParamSet    OBJECT IDENTIFIER,
//!     ephemeralPublicKey
//!       [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
//!     ukm                   OCTET STRING }           -- (8)
//! ```
//!
//! For the RFC 9189 CNT_IMIT suite (0xFF85) the client generates an *ephemeral*
//! key pair on the server's curve and carries its public key in
//! `ephemeralPublicKey`; `maskKey` is omitted. (The client certificate key is
//! used only for the `CertificateVerify` signature, not for key agreement.)
//!
//! Only the DER *encoder* lives here; it is fully offline-testable. The bytes
//! it wraps come from [`crate::gost_keywrap::WrappedKey`].

use crate::gost_keywrap::{WrappedKey, gost_key_wrap};
use crate::gost_prf::streebog256;

/// OID `id-tc26-gost-28147-param-Z` (1.2.643.7.1.2.5.1.1) — the GOST 28147-89
/// S-box parameter set used by the 0xFF85 suite.
pub const PARAM_Z_OID: &[u32] = &[1, 2, 643, 7, 1, 2, 5, 1, 1];

/// Derive the 8-byte shared UKM for the GOST `ClientKeyExchange` from the
/// handshake randoms: `UKM = Streebog256(client_random || server_random)[0..8]`
/// (the Chudov GOST TLS draft §3.6).
pub fn derive_shared_ukm(client_random: &[u8; 32], server_random: &[u8; 32]) -> [u8; 8] {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(client_random);
    buf[32..64].copy_from_slice(server_random);
    let h = streebog256(&buf);
    let mut ukm = [0u8; 8];
    ukm.copy_from_slice(&h[0..8]);
    ukm
}

/// Assemble the full GOST `ClientKeyExchange` payload (the DER
/// `GostR3410-KeyTransport` blob) given the KEK already derived from the token
/// via VKO, the handshake randoms and the 32-byte premaster secret.
///
/// This is the offline half of the exchange: only the `kek` argument depends on
/// the live token (VKO output). The shared UKM is derived from the randoms, the
/// premaster is GOST-wrapped under the KEK, and the result is DER-encoded
/// with the param-Z S-box OID.
pub fn build_client_key_exchange(
    kek: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    premaster: &[u8; 32],
    ephemeral_spki_content: Option<&[u8]>,
) -> Vec<u8> {
    let ukm = derive_shared_ukm(client_random, server_random);
    let wrapped = gost_key_wrap(kek, &ukm, premaster);
    let key_transport =
        encode_key_transport_with_param_set(&wrapped, PARAM_Z_OID, ephemeral_spki_content);
    // The CNT_IMIT (0xFF85) ClientKeyExchange body is a
    // `TLSGostKeyTransportBlob ::= SEQUENCE { keyBlob GostR3410-KeyTransport }`
    // (RFC 9189 §4.2.4.2), i.e. the `GostR3410-KeyTransport` SEQUENCE wrapped in
    // one more outer SEQUENCE. See the §A.2.2 worked example (`3081F2 3081EF…`).
    der_sequence(&key_transport)
}

/// Encode a DER length (definite form).
fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

/// Encode a tag-length-value with the given tag byte and content.
fn der_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    der_len(content.len(), out);
    out.extend_from_slice(content);
}

/// Encode an OCTET STRING (tag 0x04).
fn der_octet_string(content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 2);
    der_tlv(0x04, content, &mut v);
    v
}

/// Encode a base-128 OID component into `out`.
fn der_oid_arc(mut value: u32, out: &mut Vec<u8>) {
    let mut bytes = Vec::new();
    bytes.push((value & 0x7f) as u8);
    value >>= 7;
    while value > 0 {
        bytes.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

/// Encode an OBJECT IDENTIFIER (tag 0x06) from its arc list.
fn der_oid(arcs: &[u32]) -> Vec<u8> {
    debug_assert!(arcs.len() >= 2, "OID needs at least two arcs");
    let mut content = Vec::new();
    content.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        der_oid_arc(arc, &mut content);
    }
    let mut v = Vec::new();
    der_tlv(0x06, &content, &mut v);
    v
}

/// Encode a SEQUENCE (tag 0x30) wrapping the already-encoded `content`.
fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 4);
    der_tlv(0x30, content, &mut v);
    v
}

/// Encode the `Gost28147-89-EncryptedKey` SEQUENCE { encryptedKey, macKey }
/// (maskKey omitted).
fn encode_session_encrypted_key(wrapped: &WrappedKey) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&der_octet_string(&wrapped.cek_enc));
    content.extend_from_slice(&der_octet_string(&wrapped.cek_mac));
    der_sequence(&content)
}

/// Encode the `GostR3410-TransportParameters` body { encryptionParamSet,
/// ephemeralPublicKey?, ukm }, tagged `[0] IMPLICIT` (0xA0).
///
/// `ephemeral_spki_content`, when present, is the *content* of the ephemeral
/// `SubjectPublicKeyInfo` SEQUENCE (its `algorithm` AlgorithmIdentifier followed
/// by the `subjectPublicKey` BIT STRING); it is re-tagged `[0] IMPLICIT` (0xA0),
/// which replaces the SPKI's outer SEQUENCE tag.
fn encode_transport_parameters(
    param_set_oid: &[u32],
    ukm: &[u8; 8],
    ephemeral_spki_content: Option<&[u8]>,
) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&der_oid(param_set_oid));
    if let Some(spki) = ephemeral_spki_content {
        // ephemeralPublicKey [0] IMPLICIT SubjectPublicKeyInfo -> tag 0xA0.
        der_tlv(0xA0, spki, &mut content);
    }
    content.extend_from_slice(&der_octet_string(ukm));
    // [0] IMPLICIT SEQUENCE -> context-constructed tag 0xA0.
    let mut v = Vec::new();
    der_tlv(0xA0, &content, &mut v);
    v
}

/// Encode the full `GostR3410-KeyTransport` blob for the `ClientKeyExchange`,
/// using the param-Z S-box OID (the 0xFF85 default), with no ephemeral key.
pub fn encode_key_transport(wrapped: &WrappedKey) -> Vec<u8> {
    encode_key_transport_with_param_set(wrapped, PARAM_Z_OID, None)
}

/// Encode the blob with an explicit `encryptionParamSet` OID and an optional
/// ephemeral `SubjectPublicKeyInfo` content (see [`encode_transport_parameters`]).
pub fn encode_key_transport_with_param_set(
    wrapped: &WrappedKey,
    param_set_oid: &[u32],
    ephemeral_spki_content: Option<&[u8]>,
) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&encode_session_encrypted_key(wrapped));
    content.extend_from_slice(&encode_transport_parameters(
        param_set_oid,
        &wrapped.ukm,
        ephemeral_spki_content,
    ));
    der_sequence(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_wrapped() -> WrappedKey {
        WrappedKey {
            ukm: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            cek_enc: core::array::from_fn(|i| i as u8),
            cek_mac: [0xAA, 0xBB, 0xCC, 0xDD],
        }
    }

    /// param-Z OID encodes to the canonical 1.2.643.7.1.2.5.1.1 bytes.
    #[test]
    fn param_z_oid_bytes() {
        let oid = der_oid(PARAM_Z_OID);
        // 06 09 2A 85 03 07 01 02 05 01 01
        assert_eq!(
            oid,
            vec![
                0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
            ]
        );
    }

    /// Long-form length encoding for >127-byte content.
    #[test]
    fn der_len_long_form() {
        let mut out = Vec::new();
        der_len(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2C]);
        let mut short = Vec::new();
        der_len(40, &mut short);
        assert_eq!(short, vec![0x28]);
    }

    /// The full blob has the expected nested structure and field bytes.
    #[test]
    fn key_transport_structure() {
        let wrapped = sample_wrapped();
        let blob = encode_key_transport(&wrapped);

        // Outer SEQUENCE.
        assert_eq!(blob[0], 0x30);
        // Re-parse top level: outer length must cover the rest.
        let outer_len = blob[1] as usize;
        assert_eq!(outer_len, blob.len() - 2);

        // sessionEncryptedKey: SEQUENCE { OCTET STRING(32), OCTET STRING(4) }.
        let inner = &blob[2..];
        assert_eq!(inner[0], 0x30); // sessionEncryptedKey SEQUENCE
        let sek_len = inner[1] as usize;
        let sek = &inner[2..2 + sek_len];
        assert_eq!(sek[0], 0x04); // encryptedKey OCTET STRING
        assert_eq!(sek[1], 32);
        assert_eq!(&sek[2..34], &wrapped.cek_enc[..]);
        assert_eq!(sek[34], 0x04); // macKey OCTET STRING
        assert_eq!(sek[35], 4);
        assert_eq!(&sek[36..40], &wrapped.cek_mac[..]);

        // transportParameters: [0] (0xA0) { OID, OCTET STRING(8) }.
        let tp = &inner[2 + sek_len..];
        assert_eq!(tp[0], 0xA0);
        let tp_len = tp[1] as usize;
        let tpc = &tp[2..2 + tp_len];
        assert_eq!(tpc[0], 0x06); // encryptionParamSet OID
        let oid_len = tpc[1] as usize;
        let after_oid = &tpc[2 + oid_len..];
        assert_eq!(after_oid[0], 0x04); // ukm OCTET STRING
        assert_eq!(after_oid[1], 8);
        assert_eq!(&after_oid[2..10], &wrapped.ukm[..]);
    }

    /// Encoding is deterministic.
    #[test]
    fn encoding_is_deterministic() {
        let w = sample_wrapped();
        assert_eq!(encode_key_transport(&w), encode_key_transport(&w));
    }

    /// shared UKM is the first 8 bytes of Streebog256(cr || sr) and is
    /// order-sensitive.
    #[test]
    fn shared_ukm_derivation() {
        let cr = [0x01u8; 32];
        let sr = [0x02u8; 32];
        let ukm = derive_shared_ukm(&cr, &sr);
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&cr);
        buf[32..64].copy_from_slice(&sr);
        assert_eq!(&ukm[..], &crate::gost_prf::streebog256(&buf)[0..8]);
        // Swapping randoms changes the UKM.
        assert_ne!(ukm, derive_shared_ukm(&sr, &cr));
    }

    /// The assembled ClientKeyExchange round-trips: the UKM embedded in the blob
    /// matches the derived UKM, and unwrapping under the KEK recovers the
    /// premaster.
    #[test]
    fn client_key_exchange_unwraps_to_premaster() {
        use crate::gost_keywrap::{gost_key_unwrap, gost_key_wrap};

        let kek: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
        let cr = [0xABu8; 32];
        let sr = [0xCDu8; 32];
        let premaster: [u8; 32] = core::array::from_fn(|i| (0xF0 - i) as u8);

        let blob = build_client_key_exchange(&kek, &cr, &sr, &premaster, None);
        assert_eq!(blob[0], 0x30);

        // The UKM carried in transportParameters must equal the derived UKM.
        let ukm = derive_shared_ukm(&cr, &sr);
        let tail = &blob[blob.len() - 10..];
        assert_eq!(tail[0], 0x04);
        assert_eq!(tail[1], 8);
        assert_eq!(&tail[2..10], &ukm[..]);

        // Re-wrap independently: we can unwrap back to the premaster, and the
        // CEK_ENC bytes must appear in the blob.
        let wrapped = gost_key_wrap(&kek, &ukm, &premaster);
        let recovered = gost_key_unwrap(&kek, &wrapped).expect("valid MAC");
        assert_eq!(recovered, premaster);
        assert!(blob.windows(32).any(|w| w == &wrapped.cek_enc[..]));
    }

    /// With an ephemeral SPKI present, the blob carries `ephemeralPublicKey`
    /// (`[0] IMPLICIT`, tag 0xA0) between `encryptionParamSet` and `ukm`, and the
    /// `ukm` still terminates `transportParameters`.
    #[test]
    fn client_key_exchange_embeds_ephemeral_public_key() {
        let kek: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(3));
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let premaster = [0x33u8; 32];
        // A stand-in ephemeral SPKI content (algorithm SEQ + BIT STRING).
        let spki_content = vec![
            0x30, 0x03, 0x06, 0x01, 0x2a, // SEQUENCE { OID 1.0 }
            0x03, 0x02, 0x00, 0x07, // BIT STRING { 00 07 }
        ];

        let with = build_client_key_exchange(&kek, &cr, &sr, &premaster, Some(&spki_content));
        let without = build_client_key_exchange(&kek, &cr, &sr, &premaster, None);

        // The ephemeral variant is longer and contains the [0] IMPLICIT tag and
        // the SPKI content verbatim.
        assert!(with.len() > without.len());
        assert!(
            with.windows(spki_content.len())
                .any(|w| w == &spki_content[..])
        );

        // The ukm still terminates the blob (OCTET STRING of 8 bytes).
        let ukm = derive_shared_ukm(&cr, &sr);
        let tail = &with[with.len() - 10..];
        assert_eq!(tail[0], 0x04);
        assert_eq!(tail[1], 8);
        assert_eq!(&tail[2..10], &ukm[..]);
    }
}
