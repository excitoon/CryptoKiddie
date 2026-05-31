//! GOST 28147-89 CNT+IMIT TLS 1.2 record protection (`TLS_GOSTR341112_256_*`,
//! IANA `0xFF85`, and the GOST-2001 `0x0081` predecessor).
//!
//! This layer turns the symmetric primitives in [`crate::gost28147`] into the
//! TLS record-protection scheme defined by the Chudov GOST TLS draft:
//!
//! * the record fragment (plus its appended MAC) is encrypted with GOST
//!   28147-89 in CNT (counter) mode with GOST key meshing — a *stream*
//!   cipher, so `GenericStreamCipher` framing (RFC 5246 §6.2.3.1) applies;
//! * the MAC is `IMIT_GOST28147` (4 bytes), but — unlike standard TLS — it is
//!   a **single running MAC over the whole connection**: each record's
//!   `MACed_data` is appended to one continuous IMIT context that is never
//!   reset between records (the Chudov GOST TLS draft §2.3).
//!
//! Per direction the state is `{ CNT keystream, running IMIT, sequence number }`
//! seeded from the `key_block` (32-byte MAC key, 32-byte ENC key, 8-byte IV).
//!
//! NOTE ON VALIDATION: the cryptographic primitives are KAT-anchored, but the
//! exact record framing here (MAC-then-encrypt ordering, the per-record
//! `MACed_data` layout, and the continuous-IMIT rule) is only fully confirmable
//! against a live GOST server. The round-trip and tamper tests prove internal
//! consistency; on-wire interop is the final arbiter.

use crate::gost28147::{CntKeystream, ImitContext};
use crate::tls::{ContentType, ProtocolVersion};

/// Length of the IMIT MAC tag appended to each record fragment.
pub const IMIT_TAG_LEN: usize = 4;

/// One direction (read or write) of GOST record protection.
pub struct DirectionState {
    cnt: CntKeystream,
    imit: ImitContext,
    seq_num: u64,
}

impl DirectionState {
    /// Build a directional state from a 32-byte MAC key, 32-byte encryption
    /// key and 8-byte fixed IV (a slice of the TLS `key_block`).
    pub fn new(mac_key: &[u8; 32], enc_key: &[u8; 32], iv: &[u8; 8]) -> Self {
        Self {
            cnt: CntKeystream::new(enc_key, iv, true),
            // RFC 9189 §4.3.2: the CNT_IMIT record MAC uses gostIMIT28147 with
            // the initialization vector IV = IV0, where IV0 is all zeros — NOT
            // the connection's `sender_write_IV`. The key_block fixed IV seeds
            // only the CNT encryption keystream above.
            imit: ImitContext::new(mac_key, &[0u8; 8], true),
            seq_num: 0,
        }
    }

    /// Build the per-record `MACed_data` prefix+fragment that feeds the running
    /// IMIT (the Chudov GOST TLS draft §2.3):
    /// `seq_num(8) || type(1) || version(2) || length(2) || fragment`.
    fn maced_data(
        seq_num: u64,
        content_type: ContentType,
        version: ProtocolVersion,
        fragment: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13 + fragment.len());
        buf.extend_from_slice(&seq_num.to_be_bytes());
        buf.push(content_type as u8);
        buf.push(version.0);
        buf.push(version.1);
        buf.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        buf.extend_from_slice(fragment);
        buf
    }
}

/// Holds both directions of an established GOST connection.
pub struct RecordCrypto {
    write: DirectionState,
    read: DirectionState,
}

impl RecordCrypto {
    /// Construct from the client's and server's key material (already split out
    /// of the 144-byte `key_block`).
    pub fn new(
        client_mac_key: &[u8; 32],
        client_enc_key: &[u8; 32],
        client_iv: &[u8; 8],
        server_mac_key: &[u8; 32],
        server_enc_key: &[u8; 32],
        server_iv: &[u8; 8],
    ) -> Self {
        Self {
            write: DirectionState::new(client_mac_key, client_enc_key, client_iv),
            read: DirectionState::new(server_mac_key, server_enc_key, server_iv),
        }
    }

    /// Protect (MAC-then-encrypt) an outbound plaintext record fragment,
    /// returning the encrypted payload to place in the record.
    pub fn protect(
        &mut self,
        content_type: ContentType,
        version: ProtocolVersion,
        plaintext: &[u8],
    ) -> Vec<u8> {
        // Append this record's MACed_data to the running IMIT, then snapshot
        // the 4-byte tag.
        let maced =
            DirectionState::maced_data(self.write.seq_num, content_type, version, plaintext);
        self.write.imit.update(&maced);
        let tag = self.write.imit.finalize();

        // GenericStreamCipher: encrypt fragment || MAC together.
        let mut out = Vec::with_capacity(plaintext.len() + IMIT_TAG_LEN);
        out.extend_from_slice(plaintext);
        out.extend_from_slice(&tag);
        self.write.cnt.apply(&mut out);

        self.write.seq_num += 1;
        out
    }

    /// Unprotect (decrypt-then-verify) an inbound encrypted record payload,
    /// returning the recovered plaintext fragment on success.
    pub fn unprotect(
        &mut self,
        content_type: ContentType,
        version: ProtocolVersion,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        if ciphertext.len() < IMIT_TAG_LEN {
            return Err(RecordError::Short);
        }
        // Decrypt the whole payload, then split off the trailing MAC.
        let mut buf = ciphertext.to_vec();
        self.read.cnt.apply(&mut buf);
        let split = buf.len() - IMIT_TAG_LEN;
        let received_tag = &buf[split..];
        let fragment = &buf[..split];

        // Recompute the running MAC over this record's MACed_data.
        let maced = DirectionState::maced_data(self.read.seq_num, content_type, version, fragment);
        self.read.imit.update(&maced);
        let expected = self.read.imit.finalize();

        if !constant_time_eq(&expected, received_tag) {
            return Err(RecordError::BadMac);
        }

        self.read.seq_num += 1;
        Ok(fragment.to_vec())
    }
}

/// Constant-time 4-byte comparison for the MAC tag.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Errors from record unprotection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Ciphertext shorter than the MAC tag.
    Short,
    /// MAC verification failed.
    BadMac,
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecordError::Short => write!(f, "record shorter than IMIT tag"),
            RecordError::BadMac => write!(f, "record IMIT verification failed"),
        }
    }
}

impl std::error::Error for RecordError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> ([u8; 32], [u8; 32], [u8; 8], [u8; 32], [u8; 32], [u8; 8]) {
        let cmac: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let cenc: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(2));
        let civ: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let smac: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(9));
        let senc: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(4));
        let siv: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        (cmac, cenc, civ, smac, senc, siv)
    }

    /// RFC 9189 §A.2.1 record KAT for TLS_GOSTR341112_256_WITH_28147_CNT_IMIT:
    /// MAC key = FF*32, ENC key = 00*32, IV = 0, seqnum 0, 7-byte app data of
    /// zeros → MAC `30 01 34 a1`, ciphertext fragment
    /// `86 71 cd bf 3c 1a ae 0f 62 4b 04` (7 enc bytes + 4 enc MAC).
    #[test]
    fn rfc9189_a21_record_kat_seqnum0() {
        let mac_key = [0xFFu8; 32];
        let enc_key = [0x00u8; 32];
        let iv = [0u8; 8];
        // protect() expects a 144-byte key_block partition; we use the same key
        // material for both directions (only the write direction is exercised).
        let mut rc = RecordCrypto::new(&mac_key, &enc_key, &iv, &mac_key, &enc_key, &iv);
        let app_data = [0u8; 7];
        let ct = rc.protect(
            ContentType::ApplicationData,
            ProtocolVersion::TLS1_2,
            &app_data,
        );
        assert_eq!(
            ct,
            vec![
                0x86, 0x71, 0xcd, 0xbf, 0x3c, 0x1a, 0xae, 0x0f, 0x62, 0x4b, 0x04
            ],
            "RFC 9189 A.2.1 seqnum-0 ciphertext fragment mismatch"
        );
    }

    /// RFC 9189 §A.2.2 handshake KAT: the client's first protected record (the
    /// Finished message) must encrypt to the reference fragment. This exercises
    /// the full `protect` path with non-trivial write keys and the IV0=0 IMIT
    /// rule.
    #[test]
    fn rfc9189_a22_finished_record_kat() {
        fn hx(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        // From the §A.2.2 client connection key material
        // K_write_MAC|K_read_MAC|K_write_ENC|K_read_ENC|IV_write|IV_read.
        let k_write_mac: [u8; 32] =
            hx("F337F6A86FF31FCA52EA647CDEE3B78334AB77B57FE0DB2FC0C871ECDCACA5A8")
                .try_into()
                .unwrap();
        let k_read_mac: [u8; 32] =
            hx("FBA04C2132823A2496EF936F0EBCF30EA0CB7EAF6CA794754F1F45B17722DEB4")
                .try_into()
                .unwrap();
        let k_write_enc: [u8; 32] =
            hx("4E5BC32D4430AF5893116ACF81A3BE0C90D2EA8E76E0840728BAF5E2B2F940C0")
                .try_into()
                .unwrap();
        let k_read_enc: [u8; 32] =
            hx("AE18267BB634C16A1D1AC1247350954B2FEE9B77F30D18D554012B437860870A")
                .try_into()
                .unwrap();
        let iv_write: [u8; 8] = hx("D921A84B07FF98AF").try_into().unwrap();
        let iv_read: [u8; 8] = hx("8C82386B91FBBA64").try_into().unwrap();

        let mut rc = RecordCrypto::new(
            &k_write_mac,
            &k_write_enc,
            &iv_write,
            &k_read_mac,
            &k_read_enc,
            &iv_read,
        );

        // Finished handshake message: 14 00 00 0c || verify_data.
        let finished = hx("1400000CD3EE1DEA725CD7080C744311");
        let ct = rc.protect(ContentType::Handshake, ProtocolVersion::TLS1_2, &finished);
        let expected = hx("8854A0ED0CCBDAE076FA7D22D763A8D1AF701BBB");
        assert_eq!(ct, expected, "RFC 9189 A.2.2 Finished record mismatch");
    }

    /// A record protected by the writer is recovered by a matching reader on the
    /// other side (client write IV/keys == server read IV/keys, crossed over).
    #[test]
    fn protect_unprotect_round_trip() {
        let (cmac, cenc, civ, smac, senc, siv) = keys();
        // Client encrypts with its write keys; the peer reads them as *its*
        // read keys, so we cross the parameters in the second instance.
        let mut client = RecordCrypto::new(&cmac, &cenc, &civ, &smac, &senc, &siv);
        let mut peer = RecordCrypto::new(&smac, &senc, &siv, &cmac, &cenc, &civ);

        let msg = b"GOST record protection round trip";
        let ct = client.protect(ContentType::ApplicationData, ProtocolVersion::TLS1_2, msg);
        assert_ne!(&ct[..msg.len()], &msg[..]);
        let pt = peer
            .unprotect(ContentType::ApplicationData, ProtocolVersion::TLS1_2, &ct)
            .expect("valid MAC");
        assert_eq!(pt, msg);
    }

    /// Multiple records in sequence round-trip and the cumulative IMIT keeps
    /// both sides in lock-step.
    #[test]
    fn multiple_records_round_trip_in_order() {
        let (cmac, cenc, civ, smac, senc, siv) = keys();
        let mut client = RecordCrypto::new(&cmac, &cenc, &civ, &smac, &senc, &siv);
        let mut peer = RecordCrypto::new(&smac, &senc, &siv, &cmac, &cenc, &civ);

        for i in 0..5u8 {
            let msg = vec![i; 40 + i as usize];
            let ct = client.protect(ContentType::ApplicationData, ProtocolVersion::TLS1_2, &msg);
            let pt = peer
                .unprotect(ContentType::ApplicationData, ProtocolVersion::TLS1_2, &ct)
                .expect("valid MAC");
            assert_eq!(pt, msg);
        }
    }

    /// Tampering with any ciphertext byte must fail MAC verification.
    #[test]
    fn tampered_ciphertext_fails_mac() {
        let (cmac, cenc, civ, smac, senc, siv) = keys();
        let mut client = RecordCrypto::new(&cmac, &cenc, &civ, &smac, &senc, &siv);
        let mut peer = RecordCrypto::new(&smac, &senc, &siv, &cmac, &cenc, &civ);

        let msg = b"do not tamper with me";
        let mut ct = client.protect(ContentType::ApplicationData, ProtocolVersion::TLS1_2, msg);
        ct[0] ^= 0x01;
        let err = peer
            .unprotect(ContentType::ApplicationData, ProtocolVersion::TLS1_2, &ct)
            .unwrap_err();
        assert_eq!(err, RecordError::BadMac);
    }

    /// A record replayed out of order breaks the running-MAC lock-step and is
    /// rejected (the cumulative IMIT binds record order).
    #[test]
    fn out_of_order_record_fails() {
        let (cmac, cenc, civ, smac, senc, siv) = keys();
        let mut client = RecordCrypto::new(&cmac, &cenc, &civ, &smac, &senc, &siv);
        let mut peer = RecordCrypto::new(&smac, &senc, &siv, &cmac, &cenc, &civ);

        let first = client.protect(
            ContentType::ApplicationData,
            ProtocolVersion::TLS1_2,
            b"first",
        );
        let _second = client.protect(
            ContentType::ApplicationData,
            ProtocolVersion::TLS1_2,
            b"second",
        );
        // Peer receives the first record fine.
        assert!(
            peer.unprotect(
                ContentType::ApplicationData,
                ProtocolVersion::TLS1_2,
                &first
            )
            .is_ok()
        );
        // Re-feeding the same first ciphertext now mismatches (seq advanced).
        assert_eq!(
            peer.unprotect(
                ContentType::ApplicationData,
                ProtocolVersion::TLS1_2,
                &first
            )
            .unwrap_err(),
            RecordError::BadMac
        );
    }

    #[test]
    fn short_record_is_rejected() {
        let (cmac, cenc, civ, smac, senc, siv) = keys();
        let mut peer = RecordCrypto::new(&smac, &senc, &siv, &cmac, &cenc, &civ);
        let err = peer
            .unprotect(
                ContentType::ApplicationData,
                ProtocolVersion::TLS1_2,
                &[0u8; 3],
            )
            .unwrap_err();
        assert_eq!(err, RecordError::Short);
    }
}
