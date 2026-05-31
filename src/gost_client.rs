//! Offline driver for the GOST TLS 1.2 client handshake (0xFF85 suite).
//!
//! [`ClientHandshake`] sequences the handshake and owns the transcript and the
//! derived key material, but performs **no** I/O and touches **no** hardware.
//! The two operations that require the Rutoken — the VKO that yields the
//! key-transport KEK and the `CertificateVerify` signature — are supplied to
//! the driver as plain byte inputs by the caller, so the entire orchestration
//! is exercised offline with mock values.
//!
//! Flow (server has no `ServerKeyExchange`; key transport, mutual auth):
//! 1. [`ClientHandshake::start`] → `ClientHello` body (caller frames + sends).
//! 2. Feed the server flight (`ServerHello`, `Certificate`,
//!    `CertificateRequest`, `ServerHelloDone`) into the transcript via
//!    [`ClientHandshake::record_server_hello`] /
//!    [`ClientHandshake::record_incoming`].
//! 3. [`ClientHandshake::client_certificate`] → `Certificate` body.
//! 4. [`ClientHandshake::client_key_exchange`] (with the token VKO `kek` and a
//!    fresh premaster) → `ClientKeyExchange` body; this also derives the
//!    master secret, key block and [`RecordCrypto`].
//! 5. [`ClientHandshake::certificate_verify_digest`] → the transcript hash the
//!    token must sign; feed the signature back with
//!    [`ClientHandshake::record_certificate_verify`].
//! 6. [`ClientHandshake::client_finished`] → the 12-byte verify_data for the
//!    encrypted `Finished`.
//! 7. [`ClientHandshake::verify_server_finished`] checks the peer's
//!    verify_data.

use crate::gost_handshake::{
    ClientHelloParams, Transcript, build_client_hello, finished_body, frame_handshake,
};
use crate::gost_keytransport::build_client_key_exchange;
use crate::gost_prf::{CLIENT_FINISHED_LABEL, SERVER_FINISHED_LABEL, key_block, master_secret};
use crate::gost_record::RecordCrypto;
use crate::tls::{HandshakeType, ProtocolVersion};

/// Errors from the handshake driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// A step was called before its prerequisite (e.g. key exchange before the
    /// server random was recorded).
    OutOfOrder(&'static str),
    /// The server's `Finished` verify_data did not match.
    BadServerFinished,
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::OutOfOrder(s) => write!(f, "handshake step out of order: {s}"),
            HandshakeError::BadServerFinished => write!(f, "server Finished verify_data mismatch"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Client handshake state machine (offline; hardware results are injected).
pub struct ClientHandshake {
    version: ProtocolVersion,
    transcript: Transcript,
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    master_secret: Option<[u8; 48]>,
    record_crypto: Option<RecordCrypto>,
}

impl ClientHandshake {
    /// Begin a handshake and produce the `ClientHello` body.
    ///
    /// The returned bytes are the handshake-message body (no 4-byte header); the
    /// driver has already framed them into its transcript.
    pub fn start(
        version: ProtocolVersion,
        client_random: [u8; 32],
        session_id: &[u8],
        cipher_suites: &[u16],
        extensions: &[u8],
    ) -> (Self, Vec<u8>) {
        let params = ClientHelloParams {
            version,
            random: client_random,
            session_id,
            cipher_suites,
            extensions,
        };
        let body = build_client_hello(&params);
        let mut transcript = Transcript::new();
        transcript.push_message(HandshakeType::ClientHello, &body);
        let me = Self {
            version,
            transcript,
            client_random,
            server_random: None,
            master_secret: None,
            record_crypto: None,
        };
        (me, body)
    }

    /// Record the parsed `ServerHello`: store the server random and add the
    /// message to the transcript.
    pub fn record_server_hello(&mut self, server_random: [u8; 32], server_hello_body: &[u8]) {
        self.server_random = Some(server_random);
        self.transcript
            .push_message(HandshakeType::ServerHello, server_hello_body);
    }

    /// Add any other incoming handshake message (Certificate,
    /// CertificateRequest, ServerHelloDone, …) to the transcript.
    pub fn record_incoming(&mut self, msg_type: HandshakeType, body: &[u8]) {
        self.transcript.push_message(msg_type, body);
    }

    /// Produce the client `Certificate` message body from the DER cert chain
    /// (each entry an X.509 DER blob), framing it into the transcript.
    ///
    /// Layout: `certificate_list<0..2^24-1>` of `certificate<0..2^24-1>`.
    pub fn client_certificate(&mut self, cert_chain: &[Vec<u8>]) -> Vec<u8> {
        let mut list = Vec::new();
        for cert in cert_chain {
            let len = cert.len() as u32;
            list.extend_from_slice(&len.to_be_bytes()[1..4]);
            list.extend_from_slice(cert);
        }
        let mut body = Vec::with_capacity(3 + list.len());
        let list_len = list.len() as u32;
        body.extend_from_slice(&list_len.to_be_bytes()[1..4]);
        body.extend_from_slice(&list);

        self.transcript
            .push_message(HandshakeType::Certificate, &body);
        body
    }

    /// Build the `ClientKeyExchange` body and derive all connection secrets.
    ///
    /// `kek` is the 32-byte key-encryption key returned by the token's VKO
    /// (`VKO(client_priv, server_pub, shared_ukm)`); `premaster` is a fresh
    /// 32-byte random. The CKE blob is framed into the transcript, and the
    /// master secret, key block and [`RecordCrypto`] become available.
    pub fn client_key_exchange(
        &mut self,
        kek: &[u8; 32],
        premaster: &[u8; 32],
        ephemeral_spki_content: Option<&[u8]>,
    ) -> Result<Vec<u8>, HandshakeError> {
        let server_random = self
            .server_random
            .ok_or(HandshakeError::OutOfOrder("server random not recorded"))?;

        let body = build_client_key_exchange(
            kek,
            &self.client_random,
            &server_random,
            premaster,
            ephemeral_spki_content,
        );
        self.transcript
            .push_message(HandshakeType::ClientKeyExchange, &body);

        // Derive secrets.
        let ms = master_secret(premaster, &self.client_random, &server_random);
        let kb = key_block(&ms, &self.client_random, &server_random);
        let rc = RecordCrypto::new(
            &kb.client_mac_key,
            &kb.client_enc_key,
            &kb.client_iv,
            &kb.server_mac_key,
            &kb.server_enc_key,
            &kb.server_iv,
        );
        self.master_secret = Some(ms);
        self.record_crypto = Some(rc);
        Ok(body)
    }

    /// The transcript hash (Streebog-256) that the token must sign for
    /// `CertificateVerify`. Call this *after* `client_key_exchange` and before
    /// recording the signature.
    pub fn certificate_verify_digest(&self) -> [u8; 32] {
        self.transcript.hash()
    }

    /// Frame the token's `CertificateVerify` signature into the transcript and
    /// return the message body.
    ///
    /// `signature` is the DER-encoded GOST signature value the caller wants on
    /// the wire (the structure of the `digitally-signed` block is the caller's
    /// responsibility); this driver only frames it for the transcript.
    pub fn record_certificate_verify(&mut self, signature_block: &[u8]) -> Vec<u8> {
        self.transcript
            .push_message(HandshakeType::CertificateVerify, signature_block);
        signature_block.to_vec()
    }

    /// Compute the client `Finished` verify_data over the current transcript
    /// (which must include everything through `CertificateVerify`).
    pub fn client_finished(&mut self) -> Result<[u8; 12], HandshakeError> {
        let ms = self
            .master_secret
            .ok_or(HandshakeError::OutOfOrder("master secret not derived"))?;
        let vd = finished_body(&ms, CLIENT_FINISHED_LABEL, &self.transcript);
        // The client Finished is itself part of the transcript the *server*
        // Finished covers.
        self.transcript.push_message(HandshakeType::Finished, &vd);
        Ok(vd)
    }

    /// Verify the server's `Finished` verify_data against the transcript that
    /// includes the client `Finished`.
    pub fn verify_server_finished(
        &self,
        server_verify_data: &[u8; 12],
    ) -> Result<(), HandshakeError> {
        let ms = self
            .master_secret
            .ok_or(HandshakeError::OutOfOrder("master secret not derived"))?;
        let expected = finished_body(&ms, SERVER_FINISHED_LABEL, &self.transcript);
        if constant_time_eq12(&expected, server_verify_data) {
            Ok(())
        } else {
            Err(HandshakeError::BadServerFinished)
        }
    }

    /// Borrow the negotiated record-protection context (available after
    /// `client_key_exchange`).
    pub fn record_crypto(&mut self) -> Option<&mut RecordCrypto> {
        self.record_crypto.as_mut()
    }

    /// The negotiated handshake version.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Frame an outbound handshake body for the wire without touching the
    /// transcript (the driver already framed transcript copies internally).
    pub fn frame(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
        frame_handshake(msg_type, body)
    }
}

fn constant_time_eq12(a: &[u8; 12], b: &[u8; 12]) -> bool {
    let mut diff = 0u8;
    for i in 0..12 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cipher_suite;

    fn suites() -> Vec<u16> {
        vec![cipher_suite::LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT]
    }

    /// A full mock handshake: both peers share the same injected KEK and
    /// premaster, so the client's own derivation lets us cross-check the
    /// server-side Finished and a protected application record.
    #[test]
    fn full_mock_handshake_round_trip() {
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];
        let kek = [0x33u8; 32];
        let premaster = [0x44u8; 32];

        let (mut hs, hello) =
            ClientHandshake::start(ProtocolVersion::TLS1_2, client_random, &[], &suites(), &[]);
        assert_eq!(&hello[0..2], &[3, 3]);

        // Server flight.
        hs.record_server_hello(server_random, &[0xAB, 0xCD]);
        hs.record_incoming(HandshakeType::Certificate, &[0x01, 0x02]);
        hs.record_incoming(HandshakeType::CertificateRequest, &[0x03]);
        hs.record_incoming(HandshakeType::ServerHelloDone, &[]);

        // Client second flight.
        hs.client_certificate(&[vec![0xDE, 0xAD, 0xBE, 0xEF]]);
        let cke = hs.client_key_exchange(&kek, &premaster, None).expect("kex");
        assert_eq!(cke[0], 0x30); // DER SEQUENCE

        let digest = hs.certificate_verify_digest();
        // Mock token signature is just the digest echoed back here.
        hs.record_certificate_verify(&digest);

        let client_vd = hs.client_finished().expect("finished");
        assert_eq!(client_vd.len(), 12);

        // Independently reconstruct the server's view to produce a server
        // Finished, then verify it through the driver.
        let ms = master_secret(&premaster, &client_random, &server_random);
        let server_vd = finished_body(&ms, SERVER_FINISHED_LABEL, transcript_of(&hs));
        hs.verify_server_finished(&server_vd)
            .expect("server finished ok");

        // A wrong server Finished is rejected.
        let mut bad = server_vd;
        bad[0] ^= 0xFF;
        assert_eq!(
            hs.verify_server_finished(&bad).unwrap_err(),
            HandshakeError::BadServerFinished
        );

        // Record protection is available and round-trips a record against a
        // peer built from the same key block.
        let kb = key_block(&ms, &client_random, &server_random);
        let mut server_side = RecordCrypto::new(
            &kb.server_mac_key,
            &kb.server_enc_key,
            &kb.server_iv,
            &kb.client_mac_key,
            &kb.client_enc_key,
            &kb.client_iv,
        );
        let rc = hs.record_crypto().expect("record crypto");
        let ct = rc.protect(
            crate::tls::ContentType::ApplicationData,
            ProtocolVersion::TLS1_2,
            b"hello gost",
        );
        let pt = server_side
            .unprotect(
                crate::tls::ContentType::ApplicationData,
                ProtocolVersion::TLS1_2,
                &ct,
            )
            .expect("decrypt");
        assert_eq!(pt, b"hello gost");
    }

    // Helper to reach into the driver's transcript for the test's server-side
    // reconstruction.
    fn transcript_of(hs: &ClientHandshake) -> &Transcript {
        &hs.transcript
    }

    #[test]
    fn key_exchange_before_server_hello_is_rejected() {
        let (mut hs, _) =
            ClientHandshake::start(ProtocolVersion::TLS1_2, [0u8; 32], &[], &suites(), &[]);
        assert_eq!(
            hs.client_key_exchange(&[0u8; 32], &[0u8; 32], None)
                .unwrap_err(),
            HandshakeError::OutOfOrder("server random not recorded")
        );
    }

    #[test]
    fn client_certificate_encodes_chain_lengths() {
        let (mut hs, _) =
            ClientHandshake::start(ProtocolVersion::TLS1_2, [0u8; 32], &[], &suites(), &[]);
        let body = hs.client_certificate(&[vec![0xAA, 0xBB], vec![0xCC]]);
        // outer list length = (3 + 2) + (3 + 1) = 9
        assert_eq!(&body[0..3], &[0x00, 0x00, 0x09]);
        // first cert: len 2 then bytes
        assert_eq!(&body[3..6], &[0x00, 0x00, 0x02]);
        assert_eq!(&body[6..8], &[0xAA, 0xBB]);
        // second cert: len 1 then byte
        assert_eq!(&body[8..11], &[0x00, 0x00, 0x01]);
        assert_eq!(body[11], 0xCC);
    }
}
