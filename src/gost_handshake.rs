//! Offline GOST TLS 1.2 handshake orchestration: handshake-message framing, a
//! running transcript hash, the `ClientHello` builder, and `Finished`
//! verify-data wiring.
//!
//! This is the deterministic, hardware-independent glue that sits between the
//! wire layer ([`crate::tls`]) and the live token. Everything here can be
//! exercised offline; the only pieces that require the Rutoken — the VKO that
//! yields the key-exchange KEK and the `CertificateVerify` signature — are
//! injected by the caller, so this module stays fully testable.

use crate::gost_prf::{finished_verify_data, streebog256};
use crate::tls::{HandshakeType, ProtocolVersion};

/// Wrap a handshake message body in its 4-byte header
/// (`HandshakeType(1) || length(3)`), as it appears inside the handshake
/// content stream (and in the transcript).
pub fn frame_handshake(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type as u8);
    let len = body.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()[1..4]);
    out.extend_from_slice(body);
    out
}

/// Running handshake transcript: the concatenation of every handshake message
/// (each already framed with its 4-byte header), hashed with Streebog-256 for
/// the GOST TLS 1.2 `Finished` messages (RFC 9189 §4.3).
#[derive(Debug, Clone, Default)]
pub struct Transcript {
    data: Vec<u8>,
}

impl Transcript {
    /// Start an empty transcript.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Append an already-framed handshake message (header + body).
    pub fn push_framed(&mut self, framed: &[u8]) {
        self.data.extend_from_slice(framed);
    }

    /// Frame `body` with its header, append it, and return the framed bytes
    /// (handy for simultaneously feeding the transcript and the record layer).
    pub fn push_message(&mut self, msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
        let framed = frame_handshake(msg_type, body);
        self.data.extend_from_slice(&framed);
        framed
    }

    /// The raw transcript bytes accumulated so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Streebog-256 hash of the transcript so far (the input to
    /// `Finished.verify_data`). Non-destructive.
    pub fn hash(&self) -> [u8; 32] {
        streebog256(&self.data)
    }
}

/// Parameters for building a GOST `ClientHello`.
pub struct ClientHelloParams<'a> {
    /// Advertised handshake version (TLS 1.2 = 3,3).
    pub version: ProtocolVersion,
    /// 32-byte client random (gmt_unix_time is the caller's responsibility).
    pub random: [u8; 32],
    /// Session id to resume, or empty for a fresh session.
    pub session_id: &'a [u8],
    /// Offered cipher suites, most-preferred first.
    pub cipher_suites: &'a [u16],
    /// Raw extensions block (already TLV-encoded), or empty for none.
    pub extensions: &'a [u8],
}

/// Build the `ClientHello` body (the bytes after the 4-byte handshake header).
///
/// Layout (RFC 5246 §7.4.1.2): version(2) || random(32) || session_id<0..32> ||
/// cipher_suites<2..2^16-2> || compression_methods<1..2^8-1> || [extensions].
/// Only the null compression method is offered.
pub fn build_client_hello(params: &ClientHelloParams<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(params.version.0);
    out.push(params.version.1);
    out.extend_from_slice(&params.random);

    // session_id<0..32>
    assert!(params.session_id.len() <= 32, "session id too long");
    out.push(params.session_id.len() as u8);
    out.extend_from_slice(params.session_id);

    // cipher_suites<2..2^16-2>
    let cs_len = params.cipher_suites.len() * 2;
    out.extend_from_slice(&(cs_len as u16).to_be_bytes());
    for &cs in params.cipher_suites {
        out.extend_from_slice(&cs.to_be_bytes());
    }

    // compression_methods<1..2^8-1>: just null (0x00).
    out.push(1);
    out.push(0);

    // Optional extensions block.
    if !params.extensions.is_empty() {
        out.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(params.extensions);
    }

    out
}

/// Compute the `Finished` message body (the 12-byte verify_data) for the given
/// side, from the master secret and the current transcript.
pub fn finished_body(master_secret: &[u8; 48], label: &[u8], transcript: &Transcript) -> [u8; 12] {
    finished_verify_data(master_secret, label, &transcript.hash())
}

/// The `ChangeCipherSpec` message payload: the single byte `0x01` (RFC 5246
/// §7.1). It is sent in a record of [`crate::tls::ContentType::ChangeCipherSpec`]
/// and is *not* part of the handshake transcript.
pub const CHANGE_CIPHER_SPEC: [u8; 1] = [0x01];

/// Build the `CertificateVerify` body for the legacy GOST suite from a raw GOST
/// R 34.10 signature value (64 bytes for the 256-bit curve).
///
/// WIRE-VALIDATION CAVEAT (unconfirmed until live): for the legacy
/// `draft-chudov` GOST suites (0xFF85) the body is the bare signature with no
/// TLS 1.2 `SignatureAndHashAlgorithm` prefix and no inner length vector — the
/// 4-byte handshake header already carries the length. This matches the
/// TLS 1.0/1.1 `digitally-signed` form used by legacy GOST stacks, but the exact framing
/// must be confirmed against the live server before it can be trusted.
pub fn certificate_verify_body(signature: &[u8]) -> Vec<u8> {
    signature.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cipher_suite;

    #[test]
    fn frame_handshake_writes_type_and_24bit_length() {
        let framed = frame_handshake(HandshakeType::ClientHello, &[0xAA, 0xBB]);
        assert_eq!(framed, vec![0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn transcript_hash_matches_streebog_of_concatenation() {
        let mut t = Transcript::new();
        let a = t.push_message(HandshakeType::ClientHello, &[1, 2, 3]);
        let b = t.push_message(HandshakeType::ServerHello, &[4, 5]);

        let mut concat = a.clone();
        concat.extend_from_slice(&b);
        assert_eq!(t.as_bytes(), &concat[..]);
        assert_eq!(t.hash(), streebog256(&concat));
    }

    #[test]
    fn transcript_hash_is_order_sensitive() {
        let mut t1 = Transcript::new();
        t1.push_message(HandshakeType::ClientHello, &[1]);
        t1.push_message(HandshakeType::ServerHello, &[2]);

        let mut t2 = Transcript::new();
        t2.push_message(HandshakeType::ServerHello, &[2]);
        t2.push_message(HandshakeType::ClientHello, &[1]);

        assert_ne!(t1.hash(), t2.hash());
    }

    #[test]
    fn client_hello_has_expected_layout() {
        let random = [0x5Au8; 32];
        let suites = vec![
            cipher_suite::LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT,
            cipher_suite::GOSTR341112_256_WITH_28147_CNT_IMIT,
        ];
        let params = ClientHelloParams {
            version: ProtocolVersion::TLS1_2,
            random,
            session_id: &[],
            cipher_suites: &suites,
            extensions: &[],
        };
        let body = build_client_hello(&params);

        // version
        assert_eq!(&body[0..2], &[3, 3]);
        // random
        assert_eq!(&body[2..34], &random[..]);
        // empty session id
        assert_eq!(body[34], 0);
        // cipher_suites length = 4, then the two suites big-endian
        assert_eq!(&body[35..37], &[0x00, 0x04]);
        assert_eq!(&body[37..39], &0xFF85u16.to_be_bytes());
        assert_eq!(&body[39..41], &0xC102u16.to_be_bytes());
        // compression methods: count 1, null
        assert_eq!(&body[41..43], &[0x01, 0x00]);
        // no extensions
        assert_eq!(body.len(), 43);
    }

    #[test]
    fn client_hello_includes_session_id_and_extensions() {
        let params = ClientHelloParams {
            version: ProtocolVersion::TLS1_2,
            random: [0u8; 32],
            session_id: &[0xDE, 0xAD],
            cipher_suites: &[0xFF85],
            extensions: &[0x00, 0x0A, 0x00, 0x00],
        };
        let body = build_client_hello(&params);
        // session id
        assert_eq!(body[34], 2);
        assert_eq!(&body[35..37], &[0xDE, 0xAD]);
        // extensions length prefix then body at the tail
        assert_eq!(&body[body.len() - 6..body.len() - 4], &[0x00, 0x04]);
        assert_eq!(&body[body.len() - 4..], &[0x00, 0x0A, 0x00, 0x00]);
    }

    #[test]
    fn finished_body_is_12_bytes_and_transcript_bound() {
        let ms = [0x11u8; 48];
        let mut t = Transcript::new();
        t.push_message(HandshakeType::ClientHello, &[1, 2, 3]);
        let f1 = finished_body(&ms, crate::gost_prf::CLIENT_FINISHED_LABEL, &t);
        assert_eq!(f1.len(), 12);

        // Extending the transcript changes the verify_data.
        t.push_message(HandshakeType::ServerHello, &[4]);
        let f2 = finished_body(&ms, crate::gost_prf::CLIENT_FINISHED_LABEL, &t);
        assert_ne!(f1, f2);
    }

    #[test]
    fn change_cipher_spec_is_single_one_byte() {
        assert_eq!(CHANGE_CIPHER_SPEC, [0x01]);
    }

    #[test]
    fn certificate_verify_body_passes_signature_through() {
        let sig = [0xABu8; 64];
        assert_eq!(certificate_verify_body(&sig), sig.to_vec());
    }
}
