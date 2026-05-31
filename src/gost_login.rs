//! End-to-end GOST TLS 1.2 login driver (cipher suite 0xFF85,
//! `TLS_GOSTR341112_256_WITH_28147_CNT_IMIT`).
//!
//! This wires the offline [`ClientHandshake`](crate::gost_client::ClientHandshake)
//! state machine to a live [`TlsTransport`](crate::tls::TlsTransport) and to the
//! Rutoken, performing the complete mutual-auth handshake:
//!
//! ```text
//! flight 1:  ClientHello (with SNI)  ->
//!                                     <-  ServerHello, Certificate,
//!                                         CertificateRequest, ServerHelloDone
//! flight 2:  Certificate, ClientKeyExchange, CertificateVerify,
//!            ChangeCipherSpec, {Finished}  ->
//!                                     <-  ChangeCipherSpec, {Finished}
//! ```
//!
//! The two operations that require the token are passed in as closures so the
//! whole driver is exercised offline (see the loopback integration test):
//!
//! * `vko(server_point, ukm) -> kek` — the token's VKO key agreement against the
//!   server's public point and the 8-byte shared UKM, yielding the 32-byte
//!   key-transport KEK.
//! * `sign(digest) -> signature` — the token's `CertificateVerify` signature
//!   over the transcript hash.
//!
//! The server's public point is extracted from its leaf certificate's
//! `SubjectPublicKeyInfo` and handed to `vko` **verbatim** (exactly as stored in
//! the certificate); any byte-order conversion required by the token is the
//! `vko` closure's responsibility, keeping this driver endianness-agnostic.

use crate::CliError;
use crate::gost_client::{ClientHandshake, HandshakeError};
use crate::gost_keytransport::derive_shared_ukm;
use crate::tls::{ContentType, HandshakeType, ProtocolVersion, TlsTransport};

/// Errors raised while driving a login.
#[derive(Debug)]
pub enum LoginError {
    /// Transport-level failure (socket read/write, framing).
    Transport(CliError),
    /// Handshake state-machine failure (out-of-order, bad server Finished).
    Handshake(HandshakeError),
    /// A malformed or unexpected protocol message.
    Protocol(String),
    /// The injected token VKO closure failed.
    Vko(String),
    /// The injected token signing closure failed.
    Sign(String),
}

impl core::fmt::Display for LoginError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoginError::Transport(e) => write!(f, "transport error: {e}"),
            LoginError::Handshake(e) => write!(f, "handshake error: {e}"),
            LoginError::Protocol(m) => write!(f, "protocol error: {m}"),
            LoginError::Vko(m) => write!(f, "token VKO failed: {m}"),
            LoginError::Sign(m) => write!(f, "token CertificateVerify signing failed: {m}"),
        }
    }
}

impl std::error::Error for LoginError {}

impl From<CliError> for LoginError {
    fn from(e: CliError) -> Self {
        LoginError::Transport(e)
    }
}

impl From<HandshakeError> for LoginError {
    fn from(e: HandshakeError) -> Self {
        LoginError::Handshake(e)
    }
}

/// Inputs for a login attempt.
pub struct LoginParams<'a> {
    /// SNI host name advertised in the ClientHello.
    pub server_name: &'a str,
    /// 32 bytes of client random (the caller supplies CSPRNG entropy).
    pub client_random: [u8; 32],
    /// 32-byte premaster secret (fresh CSPRNG bytes; wrapped under the token KEK).
    pub premaster: [u8; 32],
    /// The client certificate chain (each entry a DER-encoded X.509 cert), leaf
    /// first.
    pub client_cert_chain: &'a [Vec<u8>],
    /// Cipher suites to advertise (typically just `[0xFF85]`).
    pub cipher_suites: &'a [u16],
}

/// An established session: the handshake (which owns the record-protection
/// context) plus the server's leaf certificate for the caller to validate.
pub struct LoginSession {
    handshake: ClientHandshake,
    server_leaf_cert: Vec<u8>,
}

impl LoginSession {
    /// The server's leaf certificate (DER), for the caller to validate against
    /// its trust anchors / pinned key.
    pub fn server_leaf_cert(&self) -> &[u8] {
        &self.server_leaf_cert
    }

    /// Encrypt and send `plaintext` as one or more ApplicationData records.
    ///
    /// A single TLS record's plaintext is limited to 2^14 (16384) bytes, so
    /// larger payloads (e.g. the ~35 KB ФНС registration POST) must be split
    /// across multiple records; sending an over-length record makes the peer
    /// abort the connection.
    pub fn send_application_data(
        &mut self,
        transport: &mut TlsTransport,
        plaintext: &[u8],
    ) -> Result<(), LoginError> {
        const MAX_RECORD_PLAINTEXT: usize = 16384;
        let version = self.handshake.version();
        // An empty payload still sends one (empty) record.
        let mut chunks = plaintext.chunks(MAX_RECORD_PLAINTEXT);
        let first = chunks.next().unwrap_or(&[]);
        for chunk in std::iter::once(first).chain(chunks) {
            let rc = self
                .handshake
                .record_crypto()
                .ok_or_else(|| LoginError::Protocol("record crypto unavailable".into()))?;
            let ct = rc.protect(ContentType::ApplicationData, version, chunk);
            transport.send_record(ContentType::ApplicationData, &ct)?;
        }
        Ok(())
    }

    /// Receive and decrypt one ApplicationData record.
    pub fn recv_application_data(
        &mut self,
        transport: &mut TlsTransport,
    ) -> Result<Vec<u8>, LoginError> {
        let version = self.handshake.version();
        let record = transport.recv_record()?;
        if record.content_type != ContentType::ApplicationData {
            return Err(LoginError::Protocol(format!(
                "expected ApplicationData, got {:?}",
                record.content_type
            )));
        }
        let rc = self
            .handshake
            .record_crypto()
            .ok_or_else(|| LoginError::Protocol("record crypto unavailable".into()))?;
        rc.unprotect(ContentType::ApplicationData, version, &record.payload)
            .map_err(|e| LoginError::Protocol(format!("record decrypt failed: {e:?}")))
    }

    /// Drain the entire response stream: decrypt and concatenate every
    /// `ApplicationData` record until the peer closes the connection (a
    /// `close_notify` alert or a transport-level EOF/reset). Used by the bridge,
    /// where the upstream is asked to `Connection: close`, so reading to the end
    /// yields the complete HTTP response.
    pub fn recv_all_application_data(
        &mut self,
        transport: &mut TlsTransport,
    ) -> Result<Vec<u8>, LoginError> {
        let version = self.handshake.version();
        let mut out = Vec::new();
        loop {
            let record = match transport.recv_record() {
                Ok(r) => r,
                // EOF / reset after the server finished writing: treat whatever
                // we have as the complete response.
                Err(_) => break,
            };
            match record.content_type {
                ContentType::ApplicationData => {
                    let rc = self
                        .handshake
                        .record_crypto()
                        .ok_or_else(|| LoginError::Protocol("record crypto unavailable".into()))?;
                    let pt = rc
                        .unprotect(ContentType::ApplicationData, version, &record.payload)
                        .map_err(|e| {
                            LoginError::Protocol(format!("record decrypt failed: {e:?}"))
                        })?;
                    out.extend_from_slice(&pt);
                }
                // Encrypted alerts arrive as ApplicationData and are handled
                // above; a plaintext alert here (e.g. close_notify) ends the
                // stream cleanly.
                ContentType::Alert => break,
                _ => break,
            }
        }
        Ok(out)
    }
}

/// Run the full mutual-auth GOST TLS 1.2 handshake over `transport`.
///
/// `vko` receives the server's public point (verbatim leaf-cert SPKI bytes) and
/// the 8-byte shared UKM (`Streebog256(client_random ‖ server_random)[0..8]`,
/// the same value the key-transport blob carries) and must return the 32-byte
/// KEK; `sign` receives the `CertificateVerify` transcript digest and must
/// return the signature block to place on the wire. The UKM is integral to the
/// GOST VKO agreement (RFC 4357 §5.2), so the token must apply it (MSE tag
/// `0x87`) for the derived KEK to match the server's.
pub fn run_login<F, S>(
    transport: &mut TlsTransport,
    params: &LoginParams<'_>,
    fill: F,
    sign: S,
) -> Result<LoginSession, LoginError>
where
    F: FnMut(&mut [u8]) -> Result<(), String>,
    S: FnOnce(&[u8; 32]) -> Result<Vec<u8>, String>,
{
    let version = ProtocolVersion::TLS1_2;

    // --- Flight 1: ClientHello ------------------------------------------------
    let extensions = sni_extension(params.server_name);
    let (mut hs, hello_body) = ClientHandshake::start(
        version,
        params.client_random,
        &[],
        params.cipher_suites,
        &extensions,
    );
    send_handshake(transport, HandshakeType::ClientHello, &hello_body)?;

    // --- Read the server flight ----------------------------------------------
    let mut server_leaf_cert: Option<Vec<u8>> = None;
    let mut server_random_opt: Option<[u8; 32]> = None;
    loop {
        let (msg_type, body) = transport.recv_handshake_message()?;
        match HandshakeType::from_u8(msg_type) {
            Some(HandshakeType::ServerHello) => {
                if body.len() < 34 {
                    return Err(LoginError::Protocol(format!(
                        "ServerHello too short ({} bytes)",
                        body.len()
                    )));
                }
                let mut server_random = [0u8; 32];
                server_random.copy_from_slice(&body[2..34]);
                server_random_opt = Some(server_random);
                hs.record_server_hello(server_random, &body);
            }
            Some(HandshakeType::Certificate) => {
                let leaf = first_certificate(&body)?;
                server_leaf_cert = Some(leaf);
                hs.record_incoming(HandshakeType::Certificate, &body);
            }
            Some(HandshakeType::ServerKeyExchange) => {
                // Not expected for the key-transport suite, but keep the
                // transcript faithful if a server sends it.
                hs.record_incoming(HandshakeType::ServerKeyExchange, &body);
            }
            Some(HandshakeType::CertificateRequest) => {
                dump_artifact("s1-certificaterequest.body", &body);
                hs.record_incoming(HandshakeType::CertificateRequest, &body);
            }
            Some(HandshakeType::ServerHelloDone) => {
                hs.record_incoming(HandshakeType::ServerHelloDone, &body);
                break;
            }
            other => {
                return Err(LoginError::Protocol(format!(
                    "unexpected handshake message type {msg_type} ({other:?}) in server flight"
                )));
            }
        }
    }

    let server_leaf_cert = server_leaf_cert
        .ok_or_else(|| LoginError::Protocol("server sent no Certificate message".into()))?;

    // --- Software ephemeral key transport (RFC 9189 §4.2.4.2) ----------------
    // For the CNT_IMIT suite the client uses an *ephemeral* key on the server's
    // curve, never the certificate key. We derive R = VKO_256(d_eph, Q_s, UKM)
    // in software and carry Q_eph in the blob's ephemeralPublicKey field; the
    // certificate key is used only to sign CertificateVerify below.
    let server_random = server_random_opt
        .ok_or_else(|| LoginError::Protocol("server sent no ServerHello message".into()))?;
    let ukm = derive_shared_ukm(&params.client_random, &server_random);
    let server_point = extract_subject_public_point(&server_leaf_cert)?;
    let server_spki_alg = extract_spki_algorithm(&server_leaf_cert)?;
    let transport_key =
        crate::gost_vko::software_key_transport(&server_point, &server_spki_alg, &ukm, fill)
            .map_err(LoginError::Vko)?;
    let kek = transport_key.kek;

    dump_artifact("server-leaf.der", &server_leaf_cert);
    dump_artifact("server-spki-algorithm.der", &server_spki_alg);
    dump_artifact("server-point.bin", &server_point);
    dump_artifact(
        "ephemeral-spki-content.der",
        &transport_key.ephemeral_spki_content,
    );

    // --- Flight 2 -------------------------------------------------------------
    // Certificate
    let cert_body = hs.client_certificate(params.client_cert_chain);
    dump_artifact("c2-certificate.body", &cert_body);
    if let Err(e) = send_handshake(transport, HandshakeType::Certificate, &cert_body) {
        return Err(enrich_with_alert(transport, "Certificate", e));
    }
    probe_stage(transport, "Certificate");

    // ClientKeyExchange (also derives master secret, key block, record crypto)
    let cke_body = hs.client_key_exchange(
        &kek,
        &params.premaster,
        Some(&transport_key.ephemeral_spki_content),
    )?;
    dump_artifact("c2-clientkeyexchange.body", &cke_body);
    if let Err(e) = send_handshake(transport, HandshakeType::ClientKeyExchange, &cke_body) {
        return Err(enrich_with_alert(transport, "ClientKeyExchange", e));
    }
    probe_stage(transport, "ClientKeyExchange");

    // CertificateVerify (token signs the running transcript hash)
    let digest = hs.certificate_verify_digest();
    let signature = sign(&digest).map_err(LoginError::Sign)?;
    // RFC 9189 §4.2.5 / RFC 5246 §7.4.8: the body is a `digitally-signed` struct:
    //   SignatureAndHashAlgorithm {hash, signature}
    //   opaque signature<0..2^16-1>
    // i.e. <hash> <sig> || u16(len) || sgn, where sgn = str_l(r) | str_l(s).
    //
    // This LKUL endpoint negotiates the LEGACY 0xFF85 suite and its
    // CertificateRequest advertises the legacy SignatureAndHashAlgorithm pair
    // `EE EE` (RFC 9189 §10: the old value 0xEE stands in for the modern
    // gostr34102012_256 signature + Intrinsic hash). The modern `08 40` pair is
    // not offered, so we must echo the legacy `EE EE` here.
    let mut cv = Vec::with_capacity(4 + signature.len());
    cv.extend_from_slice(&[0xEE, 0xEE]);
    cv.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    cv.extend_from_slice(&signature);
    dump_artifact("c2-certificateverify.body", &cv);
    if let Err(e) = send_handshake(transport, HandshakeType::CertificateVerify, &cv) {
        return Err(enrich_with_alert(transport, "CertificateVerify", e));
    }
    let cv_body = hs.record_certificate_verify(&cv);
    let _ = cv_body;
    probe_stage(transport, "CertificateVerify");

    // ChangeCipherSpec — everything after this is record-protected.
    if let Err(e) = transport.send_record(ContentType::ChangeCipherSpec, &[0x01]) {
        return Err(enrich_with_alert(transport, "ChangeCipherSpec", e.into()));
    }
    probe_stage(transport, "ChangeCipherSpec");

    // Finished (encrypted)
    let client_vd = hs.client_finished()?;
    let finished_msg = ClientHandshake::frame(HandshakeType::Finished, &client_vd);
    let protected = {
        let rc = hs
            .record_crypto()
            .ok_or_else(|| LoginError::Protocol("record crypto unavailable".into()))?;
        rc.protect(ContentType::Handshake, version, &finished_msg)
    };
    if let Err(e) = transport.send_record(ContentType::Handshake, &protected) {
        return Err(enrich_with_alert(transport, "Finished", e.into()));
    }

    // --- Read the server's ChangeCipherSpec + encrypted Finished -------------
    let ccs = transport.recv_record()?;
    if ccs.content_type != ContentType::ChangeCipherSpec {
        if ccs.content_type == ContentType::Alert && ccs.payload.len() >= 2 {
            return Err(LoginError::Protocol(format!(
                "server Alert after Finished: level={} description={} ({})",
                ccs.payload[0],
                ccs.payload[1],
                alert_text(ccs.payload[1]),
            )));
        }
        return Err(LoginError::Protocol(format!(
            "expected server ChangeCipherSpec, got {:?}",
            ccs.content_type
        )));
    }

    let server_fin_record = transport.recv_record()?;
    if server_fin_record.content_type != ContentType::Handshake {
        return Err(LoginError::Protocol(format!(
            "expected encrypted server Finished, got {:?}",
            server_fin_record.content_type
        )));
    }
    let server_fin_plain = {
        let rc = hs
            .record_crypto()
            .ok_or_else(|| LoginError::Protocol("record crypto unavailable".into()))?;
        rc.unprotect(ContentType::Handshake, version, &server_fin_record.payload)
            .map_err(|e| LoginError::Protocol(format!("server Finished decrypt failed: {e:?}")))?
    };
    // Strip the 4-byte handshake header (type 20 || u24 length) → 12-byte vd.
    if server_fin_plain.len() < 4 + 12 || server_fin_plain[0] != HandshakeType::Finished as u8 {
        return Err(LoginError::Protocol(format!(
            "malformed server Finished message ({} bytes)",
            server_fin_plain.len()
        )));
    }
    let mut server_vd = [0u8; 12];
    server_vd.copy_from_slice(&server_fin_plain[4..16]);
    hs.verify_server_finished(&server_vd)?;

    Ok(LoginSession {
        handshake: hs,
        server_leaf_cert,
    })
}

/// Frame a handshake body and send it as a plaintext Handshake record.
fn send_handshake(
    transport: &mut TlsTransport,
    msg_type: HandshakeType,
    body: &[u8],
) -> Result<(), LoginError> {
    let framed = ClientHandshake::frame(msg_type, body);
    transport.send_record(ContentType::Handshake, &framed)?;
    Ok(())
}

/// Diagnostic: after each flight-2 message, when `GOST_LOGIN_PROBE` is set,
/// briefly check whether the server already reset or sent an alert. Output goes
/// to stderr; it never changes control flow (purely observational).
fn probe_stage(transport: &mut TlsTransport, stage: &str) {
    if std::env::var("GOST_LOGIN_PROBE").is_err() {
        return;
    }
    let probe = std::time::Duration::from_millis(700);
    let normal = std::time::Duration::from_secs(8);
    match transport.probe_peer(probe, normal) {
        Ok(None) => eprintln!("[probe] after {stage}: connection alive (no response)"),
        Ok(Some(rec)) if rec.content_type == ContentType::Alert && rec.payload.len() >= 2 => {
            eprintln!(
                "[probe] after {stage}: server ALERT level={} description={} ({})",
                rec.payload[0],
                rec.payload[1],
                alert_text(rec.payload[1])
            );
        }
        Ok(Some(rec)) => eprintln!(
            "[probe] after {stage}: server sent {:?} record ({} bytes)",
            rec.content_type,
            rec.payload.len()
        ),
        Err(e) => eprintln!("[probe] after {stage}: connection RESET/closed ({e})"),
    }
}

/// Write a flight artifact to `$GOST_LOGIN_DUMP_DIR/<name>` when that env var is
/// set (diagnostics only; no-op otherwise).
fn dump_artifact(name: &str, bytes: &[u8]) {
    if let Ok(dir) = std::env::var("GOST_LOGIN_DUMP_DIR") {
        let path = std::path::Path::new(&dir).join(name);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(&path, bytes);
    }
}

/// After a flight-2 write fails (the server reset the connection), try to read
/// the TLS alert the server sent so the error names *why* it rejected us.
fn enrich_with_alert(
    transport: &mut TlsTransport,
    stage: &str,
    original: LoginError,
) -> LoginError {
    match transport.recv_record() {
        Ok(rec) if rec.content_type == ContentType::Alert && rec.payload.len() >= 2 => {
            let level = rec.payload[0];
            let desc = rec.payload[1];
            LoginError::Protocol(format!(
                "after sending {stage}: {original}; server TLS alert level={level} description={desc} ({})",
                alert_text(desc)
            ))
        }
        Ok(rec) => LoginError::Protocol(format!(
            "after sending {stage}: {original}; server sent {:?} record ({} bytes) instead of an alert",
            rec.content_type,
            rec.payload.len()
        )),
        Err(e) => LoginError::Protocol(format!(
            "after sending {stage}: {original}; no TLS alert readable after reset (recv: {e})"
        )),
    }
}

/// RFC 5246 §7.2 alert description names (the subset relevant to a GOST handshake).
fn alert_text(desc: u8) -> &'static str {
    match desc {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        90 => "user_canceled",
        109 => "missing_extension",
        112 => "unrecognized_name",
        _ => "unknown",
    }
}

/// Build the extensions-list bytes carrying a single `server_name` (SNI)
/// extension for `host`, suitable for `ClientHandshake::start`'s `extensions`.
pub fn sni_extension(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    // ServerNameList: name_type(1)=host_name(0) || HostName<2-byte len>.
    let mut name_entry = Vec::with_capacity(3 + host.len());
    name_entry.push(0x00); // host_name
    name_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    name_entry.extend_from_slice(host);

    let mut server_name_list = Vec::with_capacity(2 + name_entry.len());
    server_name_list.extend_from_slice(&(name_entry.len() as u16).to_be_bytes());
    server_name_list.extend_from_slice(&name_entry);

    // Extension: extension_type(2)=server_name(0) || extension_data<2-byte len>.
    let mut ext = Vec::with_capacity(4 + server_name_list.len());
    ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
    ext.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&server_name_list);
    ext
}

/// Extract the first (leaf) certificate from a TLS `Certificate` message body.
///
/// Layout: `certificate_list<0..2^24-1>` of `certificate<0..2^24-1>`.
fn first_certificate(body: &[u8]) -> Result<Vec<u8>, LoginError> {
    if body.len() < 3 {
        return Err(LoginError::Protocol("Certificate message too short".into()));
    }
    let list_len = u32::from_be_bytes([0, body[0], body[1], body[2]]) as usize;
    let list = body
        .get(3..3 + list_len)
        .ok_or_else(|| LoginError::Protocol("Certificate list length out of range".into()))?;
    if list.len() < 3 {
        return Err(LoginError::Protocol("empty certificate list".into()));
    }
    let cert_len = u32::from_be_bytes([0, list[0], list[1], list[2]]) as usize;
    let cert = list
        .get(3..3 + cert_len)
        .ok_or_else(|| LoginError::Protocol("certificate length out of range".into()))?;
    Ok(cert.to_vec())
}

/// Extract the raw `subjectPublicKey` point bytes from an X.509 certificate's
/// `SubjectPublicKeyInfo`.
///
/// For a GOST R 34.10-2012 (256-bit) key the returned slice is the 64-byte
/// public point exactly as stored in the certificate (the contents of the
/// `OCTET STRING` wrapped inside the `subjectPublicKey` `BIT STRING`). The
/// caller's `vko` closure is responsible for any coordinate byte-order
/// conversion the token expects.
pub fn extract_subject_public_point(cert_der: &[u8]) -> Result<Vec<u8>, LoginError> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, ... }
    let cert = der_expect_sequence(cert_der)?;
    // First element of the cert body is tbsCertificate; take its content.
    let (tbs, _) = der_read_tlv(cert, 0)?;

    // tbsCertificate fields, in order:
    //   [0] version (OPTIONAL), serialNumber, signature, issuer, validity,
    //   subject, subjectPublicKeyInfo, ...
    let mut pos = 0usize;
    // Skip optional [0] EXPLICIT version (context tag 0xA0).
    let (first_tag, _, _) = der_peek(tbs, pos)?;
    if first_tag == 0xA0 {
        pos = der_skip(tbs, pos)?; // version
    }
    pos = der_skip(tbs, pos)?; // serialNumber
    pos = der_skip(tbs, pos)?; // signature
    pos = der_skip(tbs, pos)?; // issuer
    pos = der_skip(tbs, pos)?; // validity
    pos = der_skip(tbs, pos)?; // subject

    // subjectPublicKeyInfo SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
    let (spki, _) = der_read_tlv(tbs, pos)?;
    let after_alg = der_skip(spki, 0)?; // skip algorithm
    let (tag, content, _) = der_peek(spki, after_alg)?;
    if tag != 0x03 {
        return Err(LoginError::Protocol(format!(
            "expected subjectPublicKey BIT STRING, got tag 0x{tag:02x}"
        )));
    }
    // BIT STRING content = unused-bits byte (must be 0) || DER-encoded point.
    if content.is_empty() {
        return Err(LoginError::Protocol("empty subjectPublicKey".into()));
    }
    if content[0] != 0x00 {
        return Err(LoginError::Protocol(format!(
            "subjectPublicKey has {} unused bits (expected 0)",
            content[0]
        )));
    }
    let inner = &content[1..];
    // GOST keys wrap the point in an OCTET STRING (04 len || point).
    let (octet_tag, point, _) = der_peek(inner, 0)?;
    if octet_tag != 0x04 {
        return Err(LoginError::Protocol(format!(
            "expected OCTET STRING in subjectPublicKey, got tag 0x{octet_tag:02x}"
        )));
    }
    Ok(point.to_vec())
}

/// Extract the full `algorithm` AlgorithmIdentifier TLV (tag `0x30…`) from an
/// X.509 certificate's `SubjectPublicKeyInfo`.
///
/// This is reused verbatim as the ephemeral key's algorithm identifier so its
/// `publicKeyParamSet` exactly matches the server's curve.
pub fn extract_spki_algorithm(cert_der: &[u8]) -> Result<Vec<u8>, LoginError> {
    let cert = der_expect_sequence(cert_der)?;
    let (tbs, _) = der_read_tlv(cert, 0)?;

    let mut pos = 0usize;
    let (first_tag, _, _) = der_peek(tbs, pos)?;
    if first_tag == 0xA0 {
        pos = der_skip(tbs, pos)?; // version
    }
    pos = der_skip(tbs, pos)?; // serialNumber
    pos = der_skip(tbs, pos)?; // signature
    pos = der_skip(tbs, pos)?; // issuer
    pos = der_skip(tbs, pos)?; // validity
    pos = der_skip(tbs, pos)?; // subject

    let (spki, _) = der_read_tlv(tbs, pos)?;
    // The algorithm is the first element of the SPKI SEQUENCE; return its TLV.
    let (tag, content, end) = der_peek(spki, 0)?;
    if tag != 0x30 {
        return Err(LoginError::Protocol(format!(
            "expected SPKI algorithm SEQUENCE, got tag 0x{tag:02x}"
        )));
    }
    let _ = content;
    Ok(spki[0..end].to_vec())
}

// --- Minimal DER helpers (TLV walking only; no validation beyond lengths) ----

/// Read one TLV at `pos`, returning `(content_slice, next_pos)`.
fn der_read_tlv(data: &[u8], pos: usize) -> Result<(&[u8], usize), LoginError> {
    let (_, content, next) = der_peek(data, pos)?;
    Ok((content, next))
}

/// Peek one TLV at `pos`, returning `(tag, content_slice, next_pos)`.
fn der_peek(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize), LoginError> {
    let tag = *data
        .get(pos)
        .ok_or_else(|| LoginError::Protocol("DER: truncated tag".into()))?;
    let len_byte = *data
        .get(pos + 1)
        .ok_or_else(|| LoginError::Protocol("DER: truncated length".into()))?;
    let (len, header) = if len_byte < 0x80 {
        (len_byte as usize, 2usize)
    } else {
        let num = (len_byte & 0x7f) as usize;
        if num == 0 || num > 4 {
            return Err(LoginError::Protocol(format!(
                "DER: unsupported length form 0x{len_byte:02x}"
            )));
        }
        let mut len = 0usize;
        for i in 0..num {
            let b = *data
                .get(pos + 2 + i)
                .ok_or_else(|| LoginError::Protocol("DER: truncated long-form length".into()))?;
            len = (len << 8) | b as usize;
        }
        (len, 2 + num)
    };
    let start = pos + header;
    let end = start
        .checked_add(len)
        .ok_or_else(|| LoginError::Protocol("DER: length overflow".into()))?;
    let content = data
        .get(start..end)
        .ok_or_else(|| LoginError::Protocol("DER: content out of range".into()))?;
    Ok((tag, content, end))
}

/// Skip one TLV at `pos`, returning the position after it.
fn der_skip(data: &[u8], pos: usize) -> Result<usize, LoginError> {
    let (_, _, next) = der_peek(data, pos)?;
    Ok(next)
}

/// Assert the whole input is a single SEQUENCE and return its content.
fn der_expect_sequence(data: &[u8]) -> Result<&[u8], LoginError> {
    let (tag, content, _) = der_peek(data, 0)?;
    if tag != 0x30 {
        return Err(LoginError::Protocol(format!(
            "expected SEQUENCE, got tag 0x{tag:02x}"
        )));
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gost_handshake::{Transcript, frame_handshake};
    use crate::gost_prf::{CLIENT_FINISHED_LABEL, SERVER_FINISHED_LABEL, key_block, master_secret};
    use crate::gost_record::RecordCrypto;
    use crate::tls::cipher_suite;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn sni_extension_has_expected_tlv_shape() {
        let ext = sni_extension("ab.ru");
        // extension_type = 0x0000 (server_name)
        assert_eq!(&ext[0..2], &[0x00, 0x00]);
        // extension_data length
        assert_eq!(u16::from_be_bytes([ext[2], ext[3]]) as usize, ext.len() - 4);
        // ServerNameList length
        assert_eq!(u16::from_be_bytes([ext[4], ext[5]]) as usize, ext.len() - 6);
        // name_type host_name
        assert_eq!(ext[6], 0x00);
        // host length + bytes
        assert_eq!(u16::from_be_bytes([ext[7], ext[8]]) as usize, 5);
        assert_eq!(&ext[9..], b"ab.ru");
    }

    // Build a DER TLV with short/long-form length.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    /// A synthetic but structurally valid GOST certificate carrying a known
    /// 64-byte public point, to validate the SPKI walker.
    fn synthetic_gost_cert(point: &[u8; 64]) -> Vec<u8> {
        let version = der(0xA0, &der(0x02, &[0x02])); // [0] { INTEGER 2 }
        let serial = der(0x02, &[0x01, 0x23, 0x45]);
        let sigalg = der(0x30, &der(0x06, &[0x2a, 0x85, 0x03])); // SEQ { OID }
        let issuer = der(0x30, &[]);
        let validity = der(0x30, &[]);
        let subject = der(0x30, &[]);

        // subjectPublicKey BIT STRING = 00 || OCTET STRING(point)
        let octet = der(0x04, point);
        let mut bitstr_content = vec![0x00];
        bitstr_content.extend_from_slice(&octet);
        let bitstring = der(0x03, &bitstr_content);
        let spki_alg = der(
            0x30,
            &der(0x06, &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01]),
        );
        let mut spki_content = spki_alg;
        spki_content.extend_from_slice(&bitstring);
        let spki = der(0x30, &spki_content);

        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&sigalg);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);
        let tbs = der(0x30, &tbs);

        let sig_alg2 = der(0x30, &der(0x06, &[0x2a, 0x85, 0x03]));
        let sig = der(0x03, &[0x00, 0xAA, 0xBB]);
        let mut cert = tbs;
        cert.extend_from_slice(&sig_alg2);
        cert.extend_from_slice(&sig);
        der(0x30, &cert)
    }

    #[test]
    fn extract_point_from_synthetic_gost_cert() {
        let mut point = [0u8; 64];
        for (i, b) in point.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }
        let cert = synthetic_gost_cert(&point);
        let extracted = extract_subject_public_point(&cert).expect("extract");
        assert_eq!(extracted, point.to_vec());
    }

    #[test]
    fn first_certificate_returns_leaf() {
        // certificate_list { cert("LEAF"), cert("CA") }
        let leaf = b"LEAF";
        let ca = b"CAxx";
        let mut list = Vec::new();
        for c in [leaf.as_slice(), ca.as_slice()] {
            list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..4]);
            list.extend_from_slice(c);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..4]);
        body.extend_from_slice(&list);
        assert_eq!(first_certificate(&body).unwrap(), leaf.to_vec());
    }

    /// Full login over a real loopback socket against a scripted server that
    /// shares the premaster/KEK (mock closures), so the server can recompute the
    /// transcript and Finished messages and cross-check the driver end to end.
    #[test]
    fn run_login_round_trips_over_loopback() {
        let client_random = [0x41u8; 32];
        let server_random = [0x52u8; 32];
        let premaster = [0x63u8; 32];
        // The server leaf must carry a real on-curve point so the software
        // ephemeral key transport can identify the curve and run VKO.
        let curve = crate::gost_ec::tc26_256_paramset_b();
        let point_vec = curve
            .encode_point_le(&curve.generator())
            .expect("generator encodes");
        let mut point = [0u8; 64];
        point.copy_from_slice(&point_vec);
        let leaf_cert = synthetic_gost_cert(&point);
        let client_cert = vec![0xC1, 0xC2, 0xC3];

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_leaf = leaf_cert.clone();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            mock_server(sock, server_random, premaster, &server_leaf);
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut transport = TlsTransport::from_stream(stream);

        let params = LoginParams {
            server_name: "lkulgost.nalog.ru",
            client_random,
            premaster,
            client_cert_chain: std::slice::from_ref(&client_cert),
            cipher_suites: &[cipher_suite::LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT],
        };

        let session = run_login(
            &mut transport,
            &params,
            |buf| {
                // Deterministic "entropy" for the ephemeral key in this test.
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(7).wrapping_add(0x5A);
                }
                Ok(())
            },
            |digest| Ok(digest.to_vec()), // mock token: echo the digest as the signature
        )
        .expect("login");

        assert_eq!(session.server_leaf_cert(), leaf_cert.as_slice());
        server.join().expect("server thread");
    }

    /// Minimal scripted TLS server for the loopback test. It mirrors the
    /// transcript by pushing the exact framed bytes it sends/receives, shares
    /// `premaster` (as the mock VKO/key-transport result), and produces a
    /// correct server `Finished`.
    fn mock_server(
        mut sock: TcpStream,
        server_random: [u8; 32],
        premaster: [u8; 32],
        leaf_cert: &[u8],
    ) {
        let mut transcript = Transcript::new();

        // 1) Read ClientHello record, recover client_random + framed bytes.
        let ch = read_plain_handshake_record(&mut sock);
        transcript.push_framed(&ch);
        // framed = type(1) || len(3) || body; body = ver(2) || random(32) || ...
        let client_random: [u8; 32] = ch[6..38].try_into().unwrap();

        // 2) Send ServerHello, Certificate, CertificateRequest, ServerHelloDone.
        let sh_body = {
            let mut b = Vec::new();
            b.extend_from_slice(&[0x03, 0x03]); // version
            b.extend_from_slice(&server_random);
            b.push(0x00); // session_id len 0
            b.extend_from_slice(&[0xFF, 0x85]); // cipher suite
            b.push(0x00); // compression null
            b
        };
        send_plain_handshake(&mut sock, &mut transcript, 0x02, &sh_body);

        let cert_body = {
            let mut list = Vec::new();
            list.extend_from_slice(&(leaf_cert.len() as u32).to_be_bytes()[1..4]);
            list.extend_from_slice(leaf_cert);
            let mut b = Vec::new();
            b.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..4]);
            b.extend_from_slice(&list);
            b
        };
        send_plain_handshake(&mut sock, &mut transcript, 0x0b, &cert_body);
        send_plain_handshake(&mut sock, &mut transcript, 0x0d, &[0x00, 0x00, 0x00]); // CertReq (mock)
        send_plain_handshake(&mut sock, &mut transcript, 0x0e, &[]); // ServerHelloDone

        // 3) Read client Certificate, ClientKeyExchange, CertificateVerify.
        for _ in 0..3 {
            let m = read_plain_handshake_record(&mut sock);
            transcript.push_framed(&m);
        }

        // 4) Read ChangeCipherSpec, then the encrypted Finished.
        let ccs = read_record(&mut sock);
        assert_eq!(ccs.0, ContentType::ChangeCipherSpec as u8);

        // Derive the same secrets the client derived.
        let ms = master_secret(&premaster, &client_random, &server_random);
        let kb = key_block(&ms, &client_random, &server_random);
        // Server's record context: its *read* keys are the client's write keys.
        let mut server_rc = RecordCrypto::new(
            &kb.server_mac_key,
            &kb.server_enc_key,
            &kb.server_iv,
            &kb.client_mac_key,
            &kb.client_enc_key,
            &kb.client_iv,
        );

        let enc_fin = read_record(&mut sock);
        assert_eq!(enc_fin.0, ContentType::Handshake as u8);
        let client_fin = server_rc
            .unprotect(ContentType::Handshake, ProtocolVersion::TLS1_2, &enc_fin.1)
            .expect("decrypt client finished");
        // Verify the client's verify_data over the transcript so far.
        let expected_client_vd =
            crate::gost_handshake::finished_body(&ms, CLIENT_FINISHED_LABEL, &transcript);
        assert_eq!(&client_fin[4..16], &expected_client_vd);
        // Add the client Finished to the transcript before computing ours.
        transcript.push_framed(&client_fin);

        // 5) Send our ChangeCipherSpec + encrypted Finished.
        let ccs_rec = encode_record(ContentType::ChangeCipherSpec as u8, &[0x01]);
        sock.write_all(&ccs_rec).unwrap();

        let server_vd =
            crate::gost_handshake::finished_body(&ms, SERVER_FINISHED_LABEL, &transcript);
        let server_fin_msg = frame_handshake(HandshakeType::Finished, &server_vd);
        let protected = server_rc.protect(
            ContentType::Handshake,
            ProtocolVersion::TLS1_2,
            &server_fin_msg,
        );
        let rec = encode_record(ContentType::Handshake as u8, &protected);
        sock.write_all(&rec).unwrap();
        sock.flush().unwrap();
    }

    fn encode_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut r = vec![content_type, 0x03, 0x03];
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(payload);
        r
    }

    fn read_record(sock: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 5];
        sock.read_exact(&mut hdr).unwrap();
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut payload = vec![0u8; len];
        sock.read_exact(&mut payload).unwrap();
        (hdr[0], payload)
    }

    /// Read one plaintext Handshake record and return the framed message bytes.
    fn read_plain_handshake_record(sock: &mut TcpStream) -> Vec<u8> {
        let (ct, payload) = read_record(sock);
        assert_eq!(ct, ContentType::Handshake as u8);
        payload
    }

    fn send_plain_handshake(
        sock: &mut TcpStream,
        transcript: &mut Transcript,
        msg_type: u8,
        body: &[u8],
    ) {
        let mut framed = vec![msg_type];
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        framed.extend_from_slice(body);
        transcript.push_framed(&framed);
        let rec = encode_record(ContentType::Handshake as u8, &framed);
        sock.write_all(&rec).unwrap();
        sock.flush().unwrap();
    }
}
