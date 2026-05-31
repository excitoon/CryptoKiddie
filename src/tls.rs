//! Minimal GOST TLS 1.2 client foundation (RFC 9189 cipher suites).
//!
//! This module implements the wire-level building blocks of a TLS 1.2 client
//! speaking the Russian GOST cipher suites used by services such as
//! `lkulgost.nalog.ru`:
//!
//! * the TLS record layer (`TLSPlaintext` framing over a byte stream);
//! * handshake-message reassembly across records;
//! * a `ClientHello` builder advertising the GOST suites (RFC 9189) plus SNI;
//! * decoders for the server's first flight (`ServerHello`, `Certificate`,
//!   `ServerKeyExchange`, `ServerHelloDone`) and `Alert` records;
//! * a TCP transport that performs the opening handshake round-trip.
//!
//! The cryptographic completion of the handshake — the GOST VKO key exchange
//! (driven by the Rutoken token), key-material derivation, record encryption
//! (Magma/Kuznyechik CTR-ACPKM + OMAC) and `Finished` verification — builds on
//! top of these primitives and is staged separately. Everything here is pure,
//! deterministic wire handling with no cryptographic state, so it is fully
//! unit-testable offline.

use super::CliError;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// TLS `ContentType` (RFC 5246 §6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// TLS protocol version. Only the values relevant to a GOST TLS 1.2 client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion(pub u8, pub u8);

impl ProtocolVersion {
    /// TLS 1.2 = {3, 3}.
    pub const TLS1_2: ProtocolVersion = ProtocolVersion(3, 3);
    /// TLS 1.0 = {3, 1} — the lowest version some GOST endpoints place in the
    /// record-layer `legacy_record_version` field.
    pub const TLS1_0: ProtocolVersion = ProtocolVersion(3, 1);
}

/// TLS `HandshakeType` (RFC 5246 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl HandshakeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            11 => Some(Self::Certificate),
            12 => Some(Self::ServerKeyExchange),
            13 => Some(Self::CertificateRequest),
            14 => Some(Self::ServerHelloDone),
            15 => Some(Self::CertificateVerify),
            16 => Some(Self::ClientKeyExchange),
            20 => Some(Self::Finished),
            _ => None,
        }
    }
}

/// GOST cipher suites understood by this client.
///
/// The primary three are the IANA-registered RFC 9189 values; the trailing two
/// are the legacy TC26 code points still offered by some government
/// endpoints for backward compatibility.
pub mod cipher_suite {
    /// `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` (RFC 9189).
    pub const GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC: u16 = 0xC100;
    /// `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC` (RFC 9189).
    pub const GOSTR341112_256_WITH_MAGMA_CTR_OMAC: u16 = 0xC101;
    /// `TLS_GOSTR341112_256_WITH_28147_CNT_IMIT` (RFC 9189).
    pub const GOSTR341112_256_WITH_28147_CNT_IMIT: u16 = 0xC102;
    /// Legacy TC26 draft code point for the 28147 CNT+IMIT suite.
    pub const LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT: u16 = 0xFF85;
    /// Legacy GOST R 34.10-2001 suite (`TLS_GOSTR341001_WITH_28147_CNT_IMIT`).
    pub const LEGACY_GOSTR341001_WITH_28147_CNT_IMIT: u16 = 0x0081;

    /// The default suite list advertised in a GOST `ClientHello`, most-preferred
    /// first.
    pub fn gost_default_list() -> Vec<u16> {
        vec![
            GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC,
            GOSTR341112_256_WITH_MAGMA_CTR_OMAC,
            GOSTR341112_256_WITH_28147_CNT_IMIT,
            LEGACY_GOSTR341112_256_WITH_28147_CNT_IMIT,
            LEGACY_GOSTR341001_WITH_28147_CNT_IMIT,
        ]
    }
}

/// Little buffer-writer with TLS length-prefix helpers.
#[derive(Debug, Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn u24(&mut self, value: u32) {
        let bytes = value.to_be_bytes();
        self.buf.extend_from_slice(&bytes[1..4]);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }

    /// Append `body`, prefixed with its length encoded in `len_bytes` (1, 2 or 3).
    fn with_len<F: FnOnce(&mut Writer)>(&mut self, len_bytes: usize, body: F) {
        let mut inner = Writer::new();
        body(&mut inner);
        let len = inner.buf.len();
        match len_bytes {
            1 => self.u8(len as u8),
            2 => self.u16(len as u16),
            3 => self.u24(len as u32),
            _ => unreachable!("unsupported TLS length prefix width"),
        }
        self.buf.extend_from_slice(&inner.buf);
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Cursor-based reader with TLS length-prefix helpers; every accessor is
/// bounds-checked and returns a descriptive [`CliError`] on truncation.
#[derive(Debug)]
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CliError> {
        if self.remaining() < n {
            return Err(CliError::Message(format!(
                "TLS decode: wanted {n} bytes, only {} remain",
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, CliError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CliError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, CliError> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// Read a length-prefixed vector whose length occupies `len_bytes` bytes.
    fn vec(&mut self, len_bytes: usize) -> Result<&'a [u8], CliError> {
        let len = match len_bytes {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            3 => self.u24()? as usize,
            _ => unreachable!("unsupported TLS length prefix width"),
        };
        self.take(len)
    }
}

/// A single TLS record as it appears on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub payload: Vec<u8>,
}

impl Record {
    /// Serialize a `TLSPlaintext` record header followed by its fragment.
    pub fn encode(content_type: ContentType, version: ProtocolVersion, payload: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(content_type as u8);
        w.u8(version.0);
        w.u8(version.1);
        w.u16(payload.len() as u16);
        w.bytes(payload);
        w.into_vec()
    }
}

/// Parsed `ServerHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<u8>,
}

impl ServerHello {
    fn parse(body: &[u8]) -> Result<Self, CliError> {
        let mut r = Reader::new(body);
        let server_version = ProtocolVersion(r.u8()?, r.u8()?);
        let random: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| CliError::Message("ServerHello random not 32 bytes".to_string()))?;
        let session_id = r.vec(1)?.to_vec();
        let cipher_suite = r.u16()?;
        let compression_method = r.u8()?;
        // Extensions block is optional in TLS 1.2.
        let extensions = if r.remaining() >= 2 {
            r.vec(2)?.to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

/// Parsed `Certificate` handshake message — the server's certificate chain in
/// DER, leaf first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMessage {
    pub certificates: Vec<Vec<u8>>,
}

impl CertificateMessage {
    fn parse(body: &[u8]) -> Result<Self, CliError> {
        let mut r = Reader::new(body);
        let list = r.vec(3)?;
        let mut inner = Reader::new(list);
        let mut certificates = Vec::new();
        while inner.remaining() > 0 {
            certificates.push(inner.vec(3)?.to_vec());
        }
        Ok(Self { certificates })
    }
}

/// A handshake message decoded from the server flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    ServerHello(ServerHello),
    Certificate(CertificateMessage),
    /// `ServerKeyExchange` body is suite-specific (GOST carries the ephemeral
    /// key-transport parameters); kept raw for the key-exchange stage.
    ServerKeyExchange(Vec<u8>),
    CertificateRequest(Vec<u8>),
    ServerHelloDone,
    /// Any modelled handshake type not separately handled, kept with its raw body.
    Other(HandshakeType, Vec<u8>),
    /// A handshake type this client does not recognize, with its raw type byte.
    Unknown(u8, Vec<u8>),
}

/// A TLS alert (RFC 5246 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: u8,
    pub description: u8,
}

impl Alert {
    fn parse(payload: &[u8]) -> Result<Self, CliError> {
        if payload.len() < 2 {
            return Err(CliError::Message(
                "Alert record shorter than 2 bytes".to_string(),
            ));
        }
        Ok(Self {
            level: payload[0],
            description: payload[1],
        })
    }

    /// Human-readable RFC 5246 alert description.
    pub fn description_text(&self) -> &'static str {
        match self.description {
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
}

/// Decode a buffer of concatenated handshake messages (as carried in one or
/// more `Handshake` records) into structured messages.
pub fn decode_handshake_messages(buf: &[u8]) -> Result<Vec<HandshakeMessage>, CliError> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let raw_type = r.u8()?;
        let body = r.vec(3)?;
        let Some(handshake_type) = HandshakeType::from_u8(raw_type) else {
            // Unknown handshake type: preserve its raw body for diagnostics
            // without inventing a discriminant.
            out.push(HandshakeMessage::Unknown(raw_type, body.to_vec()));
            continue;
        };
        let message = match handshake_type {
            HandshakeType::ServerHello => HandshakeMessage::ServerHello(ServerHello::parse(body)?),
            HandshakeType::Certificate => {
                HandshakeMessage::Certificate(CertificateMessage::parse(body)?)
            }
            HandshakeType::ServerKeyExchange => HandshakeMessage::ServerKeyExchange(body.to_vec()),
            HandshakeType::CertificateRequest => {
                HandshakeMessage::CertificateRequest(body.to_vec())
            }
            HandshakeType::ServerHelloDone => HandshakeMessage::ServerHelloDone,
            other => HandshakeMessage::Other(other, body.to_vec()),
        };
        out.push(message);
    }
    Ok(out)
}

/// Builder for a GOST TLS 1.2 `ClientHello`.
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub server_name: Option<String>,
}

impl ClientHello {
    /// Construct a ClientHello advertising the default GOST suites and the given
    /// SNI host. `random` should be 32 bytes of (ideally CSPRNG) entropy; the
    /// first 4 bytes are conventionally the gmt_unix_time.
    pub fn new_gost(server_name: impl Into<String>, random: [u8; 32]) -> Self {
        Self {
            random,
            session_id: Vec::new(),
            cipher_suites: cipher_suite::gost_default_list(),
            server_name: Some(server_name.into()),
        }
    }

    /// Encode the full handshake message: `HandshakeType(1) || u24 length || body`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        // client_version = TLS 1.2
        body.u8(ProtocolVersion::TLS1_2.0);
        body.u8(ProtocolVersion::TLS1_2.1);
        body.bytes(&self.random);
        body.with_len(1, |w| w.bytes(&self.session_id));
        body.with_len(2, |w| {
            for &suite in &self.cipher_suites {
                w.u16(suite);
            }
        });
        // compression_methods = { null }
        body.with_len(1, |w| w.u8(0));
        // extensions
        body.with_len(2, |w| {
            if let Some(host) = &self.server_name {
                Self::encode_sni(w, host);
            }
        });

        let mut msg = Writer::new();
        msg.u8(HandshakeType::ClientHello as u8);
        msg.with_len(3, |w| w.bytes(&body.into_vec()));
        msg.into_vec()
    }

    fn encode_sni(w: &mut Writer, host: &str) {
        // extension_type = server_name (0)
        w.u16(0);
        w.with_len(2, |ext| {
            // ServerNameList
            ext.with_len(2, |list| {
                // name_type = host_name (0)
                list.u8(0);
                list.with_len(2, |name| name.bytes(host.as_bytes()));
            });
        });
    }
}

/// Outcome of the opening handshake round-trip.
#[derive(Debug, Clone)]
pub struct ServerFlight {
    pub server_hello: ServerHello,
    pub certificates: Vec<Vec<u8>>,
    pub server_key_exchange: Option<Vec<u8>>,
    pub certificate_request: Option<Vec<u8>>,
    pub server_hello_done: bool,
}

/// TLS transport over a TCP stream that frames and reassembles records.
#[derive(Debug)]
pub struct TlsTransport {
    stream: TcpStream,
    /// Leftover handshake bytes spanning record boundaries.
    handshake_buf: Vec<u8>,
}

impl TlsTransport {
    /// Connect to `host:port` over TCP with the given timeout.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, CliError> {
        use std::net::ToSocketAddrs;
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|e| CliError::Message(format!("resolve {host}:{port}: {e}")))?
            .next()
            .ok_or_else(|| CliError::Message(format!("no addresses for {host}:{port}")))?;
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| CliError::Message(format!("connect {host}:{port}: {e}")))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| CliError::Message(format!("set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| CliError::Message(format!("set write timeout: {e}")))?;
        Ok(Self {
            stream,
            handshake_buf: Vec::new(),
        })
    }

    /// Wrap an already-connected TCP stream (e.g. for testing over a loopback,
    /// or when the socket was established elsewhere).
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            handshake_buf: Vec::new(),
        }
    }

    /// Send a single plaintext handshake record carrying `payload`.
    fn send_handshake(&mut self, payload: &[u8]) -> Result<(), CliError> {
        self.send_record(ContentType::Handshake, payload)
    }

    /// Send one TLS record of the given `content_type` carrying `payload`.
    ///
    /// This is the flight-2 primitive used by the login driver to put
    /// Certificate / ClientKeyExchange / CertificateVerify / ChangeCipherSpec /
    /// (encrypted) Finished / ApplicationData records on the wire. `payload` is
    /// the record fragment exactly as it should appear after the 5-byte record
    /// header — already encrypted for post-ChangeCipherSpec traffic.
    pub fn send_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<(), CliError> {
        let record = Record::encode(content_type, ProtocolVersion::TLS1_2, payload);
        self.stream
            .write_all(&record)
            .map_err(|e| CliError::Message(format!("write {content_type:?} record: {e}")))?;
        self.stream
            .flush()
            .map_err(|e| CliError::Message(format!("flush {content_type:?} record: {e}")))
    }

    /// Read exactly one TLS record off the wire (public flight-2 primitive).
    pub fn recv_record(&mut self) -> Result<Record, CliError> {
        self.read_record()
    }

    /// Diagnostic: briefly check whether the peer has already reset the
    /// connection or sent a record (typically an `Alert`). Sets a short read
    /// timeout, attempts a single record read, then restores `normal` timeout.
    ///
    /// Returns:
    /// - `Ok(Some(record))` — the peer sent a record (e.g. an alert);
    /// - `Ok(None)` — connection still alive, nothing pending (read timed out);
    /// - `Err(_)` — the peer reset/closed the connection.
    pub fn probe_peer(
        &mut self,
        probe: Duration,
        normal: Duration,
    ) -> Result<Option<Record>, CliError> {
        let _ = self.stream.set_read_timeout(Some(probe));
        let result = match self.read_record() {
            Ok(rec) => Ok(Some(rec)),
            Err(e) => {
                let msg = format!("{e}");
                // WouldBlock / TimedOut means "still alive, nothing pending".
                if msg.contains("timed out")
                    || msg.contains("would block")
                    || msg.contains("Resource temporarily unavailable")
                    || msg.contains("os error 35")
                    || msg.contains("os error 11")
                {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        };
        let _ = self.stream.set_read_timeout(Some(normal));
        result
    }

    /// Read the next raw handshake message as `(msg_type, body)`, where `body`
    /// excludes the 4-byte `HandshakeType || u24 length` header.
    ///
    /// Handshake messages may be split across records or packed several to a
    /// record; this buffers as needed so the caller always receives exactly one
    /// message with its bytes preserved verbatim — essential for feeding the
    /// handshake transcript (Finished / CertificateVerify are computed over the
    /// exact on-wire message bytes). A server `Alert` record is surfaced as an
    /// error rather than silently buffered.
    pub fn recv_handshake_message(&mut self) -> Result<(u8, Vec<u8>), CliError> {
        loop {
            if self.handshake_buf.len() >= 4 {
                let body_len = u32::from_be_bytes([
                    0,
                    self.handshake_buf[1],
                    self.handshake_buf[2],
                    self.handshake_buf[3],
                ]) as usize;
                let total = 4 + body_len;
                if self.handshake_buf.len() >= total {
                    let msg_type = self.handshake_buf[0];
                    let body = self.handshake_buf[4..total].to_vec();
                    self.handshake_buf.drain(..total);
                    return Ok((msg_type, body));
                }
            }
            let record = self.read_record()?;
            match record.content_type {
                ContentType::Handshake => self.handshake_buf.extend_from_slice(&record.payload),
                ContentType::Alert => {
                    let alert = Alert::parse(&record.payload)?;
                    return Err(CliError::Message(format!(
                        "server sent TLS alert: level {} description {} ({})",
                        alert.level,
                        alert.description,
                        alert.description_text()
                    )));
                }
                other => {
                    return Err(CliError::Message(format!(
                        "expected handshake record, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Read exactly one TLS record off the wire.
    fn read_record(&mut self) -> Result<Record, CliError> {
        let mut header = [0u8; 5];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| CliError::Message(format!("read record header: {e}")))?;
        let content_type = ContentType::from_u8(header[0])
            .ok_or_else(|| CliError::Message(format!("unknown TLS content type {}", header[0])))?;
        let version = ProtocolVersion(header[1], header[2]);
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| CliError::Message(format!("read record body ({len} bytes): {e}")))?;
        Ok(Record {
            content_type,
            version,
            payload,
        })
    }

    /// Perform the opening handshake: send `client_hello`, then read records
    /// until `ServerHelloDone` (or a server alert) is received, returning the
    /// parsed server flight.
    pub fn opening_handshake(
        &mut self,
        client_hello: &ClientHello,
    ) -> Result<ServerFlight, CliError> {
        self.send_handshake(&client_hello.encode())?;

        let mut server_hello: Option<ServerHello> = None;
        let mut certificates: Vec<Vec<u8>> = Vec::new();
        let mut server_key_exchange: Option<Vec<u8>> = None;
        let mut certificate_request: Option<Vec<u8>> = None;
        let mut done = false;

        while !done {
            let record = self.read_record()?;
            match record.content_type {
                ContentType::Alert => {
                    let alert = Alert::parse(&record.payload)?;
                    return Err(CliError::Message(format!(
                        "server sent TLS alert: level {} description {} ({})",
                        alert.level,
                        alert.description,
                        alert.description_text()
                    )));
                }
                ContentType::Handshake => {
                    self.handshake_buf.extend_from_slice(&record.payload);
                    for message in self.drain_handshake_messages()? {
                        match message {
                            HandshakeMessage::ServerHello(sh) => server_hello = Some(sh),
                            HandshakeMessage::Certificate(c) => certificates = c.certificates,
                            HandshakeMessage::ServerKeyExchange(b) => server_key_exchange = Some(b),
                            HandshakeMessage::CertificateRequest(b) => {
                                certificate_request = Some(b)
                            }
                            HandshakeMessage::ServerHelloDone => done = true,
                            HandshakeMessage::Other(_, _) | HandshakeMessage::Unknown(_, _) => {}
                        }
                    }
                }
                other => {
                    return Err(CliError::Message(format!(
                        "unexpected {other:?} record during opening handshake"
                    )));
                }
            }
        }

        let server_hello = server_hello.ok_or_else(|| {
            CliError::Message("handshake completed without a ServerHello".to_string())
        })?;
        Ok(ServerFlight {
            server_hello,
            certificates,
            server_key_exchange,
            certificate_request,
            server_hello_done: done,
        })
    }

    /// Drain complete handshake messages from `handshake_buf`, leaving any
    /// trailing partial message buffered for the next record.
    fn drain_handshake_messages(&mut self) -> Result<Vec<HandshakeMessage>, CliError> {
        let mut out = Vec::new();
        loop {
            if self.handshake_buf.len() < 4 {
                break;
            }
            let body_len = u32::from_be_bytes([
                0,
                self.handshake_buf[1],
                self.handshake_buf[2],
                self.handshake_buf[3],
            ]) as usize;
            let total = 4 + body_len;
            if self.handshake_buf.len() < total {
                break;
            }
            let message = self.handshake_buf[..total].to_vec();
            self.handshake_buf.drain(..total);
            out.extend(decode_handshake_messages(&message)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_encode_has_correct_header() {
        let payload = [0xAA, 0xBB, 0xCC];
        let record = Record::encode(ContentType::Handshake, ProtocolVersion::TLS1_2, &payload);
        assert_eq!(record[0], 22); // handshake
        assert_eq!(&record[1..3], &[3, 3]); // TLS 1.2
        assert_eq!(&record[3..5], &[0x00, 0x03]); // length 3
        assert_eq!(&record[5..], &payload);
    }

    #[test]
    fn client_hello_encodes_gost_suites_and_sni() {
        let random = [0x11u8; 32];
        let hello = ClientHello::new_gost("lkulgost.nalog.ru", random);
        let bytes = hello.encode();

        // HandshakeType::ClientHello
        assert_eq!(bytes[0], 1);
        // u24 length matches remaining body
        let body_len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(body_len, bytes.len() - 4);
        // client_version TLS 1.2
        assert_eq!(&bytes[4..6], &[3, 3]);
        // random
        assert_eq!(&bytes[6..38], &random);
        // session_id length 0
        assert_eq!(bytes[38], 0);
        // cipher-suite vector length = 5 suites * 2 bytes = 10
        assert_eq!(u16::from_be_bytes([bytes[39], bytes[40]]), 10);
        // first advertised suite = Kuznyechik CTR OMAC
        assert_eq!(
            u16::from_be_bytes([bytes[41], bytes[42]]),
            cipher_suite::GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
        );

        // SNI host must appear verbatim in the extensions.
        let needle = b"lkulgost.nalog.ru";
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "SNI host not found in ClientHello"
        );
    }

    #[test]
    fn server_hello_round_trips_through_parser() {
        // Build a minimal ServerHello body and wrap it as a handshake message.
        let mut body = Writer::new();
        body.u8(3);
        body.u8(3);
        body.bytes(&[0x22u8; 32]);
        body.with_len(1, |w| w.bytes(&[0xDE, 0xAD])); // session id
        body.u16(cipher_suite::GOSTR341112_256_WITH_MAGMA_CTR_OMAC);
        body.u8(0); // compression
        body.with_len(2, |_w| {}); // empty extensions
        let body = body.into_vec();

        let mut msg = Writer::new();
        msg.u8(HandshakeType::ServerHello as u8);
        msg.with_len(3, |w| w.bytes(&body));
        let msg = msg.into_vec();

        let parsed = decode_handshake_messages(&msg).expect("decode");
        assert_eq!(parsed.len(), 1);
        match &parsed[0] {
            HandshakeMessage::ServerHello(sh) => {
                assert_eq!(sh.server_version, ProtocolVersion::TLS1_2);
                assert_eq!(sh.random, [0x22u8; 32]);
                assert_eq!(sh.session_id, vec![0xDE, 0xAD]);
                assert_eq!(
                    sh.cipher_suite,
                    cipher_suite::GOSTR341112_256_WITH_MAGMA_CTR_OMAC
                );
                assert_eq!(sh.compression_method, 0);
            }
            other => panic!("expected ServerHello, got {other:?}"),
        }
    }

    #[test]
    fn certificate_message_parses_chain() {
        let cert_a = vec![0x01u8, 0x02, 0x03];
        let cert_b = vec![0x04u8, 0x05];

        let mut body = Writer::new();
        body.with_len(3, |list| {
            list.with_len(3, |c| c.bytes(&cert_a));
            list.with_len(3, |c| c.bytes(&cert_b));
        });
        let body = body.into_vec();

        let parsed = CertificateMessage::parse(&body).expect("parse");
        assert_eq!(parsed.certificates, vec![cert_a, cert_b]);
    }

    #[test]
    fn server_hello_done_decodes() {
        let msg = vec![HandshakeType::ServerHelloDone as u8, 0, 0, 0];
        let parsed = decode_handshake_messages(&msg).expect("decode");
        assert_eq!(parsed, vec![HandshakeMessage::ServerHelloDone]);
    }

    #[test]
    fn alert_parses_and_describes() {
        let alert = Alert::parse(&[2, 48]).expect("parse");
        assert_eq!(alert.level, 2);
        assert_eq!(alert.description_text(), "unknown_ca");
    }

    #[test]
    fn reader_rejects_truncation() {
        let mut r = Reader::new(&[0x00]);
        assert!(r.u16().is_err());
    }

    #[test]
    fn flight_two_record_io_round_trips_over_loopback() {
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        // A mock "server" that echoes back what the client sends as records,
        // plus emits two handshake messages packed into a single record and a
        // third message split across two records, to exercise the buffering in
        // recv_handshake_message.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");

            // 1) Two handshake messages packed in ONE record.
            let mut packed = Vec::new();
            packed.extend_from_slice(&[0x0b, 0, 0, 2, 0xAA, 0xBB]); // type 11, body 2
            packed.extend_from_slice(&[0x0e, 0, 0, 0]); // type 14, empty body
            let rec = Record::encode(ContentType::Handshake, ProtocolVersion::TLS1_2, &packed);
            sock.write_all(&rec).unwrap();

            // 2) A single handshake message SPLIT across two records.
            let msg = [0x0c_u8, 0, 0, 3, 0x01, 0x02, 0x03]; // type 12, body 3
            let r1 = Record::encode(ContentType::Handshake, ProtocolVersion::TLS1_2, &msg[..5]);
            let r2 = Record::encode(ContentType::Handshake, ProtocolVersion::TLS1_2, &msg[5..]);
            sock.write_all(&r1).unwrap();
            sock.write_all(&r2).unwrap();

            // 3) Read one ApplicationData record the client sends and echo it.
            let mut hdr = [0u8; 5];
            sock.read_exact(&mut hdr).unwrap();
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body).unwrap();
            let echo = Record::encode(ContentType::ApplicationData, ProtocolVersion::TLS1_2, &body);
            sock.write_all(&echo).unwrap();
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut transport = TlsTransport {
            stream,
            handshake_buf: Vec::new(),
        };

        let (t1, b1) = transport.recv_handshake_message().expect("msg1");
        assert_eq!((t1, b1), (0x0b, vec![0xAA, 0xBB]));
        let (t2, b2) = transport.recv_handshake_message().expect("msg2");
        assert_eq!((t2, b2), (0x0e, vec![]));
        let (t3, b3) = transport.recv_handshake_message().expect("msg3");
        assert_eq!((t3, b3), (0x0c, vec![0x01, 0x02, 0x03]));

        // send_record + recv_record round trip (ApplicationData echo).
        transport
            .send_record(ContentType::ApplicationData, &[0xDE, 0xAD, 0xBE, 0xEF])
            .expect("send");
        let echoed = transport.recv_record().expect("recv");
        assert_eq!(echoed.content_type, ContentType::ApplicationData);
        assert_eq!(echoed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        server.join().expect("server thread");
    }
}
