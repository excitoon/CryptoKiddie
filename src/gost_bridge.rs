//! HTTP reverse-proxy helpers for the GOST mTLS bridge.
//!
//! The bridge lets an ordinary browser use a GOST-only mutual-TLS endpoint
//! (cipher suite 0xFF85) that it could not otherwise speak. The browser talks
//! plain HTTP to a local listener; for each request the bridge performs a full
//! token-authenticated GOST TLS 1.2 handshake to the upstream, replays the
//! request, and returns the response.
//!
//! This module contains only the *transport-agnostic* HTTP plumbing (request
//! parsing, upstream-request building, response rewriting, and a server-side
//! cookie jar). The token/handshake wiring lives in the CLI command, which
//! supplies a closure that turns request bytes into response bytes.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;

/// A parsed HTTP/1.x request from the browser side.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request method, e.g. `GET`.
    pub method: String,
    /// Request target as sent by the browser (origin-form `/path` or, for a
    /// forward proxy, absolute-form `http://host/path`).
    pub target: String,
    /// Header lines as `(name, value)` preserving order, names as received.
    pub headers: Vec<(String, String)>,
    /// Request body (may be empty).
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Look up the first header whose name matches `name` case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The origin-form path+query to send upstream, derived from `target`
    /// (absolute-form targets are reduced to their path+query).
    pub fn origin_form_target(&self) -> String {
        let t = self.target.as_str();
        if let Some(rest) = t
            .strip_prefix("http://")
            .or_else(|| t.strip_prefix("https://"))
        {
            // absolute-form: drop scheme + authority, keep from the first '/'.
            match rest.find('/') {
                Some(idx) => rest[idx..].to_string(),
                None => "/".to_string(),
            }
        } else if t.is_empty() {
            "/".to_string()
        } else {
            t.to_string()
        }
    }
}

/// Read one HTTP/1.x request (request line + headers + body) from `stream`.
///
/// Returns `Ok(None)` on a clean EOF before any bytes (browser closed an idle
/// keep-alive connection).
pub fn read_request(stream: &TcpStream) -> std::io::Result<Option<HttpRequest>> {
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line)?;
    if n == 0 {
        return Ok(None); // clean EOF
    }
    let request_line = request_line.trim_end_matches(['\r', '\n']).to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed HTTP request line",
        ));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let value = line[colon + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    // Read the body when a Content-Length is present.
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(HttpRequest {
        method,
        target,
        headers,
        body,
    }))
}

/// A minimal server-side cookie jar (name → value), shared across the many
/// short-lived upstream TLS connections so the authenticated session (e.g.
/// `PHPSESSID`) persists even though each request is a fresh handshake.
#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: BTreeMap<String, String>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Format the stored cookies as a single `Cookie:` header value, or `None`
    /// when the jar is empty.
    pub fn header_value(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        let mut parts = Vec::with_capacity(self.cookies.len());
        for (k, v) in &self.cookies {
            parts.push(format!("{k}={v}"));
        }
        Some(parts.join("; "))
    }

    /// Absorb a `Set-Cookie` header value (`name=value; Path=/; ...`), storing
    /// just the `name=value` pair.
    pub fn absorb_set_cookie(&mut self, set_cookie: &str) {
        let first = set_cookie.split(';').next().unwrap_or("").trim();
        if let Some(eq) = first.find('=') {
            let name = first[..eq].trim().to_string();
            let value = first[eq + 1..].trim().to_string();
            if !name.is_empty() {
                self.cookies.insert(name, value);
            }
        }
    }
}

/// Build the raw bytes of the upstream HTTP/1.1 request to send over the GOST
/// channel: origin-form target, `Host: upstream_host`, the jar's cookies, and a
/// forced `Connection: close` (so the bridge can drain the response to EOF).
///
/// Hop-by-hop and proxy-specific headers are dropped; the browser's own
/// `Cookie` header is ignored in favour of the server-side jar.
pub fn build_upstream_request(req: &HttpRequest, upstream_host: &str, jar: &CookieJar) -> Vec<u8> {
    let target = req.origin_form_target();
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, target);
    out.push_str(&format!("Host: {upstream_host}\r\n"));

    for (name, value) in &req.headers {
        let lname = name.to_ascii_lowercase();
        match lname.as_str() {
            // Set by us / hop-by-hop / proxy-specific — skip.
            "host" | "connection" | "proxy-connection" | "keep-alive" | "cookie" | "upgrade"
            | "transfer-encoding" | "te" | "trailer" => continue,
            // Force identity encoding so we hand the browser bytes verbatim.
            "accept-encoding" => {
                out.push_str("Accept-Encoding: identity\r\n");
            }
            _ => {
                out.push_str(&format!("{name}: {value}\r\n"));
            }
        }
    }

    if let Some(cookie) = jar.header_value() {
        out.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    out.push_str("Connection: close\r\n");
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&req.body);
    bytes
}

/// A response split into its header block and body.
struct RawResponse<'a> {
    status_line: &'a [u8],
    header_lines: Vec<&'a [u8]>,
    body: &'a [u8],
}

fn split_response(raw: &[u8]) -> Option<RawResponse<'_>> {
    // Find the CRLFCRLF (or LFLF) that ends the header block.
    let sep = find_subslice(raw, b"\r\n\r\n").map(|i| (i, 4));
    let sep = sep.or_else(|| find_subslice(raw, b"\n\n").map(|i| (i, 2)));
    let (hdr_end, sep_len) = sep?;
    let header_block = &raw[..hdr_end];
    let body = &raw[hdr_end + sep_len..];

    let mut lines = header_block.split(|&b| b == b'\n').map(strip_cr);
    let status_line = lines.next()?;
    let header_lines: Vec<&[u8]> = lines.filter(|l| !l.is_empty()).collect();
    Some(RawResponse {
        status_line,
        header_lines,
        body,
    })
}

fn strip_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Rewrite an upstream HTTP response for the browser:
/// - capture `Set-Cookie` pairs into `jar` and drop those headers (the jar
///   re-injects them on subsequent upstream requests);
/// - rewrite `Location` redirects pointing at `https://upstream_host` (or
///   `http://upstream_host`) to the local `bridge_origin` so the browser stays
///   on the bridge;
/// - drop hop-by-hop headers and force `Connection: close`;
/// - leave the body untouched.
///
/// `bridge_origin` is e.g. `http://127.0.0.1:18888`.
pub fn rewrite_response(
    raw: &[u8],
    upstream_host: &str,
    bridge_origin: &str,
    jar: &mut CookieJar,
) -> Vec<u8> {
    let parsed = match split_response(raw) {
        Some(p) => p,
        // Not parseable as HTTP — pass through unchanged.
        None => return raw.to_vec(),
    };

    let https_prefix = format!("https://{upstream_host}");
    let http_prefix = format!("http://{upstream_host}");

    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    out.extend_from_slice(parsed.status_line);
    out.extend_from_slice(b"\r\n");

    for line in &parsed.header_lines {
        let text = String::from_utf8_lossy(line);
        let lower = text.to_ascii_lowercase();

        if lower.starts_with("set-cookie:") {
            let value = text[text.find(':').map(|i| i + 1).unwrap_or(text.len())..].trim();
            jar.absorb_set_cookie(value);
            continue; // jar handles cookies; don't forward to the browser
        }
        if lower.starts_with("connection:")
            || lower.starts_with("keep-alive:")
            || lower.starts_with("transfer-encoding:")
            || lower.starts_with("proxy-connection:")
        {
            continue;
        }
        if lower.starts_with("location:") {
            let value = text[text.find(':').map(|i| i + 1).unwrap_or(text.len())..].trim();
            let rewritten = value
                .replace(&https_prefix, bridge_origin)
                .replace(&http_prefix, bridge_origin);
            out.extend_from_slice(format!("Location: {rewritten}\r\n").as_bytes());
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(parsed.body);
    out
}

/// Parse a raw upstream HTTP response: absorb its `Set-Cookie` pairs into `jar`
/// and return `(status_code, decoded_body)`.
///
/// Unlike [`rewrite_response`] (which targets the browser), this is for the
/// bridge's own server-side requests (e.g. the certificate-login challenge):
/// it needs the numeric status and the *decoded* body. `Transfer-Encoding:
/// chunked` bodies are de-chunked; otherwise the body is returned verbatim.
/// Returns `(0, raw.to_vec())` if the response is not parseable as HTTP.
pub fn absorb_response(raw: &[u8], jar: &mut CookieJar) -> (u16, Vec<u8>) {
    let parsed = match split_response(raw) {
        Some(p) => p,
        None => return (0, raw.to_vec()),
    };

    // Status code = 2nd whitespace-separated token of the status line.
    let status_line = String::from_utf8_lossy(parsed.status_line);
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut chunked = false;
    for line in &parsed.header_lines {
        let text = String::from_utf8_lossy(line);
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("set-cookie:") {
            let value = text[text.find(':').map(|i| i + 1).unwrap_or(text.len())..].trim();
            jar.absorb_set_cookie(value);
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }

    let body = if chunked {
        decode_chunked(parsed.body)
    } else {
        parsed.body.to_vec()
    };
    (status, body)
}

/// Decode an HTTP/1.1 `chunked` transfer-encoded body into its raw bytes.
/// Tolerant of a missing terminal `0\r\n\r\n` (stops at EOF).
fn decode_chunked(mut input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    loop {
        let Some(nl) = find_subslice(input, b"\r\n") else {
            break;
        };
        let size_line = &input[..nl];
        // Chunk size is hex, optionally followed by ';ext'.
        let hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
        let hex_str = String::from_utf8_lossy(hex);
        let hex_str = hex_str.trim();
        let Ok(size) = usize::from_str_radix(hex_str, 16) else {
            break;
        };
        let data_start = nl + 2;
        if size == 0 {
            break; // last chunk
        }
        if data_start + size > input.len() {
            // Truncated; take what we have.
            out.extend_from_slice(&input[data_start..]);
            break;
        }
        out.extend_from_slice(&input[data_start..data_start + size]);
        // Advance past the chunk data and its trailing CRLF.
        let next = data_start + size + 2;
        if next > input.len() {
            break;
        }
        input = &input[next..];
    }
    out
}

/// Build a `multipart/form-data` request body from `(name, value)` text fields.
/// Returns `(boundary, body_bytes)`; the caller sets
/// `Content-Type: multipart/form-data; boundary=<boundary>`.
pub fn build_multipart_form(fields: &[(&str, &str)], boundary: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

/// Extract the `boundary=...` value from a `multipart/form-data` Content-Type.
pub fn multipart_boundary(content_type: &str) -> Option<String> {
    let idx = content_type.to_ascii_lowercase().find("boundary=")?;
    let rest = &content_type[idx + "boundary=".len()..];
    let value = rest.split(';').next().unwrap_or(rest).trim();
    let value = value.trim_matches('"');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parse a `multipart/form-data` body into `(name, value_bytes)` pairs.
///
/// Minimal parser sufficient for the simple flat string forms the ФНС SPA
/// posts (`agreement`/`inn`/`email`/`signature`); only the `name="..."`
/// parameter of each part's `Content-Disposition` is honoured.
pub fn parse_multipart_fields(body: &[u8], boundary: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = find_subslice(&body[pos..], delim_bytes) {
        let start = pos + rel + delim_bytes.len();
        // End of this part is the next boundary delimiter.
        let next = find_subslice(&body[start..], delim_bytes).map(|r| start + r);
        let end = next.unwrap_or(body.len());
        let part = &body[start..end];
        // Skip leading CRLF (or "--\r\n" closing marker).
        let part = part.strip_prefix(b"\r\n").unwrap_or(part);
        // Split headers from value at the first blank line.
        if let Some(hrel) = find_subslice(part, b"\r\n\r\n") {
            let headers = &part[..hrel];
            let mut value = &part[hrel + 4..];
            // Trim the trailing CRLF that precedes the next boundary.
            if value.ends_with(b"\r\n") {
                value = &value[..value.len() - 2];
            }
            let headers_str = String::from_utf8_lossy(headers);
            if let Some(name) = headers_str
                .split(';')
                .find_map(|p| p.trim().strip_prefix("name=").map(|n| n.trim_matches('"')))
            {
                out.push((name.to_string(), value.to_vec()));
            }
        }
        match next {
            Some(n) => pos = n,
            None => break,
        }
    }
    out
}

/// JavaScript that emulates the GOST signing plugin's `window.cadesplugin` API
/// (the CAdESCOM COM object graph) entirely in-page, with **no browser
/// extension**.
///
/// The ФНС ЛКЮЛ SPA bundles the `reference implementation` library, which drives
/// `window.cadesplugin`: it awaits the object (readiness), opens a `CAdESCOM.Store`,
/// enumerates certificates, builds `CPSigner`/`CadesSignedData` and calls
/// `SignCades`. The real implementation is an extension that is blocked here.
///
/// Instead of the extension, this script installs a faithful **plain object**
/// (not a Proxy — `reference implementation`'s `isAvailable()` does
/// `window.cadesplugin = Object.assign({}, window.cadesplugin)`, which a Proxy
/// breaks, and a self-thenable Proxy recurses to OOM). Every method resolves to a
/// concrete value:
/// - readiness: a non-thenable object → `yield window.cadesplugin` returns immediately;
/// - `getSystemInfo`: reports a supported plugin/extension version so
///   `isValidSystemSetup()` passes;
/// - the store enumerates the *real* signer certificate fetched from
///   `/__bridge/cert-info` (subject, validity, SHA-1 thumbprint), so the SPA's
///   picker shows the real identity and `Find` always resolves to it;
/// - `SignCades`/`SignHash` return a placeholder.
///
/// The SPA then POSTs `/api/auth/challenge`; the bridge intercepts that POST,
/// discards the placeholder, and performs the real Rutoken-backed detached-CMS
/// signature server-side, so the browser receives the genuine upstream response
/// (e.g. `registration_required`) and renders the portal's own native screen.
///
/// Served two ways (idempotent via the `__ckCadesShim` guard): injected into
/// every HTML `<head>`, and as the body of the SPA's dynamically loaded
/// `cadesplugin_api.js` (so the real extension loader never clobbers it).
pub const CADESPLUGIN_SHIM_JS: &str = r##"(function(){
if(window.__ckCadesShim)return;window.__ckCadesShim=true;
function P(v){return Promise.resolve(v);}
var CI=null;
function def(){return {thumbprint:'0000000000000000000000000000000000000000',certB64:'',subject:'CN=Rutoken',issuer:'CN=CA',serialNumber:'00',notBefore:1577836800,notAfter:4102444800,subjectCN:'Rutoken'};}
function certInfo(){if(!CI){CI=fetch('/__bridge/cert-info',{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){return (j&&!j.error)?j:def();}).catch(function(){return def();});}return CI;}
function mkCert(info){return {
Thumbprint:info.thumbprint,SubjectName:info.subject,IssuerName:info.issuer,
SerialNumber:info.serialNumber,Version:3,
ValidFromDate:new Date(info.notBefore*1000),ValidToDate:new Date(info.notAfter*1000),
HasPrivateKey:function(){return P(true);},
IsValid:function(){return P({Result:true});},
Export:function(){return P(info.certB64);},
PublicKey:function(){return {Algorithm:{FriendlyName:'GOST R 34.10-2012 256 bits',Value:'1.2.643.7.1.1.1.1'}};},
ExtendedKeyUsage:function(){return P({EKUs:{Count:0,Item:function(){return P(null);}}});}
};}
function mkColl(list){return {Count:list.length,Item:function(i){return P(list[i-1]);},Find:function(){return P(mkColl(list));}};}
function mkStore(list){return {Open:function(){return P(undefined);},Close:function(){return P(undefined);},Certificates:mkColl(list)};}
function mkAbout(){var pv={MajorVersion:2,MinorVersion:0,BuildVersion:14590,toString:function(){return '2.0.14590';}};
return {PluginVersion:pv,MajorVersion:2,MinorVersion:0,BuildVersion:14590,Version:'2.0.14590',
CSPName:function(){return P('Reference GOST R 34.10-2012 KC1 CSP');},
CSPVersion:function(){return P({MajorVersion:5,MinorVersion:0,BuildVersion:13000,toString:function(){return '5.0.13000';}});}};}
function mkAttr(){return {propset_Name:function(){return P(undefined);},propset_Value:function(){return P(undefined);},Name:0,Value:''};}
function mkSigner(){var attrs={Add:function(){return P(undefined);}};
return {propset_Certificate:function(){return P(undefined);},propset_Options:function(){return P(undefined);},
propset_TSAAddress:function(){return P(undefined);},AuthenticatedAttributes2:attrs};}
function mkHashed(){var v='';return {propset_Algorithm:function(){return P(undefined);},
propset_DataEncoding:function(){return P(undefined);},SetHashValue:function(h){v=h;return P(undefined);},
Hash:function(){return P(undefined);},Value:v};}
var PLACEHOLDER='Q3J5cHRvS2lkZGllLWJyaWRnZS1yZXNpZ25zLXRoaXMtc2VydmVyLXNpZGU=';
function mkSigned(){return {propset_ContentEncoding:function(){return P(undefined);},
propset_Content:function(){return P(undefined);},propset_Certificate:function(){return P(undefined);},
SignCades:function(){return P(PLACEHOLDER);},SignHash:function(){return P(PLACEHOLDER);},Sign:function(){return P(PLACEHOLDER);}};}
function makeAsync(progId){progId=String(progId||'');
if(progId.indexOf('Store')>=0){return certInfo().then(function(info){return mkStore([mkCert(info)]);});}
if(progId.indexOf('About')>=0){return P(mkAbout());}
if(progId.indexOf('CPAttribute')>=0||progId.indexOf('CPAttr')>=0){return P(mkAttr());}
if(progId.indexOf('SignedData')>=0||progId.indexOf('SignedXML')>=0){return P(mkSigned());}
if(progId.indexOf('Signer')>=0){return P(mkSigner());}
if(progId.indexOf('HashedData')>=0){return P(mkHashed());}
return P({});}
var consts={
CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256:101,CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512:111,
CADESCOM_HASH_ALGORITHM_CP_GOST_3411:100,CADESCOM_CADES_BES:1,CADESCOM_CADES_DEFAULT:0,
CADESCOM_BASE64_TO_BINARY:1,CADESCOM_STRING_TO_UCS2LE:0,CADESCOM_ENCODE_BASE64:0,CADESCOM_ENCODE_BINARY:1,
CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME:0,CADESCOM_CURRENT_USER_STORE:2,CADESCOM_LOCAL_MACHINE_STORE:1,
CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED:0,
CAPICOM_CURRENT_USER_STORE:2,CAPICOM_LOCAL_MACHINE_STORE:1,CAPICOM_MY_STORE:'My',
CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED:2,CAPICOM_STORE_OPEN_READ_ONLY:0,
CAPICOM_CERTIFICATE_FIND_SHA1_HASH:0,CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME:1,
CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY:2,CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN:0,
XmlDsigGost3410Url2012256:'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256',
XmlDsigGost3411Url2012256:'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256',
LOG_LEVEL_DEBUG:4,LOG_LEVEL_INFO:2,LOG_LEVEL_ERROR:1};
var cp={set_log_level:function(){},set:function(){},getLastError:function(){return '';},
CreateObjectAsync:function(p){return makeAsync(p);},CreateObject:function(){return {};}};
for(var k in consts){cp[k]=consts[k];}
try{window.cadesplugin=cp;}catch(e){}
try{window.cadesplugin_load_error=false;}catch(e){}
console.log('[CryptoKiddie] cadesplugin emulation installed (no extension)');
})();"##;

/// Wrap [`CADESPLUGIN_SHIM_JS`] in a `<script>` element for HTML `<head>` injection.
pub fn cadesplugin_shim_script_tag() -> String {
    format!("<script>{CADESPLUGIN_SHIM_JS}</script>")
}

/// Inject [`CADESPLUGIN_SHIM`] into `text/html` upstream responses.
///
/// Returns `raw` unchanged for non-HTML responses or unparseable input. For HTML
/// responses the body is de-chunked, the shim `<script>` is inserted immediately
/// after the opening `<head>` (falling back to the body start), and the headers
/// are rebuilt with a corrected `Content-Length` and no `Transfer-Encoding`.
pub fn inject_cadesplugin_shim(raw: Vec<u8>) -> Vec<u8> {
    let Some(parsed) = split_response(&raw) else {
        return raw;
    };

    let mut is_html = false;
    let mut chunked = false;
    for line in &parsed.header_lines {
        let lower = String::from_utf8_lossy(line).to_ascii_lowercase();
        if lower.starts_with("content-type:") && lower.contains("text/html") {
            is_html = true;
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    if !is_html {
        return raw;
    }

    let decoded = if chunked {
        decode_chunked(parsed.body)
    } else {
        parsed.body.to_vec()
    };

    // Find the insertion offset: just after the first `<head ...>` tag, else at
    // the start of `<body ...>`, else at the very beginning of the document.
    let lower_body: Vec<u8> = decoded.iter().map(|b| b.to_ascii_lowercase()).collect();
    let insert_at = find_subslice(&lower_body, b"<head")
        .and_then(|i| find_subslice(&decoded[i..], b">").map(|j| i + j + 1))
        .or_else(|| {
            find_subslice(&lower_body, b"<body")
                .and_then(|i| find_subslice(&decoded[i..], b">").map(|j| i + j + 1))
        })
        .unwrap_or(0);

    let script = cadesplugin_shim_script_tag();
    let mut new_body = Vec::with_capacity(decoded.len() + script.len());
    new_body.extend_from_slice(&decoded[..insert_at]);
    new_body.extend_from_slice(script.as_bytes());
    new_body.extend_from_slice(&decoded[insert_at..]);

    // Rebuild the response: keep all headers except the length/encoding ones we
    // must recompute, then append a fresh Content-Length and the patched body.
    let mut out: Vec<u8> = Vec::with_capacity(new_body.len() + 256);
    out.extend_from_slice(parsed.status_line);
    out.extend_from_slice(b"\r\n");
    for line in &parsed.header_lines {
        let lower = String::from_utf8_lossy(line).to_ascii_lowercase();
        if lower.starts_with("content-length:") || lower.starts_with("transfer-encoding:") {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", new_body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&new_body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_reduces_absolute_target() {
        let req = HttpRequest {
            method: "GET".into(),
            target: "http://lkulgost.nalog.ru/v2/auth?x=1".into(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(req.origin_form_target(), "/v2/auth?x=1");
    }

    #[test]
    fn origin_form_keeps_relative_target() {
        let req = HttpRequest {
            method: "GET".into(),
            target: "/lk/main".into(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(req.origin_form_target(), "/lk/main");
    }

    #[test]
    fn cookie_jar_roundtrips_set_cookie() {
        let mut jar = CookieJar::new();
        assert_eq!(jar.header_value(), None);
        jar.absorb_set_cookie("PHPSESSID=abc123; path=/; HttpOnly");
        jar.absorb_set_cookie("theme=dark; Path=/");
        assert_eq!(
            jar.header_value().as_deref(),
            Some("PHPSESSID=abc123; theme=dark")
        );
        // A later Set-Cookie for the same name replaces the value.
        jar.absorb_set_cookie("PHPSESSID=xyz789; path=/");
        assert_eq!(
            jar.header_value().as_deref(),
            Some("PHPSESSID=xyz789; theme=dark")
        );
    }

    #[test]
    fn build_upstream_injects_host_cookie_and_close() {
        let req = HttpRequest {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![
                ("Host".into(), "127.0.0.1:18888".into()),
                ("User-Agent".into(), "test".into()),
                ("Accept-Encoding".into(), "gzip, br".into()),
                ("Cookie".into(), "stale=1".into()),
            ],
            body: vec![],
        };
        let mut jar = CookieJar::new();
        jar.absorb_set_cookie("PHPSESSID=sess; path=/");
        let bytes = build_upstream_request(&req, "lkulgost.nalog.ru", &jar);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(text.contains("Host: lkulgost.nalog.ru\r\n"));
        assert!(text.contains("User-Agent: test\r\n"));
        assert!(text.contains("Accept-Encoding: identity\r\n"));
        assert!(text.contains("Cookie: PHPSESSID=sess\r\n"));
        assert!(!text.contains("stale=1")); // browser cookie dropped
        assert!(text.contains("Connection: close\r\n"));
    }

    #[test]
    fn rewrite_captures_cookie_and_rewrites_location() {
        let raw = b"HTTP/1.1 302 Found\r\n\
            Server: Apache\r\n\
            Set-Cookie: PHPSESSID=zzz; path=/\r\n\
            Location: https://lkulgost.nalog.ru/v2/auth\r\n\
            Connection: close\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let mut jar = CookieJar::new();
        let out = rewrite_response(raw, "lkulgost.nalog.ru", "http://127.0.0.1:18888", &mut jar);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Location: http://127.0.0.1:18888/v2/auth\r\n"));
        assert!(!text.to_ascii_lowercase().contains("set-cookie")); // stripped
        assert!(text.contains("Server: Apache\r\n"));
        assert_eq!(jar.header_value().as_deref(), Some("PHPSESSID=zzz"));
    }

    #[test]
    fn rewrite_preserves_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut jar = CookieJar::new();
        let out = rewrite_response(raw, "lkulgost.nalog.ru", "http://127.0.0.1:1", &mut jar);
        let text = String::from_utf8(out).unwrap();
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn absorb_response_extracts_status_cookie_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\n\
            Content-Type: application/json\r\n\
            Set-Cookie: PHPSESSID=abc; path=/\r\n\
            Content-Length: 27\r\n\
            \r\n\
            {\"code\":\"c1\",\"challenge\":\"x\"}";
        let mut jar = CookieJar::new();
        let (status, body) = absorb_response(raw, &mut jar);
        assert_eq!(status, 200);
        assert_eq!(jar.header_value().as_deref(), Some("PHPSESSID=abc"));
        assert_eq!(body, b"{\"code\":\"c1\",\"challenge\":\"x\"}");
    }

    #[test]
    fn absorb_response_decodes_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\n\
            Transfer-Encoding: chunked\r\n\
            \r\n\
            5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut jar = CookieJar::new();
        let (status, body) = absorb_response(raw, &mut jar);
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn build_multipart_form_has_fields_and_boundary() {
        let body = build_multipart_form(&[("code", "c1"), ("signature", "AAAA")], "BOUND");
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("--BOUND\r\n"));
        assert!(text.contains("Content-Disposition: form-data; name=\"code\"\r\n\r\nc1\r\n"));
        assert!(
            text.contains("Content-Disposition: form-data; name=\"signature\"\r\n\r\nAAAA\r\n")
        );
        assert!(text.ends_with("--BOUND--\r\n"));
    }

    #[test]
    fn parse_multipart_fields_round_trips_build() {
        let boundary = "----CKBoundary123";
        let body = build_multipart_form(
            &[
                ("agreement", "PGh0bWw+"),
                ("inn", "1234567890"),
                ("email", "a@b.ru"),
            ],
            boundary,
        );
        let fields = parse_multipart_fields(&body, boundary);
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        };
        assert_eq!(get("agreement").as_deref(), Some("PGh0bWw+"));
        assert_eq!(get("inn").as_deref(), Some("1234567890"));
        assert_eq!(get("email").as_deref(), Some("a@b.ru"));
    }

    #[test]
    fn multipart_boundary_extracts_value() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=----WebKitFormBoundaryabc")
                .as_deref(),
            Some("----WebKitFormBoundaryabc")
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"q w\"; charset=utf-8").as_deref(),
            Some("q w")
        );
        assert_eq!(multipart_boundary("application/json"), None);
    }
}
