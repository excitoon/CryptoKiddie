use std::{
    ffi::OsString,
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
};

pub mod apdu {
    use super::CliError;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CommandApdu {
        pub cla: u8,
        pub ins: u8,
        pub p1: u8,
        pub p2: u8,
        pub data: Vec<u8>,
        pub le: Option<u8>,
    }

    impl CommandApdu {
        pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
            Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            }
        }

        pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Self {
            self.data = data.into();
            self
        }

        pub fn with_le(mut self, le: u8) -> Self {
            self.le = Some(le);
            self
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, CliError> {
            if self.data.len() > u8::MAX as usize {
                return Err(CliError::Message(
                    "extended-length APDU encoding is not implemented yet".to_string(),
                ));
            }

            let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];
            if !self.data.is_empty() {
                bytes.push(self.data.len() as u8);
                bytes.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                bytes.push(le);
            }
            Ok(bytes)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ResponseApdu {
        pub data: Vec<u8>,
        pub sw1: u8,
        pub sw2: u8,
    }

    impl ResponseApdu {
        pub fn parse(bytes: &[u8]) -> Result<Self, CliError> {
            if bytes.len() < 2 {
                return Err(CliError::Message(
                    "APDU response must contain SW1/SW2 status bytes".to_string(),
                ));
            }
            let split = bytes.len() - 2;
            Ok(Self {
                data: bytes[..split].to_vec(),
                sw1: bytes[split],
                sw2: bytes[split + 1],
            })
        }

        pub fn is_success(&self) -> bool {
            self.sw1 == 0x90 && self.sw2 == 0x00
        }
    }
}

pub mod ccid {
    use super::{CliError, apdu::CommandApdu};

    pub const RUTOKEN_ECP3_USB_VID: u16 = 0x0a89;
    pub const RUTOKEN_ECP3_USB_PID: u16 = 0x0030;
    pub const RUTOKEN_ECP3_PRODUCT: &str = "Rutoken ECP (Рутокен ЭЦП 3.0)";

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct XfrBlock {
        pub slot: u8,
        pub sequence: u8,
        pub block_waiting_integer: u8,
        pub level_parameter: u16,
        pub apdu: CommandApdu,
    }

    impl XfrBlock {
        pub fn new(slot: u8, sequence: u8, apdu: CommandApdu) -> Self {
            Self {
                slot,
                sequence,
                block_waiting_integer: 0,
                level_parameter: 0,
                apdu,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, CliError> {
            let apdu = self.apdu.to_bytes()?;
            let apdu_len = u32::try_from(apdu.len()).map_err(|_| {
                CliError::Message("APDU is too large for a CCID XfrBlock".to_string())
            })?;

            let mut bytes = Vec::with_capacity(10 + apdu.len());
            bytes.push(0x6f);
            bytes.extend_from_slice(&apdu_len.to_le_bytes());
            bytes.push(self.slot);
            bytes.push(self.sequence);
            bytes.push(self.block_waiting_integer);
            bytes.extend_from_slice(&self.level_parameter.to_le_bytes());
            bytes.extend_from_slice(&apdu);
            Ok(bytes)
        }
    }
}

pub mod gost {
    use super::{CliError, DigestAlgorithm};
    use streebog::{Digest, Streebog256, Streebog512};

    pub fn hash(data: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
        match algorithm {
            DigestAlgorithm::Gost3411_2012_256 => Streebog256::digest(data).to_vec(),
            DigestAlgorithm::Gost3411_2012_512 => Streebog512::digest(data).to_vec(),
        }
    }

    pub fn parse_digest(name: &str) -> Result<DigestAlgorithm, CliError> {
        DigestAlgorithm::parse(name)
    }
}

pub mod cms_envelope {
    use super::{CliError, DigestAlgorithm};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CmsSigningInput {
        pub content_digest: Vec<u8>,
        pub digest_algorithm: DigestAlgorithm,
        pub signer_certificate: Vec<u8>,
        pub detached: bool,
    }

    impl CmsSigningInput {
        pub fn new(
            content_digest: Vec<u8>,
            digest_algorithm: DigestAlgorithm,
            signer_certificate: Vec<u8>,
            detached: bool,
        ) -> Self {
            Self {
                content_digest,
                digest_algorithm,
                signer_certificate,
                detached,
            }
        }

        pub fn validate(&self) -> Result<(), CliError> {
            if self.content_digest.len() != self.digest_algorithm.output_len() {
                return Err(CliError::Message(format!(
                    "{} digest must be {} bytes, got {}",
                    self.digest_algorithm.name(),
                    self.digest_algorithm.output_len(),
                    self.content_digest.len()
                )));
            }
            if self.signer_certificate.is_empty() {
                return Err(CliError::Message(
                    "signer certificate must not be empty".to_string(),
                ));
            }
            Ok(())
        }
    }

    /// Diagnostic marker proving the native CMS boundary is linked.
    ///
    /// Full `SignedData` emission is intentionally gated until the token-backed
    /// signature bytes can be validated against real Rutoken hardware.
    pub fn cms_crate_backend() -> &'static str {
        std::any::type_name::<cms::content_info::ContentInfo>()
    }
}

pub mod token {
    use super::{CliError, DigestAlgorithm};
    use std::path::{Path, PathBuf};

    pub const GOST3410_2012_256_MECHANISM: &str = "CKM_GOSTR3410_2012_256";

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Pkcs11SignerConfig {
        pub module: PathBuf,
        pub key_uri: String,
        pub mechanism: &'static str,
    }

    impl Pkcs11SignerConfig {
        pub fn new(module: PathBuf, key_uri: String) -> Self {
            Self {
                module,
                key_uri,
                mechanism: GOST3410_2012_256_MECHANISM,
            }
        }

        pub fn validate(&self) -> Result<(), CliError> {
            if self.key_uri.trim().is_empty() {
                return Err(CliError::Usage("--key-uri must not be empty".to_string()));
            }
            if !self.module.is_file() {
                return Err(CliError::Message(format!(
                    "--pkcs11-module does not exist: {}",
                    self.module.display()
                )));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CcidSignerConfig {
        pub reader: Option<String>,
        pub key_uri: String,
        pub mechanism: &'static str,
    }

    impl CcidSignerConfig {
        pub fn new(reader: Option<String>, key_uri: String) -> Self {
            Self {
                reader,
                key_uri,
                mechanism: GOST3410_2012_256_MECHANISM,
            }
        }
    }

    pub fn pkcs11_crate_backend() -> &'static str {
        std::any::type_name::<pkcs11::Ctx>()
    }

    pub trait TokenSigner {
        fn sign_digest(
            &self,
            digest_algorithm: DigestAlgorithm,
            digest: &[u8],
        ) -> Result<Vec<u8>, CliError>;
    }

    impl TokenSigner for Pkcs11SignerConfig {
        fn sign_digest(
            &self,
            digest_algorithm: DigestAlgorithm,
            digest: &[u8],
        ) -> Result<Vec<u8>, CliError> {
            self.validate()?;
            if digest.len() != digest_algorithm.output_len() {
                return Err(CliError::Message(format!(
                    "{} digest must be {} bytes, got {}",
                    digest_algorithm.name(),
                    digest_algorithm.output_len(),
                    digest.len()
                )));
            }
            let _ctx = pkcs11::Ctx::new(&self.module).map_err(|error| {
                CliError::Message(format!(
                    "failed to load PKCS#11 module {}: {error}",
                    self.module.display()
                ))
            })?;

            Err(CliError::Message(format!(
                "PKCS#11 signing via {} is not yet enabled. Hardware validation is required before live token operations are supported.",
                self.module.display()
            )))
        }
    }

    impl TokenSigner for CcidSignerConfig {
        fn sign_digest(
            &self,
            digest_algorithm: DigestAlgorithm,
            digest: &[u8],
        ) -> Result<Vec<u8>, CliError> {
            if digest.len() != digest_algorithm.output_len() {
                return Err(CliError::Message(format!(
                    "{} digest must be {} bytes, got {}",
                    digest_algorithm.name(),
                    digest_algorithm.output_len(),
                    digest.len()
                )));
            }
            Err(CliError::Message(
                "Direct USB/CCID signing is not yet implemented. Rutoken-specific commands require hardware validation.".to_string(),
            ))
        }
    }

    pub fn ensure_module_path(path: &Path) -> Result<(), CliError> {
        if path.is_file() {
            Ok(())
        } else {
            Err(CliError::Message(format!(
                "--pkcs11-module does not exist: {}",
                path.display()
            )))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Gost3411_2012_256,
    Gost3411_2012_512,
}

impl DigestAlgorithm {
    pub fn parse(name: &str) -> Result<Self, CliError> {
        match name {
            "gost3411-2012-256" | "gost12-256" | "md_gost12_256" => Ok(Self::Gost3411_2012_256),
            "gost3411-2012-512" | "gost12-512" | "md_gost12_512" => Ok(Self::Gost3411_2012_512),
            _ => Err(CliError::Usage(format!(
                "unsupported --digest {name}; expected gost12-256 or gost12-512\n\n{}",
                usage()
            ))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Gost3411_2012_256 => "ГОСТ Р 34.11-2012-256",
            Self::Gost3411_2012_512 => "ГОСТ Р 34.11-2012-512",
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Gost3411_2012_256 => "gost12-256",
            Self::Gost3411_2012_512 => "gost12-512",
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Self::Gost3411_2012_256 => 32,
            Self::Gost3411_2012_512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Pkcs11,
    Ccid,
}

impl Transport {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "pkcs11" => Ok(Self::Pkcs11),
            "ccid" => Ok(Self::Ccid),
            _ => Err(CliError::Usage(format!(
                "unsupported --transport {value}; expected pkcs11 or ccid\n\n{}",
                usage()
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pkcs11 => "pkcs11",
            Self::Ccid => "ccid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignCommand {
    pub input: PathBuf,
    pub output: PathBuf,
    pub cert: PathBuf,
    pub key_uri: String,
    pub digest: DigestAlgorithm,
    pub transport: Transport,
    pub pkcs11_module: Option<PathBuf>,
    pub ccid_reader: Option<String>,
    pub embed_content: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    Message(String),
    Usage(String),
}

impl CliError {
    pub fn is_usage(&self) -> bool {
        matches!(self, Self::Usage(_))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) | Self::Usage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CliError {}

pub fn run_cli<I>(args: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    match args.next() {
        None => Err(CliError::Usage(usage())),
        Some(command) if command == "--help" || command == "-h" || command == "help" => Ok(usage()),
        Some(command) if command == "sign" => {
            let sign_command = SignCommand::parse(args)?;
            sign_command.run()
        }
        Some(command) => Err(CliError::Usage(format!(
            "unknown command: {}\n\n{}",
            command.to_string_lossy(),
            usage()
        ))),
    }
}

impl SignCommand {
    fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut input = None;
        let mut output = None;
        let mut cert = None;
        let mut key_uri = None;
        let mut digest = DigestAlgorithm::Gost3411_2012_256;
        let mut transport = Transport::Pkcs11;
        let mut pkcs11_module = None;
        let mut ccid_reader = None;
        let mut embed_content = false;
        let mut dry_run = false;

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--input" => input = Some(PathBuf::from(next_value(&mut iter, "--input")?)),
                "--output" => output = Some(PathBuf::from(next_value(&mut iter, "--output")?)),
                "--cert" => cert = Some(PathBuf::from(next_value(&mut iter, "--cert")?)),
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--digest" => {
                    digest = DigestAlgorithm::parse(
                        next_value(&mut iter, "--digest")?
                            .to_string_lossy()
                            .as_ref(),
                    )?
                }
                "--transport" => {
                    transport = Transport::parse(
                        next_value(&mut iter, "--transport")?
                            .to_string_lossy()
                            .as_ref(),
                    )?
                }
                "--pkcs11-module" => {
                    pkcs11_module = Some(PathBuf::from(next_value(&mut iter, "--pkcs11-module")?))
                }
                "--ccid-reader" => {
                    ccid_reader = Some(
                        next_value(&mut iter, "--ccid-reader")?
                            .to_string_lossy()
                            .into(),
                    )
                }
                "--embed-content" => embed_content = true,
                "--dry-run" => dry_run = true,
                "--help" | "-h" => return Err(CliError::Usage(usage())),
                flag => {
                    return Err(CliError::Usage(format!(
                        "unknown option: {flag}\n\n{}",
                        usage()
                    )));
                }
            }
        }

        let command = Self {
            input: required_path(input, "--input")?,
            output: required_path(output, "--output")?,
            cert: required_path(cert, "--cert")?,
            key_uri: required_string(key_uri, "--key-uri")?,
            digest,
            transport,
            pkcs11_module,
            ccid_reader,
            embed_content,
            dry_run,
        };

        command.validate()?;
        Ok(command)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        ensure_file_exists(&self.input, "--input")?;
        ensure_parent_exists(&self.output, "--output")?;
        ensure_file_exists(&self.cert, "--cert")?;

        if self.key_uri.trim().is_empty() {
            return Err(CliError::Usage(
                String::from("--key-uri must not be empty\n\n") + &usage(),
            ));
        }

        if self.transport == Transport::Pkcs11 {
            let Some(module) = &self.pkcs11_module else {
                return Err(CliError::Usage(
                    String::from("--pkcs11-module is required for --transport pkcs11\n\n")
                        + &usage(),
                ));
            };
            token::ensure_module_path(module)?;
        }

        Ok(())
    }

    pub fn run(&self) -> Result<String, CliError> {
        let document = fs::read(&self.input).map_err(|error| {
            CliError::Message(format!(
                "failed to read --input {}: {error}",
                self.input.display()
            ))
        })?;
        let certificate = fs::read(&self.cert).map_err(|error| {
            CliError::Message(format!(
                "failed to read --cert {}: {error}",
                self.cert.display()
            ))
        })?;
        let digest = gost::hash(&document, self.digest);
        let cms_input = cms_envelope::CmsSigningInput::new(
            digest.clone(),
            self.digest,
            certificate,
            !self.embed_content,
        );
        cms_input.validate()?;

        if self.dry_run {
            return Ok(self.render_plan(&digest));
        }

        match self.transport {
            Transport::Pkcs11 => {
                let signer = token::Pkcs11SignerConfig::new(
                    self.pkcs11_module.clone().expect("validated module"),
                    self.key_uri.clone(),
                );
                token::TokenSigner::sign_digest(&signer, self.digest, &digest)
            }
            Transport::Ccid => {
                let signer =
                    token::CcidSignerConfig::new(self.ccid_reader.clone(), self.key_uri.clone());
                token::TokenSigner::sign_digest(&signer, self.digest, &digest)
            }
        }?;

        Err(CliError::Message(
            "CMS signature generation is not yet enabled. This feature requires hardware validation and will be available in a future release.".to_string(),
        ))
    }

    pub fn render_plan(&self, digest: &[u8]) -> String {
        let mut lines = vec![
            "native signing plan".to_string(),
            format!("input={}", self.input.display()),
            format!("output={}", self.output.display()),
            format!("cert={}", self.cert.display()),
            format!("transport={}", self.transport.name()),
            format!("key_uri={}", self.key_uri),
            format!("digest_algorithm={}", self.digest.cli_name()),
            format!("digest_hex={}", hex_encode(digest)),
            format!("cms_backend={}", cms_envelope::cms_crate_backend()),
        ];

        match self.transport {
            Transport::Pkcs11 => {
                lines.push(format!("pkcs11_backend={}", token::pkcs11_crate_backend()));
                if let Some(module) = &self.pkcs11_module {
                    lines.push(format!("pkcs11_module={}", module.display()));
                }
            }
            Transport::Ccid => {
                lines.push(format!("ccid_product={}", ccid::RUTOKEN_ECP3_PRODUCT));
                lines.push(format!("ccid_vid=0x{:04x}", ccid::RUTOKEN_ECP3_USB_VID));
                lines.push(format!("ccid_pid=0x{:04x}", ccid::RUTOKEN_ECP3_USB_PID));
                if let Some(reader) = &self.ccid_reader {
                    lines.push(format!("ccid_reader={reader}"));
                }
            }
        }

        if self.embed_content {
            lines.push("cms_content=attached".to_string());
        } else {
            lines.push("cms_content=detached".to_string());
        }

        lines.join("\n")
    }
}

fn next_value<I>(iter: &mut I, flag: &str) -> Result<OsString, CliError>
where
    I: Iterator<Item = OsString>,
{
    iter.next()
        .ok_or_else(|| CliError::Usage(format!("missing value for {flag}\n\n{}", usage())))
}

fn required_path(value: Option<PathBuf>, flag: &str) -> Result<PathBuf, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required option {flag}\n\n{}", usage())))
}

fn required_string(value: Option<String>, flag: &str) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("missing required option {flag}\n\n{}", usage())))
}

fn ensure_file_exists(path: &Path, flag: &str) -> Result<(), CliError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(CliError::Message(format!(
            "{flag} must reference a file: {}",
            path.display()
        ))),
        Err(_) => Err(CliError::Message(format!(
            "{flag} does not exist: {}",
            path.display()
        ))),
    }
}

fn ensure_parent_exists(path: &Path, flag: &str) -> Result<(), CliError> {
    match path.parent() {
        None => Ok(()),
        Some(parent) if parent.as_os_str().is_empty() => Ok(()),
        Some(parent) if parent.exists() => Ok(()),
        Some(parent) => Err(CliError::Message(format!(
            "{flag} parent directory does not exist: {}",
            parent.display()
        ))),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    // Keep this tiny diagnostic encoder local instead of adding another dependency.
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn usage() -> String {
    String::from(
        "cryptokiddie sign --input <FILE> --output <FILE> --cert <FILE> --key-uri <URI> [options]\n\
         \n\
         Native Rust signing pipeline for token-backed ГОСТ Р 34.10-2012 keys.\n\
         The document is hashed in-process with ГОСТ Р 34.11-2012; the token is\n\
         responsible for the hardware signature; CMS SignedData construction is\n\
         kept behind the RustCrypto cms crate boundary.\n\
         \n\
         Options:\n\
           --digest <NAME>           gost12-256/md_gost12_256 (default) or gost12-512\n\
           --transport <NAME>        pkcs11 (default) or ccid\n\
           --pkcs11-module <FILE>    PKCS#11 module used by the pkcs11 Rust crate\n\
           --ccid-reader <NAME>      CCID reader selector for direct USB/APDU work\n\
           --embed-content           Produce an attached CMS object after signing\n\
           --dry-run                 Hash input and print the native signing plan\n\
         \n\
         Example:\n\
           cryptokiddie sign --input contract.pdf --output contract.pdf.p7s \\\n             --cert signer.der --key-uri pkcs11:token=Signer;id=%01 \\\n             --digest gost12-256 --pkcs11-module ./librtpkcs11ecp.so --dry-run\n",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CliError, DigestAlgorithm, SignCommand, Transport, apdu, ccid, cms_envelope, gost, run_cli,
    };
    use std::{
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_native_pkcs11_sign_command() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--digest"),
            OsString::from("md_gost12_256"),
            OsString::from("--pkcs11-module"),
            module.clone().into_os_string(),
        ])
        .expect("command should parse");

        assert_eq!(command.digest, DigestAlgorithm::Gost3411_2012_256);
        assert_eq!(command.transport, Transport::Pkcs11);
        assert_eq!(command.pkcs11_module.as_deref(), Some(module.as_path()));
    }

    #[test]
    fn dry_run_hashes_with_streebog_and_renders_plan() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let module = temp.write_file("pkcs11-module.so", "driver");
        let output = temp.path().join("document.txt.p7s");

        let output = run_cli([
            OsString::from("sign"),
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--pkcs11-module"),
            module.into_os_string(),
            OsString::from("--dry-run"),
        ])
        .expect("dry run should succeed");

        assert!(output.contains("native signing plan"));
        assert!(output.contains("transport=pkcs11"));
        assert!(output.contains("digest_algorithm=gost12-256"));
        assert!(output.contains("pkcs11_backend=pkcs11::Ctx"));
        assert!(output.contains("cms_backend=cms::content_info::ContentInfo"));
        assert!(!output.contains("openssl"));
    }

    #[test]
    fn renders_ccid_rutoken_identity_in_dry_run() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");

        let output = run_cli([
            OsString::from("sign"),
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("rutoken:slot=0;id=%01"),
            OsString::from("--transport"),
            OsString::from("ccid"),
            OsString::from("--ccid-reader"),
            OsString::from("Rutoken"),
            OsString::from("--dry-run"),
        ])
        .expect("dry run should succeed");

        assert!(output.contains("transport=ccid"));
        assert!(output.contains("ccid_product=Rutoken ECP"));
        assert!(output.contains("ccid_vid=0x0a89"));
        assert!(output.contains("ccid_pid=0x0030"));
    }

    #[test]
    fn streebog_digest_sizes_match_gost_3411_2012_variants() {
        assert_eq!(
            gost::hash(b"hello", DigestAlgorithm::Gost3411_2012_256).len(),
            32
        );
        assert_eq!(
            gost::hash(b"hello", DigestAlgorithm::Gost3411_2012_512).len(),
            64
        );
        assert_ne!(
            gost::hash(b"hello", DigestAlgorithm::Gost3411_2012_256),
            gost::hash(b"world", DigestAlgorithm::Gost3411_2012_256)
        );
    }

    #[test]
    fn command_apdu_serializes_short_apdu() {
        let apdu = apdu::CommandApdu::new(0x00, 0xa4, 0x04, 0x00)
            .with_data([0x3f, 0x00])
            .with_le(0x00);

        assert_eq!(
            apdu.to_bytes().expect("APDU should serialize"),
            vec![0x00, 0xa4, 0x04, 0x00, 0x02, 0x3f, 0x00, 0x00,]
        );
    }

    #[test]
    fn ccid_xfr_block_wraps_command_apdu() {
        let apdu = apdu::CommandApdu::new(0x00, 0xa4, 0x04, 0x00).with_le(0x00);
        let block = ccid::XfrBlock::new(0, 7, apdu);

        assert_eq!(
            block.to_bytes().expect("CCID block should serialize"),
            vec![
                0x6f, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x04, 0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn cms_input_rejects_wrong_digest_length() {
        let input = cms_envelope::CmsSigningInput::new(
            vec![1, 2, 3],
            DigestAlgorithm::Gost3411_2012_256,
            vec![1],
            true,
        );

        assert!(
            matches!(input.validate(), Err(CliError::Message(message)) if message.contains("32 bytes"))
        );
    }

    #[test]
    fn pkcs11_transport_requires_module() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.der", "certificate");
        let output = temp.path().join("document.txt.p7s");

        let error = SignCommand::parse([
            OsString::from("--input"),
            input.into_os_string(),
            OsString::from("--output"),
            output.into_os_string(),
            OsString::from("--cert"),
            cert.into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
        ])
        .expect_err("missing PKCS#11 module should fail");

        assert!(matches!(error, CliError::Usage(message) if message.contains("--pkcs11-module")));
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be valid")
                .as_nanos();
            let path = env::temp_dir().join(format!("cryptokiddie-tests-{unique}"));
            fs::create_dir_all(&path).expect("temp dir should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write_file(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("temp file should be written");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
