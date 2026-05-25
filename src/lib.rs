use std::{
    ffi::OsString,
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignCommand {
    pub input: PathBuf,
    pub output: PathBuf,
    pub cert: PathBuf,
    pub key_uri: String,
    pub provider: String,
    pub provider_path: Option<PathBuf>,
    pub provider_config: Option<PathBuf>,
    pub openssl_bin: PathBuf,
    pub embed_content: bool,
    pub dry_run: bool,
    pub extra_args: Vec<String>,
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
        let mut provider = String::from("pkcs11");
        let mut provider_path = None;
        let mut provider_config = None;
        let mut openssl_bin = default_openssl_binary();
        let mut embed_content = false;
        let mut dry_run = false;
        let mut extra_args = Vec::new();

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.to_string_lossy().as_ref() {
                "--input" => input = Some(PathBuf::from(next_value(&mut iter, "--input")?)),
                "--output" => output = Some(PathBuf::from(next_value(&mut iter, "--output")?)),
                "--cert" => cert = Some(PathBuf::from(next_value(&mut iter, "--cert")?)),
                "--key-uri" => {
                    key_uri = Some(next_value(&mut iter, "--key-uri")?.to_string_lossy().into())
                }
                "--provider" => {
                    provider = next_value(&mut iter, "--provider")?
                        .to_string_lossy()
                        .into()
                }
                "--provider-path" => {
                    provider_path = Some(PathBuf::from(next_value(&mut iter, "--provider-path")?))
                }
                "--provider-config" => {
                    provider_config =
                        Some(PathBuf::from(next_value(&mut iter, "--provider-config")?))
                }
                "--openssl" => openssl_bin = PathBuf::from(next_value(&mut iter, "--openssl")?),
                "--embed-content" => embed_content = true,
                "--dry-run" => dry_run = true,
                "--" => {
                    extra_args.extend(iter.map(|value| value.to_string_lossy().into_owned()));
                    break;
                }
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
            provider,
            provider_path,
            provider_config,
            openssl_bin,
            embed_content,
            dry_run,
            extra_args,
        };

        command.validate()?;
        Ok(command)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        ensure_file_exists(&self.input, "--input")?;
        ensure_parent_exists(&self.output, "--output")?;
        ensure_file_exists(&self.cert, "--cert")?;

        if let Some(provider_path) = &self.provider_path {
            ensure_dir_exists(provider_path, "--provider-path")?;
        }

        if let Some(provider_config) = &self.provider_config {
            ensure_file_exists(provider_config, "--provider-config")?;
        }

        if self.key_uri.trim().is_empty() {
            return Err(CliError::Usage(
                String::from("--key-uri must not be empty\n\n") + &usage(),
            ));
        }

        if self.provider.trim().is_empty() {
            return Err(CliError::Usage(
                String::from("--provider must not be empty\n\n") + &usage(),
            ));
        }

        Ok(())
    }

    pub fn openssl_args(&self) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("cms"),
            OsString::from("-sign"),
            OsString::from("-binary"),
            OsString::from("-in"),
            self.input.clone().into_os_string(),
            OsString::from("-out"),
            self.output.clone().into_os_string(),
            OsString::from("-outform"),
            OsString::from("DER"),
            OsString::from("-signer"),
            self.cert.clone().into_os_string(),
            OsString::from("-inkey"),
            OsString::from(&self.key_uri),
            OsString::from("-provider"),
            OsString::from("default"),
            OsString::from("-provider"),
            OsString::from(&self.provider),
        ];

        if let Some(provider_path) = &self.provider_path {
            args.push(OsString::from("-provider-path"));
            args.push(provider_path.clone().into_os_string());
        }

        if let Some(provider_config) = &self.provider_config {
            args.push(OsString::from("-config"));
            args.push(provider_config.clone().into_os_string());
        }

        if self.embed_content {
            args.push(OsString::from("-nodetach"));
        }

        args.extend(self.extra_args.iter().map(OsString::from));
        args
    }

    pub fn render_command(&self) -> String {
        let mut rendered = shell_quote(self.openssl_bin.as_os_str().to_string_lossy().as_ref());
        for arg in self.openssl_args() {
            rendered.push(' ');
            rendered.push_str(&shell_quote(arg.to_string_lossy().as_ref()));
        }
        rendered
    }

    pub fn run(&self) -> Result<String, CliError> {
        if self.dry_run {
            return Ok(self.render_command());
        }

        let output = Command::new(&self.openssl_bin)
            .args(self.openssl_args())
            .output()
            .map_err(|error| {
                CliError::Message(format!(
                    "failed to execute {}: {error}",
                    self.openssl_bin.display()
                ))
            })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let mut message = format!(
                "openssl exited with status {}",
                output.status.code().map_or_else(
                    || String::from("terminated by signal"),
                    |code| code.to_string()
                )
            );
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                let _ = write!(message, "\n{stderr}");
            }
            Err(CliError::Message(message))
        }
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

fn ensure_dir_exists(path: &Path, flag: &str) -> Result<(), CliError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(CliError::Message(format!(
            "{flag} must reference a directory: {}",
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

fn default_openssl_binary() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("openssl.exe")
    } else {
        PathBuf::from("openssl")
    }
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "/._:-".contains(character))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn usage() -> String {
    String::from(
        "cryptokiddie sign --input <FILE> --output <FILE> --cert <FILE> --key-uri <URI> [options]\n\
         \n\
         Minimal native Rust wrapper around OpenSSL CMS signing for token-backed keys.\n\
         The private key stays on the token; the certificate is provided as a PEM file.\n\
         \n\
         Options:\n\
           --provider <NAME>         OpenSSL provider name (default: pkcs11)\n\
           --provider-path <DIR>     OpenSSL provider search path\n\
           --provider-config <FILE>  OpenSSL config that wires the provider to the token module\n\
           --openssl <PATH>          OpenSSL binary to execute (default: openssl / openssl.exe)\n\
           --embed-content           Produce an attached CMS object (-nodetach)\n\
           --dry-run                 Print the OpenSSL command instead of executing it\n\
           -- <ARGS...>              Extra arguments passed through to openssl cms\n\
         \n\
         Example:\n\
           cryptokiddie sign --input contract.pdf --output contract.pdf.p7s \\\n\
             --cert signer.pem --key-uri pkcs11:token=Signer;id=%01 \\\n\
             --provider-config openssl-pkcs11.cnf --dry-run\n",
    )
}

#[cfg(test)]
mod tests {
    use super::{CliError, SignCommand, run_cli};
    use std::{
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_sign_command_with_defaults() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.pem", "-----BEGIN CERTIFICATE-----");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.clone().into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
            OsString::from("--cert"),
            cert.clone().into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
        ])
        .expect("command should parse");

        assert_eq!(command.provider, "pkcs11");
        assert_eq!(command.openssl_bin, PathBuf::from("openssl"));
        assert!(!command.embed_content);
        assert!(!command.dry_run);
        assert!(command.extra_args.is_empty());
    }

    #[test]
    fn renders_provider_configuration_and_passthrough_arguments() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.pem", "-----BEGIN CERTIFICATE-----");
        let config = temp.write_file("openssl.cnf", "[openssl_init]");
        let providers = temp.create_dir("providers");
        let output = temp.path().join("document.txt.p7s");

        let command = SignCommand::parse([
            OsString::from("--input"),
            input.clone().into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
            OsString::from("--cert"),
            cert.clone().into_os_string(),
            OsString::from("--key-uri"),
            OsString::from("pkcs11:token=Signer;id=%01"),
            OsString::from("--provider"),
            OsString::from("legacy-pkcs11"),
            OsString::from("--provider-path"),
            providers.clone().into_os_string(),
            OsString::from("--provider-config"),
            config.clone().into_os_string(),
            OsString::from("--embed-content"),
            OsString::from("--"),
            OsString::from("-md"),
            OsString::from("sha256"),
        ])
        .expect("command should parse");

        let rendered = command.render_command();
        assert!(rendered.contains("-provider legacy-pkcs11"));
        assert!(rendered.contains("-provider-path"));
        assert!(rendered.contains("-config"));
        assert!(rendered.contains("-nodetach"));
        assert!(rendered.contains("-md sha256"));
    }

    #[test]
    fn rejects_missing_output_directory() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.pem", "-----BEGIN CERTIFICATE-----");
        let output = temp.path().join("missing").join("document.txt.p7s");

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
        .expect_err("missing parent should fail");

        assert!(
            matches!(error, CliError::Message(message) if message.contains("parent directory does not exist"))
        );
    }

    #[test]
    fn dry_run_cli_returns_rendered_command() {
        let temp = TempDir::new();
        let input = temp.write_file("document.txt", "hello");
        let cert = temp.write_file("signer.pem", "-----BEGIN CERTIFICATE-----");
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
            OsString::from("--dry-run"),
        ])
        .expect("dry run should succeed");

        assert!(output.starts_with("openssl cms -sign -binary"));
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

        fn create_dir(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::create_dir_all(&path).expect("temp directory should be created");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
