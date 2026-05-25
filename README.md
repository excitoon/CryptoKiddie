# CryptoKiddie

Minimal native Rust CLI for building a self-contained document-signing path around token-backed cryptographic keys without an OpenSSL dependency.

## Direction

The signing path is native Rust plus token hardware. It does not shell out to OpenSSL or rely on OpenSSL provider configuration:

- hash document bytes in-process via RustCrypto crates:
  - `ГОСТ Р 34.11-2012` (256-bit or 512-bit) via the `streebog` crate;
  - SHA-256, SHA-384, or SHA-512 via the `sha2` crate;
- ask the token hardware to sign the digest using the configured key algorithm:
  - `ГОСТ Р 34.10-2012` via `CKM_GOSTR3410` (PKCS#11);
  - ECDSA via `CKM_ECDSA` (PKCS#11);
  - RSA PKCS#1 v1.5 via `CKM_RSA_PKCS` with automatic DigestInfo wrapping (PKCS#11);
- construct the CMS/PKCS#7 `SignedData` envelope through Rust CMS code rather than shelling out to OpenSSL;
- support two token transports:
  - `pkcs11`, using the Rust `cryptoki` crate against any supplied PKCS#11 module;
  - `ccid`, the direct USB/CCID APDU protocol boundary for hardware-specific integrations.

## Usage

```bash
# ECDSA with SHA-256 (any PKCS#11 token with an ECDSA key)
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.der \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --digest sha256 \
  --key-algorithm ecdsa \
  --pkcs11-module ./opensc-pkcs11.so \
  --pin-env TOKEN_PIN \
  --dry-run

# RSA with SHA-256
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.der \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --digest sha256 \
  --key-algorithm rsa \
  --pkcs11-module ./opensc-pkcs11.so \
  --pin-env TOKEN_PIN \
  --dry-run

# GOST 34.10-2012 with 256-bit key (any GOST-capable PKCS#11 token)
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.der \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --digest gost12-256 \
  --pkcs11-module ./gost-pkcs11.so \
  --pin-env TOKEN_PIN \
  --dry-run
```

For direct USB/CCID bring-up (any CCID-compatible reader):

```bash
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.der \
  --key-uri 'pkcs11:slot=0;id=%01' \
  --transport ccid \
  --ccid-reader "Alcor Micro AU9560" \
  --dry-run
```

`--dry-run` hashes the input and prints the native signing plan without producing a signature.

### Supported algorithms

| `--digest`    | `--key-algorithm`     | Signing OID                  |
|---------------|-----------------------|------------------------------|
| `gost12-256`  | `gost3410-2012-256`   | 1.2.643.7.1.1.1.1            |
| `gost12-512`  | `gost3410-2012-512`   | 1.2.643.7.1.1.1.2            |
| `sha256`      | `ecdsa`               | 1.2.840.10045.4.3.2          |
| `sha384`      | `ecdsa`               | 1.2.840.10045.4.3.3          |
| `sha512`      | `ecdsa`               | 1.2.840.10045.4.3.4          |
| `sha256`      | `rsa`                 | 1.2.840.113549.1.1.11        |
| `sha384`      | `rsa`                 | 1.2.840.113549.1.1.12        |
| `sha512`      | `rsa`                 | 1.2.840.113549.1.1.13        |

When `--key-algorithm` is omitted, GOST digests default to `gost3410-2012-256`/`gost3410-2012-512` and SHA-2 digests default to `ecdsa`.

## Current status

- The OpenSSL command execution path has been removed.
- All hashing is implemented in Rust: `ГОСТ Р 34.11-2012` through `streebog`, SHA-256/384/512 through `sha2`.
- CMS construction and PKCS#11 signing are wired into the non-dry-run path: the CLI hashes the input, opens a token session with `cryptoki`, signs with the token's chosen mechanism (`CKM_GOSTR3410`, `CKM_ECDSA`, or `CKM_RSA_PKCS`), builds CMS `SignedData`, and writes DER `.p7s` output.
- Direct USB/CCID signing still requires hardware-backed mechanism/APDU validation before the CLI can safely use that transport for final signatures.
