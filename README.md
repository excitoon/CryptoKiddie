# CryptoKiddie

Minimal native Rust CLI for building a self-contained document-signing path around token-backed cryptographic keys without an OpenSSL dependency.

## Direction

The signing path is native Rust plus token hardware. It does not shell out to OpenSSL or rely on OpenSSL provider configuration:

- hash document bytes in-process via RustCrypto crates:
  - `ГОСТ Р 34.11-2012` (256-bit or 512-bit) via the `streebog` crate;
  - SHA-256, SHA-384, or SHA-512 via the `sha2` crate;
- ask the token hardware to sign the digest using the configured key algorithm:
  - `ГОСТ Р 34.10-2012` via `CKM_GOSTR3410` (PKCS#11), including Rutoken devices through their PKCS#11 module;
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

# GOST 34.10-2012 with 256-bit key (any GOST-capable PKCS#11 token, including Rutoken)
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
  --key-uri 'rutoken:slot=0;id=%03' \
  --transport ccid \
  --ccid-reader "Alcor Micro AU9560" \
  --dry-run
```

`--dry-run` hashes the input and prints the native signing plan without producing a signature. For `rutoken:` URIs, `id=%XX` is the Rutoken private-key reference; the tested Osnovanie/Rutoken ECP token uses `id=%03`.

For a direct raw signature smoke test against the tested Rutoken ECP token:

```bash
cargo run -- ccid-sign-raw \
  --input README.md \
  --output target/rutoken-readme.sig \
  --key-uri 'rutoken:slot=0;id=%03' \
  --ccid-reader 'Rutoken ECP' \
  --exchange-log logs/ccid-sign-raw.log \
  --pin-env TOKEN_PIN
```

`TOKEN_PIN` can be read from the environment or from the local `.env` file. `.env` is ignored by git and should not be committed.

### Rutoken ECP Notes

- Private key material does not leave the Rutoken. The host selects a key reference and asks the token to sign; the token returns only the signature bytes.
- The algorithm and key capabilities are not secret in the same way as the private key. They are stored or enforced by the token and may also be visible through PKCS#15 metadata, PKCS#11 attributes, public keys, or certificates.
- The current direct CCID path does not yet parse PKCS#15 metadata or read certificates/public keys. It uses the OpenSC-derived GOST signing flow explicitly and addresses the discovered private key as `rutoken:slot=0;id=%03`.
- The tested signing flow computes `ГОСТ Р 34.11-2012-256` on the host, sends the digest to the token in Rutoken ECP byte order, and receives a 64-byte `ГОСТ Р 34.10-2012` signature.
- Rutoken ECP PIN references follow Aktiv/OpenSC conventions: administrator/SO PIN ref `1`, normal user PIN ref `2`. Signing uses the user PIN ref `2`.
- The tested token accepted the `.env` PIN only on user PIN ref `2`; using ref `1` queried the wrong PIN object. The tested signing key reference is `0x03`; `0x01` and `0x02` did not contain the private key file.
- OpenSC behavior mirrored by the direct driver: `6300` after VERIFY is followed by a no-data VERIFY status query, and `6f86` after VERIFY is handled by `LOGOUT` (`80 40 00 00`) plus one VERIFY retry.
- The OpenSC private-key path used successfully for `id=%03` is `3F00/1000/1000/6002/0003`.

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

When `--key-algorithm` is omitted, GOST digests default to `gost3410-2012-256`/`gost3410-2012-512` and SHA-2 digests default to `ecdsa`. Rutoken/GOST support is preserved through the generic PKCS#11 path; Rutoken USB identifiers are not hard-coded into the universal CCID dry-run output.

## Current status

- The OpenSSL command execution path has been removed.
- All hashing is implemented in Rust: `ГОСТ Р 34.11-2012` through `streebog`, SHA-256/384/512 through `sha2`.
- CMS construction and PKCS#11 signing are wired into the non-dry-run path: the CLI hashes the input, opens a token session with `cryptoki`, signs with the token's chosen mechanism (`CKM_GOSTR3410`, `CKM_ECDSA`, or `CKM_RSA_PKCS`), builds CMS `SignedData`, and writes DER `.p7s` output.
- Direct USB/CCID signing is implemented for Rutoken ECP 3.0:
  - `ccid::CcidDevice` discovers the Rutoken ECP by VID/PID (`0x0a89`/`0x0030`), claims the CCID interface (bInterfaceClass `0x0B`), and communicates via USB bulk transfer.
  - `ccid::IccPowerOn` / `ccid::RdrDataBlock` encode/decode the CCID `PC_to_RDR_IccPowerOn` and `RDR_to_PC_DataBlock` messages.
  - `rutoken::RutokenUri` parses `rutoken:slot=N;id=%XX` key URIs used with `--transport ccid`.
  - The ISO 7816-8 APDU sequence (SELECT MF → VERIFY user PIN ref 2 → SELECT private-key file → MSE SET → PSO COMPUTE DIGITAL SIGNATURE) is implemented in the `rutoken` module against OpenSC's `card-rtecp.c`, `pkcs15-rtecp.c`, and `rutoken_ecp.profile` as references.
  - macOS live APDU work falls back to PC/SC when SmartCardServices owns the raw USB CCID interface.
  - Hardware raw signing was verified on the connected Osnovanie/Rutoken ECP token with `rutoken:slot=0;id=%03`, producing a 64-byte signature at `target/rutoken-readme.sig`.
  - Hardware-in-the-loop testing requires a physical Rutoken ECP 3.0 device and appropriate USB access permissions.
