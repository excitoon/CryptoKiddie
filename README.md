# CryptoKiddie

Minimal native Rust CLI for building a self-contained document-signing path around token-backed GOST keys without an OpenSSL dependency.

## Direction

The signing path is native Rust plus token hardware. It does not shell out to OpenSSL or rely on OpenSSL provider configuration:

- hash document bytes in-process with `ГОСТ Р 34.11-2012` via the RustCrypto `streebog` crate;
- ask the token hardware to sign the digest with `ГОСТ Р 34.10-2012 с ключом 256`;
- construct the CMS/PKCS#7 `SignedData` envelope through Rust CMS code rather than shelling out to OpenSSL;
- support two token transports:
  - `pkcs11`, using the Rust `cryptoki` crate against a supplied PKCS#11 module while the module replacement is developed;
  - `ccid`, the direct USB/CCID APDU protocol boundary for replacing vendor driver behavior.

The target USB token profile discussed for this workflow is `Rutoken ECP (Рутокен ЭЦП 3.0)` from Aktiv, exposed on USB as VID `0x0a89` / PID `0x0030`.
OpenSC's `card-rutokenecp.c` / `opensc-pkcs11` and AktivCo/OpenSC are the open-source reference points for replacing the proprietary PKCS#11 driver behavior.

## Usage

```bash
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.der \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --digest gost12-256 \
  --pkcs11-module ./opensc-pkcs11.so \
  --pin-env RUTOKEN_PIN \
  --dry-run
```

For direct USB/CCID bring-up:

```bash
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.der \
  --key-uri 'rutoken:slot=0;id=%01' \
  --transport ccid \
  --ccid-reader Rutoken \
  --dry-run
```

`--dry-run` hashes the input and prints the native signing plan without producing a signature.

## Current status

- The OpenSSL command execution path has been removed.
- `ГОСТ Р 34.11-2012` hashing is implemented in Rust through `streebog` for 256-bit and 512-bit variants (`gost12-256`, `gost12-512`).
- CMS construction and PKCS#11 signing are wired into the non-dry-run path: the CLI hashes the input, opens a token session with `cryptoki`, signs with the token's `CKM_GOSTR3410` mechanism, builds CMS `SignedData`, and writes DER `.p7s` output.
- Direct USB/CCID signing is implemented and replaces the proprietary PKCS#11 driver dependency:
  - `ccid::CcidDevice` discovers the Rutoken ECP by VID/PID (`0x0a89`/`0x0030`), claims the CCID interface (bInterfaceClass `0x0B`), and communicates via USB bulk transfer.
  - `ccid::IccPowerOn` / `ccid::RdrDataBlock` encode/decode the CCID `PC_to_RDR_IccPowerOn` and `RDR_to_PC_DataBlock` messages.
  - `rutoken::RutokenUri` parses `rutoken:slot=N;id=%XX` key URIs used with `--transport ccid`.
  - The ISO 7816-8 APDU sequence (SELECT MF → VERIFY PIN → MSE SET → PSO COMPUTE DIGITAL SIGNATURE) is implemented in the `rutoken` module against OpenSC's `card-rutokenecp.c` as reference.
  - Hardware-in-the-loop testing requires a physical Rutoken ECP 3.0 device and appropriate USB access permissions.
