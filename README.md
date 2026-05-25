# CryptoKiddie

Minimal native Rust CLI for building a self-contained document-signing path around token-backed GOST keys.

## Direction

The signing path is being rewritten away from the OpenSSL-provider wrapper. The new Rust boundary is:

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
- `ГОСТ Р 34.11-2012` hashing is implemented in Rust through `streebog` for 256-bit and 512-bit variants (`gost12-256`, `gost12-512`, plus the OpenSSL-compatible aliases `md_gost12_256` and `md_gost12_512`).
- CMS construction, PKCS#11 signing, and direct USB/CCID signing are now explicit Rust module boundaries with unit coverage.
- Live Rutoken signing and complete proprietary PKCS#11 driver replacement still require hardware-backed mechanism/APDU validation before the CLI can safely emit a final CMS signature.
