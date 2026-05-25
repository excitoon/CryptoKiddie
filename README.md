# CryptoKiddie

Minimal native Rust CLI for signing documents with token-backed keys through OpenSSL providers.

## Why this shape

The issue asks for an OS X/Linux/Windows native tool and explicitly raises the OpenSSL-provider question. This repository now ships a small Rust binary that keeps the UX native while delegating the actual token access to OpenSSL 3 providers (for example `pkcs11`) configured for PKCS#11-backed keys.

That gives us:

- a single cross-platform Rust executable;
- no private-key export from the token;
- compatibility with provider-based integrations instead of hard-coding one token SDK;
- app-local provider/module wiring, so the tool does not depend on a system-wide token stack installation.

## Usage

```bash
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.pem \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --digest md_gost12_256 \
  --provider-path ./ossl-modules \
  --pkcs11-module ./pkcs11-module.so \
  --dry-run
```

Remove `--dry-run` to execute `openssl cms -sign`.

## Notes

- The private key is expected to stay on the token and be referenced by `--key-uri`.
- The signer certificate is provided as a PEM file via `--cert`.
- `--digest` selects the OpenSSL hash/digest name passed as `-md`.
- For `ГОСТ Р 34.10-2012` with a 256-bit key, use `--digest md_gost12_256`, which is the OpenSSL name for `ГОСТ Р 34.11-2012` 256-bit.
- For `ГОСТ Р 34.11-2012` 512-bit hashing, use `--digest md_gost12_512`.
- The target USB token profile discussed for this workflow is `Rutoken ECP (Рутокен ЭЦП 3.0)` from Aktiv, exposed on USB as VID `0x0a89` / PID `0x0030`.
- `--provider-path` can point at an application-bundled OpenSSL provider directory instead of relying on a system install.
- `--pkcs11-module` maps directly to `PKCS11_PROVIDER_MODULE`, so the token driver can live next to the app instead of being registered system-wide.
- The concrete PKCS#11 module path is deployment-specific and supplied explicitly with `--pkcs11-module`; the CLI does not hard-code any vendor library names.
- `--provider-config` remains available as an escape hatch for advanced provider settings that are not yet modeled directly in the CLI.
