# CryptoKiddie

Minimal native Rust CLI for signing documents with token-backed keys through OpenSSL providers.

## Why this shape

The issue asks for an OS X/Linux/Windows native tool and explicitly raises the OpenSSL-provider question. This repository now ships a small Rust binary that keeps the UX native while delegating the actual token access to OpenSSL 3 providers (for example `pkcs11`) configured for PKCS#11 tokens such as a Рутокен ЭЦП 3.0 USB stick.

That gives us:

- a single cross-platform Rust executable;
- no private-key export from the token;
- compatibility with provider-based integrations instead of hard-coding one token SDK;
- app-local provider/module wiring, so the tool does not need a system-wide CryptoPro installation.

## Usage

```bash
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.pem \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --provider-path ./ossl-modules \
  --pkcs11-module ./librtpkcs11ecp.so \
  --dry-run
```

Remove `--dry-run` to execute `openssl cms -sign`.

## Notes

- The private key is expected to stay on the token and be referenced by `--key-uri`.
- The signer certificate is provided as a PEM file via `--cert`.
- `--provider-path` can point at an application-bundled OpenSSL provider directory instead of relying on a system install.
- `--pkcs11-module` maps directly to `PKCS11_PROVIDER_MODULE`, so the token driver can live next to the app instead of being registered system-wide.
- For Рутокен ЭЦП 3.0, the bundled PKCS#11 library is typically `librtpkcs11ecp.so` on Linux, `librtpkcs11ecp.dylib` on macOS, or `rtPKCS11ECP.dll` on Windows.
- `--provider-config` remains available as an escape hatch for advanced provider settings that are not yet modeled directly in the CLI.
