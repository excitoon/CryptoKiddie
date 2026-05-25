# CryptoKiddie

Minimal native Rust CLI for signing documents with token-backed keys through OpenSSL providers.

## Why this shape

The issue asks for an OS X/Linux/Windows native tool and explicitly raises the OpenSSL-provider question. This repository now ships a small Rust binary that keeps the UX native while delegating the actual token access to OpenSSL 3 providers (for example `pkcs11`) configured for CryptoPro-compatible tokens.

That gives us:

- a single cross-platform Rust executable;
- no private-key export from the token;
- compatibility with provider-based integrations instead of hard-coding one token SDK.

## Usage

```bash
cargo run -- sign \
  --input contract.pdf \
  --output contract.pdf.p7s \
  --cert signer.pem \
  --key-uri 'pkcs11:token=Signer;id=%01' \
  --provider-config openssl-pkcs11.cnf \
  --dry-run
```

Remove `--dry-run` to execute `openssl cms -sign`.

## Notes

- The private key is expected to stay on the token and be referenced by `--key-uri`.
- The signer certificate is provided as a PEM file via `--cert`.
- `--provider-config` should point at the OpenSSL configuration that binds the chosen provider to the token module for your platform.
