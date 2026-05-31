# CryptoKiddie

Minimal native Rust CLI for building a self-contained document-signing path around token-backed cryptographic keys without an OpenSSL dependency.

The project name is currently `CryptoKiddie`; `CryptoKittie` is also under consideration as an alternate name.

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

### Gosuslugi Safari bridge

The Gosuslugi organization creation page currently looks for the JavaScript bridge object `gosuslugiPluginCrypto`. Normally that object is supplied by the Госуслуги/reference implementation browser-plugin stack. CryptoKiddie can serve a small localhost replacement for the subset observed on `https://lk.gosuslugi.ru/org-profile/create/org`:

- `certificates(...)` returns the configured signer certificate in the shape expected by the page;
- `signature(...)` accepts the page's base64 document payload, signs it through the Rutoken CCID path, and returns an attached CMS object as base64.

Start the bridge with a DER certificate that matches the Rutoken private key:

```bash
cargo run -- gosuslugi-bridge \
  --key-uri 'rutoken:slot=0;id=%03' \
  --ccid-reader 'Rutoken ECP' \
  --exchange-log logs/gosuslugi-bridge.log \
  --pin-env TOKEN_PIN
```

If Safari blocks page JavaScript from calling the localhost bridge directly, inject queue mode and pump queued plugin calls from outside Safari:

```bash
osascript - "$PWD/browser/gosuslugi-inject.js" <<'APPLESCRIPT'
on run argv
  set injectPath to item 1 of argv
  tell application "Safari"
    repeat with w in windows
      repeat with t in tabs of w
        if (URL of t) contains "gosuslugi" then
          do JavaScript "window.__CRYPTOKIDDIE_GOSUSLUGI_FORCE_QUEUE = true; window.gosuslugiPluginCrypto = undefined;" in t
          do JavaScript (read POSIX file injectPath) in t
          return
        end if
      end repeat
    end repeat
  end tell
end run
APPLESCRIPT

browser/gosuslugi-safari-pump-once.rb
```

When a DER certificate cannot be read from the token yet, `--cert-record` can serve the certificate-listing metadata expected by the Gosuslugi frontend:

```bash
cargo run -- gosuslugi-bridge \
  --cert-record target/gosuslugi-cert-record.json \
  --key-uri 'rutoken:slot=0;id=%03' \
  --ccid-reader 'Rutoken ECP' \
  --exchange-log logs/gosuslugi-bridge.log \
  --pin-env TOKEN_PIN
```

The record must use OID-keyed DN fields such as `2.5.4.3` for common name, `2.5.4.10` for organization, `1.2.643.100.3` for SNILS, `1.2.643.100.4` for organization INN, and `1.2.643.100.1` for OGRN. Metadata-only records let the page list/select a certificate, but signing still requires DER: provide `--cert` or include base64 DER in the record's `raw` field.

When `--cert` and `--cert-record` are omitted, the bridge attempts to read the matching certificate from likely Rutoken/OpenSC certificate files. On the tested token, signing key `id=%03` is present but the public certificate file was not found. To retry/export a token-stored certificate explicitly:

```bash
cargo run -- ccid-read-cert \
  --output target/rutoken-cert.der \
  --key-uri 'rutoken:slot=0;id=%03' \
  --ccid-reader 'Rutoken ECP' \
  --exchange-log logs/ccid-read-cert.log \
  --pin-env TOKEN_PIN
```

Then inject [browser/gosuslugi-inject.js](browser/gosuslugi-inject.js) into the Safari tab. If the page has already failed certificate search, reload it after injection so the marker `meta[property="gosuslugi.plugin.extension.content"]` is present before the app checks for plugin availability.

The bridge is intentionally local-only by default (`127.0.0.1:18765`). It does not install any GOST CSP, browser crypto plugin, or Rutoken vendor drivers.

### Rutoken ECP Notes

- Private key material does not leave the Rutoken. The host selects a key reference and asks the token to sign; the token returns only the signature bytes.
- The algorithm and key capabilities are not secret in the same way as the private key. They are stored or enforced by the token and may also be visible through PKCS#15 metadata, PKCS#11 attributes, public keys, or certificates.
- The current direct CCID path reads the certificate from the OpenSC-derived certificate file path and signs through the OpenSC-derived GOST signing flow explicitly. It still does not fully parse PKCS#15 metadata or enumerate all public keys.
- The tested signing flow computes `ГОСТ Р 34.11-2012-256` on the host, sends the digest to the token in native digest order, and reverses the returned 64-byte `ГОСТ Р 34.10-2012` signature before CMS encoding. This byte-order combination passed Госуслуги `crtcheck`.
- Rutoken ECP PIN references follow Aktiv/OpenSC conventions: administrator/SO PIN ref `1`, normal user PIN ref `2`. Signing uses the user PIN ref `2`.
- The tested token accepted the `.env` PIN only on user PIN ref `2`; using ref `1` queried the wrong PIN object. The tested signing key reference is `0x03`; `0x01` and `0x02` did not contain the private key file.
- OpenSC behavior mirrored by the direct driver: `6300` after VERIFY is followed by a no-data VERIFY status query, and `6f86` after VERIFY is handled by `LOGOUT` (`80 40 00 00`) plus one VERIFY retry.
- The OpenSC private-key path used successfully for `id=%03` is `3F00/1000/1000/6002/0003`.

### Supported algorithms

| `--digest`    | `--key-algorithm`     | Signing OID                  |
|---------------|-----------------------|------------------------------|
| `gost12-256`  | `gost3410-2012-256`   | 1.2.643.7.1.1.3.2            |
| `gost12-512`  | `gost3410-2012-512`   | 1.2.643.7.1.1.3.3            |
| `sha256`      | `ecdsa`               | 1.2.840.10045.4.3.2          |
| `sha384`      | `ecdsa`               | 1.2.840.10045.4.3.3          |
| `sha512`      | `ecdsa`               | 1.2.840.10045.4.3.4          |
| `sha256`      | `rsa`                 | 1.2.840.113549.1.1.11        |
| `sha384`      | `rsa`                 | 1.2.840.113549.1.1.12        |
| `sha512`      | `rsa`                 | 1.2.840.113549.1.1.13        |

When `--key-algorithm` is omitted, GOST digests default to `gost3410-2012-256`/`gost3410-2012-512` and SHA-2 digests default to `ecdsa`. Rutoken/GOST support is preserved through the generic PKCS#11 path; Rutoken USB identifiers are not hard-coded into the universal CCID dry-run output.

## Electronic signature classes (eIDAS ↔ Russian)

The signature a token can produce maps onto the eIDAS trust tiers as follows. "Cert" is the certificate class; "Device" is whether the signing key lives on a certified secure-signature-creation device (QSCD / сертифицированное СКЗИ).

| Tier | Cert | Device | Russian | Note |
|------|------|--------|---------|------|
| SES | — | — | ПЭП / PEP | Simple e-signature (password, SMS OTP, scan); no cryptographic binding. |
| AES (AdES) | any | any | УНЭП / UNEP | Advanced: uniquely linked, identifies signatory, sole control, tamper-evident. |
| AdES-QC | qualified | not certified | (no exact RU tier) | Advanced signature backed by a qualified certificate, but key not on a QSCD. |
| QES | qualified | QSCD (certified) | УКЭП / UKEP, КЭП / KEP | Qualified: AES + qualified certificate + certified device. Legally equal to a handwritten signature. |

`УКЭП` (усиленная квалифицированная ЭП) and `КЭП` (квалифицированная ЭП) are the same top tier — `КЭП` is just the short form that drops *усиленная*. There is no "non-advanced" qualified tier: QES is defined as AES plus a qualified certificate plus a QSCD, so every QES is necessarily advanced.

Russian law (63-ФЗ) defines only three legal types — `ПЭП`, `УНЭП`, and `УКЭП` — so `КЭП` is **not** a separate tier. It is colloquial shorthand for `УКЭП`: because every qualified signature is automatically advanced (*усиленная*), the «У» is redundant and routinely dropped. Both therefore map to the **same** English term, **QES**; English has no word that distinguishes them because there is nothing to distinguish. The only thing that varies is the literal transliteration:

| Russian | Literal English | Legal tier |
|---------|-----------------|------------|
| КЭП     | "Qualified ES"          | QES |
| УКЭП    | "Advanced Qualified ES" | QES |

The tested Rutoken ECP holds a qualified certificate and is itself an ФСБ-certified СКЗИ (QSCD), so the signatures it produces are **QES / УКЭП**, which is why ESIA/Gosuslugi accepts it for `dsLoginAllowed` e-signature login.

## Current status

- The OpenSSL command execution path has been removed.
- All hashing is implemented in Rust: `ГОСТ Р 34.11-2012` through `streebog`, SHA-256/384/512 through `sha2`.
- CMS construction and PKCS#11 signing are wired into the non-dry-run path: the CLI hashes the input, opens a token session with `cryptoki`, signs with the token's chosen mechanism (`CKM_GOSTR3410`, `CKM_ECDSA`, or `CKM_RSA_PKCS`), builds CMS `SignedData`, and writes DER `.p7s` output.
- Direct USB/CCID signing is implemented for Rutoken ECP 3.0:
  - `ccid::CcidDevice` discovers the Rutoken ECP by VID/PID (`0x0a89`/`0x0030`), claims the CCID interface (bInterfaceClass `0x0B`), and communicates via USB bulk transfer.
  - `ccid::IccPowerOn` / `ccid::RdrDataBlock` encode/decode the CCID `PC_to_RDR_IccPowerOn` and `RDR_to_PC_DataBlock` messages.
  - `rutoken::RutokenUri` parses `rutoken:slot=N;id=%XX` key URIs used with `--transport ccid`.
  - The ISO 7816-8 APDU sequence (SELECT MF → VERIFY user PIN ref 2 → SELECT private-key file → MSE SET → PSO COMPUTE DIGITAL SIGNATURE) is implemented in the `rutoken` module against OpenSC's `card-rtecp.c`, `pkcs15-rtecp.c`, and `rutoken_ecp.profile` as references.
  - Hardware raw signing was verified on the connected Osnovanie/Rutoken ECP token with `rutoken:slot=0;id=%03`, producing a 64-byte signature at `target/rutoken-readme.sig`.
  - Hardware-in-the-loop testing requires a physical Rutoken ECP 3.0 device and appropriate USB access permissions.
