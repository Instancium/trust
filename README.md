# Instancium.Trust

[![NuGet](https://img.shields.io/nuget/v/Instancium.Trust.svg)](https://www.nuget.org/packages/Instancium.Trust)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/Instancium/trust/blob/main/LICENSE.txt)

Crypto-agile trust library and offline key ceremony CLI for the Instancium ecosystem.

> [!WARNING]
> **Experimental Mode (Pre-2.0):** Until the Instancium ecosystem reaches release `2.0`, public APIs, container/manifest formats, trust anchors, and signing keys may change without backward compatibility or migration support. Do not pin pre-2.0 formats or keys for long-term production verification.

**Solution file:** `Instancium.Trust.slnx` (3 projects: `Instancium.Trust`, `Instancium.Trust.Cli`, `Instancium.Trust.Tests`).
**Public trust hub:** [https://github.com/Instancium/hub](https://github.com/Instancium/hub)


## 1. Why this repository exists

`Instancium.Trust` is a foundational component of the Instancium R&D Lab technology platform and the core implementation of its **Cryptography & Digital Trust** area (defined in the Instancium Doctrine: *Architecture of Digital Autonomy*).

It provides the cryptographic trust layer for **commercial SLA build signing**, **sovereign self-hosted nodes**, and **decentralized autonomous networks** operating without external Certificate Authorities or single points of control.

At the engineering level, the library moves trust from distribution channels and intermediaries to verifiable mathematics:

* **Verifiable SLA build delivery (Assumed Breach):** HTTPS protects transport, not build artifacts or state. A compromised repository, CI runner, or mirror can still serve tampered binaries over a valid connection. `Instancium.Trust` guarantees build authenticity and integrity through detached signatures, scoped release certificates with bounded validity windows, anti-rollback enforcement, and out-of-band root fingerprint anchoring.
* **Sovereign key lifecycle:** Offline ceremonies and memory-hard encrypted key containers (`Argon2id` + `AES-256-GCM`) support isolated key management, backup, and recovery without external cloud dependencies.
* **Long-term crypto-agility:** Algorithm identifiers are persisted as data across all contracts, preparing SLA pipelines and autonomous nodes for post-quantum cryptography (`ml-dsa-65` and hybrid schemes) without breaking existing verification chains.

---

## 2. Repository layout

```text
+-- src/
|   +-- Instancium.Trust/                     # net10.0 - BouncyCastle.Cryptography 2.7.0 (sole package)
|   |   +-- Algorithms/                       # ISignatureAlgorithm, SignatureAlgorithmRegistry, Ed25519
|   |   +-- Ceremony/                         # KeyCeremonyService, TrustConstantsExporter, DnsTxtRecordBuilder
|   |   +-- Certificates/                     # SignedEnvelope, ReleaseKeyCertificate
|   |   +-- Hashing/                          # Sha256Hex
|   |   +-- Keys/                             # TrustKeyPair, KeyContainerProtector, KeyContainerCodec, RootPublicKeyDocument
|   |   +-- Manifests/                        # ReleaseManifest, ManifestArtifact, ManifestSigner, DetachedSignature
|   |   +-- Serialization/                    # TrustJson, Base64Url
|   |   +-- Verification/                     # TrustVerificationEngine, TrustAnchor, AntiRollbackState, VerificationResult
|   |   +-- TrustFormat.cs                    # On-disk format version ("inst1")
|   +-- Instancium.Trust.Cli/                 # net10.0 - offline ceremony & verification CLI, zero third-party packages
+-- tests/
|   +-- Instancium.Trust.Tests/               # xUnit, 36 tests, real cryptography
+-- Instancium.Trust.slnx
+-- LICENSE.txt
+-- SECURITY.md
```

---

## 3. Cryptographic foundation

`Instancium.Trust` is built on [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) (`2.7.0`) as its sole third-party dependency, combined with .NET BCL primitives.

| Primitive | Provider | Reference | Location |
| :--- | :--- | :--- | :--- |
| Ed25519 (EdDSA) key generation, signing, verification | **BouncyCastle** (`Ed25519Signer`, `Ed25519PrivateKeyParameters`, `Ed25519PublicKeyParameters`) | RFC 8032 | `Algorithms/Ed25519SignatureAlgorithm.cs` |
| Argon2id key derivation | **BouncyCastle** (`Argon2BytesGenerator`, `Argon2Parameters`) | RFC 9106 | `Keys/KeyContainerProtector.cs` |
| AES-256-GCM authenticated encryption | .NET BCL `AesGcm` | NIST SP 800-38D, RFC 5116 | `Keys/KeyContainerProtector.cs` |
| SHA-256 fingerprints and artifact hashes | .NET BCL `SHA256` | FIPS 180-4 | `Hashing/Sha256Hex.cs` |
| CSPRNG | .NET BCL `RandomNumberGenerator` | NIST SP 800-90A | Key generation, salt, nonce |

Why this split:

* **Pure managed C#:** 100% independent of system OpenSSL; deterministic across Windows, Linux, and macOS.
* **RFC-exact Ed25519:** Raw 32-byte keys and 64-byte signatures are byte-compatible with browser WebCrypto verification.
* **Memory-hard KDF:** Argon2id protects offline and working private key containers without native bindings.
* **PQC readiness:** ML-DSA (`ml-dsa-65`) and hybrid algorithms can be registered via the same library without adding another crypto dependency.
* **BCL AEAD & SHA-256:** Hardware-accelerated and zero extra package weight.

---

## 4. Architecture & contracts

### 4.1 Crypto-agility

The algorithm identifier (`alg`) is persisted as data in `ReleaseKeyCertificate`, `ReleaseManifest`, `SignedEnvelope`, and DNS TXT records. Algorithms are resolved through `SignatureAlgorithmRegistry`; unknown identifiers fail fast with `unknown-algorithm` instead of silently falling back.

```csharp
public interface ISignatureAlgorithm
{
    string AlgId { get; }
    TrustKeyPair GenerateKeyPair();
    byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey);
    byte[] Sign(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> privateKey);
    bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey);
}
```

Reserved identifiers for post-quantum migration: `ml-dsa-65` (FIPS 204) and `ed25519+ml-dsa-65`.

### 4.2 Trust chain

```text
Trust anchor (compiled TrustConstants.g.cs / GitHub *.pub / DNS TXT)
        |  verify root signature over exact certificate payload bytes
        v
release-key.cert   -> validity window, kid binding, alg binding
        |  verify release key signature over exact manifest bytes
        v
manifest.json      -> version, issuedAt, anti-rollback state
        |  compare declared size first, then SHA-256 of the full artifact
        v
artifact (installer / PDF / driver / model weights)
```

Every failure returns a machine-readable code from `VerificationFailureCodes` (`unknown-algorithm`, `malformed-certificate`, `certificate-signature-invalid`, `unknown-root-key`, `algorithm-mismatch`, `certificate-not-yet-valid`, `certificate-expired`, `malformed-manifest`, `kid-mismatch`, `manifest-signature-invalid`, `rollback-detected`, `artifact-size-mismatch`, `artifact-hash-mismatch`).

### 4.3 Artifact formats

* **Signed envelope (`release-key.cert`):** `inst1.<alg>.<base64url(payloadJson)>.<base64url(signature)>`
* **Detached signature (`*.sig`):** plain Base64 of the raw signature over exact manifest bytes.
* **Manifest (`manifest.json`, `doctrine.manifest.json`):** unified `ReleaseManifest` schema (`v: 1`) pinning `alg`, `kid`, `product`, `version`, `issuedAt`, and `artifacts[]` (`path`, `sha256`, `size`).
* **No JSON canonicalization:** signatures always cover exact serialized bytes, preventing C#-to-JavaScript canonicalization divergence.
* **Fingerprint rule:** lowercase-hex `SHA-256` over raw public key bytes.

### 4.4 Encrypted key container

Private keys are stored in Argon2id + AES-256-GCM JSON containers (`KeyContainerProtector`, `KeyContainerCodec`):

| Parameter | Default | Notes |
| :--- | :--- | :--- |
| KDF | `argon2id` (v1.3) | RFC 9106 |
| Memory | `65536` KiB (64 MiB) | Configurable via `KeyContainerOptions` |
| Iterations | `3` | Configurable |
| Parallelism | `4` | Configurable |
| Salt / Nonce / Tag | `16` / `12` / `16` bytes | CSPRNG salt and nonce |
| AAD | `inst1\|argon2id\|m\|t\|p\|salt\|nonce` | Parameter downgrade breaks the GCM tag |

Hostile KDF parameters above safety caps (`1 GiB` RAM, `100` iterations, `64` lanes) are rejected before derivation. Only `alg` and the private key are encrypted; the public key is re-derived on load. Derived keys, password buffers, and ceremony private keys are wiped with `CryptographicOperations.ZeroMemory`.

### 4.5 Anti-rollback

`TrustVerificationEngine` is stateless; the host client supplies `AntiRollbackState(Version, IssuedAt, ManifestSha256)`. The engine rejects manifests with an older `IssuedAt` or the same `Version` carrying a different manifest hash.

---

## 5. Build and test

Requires **.NET 10 SDK**.

```bash
dotnet restore Instancium.Trust.slnx
dotnet build   Instancium.Trust.slnx
dotnet test    tests/Instancium.Trust.Tests/Instancium.Trust.Tests.csproj
```

`Instancium.Trust.Tests` contains **36 tests** using real cryptography: Ed25519 (7, including the 50 ms sign+verify budget), encrypted key containers (6, including production KDF profile and AAD downgrade detection), verification chain & anti-rollback (20), and end-to-end key ceremony (3).

---

## 6. CLI usage (`Instancium.Trust.Cli`)

### Offline key ceremony

Run on an isolated offline machine. Passwords are read interactively with masking and confirmation; they never enter `argv`, shell history, or config files.

```bash
dotnet run --project src/Instancium.Trust.Cli -- ceremony \
  --out ./ceremony-out \
  [--alg ed25519] \
  [--primary-kid root-primary-2026] \
  [--backup-kid root-backup-2026] \
  [--release-kid release-2026-11] \
  [--validity-days 365]
```

Generated artifacts:
* **Publish:** `root-primary.pub`, `root-backup.pub`, `release-key.cert` (to `Instancium/hub/keys`), `TrustConstants.g.cs` (compiled into clients), `dns-trust-record.txt` (to `_trust.instancium.com` TXT with DNSSEC).
* **Keep secret:** `root-primary.key.json` and `root-backup.key.json` (offline media only), `release-key.key.json` (protected release machine storage).

### Verification

```bash
dotnet run --project src/Instancium.Trust.Cli -- verify \
  --manifest manifest.json \
  --sig manifest.sig \
  --cert release-key.cert \
  --root root-primary.pub \
  --root root-backup.pub \
  [--artifacts-dir ./assets]
```

Exit codes: `0` (valid), `1` (verification failure or I/O/crypto error), `2` (usage error). Artifact paths are confined to `--artifacts-dir` to prevent path traversal.

---

## 7. Security

For vulnerability reporting, SLA, scope, and coordinated disclosure, see [SECURITY.md](SECURITY.md).

---

## 8. Roadmap

* **Completed:** Crypto-agile `ISignatureAlgorithm` + `Ed25519`, Argon2id + AES-256-GCM containers, offline `KeyCeremonyService`, `TrustVerificationEngine` with anti-rollback and size-before-hash checks, `Instancium.Trust.Cli`, 36 unit tests.
* **Planned:**
  * Streaming SHA-256 verification for artifacts exceeding 2 GB (drivers and `.gguf` weights).
  * Post-quantum signatures (`ml-dsa-65` and hybrid `ed25519+ml-dsa-65`).
  * Browser WebCrypto cross-validation client for official documents in `Instancium/hub/docs`.

---

## 9. License

Licensed under the **Apache License 2.0**. See [LICENSE.txt](LICENSE.txt) for details.