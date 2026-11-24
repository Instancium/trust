# Security Policy

## Supported Versions

`Instancium.Trust` currently follows a rolling release model under **Experimental Mode (Pre-2.0)**. Security fixes are applied to the latest release and the current `main` branch.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| Current `main` branch | ✅ |
| Older releases | ❌ |

## Reporting a Vulnerability

We take the security of `Instancium.Trust` seriously. If you discover a cryptographic, validation, or implementation vulnerability, please report it **responsibly**.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report via one of the following channels:

1. **GitHub Private Vulnerability Reporting** (Preferred): Use [GitHub Security Advisories](https://github.com/Instancium/trust/security/advisories/new) to submit a confidential report.
2. **Direct Email**: Send details to **support@instancium.com** with the subject line `[SECURITY] Instancium.Trust - <brief description>`.

### What to Include

To help us triage and fix the issue quickly, please provide:
- A clear description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept (PoC).
- The affected component (e.g., `TrustVerificationEngine`, `KeyContainerProtector`, `Ed25519SignatureAlgorithm`, `KeyCeremonyService`, `VerifyCommand`).
- Suggested fix or mitigation, if available.

### Response Timeline

We commit to the following Service Level Agreement (SLA) for security reports:

| Stage | Timeframe |
| --- | --- |
| Initial acknowledgment | 3 business days |
| Preliminary assessment & triage | 7 business days |
| Fix development & patch release | 14–30 business days (severity dependent) |
| Public disclosure (coordinated) | After the patch is released and users have had time to update |

## Scope

The following components are **in scope** for vulnerability reporting:

- **Signature & Algorithm Layer** (`src/Instancium.Trust/Algorithms`): Ed25519 verification bypasses, key derivation flaws, algorithm confusion in `SignatureAlgorithmRegistry`.
- **Key Container Protection** (`src/Instancium.Trust/Keys`): Argon2id parameter validation/DoS caps, AES-256-GCM AAD binding, ciphertext/parameter tampering, and private key memory hygiene in `KeyContainerProtector` and `KeyContainerCodec`.
- **Trust Chain & Anti-Rollback Engine** (`src/Instancium.Trust/Verification`, `Certificates`, `Manifests`): Certificate signature/validity bypasses, `kid`/`alg` mismatch handling, anti-rollback bypasses, and artifact size/hash verification in `TrustVerificationEngine`.
- **Key Ceremony Orchestration** (`src/Instancium.Trust/Ceremony`): Plaintext secret leakage into public outputs (`*.pub`, `TrustConstants.g.cs`, `dns-trust-record.txt`) or fingerprint inconsistencies.
- **CLI Tool** (`src/Instancium.Trust.Cli`): Path traversal in `VerifyCommand`, password/secret leakage, and malformed input handling.

### Out of Scope

- Vulnerabilities in upstream third-party dependencies (e.g., `BouncyCastle.Cryptography`, .NET runtime). Please report these directly to the upstream maintainers; we track and update dependencies promptly.
- Compromise of an offline cold root key due to physical theft or operator error.
- Malware already executing with user or administrator privileges on the verification machine.
- Missing or misconfigured DNSSEC on external DNS infrastructure.
- Key revocation, threshold signatures, and transparency logs (explicitly deferred from the current threat model).
- Speculative or theoretical attacks without a working, reproducible proof-of-concept.

## Security Architecture

`Instancium.Trust` enforces defense-in-depth invariants directly in code:

- **Assumed Breach & Out-of-Band Anchoring**: Root public key fingerprints are distributed independently via compiled constants (`TrustConstants.g.cs`), GitHub (`Instancium/hub`), and DNS TXT (`_trust.instancium.com`).
- **No JSON Canonicalization**: Signatures cover exact serialized bytes, eliminating cross-runtime canonicalization mismatches.
- **No Secret-Prefix Hashing**: `SHA-256` is used strictly for public unkeyed fingerprints and artifact pinning; authenticity comes exclusively from Ed25519 and AES-256-GCM.
- **AAD-Authenticated KDF Parameters**: Argon2id parameters (`m`, `t`, `p`, `salt`, `nonce`) are authenticated as AES-256-GCM AAD, preventing silent KDF downgrade attacks, while hard safety caps block resource-exhaustion containers before derivation runs.
- **Fail-Fast & Confinement**: Unknown algorithms fail immediately (`unknown-algorithm`); artifact verification checks declared size before hashing; CLI verification confines artifact paths inside `--artifacts-dir`.

## Disclosure Policy

We follow [Coordinated Vulnerability Disclosure (CVD)](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We ask that you:
- Give us reasonable time to fix the issue before disclosing it publicly.
- Avoid exploiting the vulnerability beyond what is strictly necessary to demonstrate it.
- Respect user privacy and data — do not exfiltrate, modify, or destroy data during testing.

We commit to:
- Not taking legal action against researchers who follow this policy in good faith.
- Acknowledging your contribution in the release notes (unless you prefer to remain anonymous).
- Working with you to verify the fix before any public disclosure.

---

Thank you for helping keep `Instancium.Trust` and its users safe.