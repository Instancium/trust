# Instancium.Publisher

Repository-wide release orchestration and cryptographic trust infrastructure for the Instancium ecosystem.

The solution contains two subsystems that share one engineering standard:

| Subsystem | Purpose |
| :--- | :--- |
| **Instancium.Publisher** | Multi-ecosystem release orchestrator: repository-wide versioning, AI-generated Conventional Commits and changelogs, Git/GitHub publication, journaled pipeline with crash recovery, Spectre.Console TUI. |
| **Instancium.Trust** | Crypto-agile trust library and offline key ceremony CLI: Ed25519 signing, Argon2id-encrypted key containers, certificate/manifest chain verification, anti-rollback. Built on **BouncyCastle.Cryptography**. |

**Repository version:** `1.7.2` — every project is aligned to the highest declared version by `RepositoryVersionPolicy`.
**Solution file:** `Instancium.Publisher.slnx` (8 projects: 6 `src`, 2 `tests`).

---

## 1. Why this repository exists

Two distinct failure modes are addressed:

1. **Release engineering drift.** Per-project version bumps, hand-written changelogs, interrupted releases leaving broken branches, and cross-branch tag anchoring produce inconsistent releases. `Instancium.Publisher` makes the *repository* the unit of release and journals every mutation so an interrupted pipeline is resumable or destructively reversible.
2. **Supply chain compromise.** HTTPS protects the transport, not the artifact. A compromised GitHub account, CI runner or build machine serves malware over a perfectly valid URL. `Instancium.Trust` moves trust from the channel to mathematics: detached signatures, a cold-root certificate chain, and out-of-band fingerprint publication under the **Assumed Breach** principle.

---

## 2. Repository layout

```text
+-- src/
|   +-- Instancium.Publisher.Domain/          # net8.0;net10.0 - pure domain, zero dependencies
|   |   +-- Versioning/                       # SemanticVersion, RepositoryVersionPolicy, 9 bump strategies
|   |   +-- Runtime/                          # RuntimeEnvironmentInfo
|   |   +-- Exceptions/                       # ProjectFileParseException
|   +-- Instancium.Publisher.Application/     # net8.0;net10.0 - abstractions, workflows, pipeline
|   |   +-- Abstractions/                     # 12 extension-point interfaces
|   |   +-- Pipeline/Steps/                   # BumpVersionStep, MergeAndPublishStep
|   |   +-- Versioning/                       # RepositoryVersionService, VersionBumpService
|   |   +-- Workflows/                        # CommitWorkflow, ReleaseWorkflow, ReleaseRecoveryService
|   +-- Instancium.Publisher.Infrastructure/  # net10.0 - adapters: Git, GitHub, AI, state, ecosystems
|   |   +-- Ai/                               # chunker, prompt builders, diff optimizer, SDK assistant
|   |   +-- Git/ GitHub/ Runtime/ State/      # process boundary, publication, journaling
|   |   +-- Versioning/DotNet/                # MsBuildProjectEcosystem, RepositoryProjectScanner
|   +-- Instancium.Publisher.Tui/             # net10.0 - Spectre.Console host (AssemblyName: Instancium.Publisher)
|   |   +-- Tui/Workspaces/                   # CommitWorkspace, ReleaseWorkspace
|   |   +-- Tui/Components/                   # markdown renderer, breadcrumbs, menu formatter
|   +-- Instancium.Trust/                     # net10.0 - BouncyCastle.Cryptography 2.7.0 (sole package)
|   |   +-- Algorithms/ Keys/ Certificates/
|   |   +-- Manifests/ Verification/ Ceremony/
|   |   +-- Hashing/ Serialization/
|   +-- Instancium.Trust.Cli/                 # net10.0 - offline ceremony + verification, zero packages
+-- tests/
|   +-- Instancium.Publisher.Tests/           # xUnit + Moq, architecture guard tests
|   +-- Instancium.Trust.Tests/               # xUnit, 36 tests, real cryptography
+-- Instancium.Publisher.slnx
+-- LICENSE.txt
```

---

## 3. Technology stack

| Layer | Technology | Why this choice |
| :--- | :--- | :--- |
| Runtime | .NET 10 (`net10.0`); Domain/Application multi-target `net8.0;net10.0` | Downstream consumers on .NET 8 can reuse the domain and application contracts; adapters stay on the current runtime. |
| Cryptography | **BouncyCastle.Cryptography 2.7.0** + `System.Security.Cryptography` (BCL) | Pure managed code, no system OpenSSL dependency, deterministic behaviour across Windows/Linux/macOS. |
| DI / configuration | `Microsoft.Extensions.DependencyInjection`, `.Configuration`, `.Hosting`, `.Options` | Standard composition root; strongly typed settings bound from `appsettings.json` with environment-variable override. |
| AI transport | `InstantAIGate.Client` over ASP.NET Core SignalR | Session lifecycle, KV-cache checkpointing and Map-Reduce recovery are delegated to the SDK; the publisher owns only domain orchestration. |
| TUI | `Spectre.Console` | Live streaming renderables, selection prompts, tables and panels without a custom terminal layer. |
| External tools | `git`, `gh` (GitHub CLI) | Invoked through `ProcessStartInfo.ArgumentList` — no shell interpolation, no injection surface. |
| Testing | xUnit, Moq, real-filesystem fixtures | Behaviour is asserted at architectural boundaries, not only at happy paths. |
| Serialization | `System.Text.Json`, `System.Xml.Linq` | Manifests/certificates are JSON; MSBuild manifests are XML edited in place, preserving structure. |

### Package management

- `Instancium.Publisher.*` projects use central package management as provided by the repository.
- `Instancium.Trust`, `Instancium.Trust.Cli`, `Instancium.Trust.Tests` are **self-contained**: `Version` and package versions are declared directly in the `.csproj`, with `ImportDirectoryBuildProps=false` and `ManagePackageVersionsCentrally=false`. They build identically regardless of repository-level props files.

---

## 4. Cryptographic foundation: BouncyCastle.Cryptography

**`Instancium.Trust` is built on the [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) library, pinned to version `2.7.0`. It is the only third-party dependency of the trust library.**

| Primitive | Provider | Reference | Where |
| :--- | :--- | :--- | :--- |
| Ed25519 (EdDSA) key generation, signing, verification | **BouncyCastle** (`Ed25519Signer`, `Ed25519PrivateKeyParameters`, `Ed25519PublicKeyParameters`) | RFC 8032 | `Algorithms/Ed25519SignatureAlgorithm.cs` |
| Argon2id key derivation | **BouncyCastle** (`Argon2BytesGenerator`, `Argon2Parameters`) | RFC 9106 | `Keys/KeyContainerProtector.cs` |
| AES-256-GCM authenticated encryption | .NET BCL `AesGcm` | NIST SP 800-38D, RFC 5116 | `Keys/KeyContainerProtector.cs` |
| SHA-256 fingerprints and artifact hashes | .NET BCL `SHA256` | FIPS 180-4 | `Hashing/Sha256Hex.cs` |
| CSPRNG | .NET BCL `RandomNumberGenerator` | NIST SP 800-90A | key generation, salt, nonce |

Why BouncyCastle for the asymmetric and password-hardening primitives:

- **Pure managed C#.** No P/Invoke, no system OpenSSL, no native runtime mismatch across platforms — a stated measurable of the trust plan (100% independence from system OpenSSL).
- **RFC-exact Ed25519.** Raw 32-byte keys and 64-byte signatures are byte-compatible with browser WebCrypto, which is required for the one-click verification client on `instancium.com/doctrine`.
- **Argon2id availability.** The BCL provides no Argon2 implementation; BouncyCastle supplies a maintained, memory-hard KDF (BLAKE2b based).
- **Algorithm breadth for the PQC migration.** ML-DSA (`ml-dsa-65`) and hybrid signatures can be added from the same library without introducing a second cryptographic dependency.

AES-256-GCM and SHA-256 intentionally use the BCL: they are hardware-accelerated, FIPS-validated on supported platforms, and add no package weight. This keeps the sign/verify budget within the required 50 ms.

---

## 5. Instancium.Trust

### 5.1 Module map

| Module | Responsibility |
| :--- | :--- |
| `Algorithms` | `ISignatureAlgorithm`, `SignatureAlgorithmRegistry`, `Ed25519SignatureAlgorithm`, `KnownSignatureAlgorithms` |
| `Keys` | `TrustKeyPair`, `PublicKeyFingerprint`, `KeyContainerOptions`, `KeyContainerProtector`, `KeyContainerCodec`, `KeyContainerException`, `RootPublicKeyDocument` |
| `Certificates` | `SignedEnvelope`, `ReleaseKeyCertificate` |
| `Manifests` | `ReleaseManifest`, `ManifestArtifact`, `ManifestSigner`, `DetachedSignature` |
| `Verification` | `TrustVerificationEngine`, `TrustAnchor`, `AntiRollbackState`, `VerificationResult`, `VerificationFailureCodes` |
| `Ceremony` | `KeyCeremonyService`, `KeyCeremonyOptions`, `KeyCeremonyResult`, `TrustConstantsExporter`, `DnsTxtRecordBuilder` |
| `Hashing` / `Serialization` | `Sha256Hex`, `TrustJson`, `Base64Url` |

### 5.2 Crypto-agility

The algorithm identifier is **data, not code**. `alg` is persisted in `ReleaseKeyCertificate`, `ReleaseManifest`, the signed envelope header and the DNS TXT record. New algorithms are registered as components; the verification engine is never modified.

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

Reserved identifiers for the post-quantum migration: `ml-dsa-65` (FIPS 204) and the hybrid `ed25519+ml-dsa-65`. Unknown identifiers fail fast with `unknown-algorithm` instead of silently falling back.

### 5.3 Trust chain

```text
Trust anchor (compiled constant / GitHub *.pub / DNS-verified fingerprint)
        |  verify root signature over exact certificate payload bytes
        v
release-key.cert   -> validity window, kid binding, alg binding
        |  verify release key signature over exact manifest bytes
        v
manifest.json      -> version, issuedAt, anti-rollback state
        |  compare declared size, then SHA-256 of the full artifact
        v
artifact (exe / pdf / driver / model weights)
```

Every rejection returns the exact broken link, so operators distinguish an attack from an expired certificate or a corrupted download.

### 5.4 Artifact formats

**Signed envelope (single file, `release-key.cert`):**

```text
inst1.<alg>.<base64url(payloadJson)>.<base64url(signature)>
```

**Detached signature (`manifest.sig`, `doctrine.sig`):** plain base64 of the raw signature over the exact file bytes.

**Manifest (`manifest.json`, `doctrine.manifest.json` — one contract for both):**

```json
{
  "v": 1,
  "alg": "ed25519",
  "kid": "release-2026-11",
  "product": "Instancium",
  "version": "1.8.0",
  "issuedAt": "2026-11-24T12:00:00+00:00",
  "artifacts": [
    { "path": "InstanciumSetup.exe", "sha256": "<64-hex>", "size": 12345678 }
  ]
}
```

**Design invariant — no canonicalization.** Signatures always cover the exact serialized bytes. JSON canonicalization (RFC 8785) is deliberately not used: it removes an entire class of C#-to-JavaScript divergence bugs instead of merely handling them.

**Fingerprint rule.** `SHA-256` over the raw public key bytes, lowercase hex. One rule anchors DNS, `README`, `*.pub` files and compiled constants to the same string.

### 5.5 Encrypted key container

Argon2id derives a 256-bit key; AES-256-GCM authenticates both the ciphertext and the KDF parameters through AAD.

| Parameter | Default | Notes |
| :--- | :--- | :--- |
| KDF | `argon2id` (version 1.3) | RFC 9106 |
| Memory | 65536 KiB (64 MiB) | RFC 9106 secondary recommendation |
| Iterations | 3 | configurable via `KeyContainerOptions` |
| Parallelism | 4 | configurable |
| Salt | 16 bytes | CSPRNG |
| Nonce / tag | 12 / 16 bytes | AES-256-GCM |
| AAD | `inst1\|argon2id\|m\|t\|p\|salt\|nonce` | parameter downgrade breaks the tag |

Safety guards reject hostile containers before the KDF runs: memory above 1 GiB, iterations above 100 or parallelism above 64 are refused. Derived keys and UTF-8 password buffers are wiped with `CryptographicOperations.ZeroMemory`; ceremony private keys are wiped in a `finally` block.

Only `alg` and the private key are encrypted. The public key is re-derived on load, so a stored public-key copy can never diverge from the private key.

### 5.6 Anti-rollback

The engine is **stateless**. The host application supplies the last accepted state; persistence belongs to the client (installer, CLI).

```csharp
public sealed record AntiRollbackState(string Version, DateTimeOffset IssuedAt, string ManifestSha256);
```

Rules:

1. `manifest.IssuedAt` older than the accepted timestamp -> `rollback-detected`.
2. Same `Version` with a different manifest hash -> `rollback-detected` (same-version substitution).

A cryptographically valid *old* release is still an attack vector: it contains known vulnerabilities. Monotonic state is the only defense.

### 5.7 Verification failure codes

| Code | Meaning |
| :--- | :--- |
| `unknown-algorithm` | Envelope or manifest declares an unregistered `alg`. |
| `malformed-certificate` | Certificate payload is not decodable or internally inconsistent. |
| `certificate-signature-invalid` | Root signature over the certificate payload failed. |
| `unknown-root-key` | No trust anchor matches `rootKid`. |
| `algorithm-mismatch` | Anchor, certificate and manifest algorithms disagree. |
| `certificate-not-yet-valid` | Validity window has not started. |
| `certificate-expired` | Validity window has ended. |
| `malformed-manifest` | Manifest schema version or fields are invalid. |
| `kid-mismatch` | Manifest key id differs from the certified release key. |
| `manifest-signature-invalid` | Release key signature over the manifest bytes failed. |
| `rollback-detected` | Anti-rollback rule violated. |
| `artifact-size-mismatch` | Artifact length differs from the declared size. |
| `artifact-hash-mismatch` | Artifact SHA-256 differs from the declared hash. |

Artifact verification order is **size first, then hash**. Size drift is rejected before paying a full SHA-256 pass over multi-gigabyte assets; equal-length substitution still falls through to the hash check, so the integrity guarantee is never weakened.

### 5.8 Security invariants

- **SHA-256 is never a MAC.** No `SHA256(secret || message)` construction exists anywhere. Hashes are public, unkeyed integrity fingerprints; authenticity comes exclusively from Ed25519. This removes length-extension attacks by construction rather than by mitigation.
- **Keyed integrity, when needed, uses AEAD or HMAC.** The key container uses AES-256-GCM (GHASH, not Merkle-Damgard). Any future authenticated local state must use HMAC/AEAD/DPAPI, never a secret-prefix hash.
- **No resumable hash state is exposed.** All hashing is one-shot, so there is no continuation surface.
- **Zero private keys in public output.** The ceremony result contains only public documents; private keys exist solely inside encrypted container files.

### 5.9 Key ceremony output

```text
root-primary.pub          # public root document (kid, alg, publicKey, sha256)
root-backup.pub           # backup root document
release-key.cert          # signed envelope: release key certified by the primary root
TrustConstants.g.cs       # compiled anchors, namespace Instancium.Trust.Generated
dns-trust-record.txt      # ready-to-paste TXT value
root-primary.key.json     # encrypted container - offline media only
root-backup.key.json      # encrypted container - offline media only
release-key.key.json      # encrypted container - working key
```

DNS TXT record layout at `_trust.instancium.com`:

```text
v=inst1; alg=ed25519; primary_kid=root-primary-2026; primary_sha256=<64-hex>; backup_kid=root-backup-2026; backup_sha256=<64-hex>
```

---

## 6. Instancium.Publisher

### 6.1 Layering

| Project | Depends on | Rule |
| :--- | :--- | :--- |
| `Domain` | nothing | Pure value objects and policies; no I/O, no framework. |
| `Application` | `Domain` | Abstractions + orchestration; never references infrastructure or `Instancium.Trust`. |
| `Infrastructure` | `Application`, `Domain` | All process, filesystem, network and AI adapters. |
| `Tui` | all three | Composition root and presentation only. |

**Constraint for future work:** `Application` multi-targets `net8.0;net10.0` while `Instancium.Trust` targets `net10.0` only. Signing abstractions introduced in `Application` must therefore be byte-oriented and Trust-free; the Trust adapter lives in `Infrastructure`.

### 6.2 Repository-wide versioning

`RepositoryVersionPolicy` defines the rules:

- The repository version is the **highest** version declared among its projects.
- No declared version anywhere -> initial baseline `1.0.0`.
- Every project is realigned to the resolved version on release; divergent projects are counted and surfaced in the TUI.

`SemanticVersion` is an immutable SemVer 2.0 value object with a source-generated parser regex and full precedence ordering (including pre-release rules).

Bump strategies are a Strategy + registry catalog (`IVersionBumpStrategy`, `VersionBumpService`):

| Id | Behaviour |
| :--- | :--- |
| `patch` | Increment patch; finalize a pre-release to its stable version. |
| `minor` / `major` | Increment component, reset lower components. |
| `pre-release-iteration` | Increment iteration, or start a patch pre-release from stable. |
| `new-pre-release-patch` / `-minor` / `-major` | Start a new pre-release line. |
| `promote-to-release` | Strip the pre-release label without incrementing. |
| `custom` | Explicit user-supplied SemVer 2.0 string. |

Ecosystems are pluggable through `IProjectEcosystem` (manifest patterns, excluded directories, read/write version). `MsBuildProjectEcosystem` is the current implementation; `RepositoryProjectScanner` discovers manifests recursively in deterministic order.

### 6.3 Journaled pipeline

`PipelineContext` is checkpointed through `IPipelineStateManager` **before** any file mutation, which makes steps idempotent on resume.

| Step | Guarantee |
| :--- | :--- |
| `BumpVersionStep` | The planned version is journaled first; a resumed run re-applies writes without re-bumping. |
| `MergeAndPublishStep` | Fast-forward-first merge; forced merge only on divergence; tag, push, then backport the target branch into the source branch so release tags stay reachable. |
| `ReleaseRecoveryService` | Destructive rollback: restore tree, return to source branch, delete local and remote release branches, clear the journal. |

State is stored outside the working tree, isolated per repository:
`%TEMP%/Instancium.Publisher/pipeline_state_<16-hex-of-repo-path>.json`.

The TUI recovery dispatcher offers **Resume / Rollback / Start Fresh** when an interrupted release is detected.

### 6.4 Git and process boundary

| Guarantee | Implementation |
| :--- | :--- |
| No shell injection | `ProcessStartInfo.ArgumentList`, never a concatenated command line. |
| No hung processes | 30 s idle timeout, entire process tree killed, `TimeoutException` surfaced. |
| Transient network resilience | Up to 4 attempts with exponential backoff on recognized transient remote errors; stale `index.lock` cleanup after a timeout. |
| Correct changelog boundaries | `git tag --merged HEAD --sort=-v:refname` — tags from unrelated branches can never anchor a release. |
| Atomic noise filtering | Structured log records delimited by ASCII RS (`0x1E`) and US (`0x1F`) keep hash, subject, body and stat together. |
| Payload hygiene | Configurable pathspec exclusions remove lockfiles, generated sources and binaries from the inference payload. |

### 6.5 AI Map-Reduce pipeline

Domain orchestration only — transport, session lifecycle, KV-cache checkpointing and Map-Reduce recovery are delegated to `InstantAIGate.Client`.

1. **Optimize** — `RegexDiffPayloadOptimizer` strips Git metadata while preserving `[ADDED] / [MODIFIED] / [DELETED] / [RENAMED]` statuses and truncates oversized hunks.
2. **Chunk** — `AiPayloadChunker` splits on file boundaries, skips generated/binary payloads and marks cross-chunk continuations.
3. **Budget** — chunk size is derived from the live model context size, a configured limit and a transport-safe ceiling (15000 characters against a 32768-byte SignalR receive clamp).
4. **Prompt** — `CommitPromptBuilder` / `ReleaseNotesPromptBuilder` are business assets; status accuracy rules prevent describing a modified file as newly added.
5. **Sanitize** — `CommitMessageSanitizer` enforces Conventional Commits (72-character header, mandatory blank line, bullet body); release notes get a version/model signature footer.

Status accuracy is enforced by architecture guard tests, not by convention.

### 6.6 TUI

- `ITuiWorkspace` plugin model; workspaces are registered in DI and rendered automatically.
- `TuiProgressReporter` with an `AsyncLocal` ambient live controller: two-line indicator (chunk progress bar + spinner), auto-clearing before streaming starts, non-interactive fallback.
- `MarkdownReleaseNotesRenderer` converts streamed Markdown into native Spectre renderables (summary panel + table).
- `CliMarkup` sanitizes malformed markup so model output can never crash the renderer.

---

## 7. Engineering principles

| Principle | Implementation |
| :--- | :--- |
| SRP | `KeyContainerProtector` does cryptography only; `KeyContainerCodec` owns key semantics; prompt builders own prompts only. |
| OCP | New algorithms, bump strategies, ecosystems and workspaces are added as registered components. |
| DIP | Workflows depend on abstractions; adapters are bound in the composition root. |
| DRY | One `Sha256Hex` rule for keys, manifests and artifacts; one manifest contract for releases and the Doctrine PDF. |
| KISS / Occam | Signing exact bytes eliminates JSON canonicalization; the ceremony CLI has zero dependencies. |
| YAGNI | No mocks where real cryptography is testable; no revocation, threshold signatures or transparency log yet. |
| Crypto-agility | `alg` persisted everywhere; registry resolution; fail-fast on unknown identifiers (RFC 7696). |
| Stateless core | The verification engine takes anti-rollback state as input; persistence is a client concern. |
| Defense in depth | AEAD + AAD binding + validity windows + three independent fingerprint channels. |
| Testable time | Ceremony and verification accept an injected clock; tests are deterministic. |

---

## 8. Configuration

`src/Instancium.Publisher.Tui/appsettings.json`, section `PublisherSettings`:

| Setting | Default in code | Purpose |
| :--- | :--- | :--- |
| `TargetBranch` | `main` | Merge target for releases. |
| `ReleaseBranchPrefix` | `release-prep/v` | Prefix of the temporary release branch. |
| `AiGatewayUrl` | `http://localhost:5000` | InstantAIGate endpoint. |
| `AiModelId` | `qwen3-vl-8b-instruct` | Fallback model id for display; the active id is queried from the gateway. |
| `AiApiKey` | empty | **Must be supplied by the operator.** |
| `MaxChunkLength` | `3000` | Upper bound for a single prompt chunk. |
| `DiffOptimization.Enabled` | `true` | Diff extraction and reduction toggle. |
| `DiffOptimization.ContextLines` | `3` | `git diff -U<n>`. |
| `DiffOptimization.IgnoreWhitespace` | `true` | `-w --ignore-blank-lines`. |
| `DiffOptimization.MaxHunkLines` | `80` | Hunk truncation threshold. |
| `DiffOptimization.ExcludedPathspecs` | lockfiles, generated, binaries | Pathspecs excluded at extraction time. |
| `RegisteredProjects` | dictionary | TUI navigation: display name -> repository path. |

The shipped `AiApiKey` value is a placeholder. Supply the real key through an environment variable and keep it out of source control:

```bash
# Windows PowerShell
$env:PublisherSettings__AiApiKey = "<your-key>"

# Linux / macOS
export PublisherSettings__AiApiKey="<your-key>"
```

---

## 9. Build and test

Requirements: **.NET 10 SDK**. `git` is required at runtime; `gh` (authenticated) is required for GitHub publication; a reachable InstantAIGate gateway is required for AI features.

```bash
dotnet restore Instancium.Publisher.slnx
dotnet build   Instancium.Publisher.slnx

dotnet test tests/Instancium.Publisher.Tests/Instancium.Publisher.Tests.csproj
dotnet test tests/Instancium.Trust.Tests/Instancium.Trust.Tests.csproj

dotnet run --project src/Instancium.Publisher.Tui
```

| Suite | Coverage |
| :--- | :--- |
| `Instancium.Publisher.Tests` | Domain (SemVer, repository policy), pipeline (bump idempotency, merge strategy), services (Git boundaries, diff optimization, chunking, scanner, ecosystems), workflows. Includes architecture guard tests that fail on regression of designed invariants. |
| `Instancium.Trust.Tests` | **36 tests**: Ed25519 (7, including the 50 ms sign+verify budget), key containers (6), verification chain and anti-rollback (20), ceremony (3). Real cryptography, reduced KDF cost for speed plus one production-profile test. |

Trust measurables asserted by tests: at least 10 unit tests, single-byte manifest/certificate tampering, version rollback, wrong password, and sign+verify within 50 ms.

---

## 10. Instancium.Trust.Cli usage

Run the ceremony on an isolated offline machine. Passwords are read interactively with masking and confirmation; they never enter argv, shell history or configuration files.

```bash
dotnet run --project src/Instancium.Trust.Cli -- ceremony --out ./ceremony-output \
  [--alg ed25519] [--primary-kid root-primary-2026] [--backup-kid root-backup-2026] \
  [--release-kid release-2026-11] [--validity-days 365]
```

Verify a full chain, optionally including every artifact declared in the manifest:

```bash
dotnet run --project src/Instancium.Trust.Cli -- verify \
  --manifest manifest.json --sig manifest.sig --cert release-key.cert \
  --root root-primary.pub --root root-backup.pub \
  [--artifacts-dir ./assets]
```

| Exit code | Meaning |
| :--- | :--- |
| `0` | Chain and artifact checks passed. |
| `1` | Verification failed (a failure code is printed) or an I/O/crypto error occurred. |
| `2` | Usage error. |

Artifact paths are confined to the artifacts root: a signed manifest still cannot read files outside the verification directory.

---

## 11. Security model

**Assumed Breach:** the design assumes one contour is already compromised. Four independent contours:

1. `Instancium.Trust` + `.Cli` — trust library and offline ceremony.
2. `Instancium.Publisher` — build, sign, publish.
3. `instancium-hub` (GitHub) — public keys, manifests, assets, philosophy and instructions.
4. Verification clients — `InstanciumSetup.exe` and `instancium.com/doctrine`.

Public root fingerprints are published in three independent places: compiled constants (`TrustConstants.g.cs`), GitHub (`/keys/*.pub`), and DNS TXT with DNSSEC.

| Threat | Covered by |
| :--- | :--- |
| Artifact substitution in transit or at rest | SHA-256 pinning inside the signed manifest + size check. |
| Manifest substitution | Ed25519 signature over exact manifest bytes. |
| Forged release key | Certificate signed by the cold root; validity window limits blast radius. |
| Compromised GitHub account | Out-of-band fingerprints in DNS and compiled constants. |
| Rollback to a vulnerable release | Anti-rollback state supplied by the client. |
| Stolen key container | Argon2id (64 MiB / 3 / 4) + AES-256-GCM with AAD-bound parameters. |
| KDF parameter downgrade | AAD binding breaks the GCM tag. |
| Hostile container driving KDF cost | Parameter safety caps before derivation. |

**Explicitly out of scope:** compromise of the cold root key itself, malware already executing on the user machine, missing DNSSEC, key revocation, threshold signatures, transparency logs and timestamping authorities. These are conscious boundaries, not oversights.

---

## 12. Roadmap

### Stage 1 — Trust library and CLI — **completed**

Delivered: `ISignatureAlgorithm` + `Ed25519SignatureAlgorithm` and registry; Argon2id + AES-256-GCM containers; `KeyCeremonyService` with `TrustConstants.g.cs` and DNS TXT export; `TrustVerificationEngine` (chain, SHA-256, anti-rollback); size-before-hash artifact verification; CLI (`ceremony`, `verify`); 36 unit tests. Pure managed, no system OpenSSL. Existing Publisher contracts and tests untouched.

### Stage 2 — Key ceremony and publication (0.5 working day)

- Run the CLI in an isolated environment; move cold Primary/Backup roots to offline media; store the working Release Key in Windows DPAPI or a local encrypted store.
- Create the public `instancium-hub` repository (`/keys`, `/doctrine`, `/drivers`, `README.md`).
- Publish the `_trust.instancium.com` TXT record and enable DNSSEC.

**Measurable:** `nslookup -type=TXT _trust.instancium.com` returns current fingerprints; DNS, `README.md`, `/keys/*.pub` and `TrustConstants.g.cs` match 100%; zero private keys in Git or configuration.

### Stage 3 — Publisher: asset build, drivers and signing (2.5 working days)

- Connect `Instancium.Trust` for manifest and signing contracts (adapter in `Infrastructure`, keeping `Application` Trust-free).
- `IArtifactBuilder` + `DeclarativeArtifactBuilder` reading `instancium.publish.json` from the target repository (.NET/Node/Rust commands, target RIDs, Vulkan/`llama.cpp` driver paths, `.zip` packaging, SHA-256 calculation).
- `IArtifactSigner` (`LocalReleaseKeySigner`) producing `manifest.json` + `manifest.sig`; optional `AuthenticodeSigner` for `.exe`.
- Extend `ReleasePublicationRequest` with `AssetPaths` (default empty) and upload archives, drivers, manifest and signature through `gh release create`.
- `BuildAndSignStep` in `ReleaseWorkflow`, journaled through `IPipelineStateManager`.

**Measurable:** 100% of existing Publisher tests pass unchanged; at least 8 new tests (`DeclarativeArtifactBuilderTests`, `GitHubCliReleasePublisherTests`, `BuildAndSignStepTests`); one Release Master run builds binaries and drivers, signs the manifest and publishes at least 4 assets.

### Stage 4 — Doctrine signing workspace (1 working day)

- `DocumentSigningWorkspace : ITuiWorkspace` in the TUI: file selection, version/date input, SHA-256, emission of `doctrine.manifest.json` + `doctrine.sig` with the working Release Key.
- Optional auto-commit and push of the signed set into a local `instancium-hub` clone through `IGitService`.

**Measurable:** signing takes at most 3 TUI steps and produces a valid manifest/signature pair; the set is published to `instancium-hub/doctrine/` and passes `Instancium.Trust.Cli` verification.

### Stage 5 — One-click verification

- `instancium-verify.js` (at most 10 KB, native WebCrypto Ed25519 with a `tweetnacl-fast` fallback, zero backend calls) for `instancium.com/doctrine`: one click downloads the PDF, manifest, signature and certificate, verifies the chain against the embedded root public key, optionally cross-checks the fingerprint through DNS-over-HTTPS.
- `InstanciumSetup.exe` integrates `Instancium.Trust` for automatic release verification and an offline `--verify <file>` command.

**Measurable:** browser verification completes in one click within 500 ms; the same `doctrine.sig` cross-validates in C# (BouncyCastle) and browser JavaScript.

### Deferred (conscious scope decisions)

| Item | Trigger to revisit |
| :--- | :--- |
| Streaming verification for artifacts above 2 GB | Stage 3 drivers and `.gguf` weights exceed the `File.ReadAllBytes` limit. |
| Persisted, authenticated anti-rollback state | Stage 5 installer; must use HMAC/AEAD/DPAPI, never a secret-prefix hash. |
| Key revocation, threshold signatures, transparency log | Adoption of TUF-style role separation. |
| ML-DSA / hybrid signatures | PQC migration; registry and `alg` fields already accommodate them. |
| Node / Rust / Python ecosystems | Stage 3 `IProjectEcosystem` implementations. |

### Known limitations

- `CommitMessageSanitizer` resides in `Application/Workflows` but declares the `Instancium.Publisher.Infrastructure.Ai` namespace; the mismatch is retained to avoid breaking existing consumers.
- `GitHubCliReleasePublisher` degrades to a local release-notes export when `gh` is unavailable or unauthenticated: the tag is pushed, but the release is not published. The TUI surfaces this as a warning.
- `ReleasePublicationRequest` carries no asset paths yet; asset upload arrives in Stage 3.

---

## 13. Contribution conventions

- Code, comments, XML documentation, commit messages, namespaces and identifiers: **English only**.
- XML documentation explains **why**, not what; document intent and invariants.
- Extend behaviour through new components and registrations, not by adding parameters to existing contracts.
- Do not break existing contracts or tests; add architecture guard tests when a new invariant is introduced.
- No hardcoded mutable values — configuration belongs in settings objects.
- Releases are repository-scoped: never bump a single project in isolation.
- Commit messages follow Conventional Commits (72-character header, blank line, bullet body).

---

## 14. References

| Topic | Source |
| :--- | :--- |
| EdDSA / Ed25519 | RFC 8032 |
| Argon2id | RFC 9106 |
| Authenticated encryption interface | RFC 5116 |
| AES-GCM | NIST SP 800-38D |
| SHA-2 | FIPS 180-4 |
| Cryptographic algorithm agility | RFC 7696 |
| JSON canonicalization (deliberately not used) | RFC 8785 |
| ML-DSA / SLH-DSA (PQC roadmap) | FIPS 204 / FIPS 205 |
| DNSSEC / DNS-over-HTTPS | RFC 4033-4035 / RFC 8484 |
| Update-framework threat model | The Update Framework (TUF) specification |

---

## 15. License

See `LICENSE.txt`.