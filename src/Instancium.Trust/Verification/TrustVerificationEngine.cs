namespace Instancium.Trust.Verification;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Certificates;
using Instancium.Trust.Hashing;
using Instancium.Trust.Manifests;
using System.Text.Json;

/// <summary>
/// Stateless chain validator: Root -> Release Certificate -> Manifest -> artifact SHA-256,
/// plus anti-rollback against caller-supplied state. Every rejection carries the exact
/// broken link so operators can distinguish attack, expiry and corruption.
/// </summary>
public sealed class TrustVerificationEngine
{
    private readonly SignatureAlgorithmRegistry _registry;

    public TrustVerificationEngine(SignatureAlgorithmRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public VerificationResult VerifyManifest(
        byte[] manifestBytes,
        byte[] manifestSignature,
        SignedEnvelope releaseCertificate,
        IReadOnlyList<TrustAnchor> roots,
        AntiRollbackState? lastAccepted = null,
        DateTimeOffset? verificationTime = null)
    {
        ArgumentNullException.ThrowIfNull(manifestBytes);
        ArgumentNullException.ThrowIfNull(manifestSignature);
        ArgumentNullException.ThrowIfNull(releaseCertificate);
        ArgumentNullException.ThrowIfNull(roots);

        DateTimeOffset now = verificationTime ?? DateTimeOffset.UtcNow;

        if (!_registry.TryResolve(releaseCertificate.Alg, out ISignatureAlgorithm? algorithm))
        {
            return VerificationResult.Fail(VerificationFailureCodes.UnknownAlgorithm,
                $"Envelope algorithm '{releaseCertificate.Alg}' is not registered.");
        }

        ReleaseKeyCertificate certificate;
        byte[] releasePublicKey;
        try
        {
            certificate = ReleaseKeyCertificate.FromJsonBytes(releaseCertificate.Payload);
            releasePublicKey = Convert.FromBase64String(certificate.PublicKey);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return VerificationResult.Fail(VerificationFailureCodes.MalformedCertificate, ex.Message);
        }

        if (string.IsNullOrWhiteSpace(certificate.Kid) ||
            string.IsNullOrWhiteSpace(certificate.RootKid) ||
            certificate.ExpiresAt <= certificate.IssuedAt ||
            !string.Equals(certificate.Alg, releaseCertificate.Alg, StringComparison.Ordinal))
        {
            return VerificationResult.Fail(VerificationFailureCodes.MalformedCertificate,
                "Certificate fields are incomplete or inconsistent with the envelope.");
        }

        TrustAnchor? root = roots.FirstOrDefault(r => string.Equals(r.Kid, certificate.RootKid, StringComparison.Ordinal));
        if (root is null)
        {
            return VerificationResult.Fail(VerificationFailureCodes.UnknownRootKey,
                $"No trust anchor matches root kid '{certificate.RootKid}'.");
        }

        if (!string.Equals(root.Alg, releaseCertificate.Alg, StringComparison.Ordinal))
        {
            return VerificationResult.Fail(VerificationFailureCodes.AlgorithmMismatch,
                "Root anchor algorithm differs from the certificate envelope algorithm.");
        }

        if (!algorithm!.Verify(releaseCertificate.Payload, releaseCertificate.Signature, root.PublicKey))
        {
            return VerificationResult.Fail(VerificationFailureCodes.CertificateSignatureInvalid,
                "Root signature over the certificate payload is invalid.");
        }

        if (now < certificate.IssuedAt)
        {
            return VerificationResult.Fail(VerificationFailureCodes.CertificateNotYetValid,
                "Certificate validity window has not started.");
        }

        if (now > certificate.ExpiresAt)
        {
            return VerificationResult.Fail(VerificationFailureCodes.CertificateExpired,
                "Certificate validity window has ended.");
        }

        ReleaseManifest manifest;
        try
        {
            manifest = ReleaseManifest.FromJsonBytes(manifestBytes);
        }
        catch (JsonException ex)
        {
            return VerificationResult.Fail(VerificationFailureCodes.MalformedManifest, ex.Message);
        }

        if (!IsManifestWellFormed(manifest, out string manifestError))
        {
            return VerificationResult.Fail(VerificationFailureCodes.MalformedManifest, manifestError);
        }

        if (!string.Equals(manifest.Kid, certificate.Kid, StringComparison.Ordinal))
        {
            return VerificationResult.Fail(VerificationFailureCodes.KidMismatch,
                "Manifest kid does not match the certified release key.");
        }

        if (!string.Equals(manifest.Alg, certificate.Alg, StringComparison.Ordinal))
        {
            return VerificationResult.Fail(VerificationFailureCodes.AlgorithmMismatch,
                "Manifest algorithm differs from the certified key algorithm.");
        }

        if (!algorithm.Verify(manifestBytes, manifestSignature, releasePublicKey))
        {
            return VerificationResult.Fail(VerificationFailureCodes.ManifestSignatureInvalid,
                "Release key signature over the manifest bytes is invalid.");
        }

        if (lastAccepted is not null)
        {
            if (manifest.IssuedAt < lastAccepted.IssuedAt)
            {
                return VerificationResult.Fail(VerificationFailureCodes.RollbackDetected,
                    "Manifest timestamp is older than the last accepted state.");
            }

            if (string.Equals(manifest.Version, lastAccepted.Version, StringComparison.Ordinal))
            {
                string manifestHash = Sha256Hex.Compute(manifestBytes);
                if (!string.Equals(manifestHash, lastAccepted.ManifestSha256, StringComparison.OrdinalIgnoreCase))
                {
                    return VerificationResult.Fail(VerificationFailureCodes.RollbackDetected,
                        "Same version with different manifest content (substitution attempt).");
                }
            }
        }

        return VerificationResult.Success();
    }

    public VerificationResult VerifyArtifact(ReadOnlySpan<byte> artifactBytes, string expectedSha256)
    {
        if (!Sha256Hex.IsValid(expectedSha256))
        {
            return VerificationResult.Fail(VerificationFailureCodes.ArtifactHashMismatch,
                "Expected hash is not a 64-character hex string.");
        }

        string actual = Sha256Hex.Compute(artifactBytes);
        return string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase)
            ? VerificationResult.Success()
            : VerificationResult.Fail(VerificationFailureCodes.ArtifactHashMismatch,
                $"Artifact hash mismatch: expected {expectedSha256}, actual {actual}.");
    }

    /// <summary>
    /// Rejects size drift before hashing: multi-gigabyte artifacts (Vulkan drivers, model weights)
    /// fail fast on truncation or appended payloads without paying a full SHA-256 pass.
    /// Equal-length substitution still falls through to the hash check, so this layer never
    /// weakens the integrity guarantee of the signed manifest.
    /// </summary>
    public VerificationResult VerifyArtifact(ReadOnlySpan<byte> artifactBytes, ManifestArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (artifactBytes.Length != artifact.Size)
        {
            return VerificationResult.Fail(VerificationFailureCodes.ArtifactSizeMismatch,
                $"Artifact '{artifact.Path}' size mismatch: expected {artifact.Size}, actual {artifactBytes.Length}.");
        }

        return VerifyArtifact(artifactBytes, artifact.Sha256);
    }

    private static bool IsManifestWellFormed(ReleaseManifest manifest, out string error)
    {
        if (manifest.V != ReleaseManifest.CurrentVersion)
        {
            error = $"Unsupported manifest schema version '{manifest.V}'.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(manifest.Alg) ||
            string.IsNullOrWhiteSpace(manifest.Kid) ||
            string.IsNullOrWhiteSpace(manifest.Product) ||
            string.IsNullOrWhiteSpace(manifest.Version))
        {
            error = "Manifest header fields are incomplete.";
            return false;
        }

        if (manifest.Artifacts is null)
        {
            error = "Manifest artifacts list is missing.";
            return false;
        }

        foreach (ManifestArtifact artifact in manifest.Artifacts)
        {
            if (string.IsNullOrWhiteSpace(artifact.Path) || !Sha256Hex.IsValid(artifact.Sha256) || artifact.Size < 0)
            {
                error = $"Artifact '{artifact.Path}' has invalid path, hash or size.";
                return false;
            }
        }

        error = string.Empty;
        return true;
    }
}
