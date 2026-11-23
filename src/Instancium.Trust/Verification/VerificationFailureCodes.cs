namespace Instancium.Trust.Verification;

/// <summary>Stable failure codes persisted into logs and UI across all verification clients.</summary>
public static class VerificationFailureCodes
{
    public const string UnknownAlgorithm = "unknown-algorithm";
    public const string MalformedCertificate = "malformed-certificate";
    public const string CertificateSignatureInvalid = "certificate-signature-invalid";
    public const string UnknownRootKey = "unknown-root-key";
    public const string AlgorithmMismatch = "algorithm-mismatch";
    public const string CertificateNotYetValid = "certificate-not-yet-valid";
    public const string CertificateExpired = "certificate-expired";
    public const string MalformedManifest = "malformed-manifest";
    public const string KidMismatch = "kid-mismatch";
    public const string ManifestSignatureInvalid = "manifest-signature-invalid";
    public const string RollbackDetected = "rollback-detected";
    public const string ArtifactHashMismatch = "artifact-hash-mismatch";
    public const string ArtifactSizeMismatch = "artifact-size-mismatch";
}
