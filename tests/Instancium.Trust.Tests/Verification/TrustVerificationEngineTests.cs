namespace Instancium.Trust.Tests.Verification;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Certificates;
using Instancium.Trust.Hashing;
using Instancium.Trust.Manifests;
using Instancium.Trust.Tests.TestInfrastructure;
using Instancium.Trust.Verification;
using Xunit;

/// <summary>
/// Verifies every chain link in isolation: root signature, validity window, kid/alg binding,
/// manifest signature, anti-rollback rules and artifact hash pinning.
/// </summary>
public sealed class TrustVerificationEngineTests
{
    private readonly TrustVerificationEngine _engine = TrustTestFactory.CreateEngine();

    [Fact]
    public void VerifyManifest_ValidChain_Succeeds()
    {
        TestTrustChain chain = TestTrustChain.Create();
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor],
            verificationTime: chain.Now);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyManifest_TamperedCertificateByte_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        byte[] payload = (byte[])chain.Certificate.Payload.Clone();
        payload[10] ^= 1;
        var tampered = new SignedEnvelope(chain.Certificate.Alg, payload, chain.Certificate.Signature);
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, tampered, [chain.Anchor], verificationTime: chain.Now);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void VerifyManifest_TamperedManifestByte_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        byte[] manifestBytes = (byte[])chain.ManifestBytes.Clone();
        manifestBytes[10] ^= 1;
        VerificationResult result = _engine.VerifyManifest(
            manifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor], verificationTime: chain.Now);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void VerifyManifest_ResignedCertificateContentWithOldSignature_FailsWithCertificateSignatureInvalid()
    {
        TestTrustChain chain = TestTrustChain.Create();
        ReleaseKeyCertificate certificate = ReleaseKeyCertificate.FromJsonBytes(chain.Certificate.Payload);
        ReleaseKeyCertificate modified = certificate with { ExpiresAt = certificate.ExpiresAt.AddDays(365) };
        var tampered = new SignedEnvelope(chain.Certificate.Alg, modified.ToJsonBytes(), chain.Certificate.Signature);
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, tampered, [chain.Anchor], verificationTime: chain.Now);
        Assert.Equal(VerificationFailureCodes.CertificateSignatureInvalid, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_ManifestContentChangedWithOldSignature_FailsWithManifestSignatureInvalid()
    {
        TestTrustChain chain = TestTrustChain.Create();
        ReleaseManifest modified = chain.Manifest with
        {
            Artifacts = [new ManifestArtifact("artifact.bin", new string('0', 64), 7)]
        };
        VerificationResult result = _engine.VerifyManifest(
            modified.ToJsonBytes(), chain.ManifestSignature, chain.Certificate, [chain.Anchor], verificationTime: chain.Now);
        Assert.Equal(VerificationFailureCodes.ManifestSignatureInvalid, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_UnknownRootKid_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        var strangerAnchor = chain.Anchor with { Kid = "root-stranger" };
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [strangerAnchor], verificationTime: chain.Now);
        Assert.Equal(VerificationFailureCodes.UnknownRootKey, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_ExpiredCertificate_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor],
            verificationTime: chain.Now.AddDays(31));
        Assert.Equal(VerificationFailureCodes.CertificateExpired, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_NotYetValidCertificate_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor],
            verificationTime: chain.Now.AddHours(-2));
        Assert.Equal(VerificationFailureCodes.CertificateNotYetValid, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_UnknownEnvelopeAlgorithm_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        var envelope = chain.Certificate with { Alg = "ml-dsa-65" };
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, envelope, [chain.Anchor], verificationTime: chain.Now);
        Assert.Equal(VerificationFailureCodes.UnknownAlgorithm, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_OlderTimestamp_RollbackRejected()
    {
        TestTrustChain chain = TestTrustChain.Create();
        var lastAccepted = new AntiRollbackState("1.9.0", chain.Now.AddHours(1), Sha256Hex.Compute(chain.ManifestBytes));
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor],
            lastAccepted, chain.Now);
        Assert.Equal(VerificationFailureCodes.RollbackDetected, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_SameVersionDifferentHash_RollbackRejected()
    {
        TestTrustChain chain = TestTrustChain.Create();
        var lastAccepted = new AntiRollbackState("1.8.0", chain.Now, new string('0', 64));
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor],
            lastAccepted, chain.Now);
        Assert.Equal(VerificationFailureCodes.RollbackDetected, result.FailureCode);
    }

    [Fact]
    public void VerifyManifest_NewerManifest_AcceptedAgainstOlderState()
    {
        TestTrustChain chain = TestTrustChain.Create();
        var lastAccepted = new AntiRollbackState("1.7.0", chain.Now.AddHours(-1), new string('0', 64));
        VerificationResult result = _engine.VerifyManifest(
            chain.ManifestBytes, chain.ManifestSignature, chain.Certificate, [chain.Anchor],
            lastAccepted, chain.Now);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyManifest_KidMismatch_Fails()
    {
        TestTrustChain chain = TestTrustChain.Create();
        ISignatureAlgorithm algorithm = TrustTestFactory.CreateRegistry().Resolve(KnownSignatureAlgorithms.Ed25519);
        ReleaseManifest foreign = TrustTestFactory.CreateManifest("release-other", algorithm.AlgId, "1.8.0", chain.Now);
        byte[] foreignBytes = foreign.ToJsonBytes();
        byte[] foreignSignature = algorithm.Sign(foreignBytes, chain.Release.PrivateKey);
        VerificationResult result = _engine.VerifyManifest(
            foreignBytes, foreignSignature, chain.Certificate, [chain.Anchor], verificationTime: chain.Now);
        Assert.Equal(VerificationFailureCodes.KidMismatch, result.FailureCode);
    }

    [Fact]
    public void VerifyArtifact_MatchingHash_Succeeds()
    {
        byte[] content = "payload"u8.ToArray();
        VerificationResult result = _engine.VerifyArtifact(content, Sha256Hex.Compute(content));
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyArtifact_TamperedContent_Fails()
    {
        byte[] content = "payload"u8.ToArray();
        string expected = Sha256Hex.Compute(content);
        content[0] ^= 1;
        VerificationResult result = _engine.VerifyArtifact(content, expected);
        Assert.Equal(VerificationFailureCodes.ArtifactHashMismatch, result.FailureCode);
    }

    [Fact]
    public void VerifyArtifact_MatchingSizeAndHash_Succeeds()
    {
        byte[] content = "payload"u8.ToArray();
        var artifact = new ManifestArtifact("artifact.bin", Sha256Hex.Compute(content), content.Length);

        VerificationResult result = _engine.VerifyArtifact(content, artifact);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyArtifact_TruncatedContent_FailsWithSizeMismatch()
    {
        byte[] content = "payload"u8.ToArray();
        var artifact = new ManifestArtifact("artifact.bin", Sha256Hex.Compute(content), content.Length);

        VerificationResult result = _engine.VerifyArtifact(content.AsSpan(0, content.Length - 1), artifact);

        Assert.Equal(VerificationFailureCodes.ArtifactSizeMismatch, result.FailureCode);
    }

    [Fact]
    public void VerifyArtifact_AppendedContent_FailsWithSizeMismatch()
    {
        byte[] content = "payload"u8.ToArray();
        var artifact = new ManifestArtifact("artifact.bin", Sha256Hex.Compute(content), content.Length);
        byte[] extended = [.. content, 0x00];

        VerificationResult result = _engine.VerifyArtifact(extended, artifact);

        Assert.Equal(VerificationFailureCodes.ArtifactSizeMismatch, result.FailureCode);
    }

    [Fact]
    public void VerifyArtifact_SizeAndHashBothInvalid_ReportsSizeFirst()
    {
        var artifact = new ManifestArtifact("artifact.bin", new string('0', 64), 7);

        VerificationResult result = _engine.VerifyArtifact("payload-with-tail"u8, artifact);

        Assert.Equal(VerificationFailureCodes.ArtifactSizeMismatch, result.FailureCode);
    }

    [Fact]
    public void VerifyArtifact_EqualLengthSubstitution_FailsWithHashMismatch()
    {
        byte[] content = "payload"u8.ToArray();
        var artifact = new ManifestArtifact("artifact.bin", Sha256Hex.Compute(content), content.Length);
        byte[] substituted = (byte[])content.Clone();
        substituted[0] ^= 1;

        VerificationResult result = _engine.VerifyArtifact(substituted, artifact);

        Assert.Equal(VerificationFailureCodes.ArtifactHashMismatch, result.FailureCode);
    }
}
