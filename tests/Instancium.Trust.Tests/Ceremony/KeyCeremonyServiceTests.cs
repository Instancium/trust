namespace Instancium.Trust.Tests.Ceremony;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Ceremony;
using Instancium.Trust.Certificates;
using Instancium.Trust.Keys;
using Instancium.Trust.Manifests;
using Instancium.Trust.Tests.TestInfrastructure;
using Instancium.Trust.Verification;
using Xunit;

/// <summary>
/// Verifies the ceremony as a whole: fingerprint identity across every export channel,
/// end-to-end chain verification from written files, and absence of plaintext key material.
/// </summary>
public sealed class KeyCeremonyServiceTests
{
    private static KeyCeremonyOptions CreateOptions(string outputDirectory) => new()
    {
        OutputDirectory = outputDirectory,
        PrimaryRootKid = "root-primary-test",
        BackupRootKid = "root-backup-test",
        ReleaseKeyKid = "release-test",
        RootContainerPassword = "root-password",
        ReleaseContainerPassword = "release-password",
        Container = TrustTestFactory.FastContainerOptions,
        CeremonyTime = DateTimeOffset.UtcNow,
        ReleaseKeyValidity = TimeSpan.FromDays(30)
    };

    private static KeyCeremonyService CreateService(SignatureAlgorithmRegistry registry) =>
        new(registry, new KeyContainerCodec(registry, new KeyContainerProtector()));

    [Fact]
    public void Execute_FingerprintsConsistentAcrossAllExports()
    {
        using var scope = new TemporaryDirectoryScope();
        SignatureAlgorithmRegistry registry = TrustTestFactory.CreateRegistry();
        KeyCeremonyResult result = CreateService(registry).Execute(CreateOptions(scope.RootPath));

        string expectedPrimary = PublicKeyFingerprint.Compute(Convert.FromBase64String(result.PrimaryRoot.PublicKey));
        string expectedBackup = PublicKeyFingerprint.Compute(Convert.FromBase64String(result.BackupRoot.PublicKey));

        Assert.Equal(expectedPrimary, result.PrimaryRoot.Sha256);
        Assert.Equal(expectedBackup, result.BackupRoot.Sha256);
        Assert.Contains(expectedPrimary, result.TrustConstantsSource);
        Assert.Contains(expectedBackup, result.TrustConstantsSource);
        Assert.Contains($"primary_sha256={expectedPrimary}", result.DnsTxtRecord);
        Assert.Contains($"backup_sha256={expectedBackup}", result.DnsTxtRecord);
        Assert.Contains(expectedPrimary, File.ReadAllText(Path.Combine(scope.RootPath, "root-primary.pub")));
        Assert.StartsWith("v=inst1; alg=ed25519;", result.DnsTxtRecord);
    }

    [Fact]
    public void Execute_ProducedChain_VerifiesEndToEnd()
    {
        using var scope = new TemporaryDirectoryScope();
        SignatureAlgorithmRegistry registry = TrustTestFactory.CreateRegistry();
        KeyCeremonyOptions options = CreateOptions(scope.RootPath);
        KeyCeremonyResult result = CreateService(registry).Execute(options);

        var codec = new KeyContainerCodec(registry, new KeyContainerProtector());
        TrustKeyPair releaseKey = codec.Unprotect(
            File.ReadAllText(Path.Combine(scope.RootPath, "release-key.key.json")),
            options.ReleaseContainerPassword);

        ReleaseManifest manifest = TrustTestFactory.CreateManifest(
            options.ReleaseKeyKid, KnownSignatureAlgorithms.Ed25519, "1.8.0", options.CeremonyTime);
        byte[] manifestBytes = manifest.ToJsonBytes();
        string signatureText = new ManifestSigner(registry).Sign(manifestBytes, releaseKey);

        Assert.True(SignedEnvelope.TryDecode(result.ReleaseCertificateEnvelope, out SignedEnvelope? envelope));
        VerificationResult verification = TrustTestFactory.CreateEngine().VerifyManifest(
            manifestBytes,
            DetachedSignature.FromText(signatureText),
            envelope!,
            [result.PrimaryRoot.ToAnchor(), result.BackupRoot.ToAnchor()],
            verificationTime: options.CeremonyTime.AddMinutes(1));

        Assert.True(verification.IsValid);
    }

    [Fact]
    public void Execute_PrivateContainersAreEncrypted_NoPlaintextKeyMaterial()
    {
        using var scope = new TemporaryDirectoryScope();
        SignatureAlgorithmRegistry registry = TrustTestFactory.CreateRegistry();
        KeyCeremonyResult result = CreateService(registry).Execute(CreateOptions(scope.RootPath));

        foreach (string path in result.WrittenFiles.Where(p => p.EndsWith(".key.json", StringComparison.Ordinal)))
        {
            string content = File.ReadAllText(path);
            Assert.Contains("\"kdf\": \"argon2id\"", content);
            Assert.DoesNotContain("\"sk\"", content);
        }
    }
}
