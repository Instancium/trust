namespace Instancium.Trust.Tests.TestInfrastructure;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Certificates;
using Instancium.Trust.Keys;
using Instancium.Trust.Manifests;
using Instancium.Trust.Verification;

/// <summary>
/// In-memory valid chain built once per test: any single mutation then isolates
/// exactly one broken link of the verification pipeline.
/// </summary>
internal sealed record TestTrustChain(
    TrustKeyPair Root,
    TrustKeyPair Release,
    SignedEnvelope Certificate,
    TrustAnchor Anchor,
    byte[] ManifestBytes,
    byte[] ManifestSignature,
    ReleaseManifest Manifest,
    DateTimeOffset Now)
{
    public static TestTrustChain Create()
    {
        ISignatureAlgorithm algorithm = TrustTestFactory.CreateRegistry().Resolve(KnownSignatureAlgorithms.Ed25519);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        TrustKeyPair root = algorithm.GenerateKeyPair();
        TrustKeyPair release = algorithm.GenerateKeyPair();

        var certificate = new ReleaseKeyCertificate(
            "release-test", algorithm.AlgId, Convert.ToBase64String(release.PublicKey),
            now.AddHours(-1), now.AddDays(30), "root-test");
        byte[] payload = certificate.ToJsonBytes();
        var envelope = new SignedEnvelope(algorithm.AlgId, payload, algorithm.Sign(payload, root.PrivateKey));

        ReleaseManifest manifest = TrustTestFactory.CreateManifest("release-test", algorithm.AlgId, "1.8.0", now);
        byte[] manifestBytes = manifest.ToJsonBytes();
        byte[] signature = algorithm.Sign(manifestBytes, release.PrivateKey);

        return new TestTrustChain(
            root, release, envelope,
            new TrustAnchor("root-test", algorithm.AlgId, root.PublicKey),
            manifestBytes, signature, manifest, now);
    }
}
