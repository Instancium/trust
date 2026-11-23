namespace Instancium.Trust.Tests.TestInfrastructure;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Hashing;
using Instancium.Trust.Keys;
using Instancium.Trust.Manifests;
using Instancium.Trust.Verification;

internal static class TrustTestFactory
{
    public static SignatureAlgorithmRegistry CreateRegistry() => new([new Ed25519SignatureAlgorithm()]);

    public static TrustVerificationEngine CreateEngine() => new(CreateRegistry());

    /// <summary>Reduced KDF cost keeps the suite fast; production cost is covered by a dedicated test.</summary>
    public static KeyContainerOptions FastContainerOptions => new() { MemoryKiB = 8192, Iterations = 1, Parallelism = 1 };

    public static ReleaseManifest CreateManifest(string kid, string alg, string version, DateTimeOffset issuedAt) =>
        new(ReleaseManifest.CurrentVersion, alg, kid, "Instancium.Tests", version, issuedAt,
            [new ManifestArtifact("artifact.bin", Sha256Hex.Compute("payload"u8), 7)]);
}
