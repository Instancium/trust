namespace Instancium.Trust.Tests.Keys;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Keys;
using Instancium.Trust.Tests.TestInfrastructure;
using Xunit;

/// <summary>
/// Verifies that encrypted containers restore a fully usable key pair with a re-derived
/// public key, so stored public key copies can never diverge from the private key.
/// </summary>
public sealed class KeyContainerCodecTests
{
    [Fact]
    public void ProtectUnprotect_RestoresKeyPairAndDerivesPublicKey()
    {
        SignatureAlgorithmRegistry registry = TrustTestFactory.CreateRegistry();
        var codec = new KeyContainerCodec(registry, new KeyContainerProtector());
        TrustKeyPair original = registry.Resolve(KnownSignatureAlgorithms.Ed25519).GenerateKeyPair();

        string container = codec.Protect(original, "password", TrustTestFactory.FastContainerOptions);
        TrustKeyPair restored = codec.Unprotect(container, "password");

        Assert.Equal(original.Alg, restored.Alg);
        Assert.Equal(original.PrivateKey, restored.PrivateKey);
        Assert.Equal(original.PublicKey, restored.PublicKey);
    }
}
