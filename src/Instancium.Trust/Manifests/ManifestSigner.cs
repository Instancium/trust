namespace Instancium.Trust.Manifests;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Keys;

/// <summary>
/// Single signing path for every manifest kind (release, doctrine): the algorithm is taken
/// from the key pair itself, making alg/key mismatch structurally impossible.
/// </summary>
public sealed class ManifestSigner
{
    private readonly SignatureAlgorithmRegistry _registry;

    public ManifestSigner(SignatureAlgorithmRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public string Sign(byte[] manifestBytes, TrustKeyPair releaseKey)
    {
        ArgumentNullException.ThrowIfNull(manifestBytes);
        ArgumentNullException.ThrowIfNull(releaseKey);
        ISignatureAlgorithm algorithm = _registry.Resolve(releaseKey.Alg);
        return DetachedSignature.ToText(algorithm.Sign(manifestBytes, releaseKey.PrivateKey));
    }
}
