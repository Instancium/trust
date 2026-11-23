namespace Instancium.Trust.Manifests;

using Instancium.Trust.Serialization;
using System.Text.Json;

/// <summary>
/// One manifest contract for release assets and the Doctrine PDF (DRY): integrity of every
/// file is pinned by SHA-256 inside the signed payload, so a single signature covers all files.
/// </summary>
/// <param name="V">Schema version for forward-compatible evolution.</param>
/// <param name="Alg">Signature algorithm id (crypto-agility anchor).</param>
/// <param name="Kid">Release key identifier that must match the certificate.</param>
/// <param name="Product">Product scope of the manifest.</param>
/// <param name="Version">SemVer string used by anti-rollback state.</param>
/// <param name="IssuedAt">Monotonic issuance timestamp used by anti-rollback state.</param>
/// <param name="Artifacts">Pinned file hashes and sizes.</param>
public sealed record ReleaseManifest(
    int V, string Alg, string Kid, string Product, string Version,
    DateTimeOffset IssuedAt, IReadOnlyList<ManifestArtifact> Artifacts)
{
    public const int CurrentVersion = 1;

    public byte[] ToJsonBytes() => JsonSerializer.SerializeToUtf8Bytes(this, TrustJson.Options);

    public static ReleaseManifest FromJsonBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return JsonSerializer.Deserialize<ReleaseManifest>(bytes, TrustJson.Options)
            ?? throw new JsonException("Manifest deserialized to null.");
    }
}

/// <param name="Path">Relative artifact path inside the release layout.</param>
/// <param name="Sha256">Lowercase-hex SHA-256 of the exact artifact bytes.</param>
/// <param name="Size">Artifact size in bytes for early corruption detection.</param>
public sealed record ManifestArtifact(string Path, string Sha256, long Size);
