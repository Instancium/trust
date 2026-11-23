namespace Instancium.Trust.Certificates;

using Instancium.Trust.Serialization;
using System.Text.Json;

/// <summary>
/// Binds a hot Release Key to a cold Root Key. The alg field is persisted explicitly,
/// enabling future PQC or hybrid certificates without rewriting the trust chain contract.
/// </summary>
/// <param name="Kid">Release key identifier referenced by manifests.</param>
/// <param name="Alg">Signature algorithm id of the release key.</param>
/// <param name="PublicKey">Base64 of raw release public key bytes.</param>
/// <param name="IssuedAt">Start of the validity window.</param>
/// <param name="ExpiresAt">End of the validity window; limits blast radius of a leaked release key.</param>
/// <param name="RootKid">Identifier of the cold root key that signed this certificate.</param>
public sealed record ReleaseKeyCertificate(
    string Kid, string Alg, string PublicKey,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string RootKid)
{
    public byte[] ToJsonBytes() => JsonSerializer.SerializeToUtf8Bytes(this, TrustJson.Options);

    public static ReleaseKeyCertificate FromJsonBytes(byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return JsonSerializer.Deserialize<ReleaseKeyCertificate>(payload, TrustJson.Options)
            ?? throw new JsonException("Certificate payload deserialized to null.");
    }
}
