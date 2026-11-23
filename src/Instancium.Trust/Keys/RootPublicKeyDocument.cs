namespace Instancium.Trust.Keys;

using Instancium.Trust.Hashing;
using Instancium.Trust.Serialization;
using Instancium.Trust.Verification;
using System.Text.Json;

/// <summary>
/// Published root key file (*.pub): self-describing JSON with an embedded fingerprint,
/// so README, DNS and compiled constants can be cross-checked against the file itself.
/// </summary>
/// <param name="Kid">Stable key identifier referenced by certificates and DNS.</param>
/// <param name="Alg">Signature algorithm id (crypto-agility anchor).</param>
/// <param name="PublicKey">Base64 of raw public key bytes.</param>
/// <param name="Sha256">Lowercase-hex fingerprint of the raw public key bytes.</param>
public sealed record RootPublicKeyDocument(string Kid, string Alg, string PublicKey, string Sha256)
{
    public static RootPublicKeyDocument FromKeyPair(string kid, TrustKeyPair keyPair)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);
        ArgumentNullException.ThrowIfNull(keyPair);
        return new RootPublicKeyDocument(
            kid, keyPair.Alg,
            Convert.ToBase64String(keyPair.PublicKey),
            PublicKeyFingerprint.Compute(keyPair.PublicKey));
    }

    public byte[] ToJsonBytes() => JsonSerializer.SerializeToUtf8Bytes(this, TrustJson.Options);

    public static RootPublicKeyDocument FromJsonBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return JsonSerializer.Deserialize<RootPublicKeyDocument>(bytes, TrustJson.Options)
            ?? throw new JsonException("Root public key document deserialized to null.");
    }

    public bool HasValidFingerprint()
    {
        try
        {
            return string.Equals(
                Sha256Hex.Compute(Convert.FromBase64String(PublicKey)),
                Sha256, StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public TrustAnchor ToAnchor()
    {
        if (!HasValidFingerprint())
        {
            throw new InvalidOperationException($"Root key '{Kid}' fingerprint does not match its public key bytes.");
        }

        return new TrustAnchor(Kid, Alg, Convert.FromBase64String(PublicKey));
    }
}
