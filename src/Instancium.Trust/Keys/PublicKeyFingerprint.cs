namespace Instancium.Trust.Keys;

using Instancium.Trust.Hashing;

/// <summary>
/// Fingerprint = SHA-256 over raw public key bytes. This single rule anchors DNS TXT,
/// README, compiled constants and browser verification to the same value.
/// </summary>
public static class PublicKeyFingerprint
{
    public static string Compute(ReadOnlySpan<byte> publicKey) => Sha256Hex.Compute(publicKey);
}
