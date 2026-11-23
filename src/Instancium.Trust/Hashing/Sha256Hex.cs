namespace Instancium.Trust.Hashing;

using System.Security.Cryptography;

/// <summary>
/// Canonical lowercase-hex SHA-256 used identically for key fingerprints, artifact hashes
/// and DNS records, so every channel compares byte-identical strings.
/// </summary>
public static class Sha256Hex
{
    public static string Compute(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public static bool IsValid(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);
}
