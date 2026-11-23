namespace Instancium.Trust.Keys;

using System.Security.Cryptography;

/// <summary>
/// Raw key material carrier. Private key bytes are wipeable to minimize the lifetime
/// of secrets in memory (Assumed Breach principle).
/// </summary>
/// <param name="Alg">Persisted algorithm id, travels with every artifact signed by this key.</param>
/// <param name="PublicKey">Raw public key bytes (32 bytes for Ed25519).</param>
/// <param name="PrivateKey">Raw private key bytes; never serialized in plaintext.</param>
public sealed record TrustKeyPair(string Alg, byte[] PublicKey, byte[] PrivateKey)
{
    public void WipePrivateKey() => CryptographicOperations.ZeroMemory(PrivateKey);
}
