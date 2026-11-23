namespace Instancium.Trust.Algorithms;

using Instancium.Trust.Keys;

/// <summary>
/// Crypto-agile signing contract. The algorithm id is persisted inside every signed artifact,
/// so a future PQC migration never rewrites existing manifests or certificates.
/// </summary>
public interface ISignatureAlgorithm
{
    string AlgId { get; }

    TrustKeyPair GenerateKeyPair();

    /// <summary>
    /// Reconstructs the public key from a private key so encrypted containers can stay
    /// minimal (algorithm id + private key only) without trusting stored public key copies.
    /// </summary>
    byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey);

    byte[] Sign(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> privateKey);

    /// <summary>
    /// Returns false for attacker-controlled malformed inputs instead of throwing,
    /// keeping the verification engine exception-free on the hot path.
    /// </summary>
    bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey);
}
