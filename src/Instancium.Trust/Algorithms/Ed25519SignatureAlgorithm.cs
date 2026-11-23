namespace Instancium.Trust.Algorithms;

using Instancium.Trust.Keys;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;

/// <summary>
/// RFC 8032 Ed25519 via pure managed BouncyCastle: raw 32-byte keys and 64-byte signatures
/// guarantee byte-level cross-validation with browser WebCrypto implementations.
/// </summary>
public sealed class Ed25519SignatureAlgorithm : ISignatureAlgorithm
{
    private const int SignatureSizeBytes = 64;

    public string AlgId => KnownSignatureAlgorithms.Ed25519;

    public TrustKeyPair GenerateKeyPair()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(Ed25519PrivateKeyParameters.KeySize);
        try
        {
            var privateKey = new Ed25519PrivateKeyParameters(seed, 0);
            return new TrustKeyPair(AlgId, privateKey.GeneratePublicKey().GetEncoded(), privateKey.GetEncoded());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != Ed25519PrivateKeyParameters.KeySize)
        {
            throw new ArgumentException("Ed25519 private key must be 32 bytes.", nameof(privateKey));
        }

        return new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0).GeneratePublicKey().GetEncoded();
    }

    public byte[] Sign(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != Ed25519PrivateKeyParameters.KeySize)
        {
            throw new ArgumentException("Ed25519 private key must be 32 bytes.", nameof(privateKey));
        }

        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0));
        byte[] buffer = payload.ToArray();
        signer.BlockUpdate(buffer, 0, buffer.Length);
        return signer.GenerateSignature();
    }

    public bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureSizeBytes || publicKey.Length != Ed25519PublicKeyParameters.KeySize)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey.ToArray(), 0));
            byte[] buffer = payload.ToArray();
            verifier.BlockUpdate(buffer, 0, buffer.Length);
            return verifier.VerifySignature(signature.ToArray());
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
