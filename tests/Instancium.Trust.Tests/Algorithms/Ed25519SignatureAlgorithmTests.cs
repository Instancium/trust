namespace Instancium.Trust.Tests.Algorithms;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Keys;
using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;

/// <summary>
/// Verifies the Ed25519 primitive: roundtrip, rejection of every tampering class,
/// key derivation consistency and the 50 ms sign+verify budget of the trust plan.
/// </summary>
public sealed class Ed25519SignatureAlgorithmTests
{
    private readonly Ed25519SignatureAlgorithm _algorithm = new();

    [Fact]
    public void SignAndVerify_RoundTrip_ReturnsTrue()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        byte[] payload = "instancium doctrine"u8.ToArray();
        byte[] signature = _algorithm.Sign(payload, key.PrivateKey);
        Assert.True(_algorithm.Verify(payload, signature, key.PublicKey));
    }

    [Fact]
    public void Verify_TamperedPayload_ReturnsFalse()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        byte[] payload = "instancium doctrine"u8.ToArray();
        byte[] signature = _algorithm.Sign(payload, key.PrivateKey);
        payload[0] ^= 1;
        Assert.False(_algorithm.Verify(payload, signature, key.PublicKey));
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        byte[] payload = "instancium doctrine"u8.ToArray();
        byte[] signature = _algorithm.Sign(payload, key.PrivateKey);
        signature[0] ^= 1;
        Assert.False(_algorithm.Verify(payload, signature, key.PublicKey));
    }

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        TrustKeyPair stranger = _algorithm.GenerateKeyPair();
        byte[] payload = "instancium doctrine"u8.ToArray();
        byte[] signature = _algorithm.Sign(payload, key.PrivateKey);
        Assert.False(_algorithm.Verify(payload, signature, stranger.PublicKey));
    }

    [Fact]
    public void Verify_MalformedSignatureLength_ReturnsFalseWithoutThrowing()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        Assert.False(_algorithm.Verify("payload"u8, new byte[10], key.PublicKey));
    }

    [Fact]
    public void DerivePublicKey_MatchesGeneratedPublicKey()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        Assert.Equal(key.PublicKey, _algorithm.DerivePublicKey(key.PrivateKey));
    }

    [Fact]
    public void SignAndVerify_CompletesWithin50MsBudget()
    {
        TrustKeyPair key = _algorithm.GenerateKeyPair();
        byte[] payload = RandomNumberGenerator.GetBytes(1024);

        // JIT warmup isolates the steady-state budget from first-call compilation noise.
        for (int i = 0; i < 5; i++)
        {
            byte[] warmup = _algorithm.Sign(payload, key.PrivateKey);
            Assert.True(_algorithm.Verify(payload, warmup, key.PublicKey));
        }

        var stopwatch = Stopwatch.StartNew();
        byte[] signature = _algorithm.Sign(payload, key.PrivateKey);
        bool valid = _algorithm.Verify(payload, signature, key.PublicKey);
        stopwatch.Stop();

        Assert.True(valid);
        Assert.True(stopwatch.ElapsedMilliseconds <= 50,
            $"Sign+Verify took {stopwatch.ElapsedMilliseconds} ms, exceeding the 50 ms budget.");
    }
}
