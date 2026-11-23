namespace Instancium.Trust.Keys;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Serialization;
using System.Security.Cryptography;
using System.Text.Json;

/// <summary>
/// Bridges key semantics and the generic protector: only algorithm id + private key are
/// encrypted; the public key is re-derived on load, eliminating stored-copy mismatch attacks.
/// </summary>
public sealed class KeyContainerCodec
{
    private readonly SignatureAlgorithmRegistry _registry;
    private readonly KeyContainerProtector _protector;

    public KeyContainerCodec(SignatureAlgorithmRegistry registry, KeyContainerProtector protector)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
    }

    public string Protect(TrustKeyPair keyPair, string password, KeyContainerOptions options)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(
            new KeyMaterial(keyPair.Alg, Convert.ToBase64String(keyPair.PrivateKey)), TrustJson.Options);
        try
        {
            return _protector.Protect(payload, password, options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public TrustKeyPair Unprotect(string containerJson, string password)
    {
        byte[] payload = _protector.Unprotect(containerJson, password);
        try
        {
            KeyMaterial? material = JsonSerializer.Deserialize<KeyMaterial>(payload, TrustJson.Options);
            if (material is null || string.IsNullOrWhiteSpace(material.Alg) || string.IsNullOrWhiteSpace(material.Sk))
            {
                throw new KeyContainerException("Container key material is incomplete.");
            }

            byte[] privateKey = Convert.FromBase64String(material.Sk);
            ISignatureAlgorithm algorithm = _registry.Resolve(material.Alg);
            return new TrustKeyPair(material.Alg, algorithm.DerivePublicKey(privateKey), privateKey);
        }
        catch (JsonException ex)
        {
            throw new KeyContainerException("Container key material is not valid JSON.", ex);
        }
        catch (FormatException ex)
        {
            throw new KeyContainerException("Container key material is not valid base64.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private sealed record KeyMaterial(string Alg, string Sk);
}
