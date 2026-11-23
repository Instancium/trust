namespace Instancium.Trust.Keys;

using Instancium.Trust.Serialization;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// Password-protected byte container: Argon2id derives a 256-bit key, AES-256-GCM (BCL,
/// hardware-accelerated) authenticates ciphertext AND KDF parameters via AAD, so editing
/// cost parameters in the JSON is detected as tampering, not accepted as a downgrade.
/// </summary>
public sealed class KeyContainerProtector
{
    private const int DerivedKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    // Safety guards against hostile containers driving KDF cost (DoS), not business configuration.
    private const int MaxMemoryKiB = 1_048_576;
    private const int MaxIterations = 100;
    private const int MaxParallelism = 64;

    public string Protect(ReadOnlySpan<byte> plaintext, string password, KeyContainerOptions options)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        byte[] salt = RandomNumberGenerator.GetBytes(options.SaltSizeBytes);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] key = new byte[DerivedKeySizeBytes];
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSizeBytes];
        try
        {
            DeriveKey(passwordBytes, salt, options.MemoryKiB, options.Iterations, options.Parallelism, key);
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Encrypt(nonce, plaintext, ciphertext, tag,
                BuildAad(options.MemoryKiB, options.Iterations, options.Parallelism, salt, nonce));

            var envelope = new ContainerEnvelope(
                TrustFormat.Version, "argon2id",
                options.MemoryKiB, options.Iterations, options.Parallelism,
                Convert.ToBase64String(salt), Convert.ToBase64String(nonce),
                Convert.ToBase64String(ciphertext), Convert.ToBase64String(tag));
            return JsonSerializer.Serialize(envelope, TrustJson.Options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    public byte[] Unprotect(string containerJson, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerJson);
        ArgumentException.ThrowIfNullOrEmpty(password);

        ContainerEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<ContainerEnvelope>(containerJson, TrustJson.Options);
        }
        catch (JsonException ex)
        {
            throw new KeyContainerException("Container is not valid JSON.", ex);
        }

        if (envelope is null ||
            !string.Equals(envelope.V, TrustFormat.Version, StringComparison.Ordinal) ||
            !string.Equals(envelope.Kdf, "argon2id", StringComparison.Ordinal))
        {
            throw new KeyContainerException("Unsupported container format or KDF.");
        }

        if (envelope.M < 8 * envelope.P || envelope.M > MaxMemoryKiB ||
            envelope.T < 1 || envelope.T > MaxIterations ||
            envelope.P < 1 || envelope.P > MaxParallelism)
        {
            throw new KeyContainerException("Container KDF parameters are outside the accepted safety range.");
        }

        byte[] salt, nonce, ciphertext, tag;
        try
        {
            salt = Convert.FromBase64String(envelope.Salt);
            nonce = Convert.FromBase64String(envelope.Nonce);
            ciphertext = Convert.FromBase64String(envelope.Ct);
            tag = Convert.FromBase64String(envelope.Tag);
        }
        catch (FormatException ex)
        {
            throw new KeyContainerException("Container fields are not valid base64.", ex);
        }

        if (salt.Length < 8 || nonce.Length != NonceSizeBytes || tag.Length != TagSizeBytes || ciphertext.Length == 0)
        {
            throw new KeyContainerException("Container field sizes are invalid.");
        }

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] key = new byte[DerivedKeySizeBytes];
        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            DeriveKey(passwordBytes, salt, envelope.M, envelope.T, envelope.P, key);
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext,
                BuildAad(envelope.M, envelope.T, envelope.P, salt, nonce));
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new KeyContainerException("Container authentication failed: wrong password or tampered data.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static void DeriveKey(byte[] password, byte[] salt, int memoryKiB, int iterations, int parallelism, byte[] output)
    {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(memoryKiB)
            .WithIterations(iterations)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();

        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);
        generator.GenerateBytes(password, output);
    }

    private static byte[] BuildAad(int memoryKiB, int iterations, int parallelism, byte[] salt, byte[] nonce) =>
        Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture,
            $"{TrustFormat.Version}|argon2id|{memoryKiB}|{iterations}|{parallelism}|{Convert.ToBase64String(salt)}|{Convert.ToBase64String(nonce)}"));

    private sealed record ContainerEnvelope(
        string V, string Kdf, int M, int T, int P,
        string Salt, string Nonce, string Ct, string Tag);
}
