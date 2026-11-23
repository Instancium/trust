namespace Instancium.Trust.Tests.Keys;

using Instancium.Trust.Keys;
using Instancium.Trust.Tests.TestInfrastructure;
using System.Text.Json;
using Xunit;

/// <summary>
/// Verifies Argon2id + AES-256-GCM containers: roundtrip, wrong password, ciphertext tampering
/// and KDF parameter downgrade attempts (AAD binding), plus the production-cost profile.
/// </summary>
public sealed class KeyContainerProtectorTests
{
    private readonly KeyContainerProtector _protector = new();

    [Fact]
    public void ProtectUnprotect_RoundTrip_ReturnsOriginalBytes()
    {
        byte[] secret = "private-key-material"u8.ToArray();
        string container = _protector.Protect(secret, "correct horse", TrustTestFactory.FastContainerOptions);
        Assert.Equal(secret, _protector.Unprotect(container, "correct horse"));
    }

    [Fact]
    public void Unprotect_WrongPassword_ThrowsKeyContainerException()
    {
        string container = _protector.Protect("secret"u8, "correct horse", TrustTestFactory.FastContainerOptions);
        Assert.Throws<KeyContainerException>(() => _protector.Unprotect(container, "wrong horse"));
    }

    [Fact]
    public void Unprotect_TamperedCiphertext_ThrowsKeyContainerException()
    {
        string container = _protector.Protect("secret"u8, "password", TrustTestFactory.FastContainerOptions);
        using JsonDocument document = JsonDocument.Parse(container);
        byte[] ciphertext = Convert.FromBase64String(document.RootElement.GetProperty("ct").GetString()!);
        ciphertext[0] ^= 1;
        string tampered = ReplaceJsonProperty(container, "ct", Convert.ToBase64String(ciphertext));
        Assert.Throws<KeyContainerException>(() => _protector.Unprotect(tampered, "password"));
    }

    [Fact]
    public void Unprotect_TamperedKdfParameters_ThrowsKeyContainerException()
    {
        string container = _protector.Protect("secret"u8, "password", TrustTestFactory.FastContainerOptions);
        string downgraded = ReplaceJsonProperty(container, "m", "4096");
        Assert.Throws<KeyContainerException>(() => _protector.Unprotect(downgraded, "password"));
    }

    [Fact]
    public void ProtectUnprotect_ProductionCostProfile_RoundTrips()
    {
        byte[] secret = "production-profile"u8.ToArray();
        string container = _protector.Protect(secret, "password", new KeyContainerOptions());
        Assert.Equal(secret, _protector.Unprotect(container, "password"));
    }

    private static string ReplaceJsonProperty(string json, string propertyName, string newValue)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        var dictionary = new Dictionary<string, JsonElement>();
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            dictionary[property.Name] = property.Value;
        }

        string rawValue = propertyName == "m" ? newValue : $"\"{newValue}\"";
        var parts = dictionary.Select(kvp =>
            $"\"{kvp.Key}\":{(kvp.Key == propertyName ? rawValue : kvp.Value.GetRawText())}");
        return "{" + string.Join(",", parts) + "}";
    }
}
