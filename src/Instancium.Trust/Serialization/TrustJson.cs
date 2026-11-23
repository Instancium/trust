namespace Instancium.Trust.Serialization;

using System.Text.Json;

/// <summary>
/// Shared serializer settings. Signatures cover exact serialized bytes (no canonicalization),
/// therefore indentation is a readability choice and never a verification concern.
/// </summary>
public static class TrustJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };
}
