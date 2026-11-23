namespace Instancium.Trust.Serialization;

/// <summary>
/// URL-safe base64 without padding for compact signed envelopes; keeps certificates
/// paste-safe into DNS, markdown and query strings without escaping.
/// </summary>
internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string text)
    {
        int padding = (4 - text.Length % 4) % 4;
        string base64 = text.Replace('-', '+').Replace('_', '/') + new string('=', padding);
        return Convert.FromBase64String(base64);
    }
}
