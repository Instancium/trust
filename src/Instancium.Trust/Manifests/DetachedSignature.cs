namespace Instancium.Trust.Manifests;

/// <summary>
/// Detached *.sig file content: plain base64 of the raw signature over exact manifest bytes.
/// Keeps signature files human-inspectable and trivially decodable in browser JS.
/// </summary>
public static class DetachedSignature
{
    public static string ToText(byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        return Convert.ToBase64String(signature);
    }

    public static byte[] FromText(string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        try
        {
            return Convert.FromBase64String(text.Trim());
        }
        catch (FormatException ex)
        {
            throw new FormatException("Detached signature is not valid base64.", ex);
        }
    }
}
