namespace Instancium.Trust.Certificates;

using Instancium.Trust.Serialization;

/// <summary>
/// Single-file signed artifact: inst1.{alg}.{b64url(payload)}.{b64url(sig)}.
/// The signature covers exact payload bytes, so no JSON canonicalization exists anywhere
/// in the chain and C#/JS verifiers stay trivially compatible.
/// </summary>
/// <param name="Alg">Algorithm id used for the embedded signature.</param>
/// <param name="Payload">Exact signed bytes (certificate JSON).</param>
/// <param name="Signature">Raw signature bytes over <paramref name="Payload"/>.</param>
public sealed record SignedEnvelope(string Alg, byte[] Payload, byte[] Signature)
{
    public string Encode() =>
        string.Join('.', TrustFormat.Version, Alg, Base64Url.Encode(Payload), Base64Url.Encode(Signature));

    public static bool TryDecode(string? text, out SignedEnvelope? envelope)
    {
        envelope = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string[] parts = text.Trim().Split('.');
        if (parts.Length != 4 ||
            !string.Equals(parts[0], TrustFormat.Version, StringComparison.Ordinal) ||
            parts[1].Length == 0)
        {
            return false;
        }

        try
        {
            byte[] payload = Base64Url.Decode(parts[2]);
            byte[] signature = Base64Url.Decode(parts[3]);
            if (payload.Length == 0 || signature.Length == 0)
            {
                return false;
            }

            envelope = new SignedEnvelope(parts[1], payload, signature);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
