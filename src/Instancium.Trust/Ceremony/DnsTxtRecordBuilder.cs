namespace Instancium.Trust.Ceremony;

using Instancium.Trust.Keys;
using System.Globalization;

/// <summary>
/// Emits the exact _trust.instancium.com TXT layout fixed by the trust plan, so DNS,
/// README and compiled constants can be compared as literal strings.
/// </summary>
public static class DnsTxtRecordBuilder
{
    public static string Build(RootPublicKeyDocument primary, RootPublicKeyDocument backup)
    {
        ArgumentNullException.ThrowIfNull(primary);
        ArgumentNullException.ThrowIfNull(backup);
        if (!string.Equals(primary.Alg, backup.Alg, StringComparison.Ordinal))
        {
            throw new ArgumentException("Primary and backup roots must declare the same algorithm.");
        }

        return string.Create(CultureInfo.InvariantCulture,
            $"v={TrustFormat.Version}; alg={primary.Alg}; primary_kid={primary.Kid}; primary_sha256={primary.Sha256}; backup_kid={backup.Kid}; backup_sha256={backup.Sha256}");
    }
}
