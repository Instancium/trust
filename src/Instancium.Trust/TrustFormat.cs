namespace Instancium.Trust;

/// <summary>
/// Single source of the on-disk format version so containers, envelopes and DNS records
/// can never drift apart during future format migrations.
/// </summary>
public static class TrustFormat
{
    public const string Version = "inst1";
}
