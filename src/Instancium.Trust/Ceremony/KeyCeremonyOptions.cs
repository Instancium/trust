namespace Instancium.Trust.Ceremony;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Keys;
using System.Globalization;

/// <summary>
/// Ceremony inputs as configuration: kids, validity and KDF cost can be adjusted per
/// ceremony without code changes; passwords are supplied at runtime, never persisted.
/// </summary>
public sealed class KeyCeremonyOptions
{
    public string OutputDirectory { get; set; } = string.Empty;
    public string SignatureAlgorithmId { get; set; } = KnownSignatureAlgorithms.Ed25519;
    public string PrimaryRootKid { get; set; } = string.Create(CultureInfo.InvariantCulture, $"root-primary-{DateTimeOffset.UtcNow.Year}");
    public string BackupRootKid { get; set; } = string.Create(CultureInfo.InvariantCulture, $"root-backup-{DateTimeOffset.UtcNow.Year}");
    public string ReleaseKeyKid { get; set; } = string.Create(CultureInfo.InvariantCulture, $"release-{DateTimeOffset.UtcNow:yyyy-MM}");
    public TimeSpan ReleaseKeyValidity { get; set; } = TimeSpan.FromDays(365);
    public string RootContainerPassword { get; set; } = string.Empty;
    public string ReleaseContainerPassword { get; set; } = string.Empty;
    public KeyContainerOptions Container { get; set; } = new();

    /// <summary>Injected clock keeps ceremony output deterministic in tests.</summary>
    public DateTimeOffset CeremonyTime { get; set; } = DateTimeOffset.UtcNow;
}
