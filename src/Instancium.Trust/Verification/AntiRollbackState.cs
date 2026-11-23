namespace Instancium.Trust.Verification;

/// <summary>
/// Last accepted release state supplied by the host application. The engine stays stateless;
/// persistence belongs to clients (installer, CLI), keeping the library reusable everywhere.
/// </summary>
/// <param name="Version">Last accepted manifest version.</param>
/// <param name="IssuedAt">Last accepted issuance timestamp (monotonic boundary).</param>
/// <param name="ManifestSha256">Hash of the last accepted manifest bytes; detects same-version substitution.</param>
public sealed record AntiRollbackState(string Version, DateTimeOffset IssuedAt, string ManifestSha256);
