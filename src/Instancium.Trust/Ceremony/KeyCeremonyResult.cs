namespace Instancium.Trust.Ceremony;

using Instancium.Trust.Keys;

/// <summary>
/// Public-only ceremony output. Private keys exist solely inside encrypted container files,
/// enforcing the "zero private keys in Git" measurable of the trust plan.
/// </summary>
/// <param name="PrimaryRoot">Published primary root document.</param>
/// <param name="BackupRoot">Published backup root document.</param>
/// <param name="ReleaseCertificateEnvelope">Encoded release-key.cert content.</param>
/// <param name="TrustConstantsSource">Generated TrustConstants.g.cs source.</param>
/// <param name="DnsTxtRecord">Ready-to-paste _trust.instancium.com TXT value.</param>
/// <param name="WrittenFiles">Absolute paths of every written artifact.</param>
public sealed record KeyCeremonyResult(
    RootPublicKeyDocument PrimaryRoot,
    RootPublicKeyDocument BackupRoot,
    string ReleaseCertificateEnvelope,
    string TrustConstantsSource,
    string DnsTxtRecord,
    IReadOnlyList<string> WrittenFiles);
