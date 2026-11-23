namespace Instancium.Trust.Ceremony;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Certificates;
using Instancium.Trust.Keys;
using System.Text;

/// <summary>
/// Offline ceremony orchestrator: generates cold Primary/Backup roots and a hot Release Key,
/// then exports every trust channel from one key set. Private keys are wiped after writing
/// encrypted containers, so ceremony output is safe to publish verbatim.
/// </summary>
public sealed class KeyCeremonyService
{
    private const string PrimaryPublicFileName = "root-primary.pub";
    private const string BackupPublicFileName = "root-backup.pub";
    private const string PrimaryContainerFileName = "root-primary.key.json";
    private const string BackupContainerFileName = "root-backup.key.json";
    private const string ReleaseContainerFileName = "release-key.key.json";
    private const string CertificateFileName = "release-key.cert";
    private const string ConstantsFileName = "TrustConstants.g.cs";
    private const string DnsFileName = "dns-trust-record.txt";

    private readonly SignatureAlgorithmRegistry _registry;
    private readonly KeyContainerCodec _containerCodec;

    public KeyCeremonyService(SignatureAlgorithmRegistry registry, KeyContainerCodec containerCodec)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _containerCodec = containerCodec ?? throw new ArgumentNullException(nameof(containerCodec));
    }

    public KeyCeremonyResult Execute(KeyCeremonyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);

        ISignatureAlgorithm algorithm = _registry.Resolve(options.SignatureAlgorithmId);
        TrustKeyPair primary = algorithm.GenerateKeyPair();
        TrustKeyPair backup = algorithm.GenerateKeyPair();
        TrustKeyPair release = algorithm.GenerateKeyPair();
        try
        {
            var primaryDocument = RootPublicKeyDocument.FromKeyPair(options.PrimaryRootKid, primary);
            var backupDocument = RootPublicKeyDocument.FromKeyPair(options.BackupRootKid, backup);

            var certificate = new ReleaseKeyCertificate(
                options.ReleaseKeyKid, algorithm.AlgId,
                Convert.ToBase64String(release.PublicKey),
                options.CeremonyTime,
                options.CeremonyTime + options.ReleaseKeyValidity,
                options.PrimaryRootKid);
            byte[] certificatePayload = certificate.ToJsonBytes();
            var envelope = new SignedEnvelope(
                algorithm.AlgId, certificatePayload,
                algorithm.Sign(certificatePayload, primary.PrivateKey));

            string constants = TrustConstantsExporter.Export(primaryDocument, backupDocument);
            string dnsRecord = DnsTxtRecordBuilder.Build(primaryDocument, backupDocument);

            Directory.CreateDirectory(options.OutputDirectory);
            var writtenFiles = new List<string>();
            WriteText(writtenFiles, options.OutputDirectory, PrimaryPublicFileName, Encoding.UTF8.GetString(primaryDocument.ToJsonBytes()));
            WriteText(writtenFiles, options.OutputDirectory, BackupPublicFileName, Encoding.UTF8.GetString(backupDocument.ToJsonBytes()));
            WriteText(writtenFiles, options.OutputDirectory, CertificateFileName, envelope.Encode());
            WriteText(writtenFiles, options.OutputDirectory, ConstantsFileName, constants);
            WriteText(writtenFiles, options.OutputDirectory, DnsFileName, dnsRecord);
            WriteText(writtenFiles, options.OutputDirectory, PrimaryContainerFileName,
                _containerCodec.Protect(primary, options.RootContainerPassword, options.Container));
            WriteText(writtenFiles, options.OutputDirectory, BackupContainerFileName,
                _containerCodec.Protect(backup, options.RootContainerPassword, options.Container));
            WriteText(writtenFiles, options.OutputDirectory, ReleaseContainerFileName,
                _containerCodec.Protect(release, options.ReleaseContainerPassword, options.Container));

            return new KeyCeremonyResult(
                primaryDocument, backupDocument, envelope.Encode(), constants, dnsRecord, writtenFiles);
        }
        finally
        {
            primary.WipePrivateKey();
            backup.WipePrivateKey();
            release.WipePrivateKey();
        }
    }

    private static void ValidateOptions(KeyCeremonyOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.OutputDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.PrimaryRootKid);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.BackupRootKid);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ReleaseKeyKid);
        ArgumentException.ThrowIfNullOrEmpty(options.RootContainerPassword);
        ArgumentException.ThrowIfNullOrEmpty(options.ReleaseContainerPassword);
        if (options.ReleaseKeyValidity <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Release key validity must be positive.");
        }

        options.Container.Validate();
    }

    private static void WriteText(List<string> writtenFiles, string directory, string fileName, string content)
    {
        string path = Path.Combine(directory, fileName);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        writtenFiles.Add(path);
    }
}
