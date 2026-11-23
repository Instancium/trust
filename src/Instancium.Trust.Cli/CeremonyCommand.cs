namespace Instancium.Trust.Cli;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Ceremony;
using Instancium.Trust.Keys;
using System.Globalization;

/// <summary>
/// Offline key ceremony entry point: interactive passwords never enter argv, shell history
/// or configuration files, matching the zero-private-key-leak measurable.
/// </summary>
internal static class CeremonyCommand
{
    public static int Run(Dictionary<string, List<string>> values)
    {
        string? output = ArgumentParser.Single(values, "out");
        if (string.IsNullOrWhiteSpace(output))
        {
            Console.Error.WriteLine("Usage: ceremony --out <dir> [--alg ed25519] [--primary-kid <id>] [--backup-kid <id>] [--release-kid <id>] [--validity-days <n>]");
            return 2;
        }

        var options = new KeyCeremonyOptions { OutputDirectory = Path.GetFullPath(output) };
        options.SignatureAlgorithmId = ArgumentParser.Single(values, "alg") ?? options.SignatureAlgorithmId;
        options.PrimaryRootKid = ArgumentParser.Single(values, "primary-kid") ?? options.PrimaryRootKid;
        options.BackupRootKid = ArgumentParser.Single(values, "backup-kid") ?? options.BackupRootKid;
        options.ReleaseKeyKid = ArgumentParser.Single(values, "release-kid") ?? options.ReleaseKeyKid;

        string? validityDays = ArgumentParser.Single(values, "validity-days");
        if (validityDays is not null)
        {
            if (!int.TryParse(validityDays, CultureInfo.InvariantCulture, out int days) || days <= 0)
            {
                Console.Error.WriteLine("--validity-days must be a positive integer.");
                return 2;
            }

            options.ReleaseKeyValidity = TimeSpan.FromDays(days);
        }

        Console.WriteLine("Instancium Key Ceremony (run on an isolated offline machine).");
        options.RootContainerPassword = SecureConsole.ReadConfirmedPassword("Root container password: ");
        options.ReleaseContainerPassword = SecureConsole.ReadConfirmedPassword("Release container password: ");

        var registry = new SignatureAlgorithmRegistry([new Ed25519SignatureAlgorithm()]);
        var service = new KeyCeremonyService(registry, new KeyContainerCodec(registry, new KeyContainerProtector()));
        KeyCeremonyResult result = service.Execute(options);

        Console.WriteLine();
        Console.WriteLine($"Primary root: {result.PrimaryRoot.Kid}  sha256={result.PrimaryRoot.Sha256}");
        Console.WriteLine($"Backup root:  {result.BackupRoot.Kid}  sha256={result.BackupRoot.Sha256}");
        Console.WriteLine();
        Console.WriteLine("DNS TXT for _trust.instancium.com:");
        Console.WriteLine(result.DnsTxtRecord);
        Console.WriteLine();
        Console.WriteLine("Written artifacts:");
        foreach (string path in result.WrittenFiles)
        {
            Console.WriteLine($"  {path}");
        }

        Console.WriteLine();
        Console.WriteLine("Move *.key.json containers to offline media. Publish only *.pub, release-key.cert, TrustConstants.g.cs and the DNS record.");
        return 0;
    }
}
