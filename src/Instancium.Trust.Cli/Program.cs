namespace Instancium.Trust.Cli;

using Instancium.Trust.Keys;
using System.Text;

internal static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0)
        {
            PrintUsage();
            return 2;
        }

        if (!ArgumentParser.TryParse(args[1..], out Dictionary<string, List<string>> values, out string? error))
        {
            Console.Error.WriteLine(error);
            return 2;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "ceremony" => CeremonyCommand.Run(values),
                "verify" => VerifyCommand.Run(values),
                _ => PrintUsage()
            };
        }
        catch (Exception ex) when (ex is IOException or FormatException or KeyContainerException or ArgumentException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static int PrintUsage()
    {
        Console.WriteLine("Instancium.Trust.Cli");
        Console.WriteLine("  ceremony --out <dir> [--alg ed25519] [--primary-kid <id>] [--backup-kid <id>] [--release-kid <id>] [--validity-days <n>]");
        Console.WriteLine("  verify   --manifest <file> --sig <file> --cert <file> --root <file.pub> [--root ...] [--artifacts-dir <dir>]");
        return 2;
    }
}
