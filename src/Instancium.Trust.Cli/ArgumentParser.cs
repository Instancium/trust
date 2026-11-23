namespace Instancium.Trust.Cli;

/// <summary>
/// Minimal --name value parser (repeatable keys). Zero dependencies keep the offline
/// ceremony tool auditable and runnable on an air-gapped machine without package feeds.
/// </summary>
internal static class ArgumentParser
{
    public static bool TryParse(IReadOnlyList<string> args, out Dictionary<string, List<string>> values, out string? error)
    {
        values = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        error = null;
        for (int i = 0; i < args.Count; i++)
        {
            string token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal) || token.Length <= 2)
            {
                error = $"Unexpected token '{token}'. Expected --name value pairs.";
                return false;
            }

            if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                error = $"Missing value for '{token}'.";
                return false;
            }

            string name = token[2..];
            if (!values.TryGetValue(name, out List<string>? list))
            {
                list = [];
                values[name] = list;
            }

            list.Add(args[++i]);
        }

        return true;
    }

    public static string? Single(Dictionary<string, List<string>> values, string name) =>
        values.TryGetValue(name, out List<string>? list) && list.Count > 0 ? list[^1] : null;
}
