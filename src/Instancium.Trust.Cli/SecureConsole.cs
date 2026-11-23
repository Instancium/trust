namespace Instancium.Trust.Cli;

using System.Text;

/// <summary>
/// Masked password input with confirmation. Strings cannot be zeroized in .NET, therefore
/// password lifetime is kept to the ceremony call only; key material itself is zeroized.
/// </summary>
internal static class SecureConsole
{
    public static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var builder = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length > 0)
                {
                    builder.Remove(builder.Length - 1, 1);
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
            }
        }

        return builder.ToString();
    }

    public static string ReadConfirmedPassword(string prompt)
    {
        while (true)
        {
            string first = ReadPassword(prompt);
            if (first.Length == 0)
            {
                Console.WriteLine("Password must not be empty.");
                continue;
            }

            string second = ReadPassword("Confirm password: ");
            if (string.Equals(first, second, StringComparison.Ordinal))
            {
                return first;
            }

            Console.WriteLine("Passwords do not match. Try again.");
        }
    }
}
