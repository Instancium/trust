namespace Instancium.Trust.Keys;

/// <summary>
/// Uniform failure type for wrong password, tampered ciphertext and malformed containers,
/// so callers never need to distinguish cryptographic exception subtypes.
/// </summary>
public sealed class KeyContainerException : Exception
{
    public KeyContainerException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
