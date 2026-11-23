namespace Instancium.Trust.Keys;

/// <summary>
/// Argon2id cost parameters as configuration, not hardcode: hardware hardening can raise
/// the cost later without breaking existing containers (parameters are stored per container).
/// </summary>
public sealed class KeyContainerOptions
{
    public int MemoryKiB { get; set; } = 65536;
    public int Iterations { get; set; } = 3;
    public int Parallelism { get; set; } = 4;
    public int SaltSizeBytes { get; set; } = 16;

    public void Validate()
    {
        if (Parallelism < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(Parallelism), "Parallelism must be at least 1.");
        }

        if (MemoryKiB < 8 * Parallelism)
        {
            throw new ArgumentOutOfRangeException(nameof(MemoryKiB), "Argon2 memory must be at least 8 KiB per lane.");
        }

        if (Iterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(Iterations), "Iterations must be at least 1.");
        }

        if (SaltSizeBytes < 8)
        {
            throw new ArgumentOutOfRangeException(nameof(SaltSizeBytes), "Salt must be at least 8 bytes.");
        }
    }
}
