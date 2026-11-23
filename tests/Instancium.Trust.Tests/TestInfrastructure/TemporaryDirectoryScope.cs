namespace Instancium.Trust.Tests.TestInfrastructure;

/// <summary>
/// Isolated temp tree with recursive cleanup, mirroring the Publisher test convention
/// so ceremony file output never pollutes the working tree.
/// </summary>
public sealed class TemporaryDirectoryScope : IDisposable
{
    public TemporaryDirectoryScope()
    {
        RootPath = Path.GetFullPath(
            Path.Combine(Path.GetTempPath(), "instancium-trust-tests", Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(RootPath);
    }

    public string RootPath { get; }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(RootPath))
            {
                Directory.Delete(RootPath, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
