namespace Instancium.Trust.Algorithms;

/// <summary>
/// Plugin registry inside the trust library: new algorithms (e.g. ML-DSA) are added as
/// components without touching the verification engine or persisted artifact contracts.
/// </summary>
public sealed class SignatureAlgorithmRegistry
{
    private readonly Dictionary<string, ISignatureAlgorithm> _byId;

    public SignatureAlgorithmRegistry(IEnumerable<ISignatureAlgorithm> algorithms)
    {
        ArgumentNullException.ThrowIfNull(algorithms);
        _byId = new Dictionary<string, ISignatureAlgorithm>(StringComparer.Ordinal);
        foreach (ISignatureAlgorithm algorithm in algorithms)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(algorithm.AlgId);
            if (!_byId.TryAdd(algorithm.AlgId, algorithm))
            {
                throw new InvalidOperationException($"Duplicate signature algorithm id '{algorithm.AlgId}'.");
            }
        }

        if (_byId.Count == 0)
        {
            throw new ArgumentException("At least one signature algorithm must be registered.", nameof(algorithms));
        }
    }

    public IReadOnlyCollection<string> SupportedAlgorithms => _byId.Keys;

    public ISignatureAlgorithm Resolve(string algId)
    {
        return TryResolve(algId, out ISignatureAlgorithm? algorithm)
            ? algorithm!
            : throw new ArgumentOutOfRangeException(
                nameof(algId), algId,
                $"Unknown signature algorithm '{algId}'. Known: {string.Join(", ", _byId.Keys)}");
    }

    public bool TryResolve(string? algId, out ISignatureAlgorithm? algorithm)
    {
        if (string.IsNullOrWhiteSpace(algId))
        {
            algorithm = null;
            return false;
        }

        return _byId.TryGetValue(algId, out algorithm);
    }
}
