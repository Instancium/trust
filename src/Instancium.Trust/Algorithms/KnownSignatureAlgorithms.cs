namespace Instancium.Trust.Algorithms;

/// <summary>
/// Well-known algorithm ids persisted in signed artifacts. Reserved for PQC migration:
/// "ml-dsa-65" and the hybrid "ed25519+ml-dsa-65" (registered later without contract changes).
/// </summary>
public static class KnownSignatureAlgorithms
{
    public const string Ed25519 = "ed25519";
}
