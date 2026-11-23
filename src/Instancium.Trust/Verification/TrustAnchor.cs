namespace Instancium.Trust.Verification;

/// <summary>
/// Out-of-band trust anchor (compiled constant, GitHub *.pub or DNS-verified fingerprint).
/// Multiple anchors implement the Primary/Backup root redundancy of the Assumed Breach model.
/// </summary>
/// <param name="Kid">Root key identifier.</param>
/// <param name="Alg">Expected signature algorithm id.</param>
/// <param name="PublicKey">Raw public key bytes.</param>
public sealed record TrustAnchor(string Kid, string Alg, byte[] PublicKey);
