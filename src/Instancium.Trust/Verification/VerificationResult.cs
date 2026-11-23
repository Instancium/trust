namespace Instancium.Trust.Verification;

/// <summary>
/// Machine-readable failure codes let clients localize messages and let tests assert
/// the exact broken chain link instead of a generic boolean.
/// </summary>
/// <param name="IsValid">True only when the whole chain passed.</param>
/// <param name="FailureCode">Stable code from <see cref="VerificationFailureCodes"/>.</param>
/// <param name="FailureReason">Human-readable diagnostic detail.</param>
public sealed record VerificationResult(bool IsValid, string? FailureCode, string? FailureReason)
{
    public static VerificationResult Success() => new(true, null, null);

    public static VerificationResult Fail(string code, string reason) => new(false, code, reason);
}
