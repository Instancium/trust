namespace Instancium.Trust.Cli;

using Instancium.Trust.Algorithms;
using Instancium.Trust.Certificates;
using Instancium.Trust.Keys;
using Instancium.Trust.Manifests;
using Instancium.Trust.Verification;

/// <summary>
/// Full-chain verification entry point reused later by the installer (--verify).
/// Artifact paths are confined to the artifacts root: a signed manifest must still not
/// be able to read files outside the verification directory (path traversal guard).
/// </summary>
internal static class VerifyCommand
{
    public static int Run(Dictionary<string, List<string>> values)
    {
        string? manifestPath = ArgumentParser.Single(values, "manifest");
        string? signaturePath = ArgumentParser.Single(values, "sig");
        string? certificatePath = ArgumentParser.Single(values, "cert");
        if (manifestPath is null || signaturePath is null || certificatePath is null ||
            !values.TryGetValue("root", out List<string>? rootPaths) || rootPaths.Count == 0)
        {
            Console.Error.WriteLine("Usage: verify --manifest <file> --sig <file> --cert <file> --root <file.pub> [--root <file.pub> ...] [--artifacts-dir <dir>]");
            return 2;
        }

        byte[] manifestBytes = File.ReadAllBytes(manifestPath);
        byte[] manifestSignature = DetachedSignature.FromText(File.ReadAllText(signaturePath));
        if (!SignedEnvelope.TryDecode(File.ReadAllText(certificatePath), out SignedEnvelope? envelope))
        {
            Console.WriteLine("FAIL malformed-certificate: certificate envelope cannot be decoded.");
            return 1;
        }

        var roots = new List<TrustAnchor>();
        foreach (string rootPath in rootPaths)
        {
            RootPublicKeyDocument document = RootPublicKeyDocument.FromJsonBytes(File.ReadAllBytes(rootPath));
            if (!document.HasValidFingerprint())
            {
                Console.WriteLine($"FAIL unknown-root-key: '{rootPath}' fingerprint does not match its public key.");
                return 1;
            }

            roots.Add(document.ToAnchor());
        }

        var engine = new TrustVerificationEngine(new SignatureAlgorithmRegistry([new Ed25519SignatureAlgorithm()]));
        VerificationResult result = engine.VerifyManifest(manifestBytes, manifestSignature, envelope!, roots);
        if (!result.IsValid)
        {
            Console.WriteLine($"FAIL {result.FailureCode}: {result.FailureReason}");
            return 1;
        }

        string? artifactsDir = ArgumentParser.Single(values, "artifacts-dir");
        if (artifactsDir is not null)
        {
            string artifactsRoot = Path.GetFullPath(artifactsDir);
            ReleaseManifest manifest = ReleaseManifest.FromJsonBytes(manifestBytes);
            foreach (ManifestArtifact artifact in manifest.Artifacts)
            {
                string artifactPath = Path.GetFullPath(Path.Combine(artifactsRoot, artifact.Path));
                if (!artifactPath.StartsWith(artifactsRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                {
                    Console.WriteLine($"FAIL artifact-hash-mismatch: artifact path '{artifact.Path}' escapes the artifacts root.");
                    return 1;
                }

                if (!File.Exists(artifactPath))
                {
                    Console.WriteLine($"FAIL artifact-hash-mismatch: artifact '{artifact.Path}' is missing.");
                    return 1;
                }

                VerificationResult artifactResult = engine.VerifyArtifact(File.ReadAllBytes(artifactPath), artifact);
                if (!artifactResult.IsValid)
                {
                    Console.WriteLine($"FAIL {artifactResult.FailureCode}: {artifactResult.FailureReason}");
                    return 1;
                }
            }
        }

        Console.WriteLine("OK: trust chain and artifact hashes are valid.");
        return 0;
    }
}
