using System.Text.Json;

namespace LancerNexus.Updater;

public sealed record FailedRelease(int Schema, long ManifestVersion, string ClientPackageSha256,
    string DataManifestId, string SelectionFingerprint, DateTime FailedAtUtc);

public static class FailedReleaseStore
{
    public static bool IsKnownFailure(string installRoot, UpdateManifest manifest, UpdatePackage clientPackage,
        IReadOnlySet<string> optionalPackageIds)
    {
        var path = Path.Combine(Path.GetFullPath(installRoot), "failed-release.json");
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length is <= 0 or > 16_384) return false;
            using var input = File.OpenRead(path);
            var failed = JsonSerializer.Deserialize<FailedRelease>(input, TrustRoot.JsonOptions);
            return failed is { Schema: 1 } && failed.ManifestVersion == manifest.Version &&
                   failed.ClientPackageSha256 == clientPackage.Sha256 &&
                   failed.DataManifestId == manifest.DataManifestId &&
                   failed.SelectionFingerprint == DataPackageStager.SelectionFingerprint(manifest, optionalPackageIds);
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static void Record(string installRoot, UpdateManifest manifest, UpdatePackage clientPackage,
        IReadOnlySet<string> optionalPackageIds)
    {
        var path = Path.Combine(Path.GetFullPath(installRoot), "failed-release.json");
        var failure = new FailedRelease(1, manifest.Version, clientPackage.Sha256,
            manifest.DataManifestId, DataPackageStager.SelectionFingerprint(manifest, optionalPackageIds), DateTime.UtcNow);
        var temporary = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(output, failure, TrustRoot.JsonOptions);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public static void Clear(string installRoot)
    {
        var path = Path.Combine(Path.GetFullPath(installRoot), "failed-release.json");
        if (File.Exists(path)) File.Delete(path);
    }
}
