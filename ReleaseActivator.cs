using System.Diagnostics;
using System.Text.Json;

namespace LancerNexus.Updater;

public static class ReleaseActivator
{
    public static bool TryStartCurrent(UpdateManifest manifest, UpdatePackage clientPackage, UpdaterOptions options)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var current = TryReadCurrentRelease(Path.Combine(installRoot, "current.json"));
        if (current is null || current.PackageSha256 != clientPackage.Sha256 ||
            current.ClientVersion != manifest.ClientVersion || current.BuildId != manifest.BuildId ||
            current.DataManifestId != manifest.DataManifestId)
            return false;

        var releasePath = ResolveReleasePath(installRoot, current.ReleaseDirectory);
        if (releasePath is null || !Directory.Exists(releasePath) ||
            (File.GetAttributes(releasePath) & FileAttributes.ReparsePoint) != 0 ||
            !MetadataMatches(Path.Combine(releasePath, "client-version.json"), manifest))
            return false;

        var executableName = OperatingSystem.IsWindows() ? "lancer.exe" : "lancer";
        var executablePath = Path.Combine(releasePath, executableName);
        if (!File.Exists(executablePath) || (File.GetAttributes(executablePath) & FileAttributes.ReparsePoint) != 0)
            return false;
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(executablePath);
            if ((mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0)
                return false;
        }

        var process = Process.Start(new ProcessStartInfo
        {
            FileName = executablePath,
            WorkingDirectory = releasePath,
            UseShellExecute = false
        }) ?? throw new InvalidOperationException("LibreLancer-Prozess konnte nicht gestartet werden.");
        Console.WriteLine($"LibreLancer wurde aus dem aktivierten Release gestartet (PID {process.Id}).");
        process.Dispose();
        return true;
    }

    public static string Activate(string stagedRelease, UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var stagingRoot = Path.Combine(installRoot, "staging");
        var expectedStagingRoot = Path.GetFullPath(stagingRoot) + Path.DirectorySeparatorChar;
        var stagedPath = Path.GetFullPath(stagedRelease);
        if (!stagedPath.StartsWith(expectedStagingRoot, StringComparison.Ordinal) ||
            !Directory.Exists(stagedPath) || Path.GetFileName(stagedPath).Length == 0)
            throw new InvalidOperationException("Stagingrelease liegt nicht im Installations-Stagingbereich.");

        var releasesRoot = Path.Combine(installRoot, "releases");
        Directory.CreateDirectory(releasesRoot);
        var releaseName = Path.GetFileName(stagedPath);
        var releasePath = Path.Combine(releasesRoot, releaseName);
        Directory.Move(stagedPath, releasePath);

        var pointerPath = Path.Combine(installRoot, "current.json");
        var previousRelease = TryReadCurrentRelease(pointerPath)?.ReleaseDirectory;
        var pointer = new CurrentRelease(1, manifest.ClientVersion, manifest.BuildId,
            $"releases/{releaseName}", previousRelease, clientPackage.Sha256,
            manifest.DataManifestId, DateTime.UtcNow);
        var temporaryPath = Path.Combine(installRoot, $".current-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(output, pointer, TrustRoot.JsonOptions);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, pointerPath, overwrite: true);
            return releasePath;
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static CurrentRelease? TryReadCurrentRelease(string pointerPath)
    {
        try
        {
            var info = new FileInfo(pointerPath);
            if (!info.Exists || info.Length is <= 0 or > 16_384)
                return null;
            using var input = File.OpenRead(pointerPath);
            var current = JsonSerializer.Deserialize<CurrentRelease>(input, TrustRoot.JsonOptions);
            if (current is null || current.Schema != 1 || !IsSafeReleasePath(current.ReleaseDirectory) ||
                string.IsNullOrWhiteSpace(current.ClientVersion) || string.IsNullOrWhiteSpace(current.BuildId) ||
                string.IsNullOrWhiteSpace(current.DataManifestId) || string.IsNullOrWhiteSpace(current.PackageSha256) ||
                current.PackageSha256.Length != 64 ||
                !current.PackageSha256.All(Uri.IsHexDigit))
                return null;
            return current;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? ResolveReleasePath(string installRoot, string relativePath)
    {
        if (!IsSafeReleasePath(relativePath))
            return null;
        var releasesRoot = Path.GetFullPath(Path.Combine(installRoot, "releases")) + Path.DirectorySeparatorChar;
        var releasePath = Path.GetFullPath(Path.Combine(installRoot, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        return releasePath.StartsWith(releasesRoot, StringComparison.Ordinal) ? releasePath : null;
    }

    private static bool MetadataMatches(string metadataPath, UpdateManifest manifest)
    {
        try
        {
            var info = new FileInfo(metadataPath);
            if (!info.Exists || info.Length is <= 0 or > 16_384 ||
                (File.GetAttributes(metadataPath) & FileAttributes.ReparsePoint) != 0)
                return false;
            using var input = File.OpenRead(metadataPath);
            var metadata = JsonSerializer.Deserialize<ClientVersionMetadata>(input, TrustRoot.JsonOptions);
            return metadata is not null && metadata.Capabilities is not null &&
                   metadata.ClientVersion == manifest.ClientVersion &&
                   metadata.BuildId == manifest.BuildId && metadata.ProtocolVersion == manifest.ProtocolVersion &&
                   metadata.DataManifestId == manifest.DataManifestId &&
                   metadata.Platform == $"{manifest.Platform}-{manifest.Architecture}" &&
                   metadata.Channel == manifest.Channel && metadata.Capabilities.SequenceEqual(manifest.Capabilities);
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsSafeReleasePath(string path) =>
        !string.IsNullOrWhiteSpace(path) && path.StartsWith("releases/", StringComparison.Ordinal) &&
        path.Length > "releases/".Length && !path["releases/".Length..].Contains('/') &&
        !path.Contains('\\') && path["releases/".Length..] is not ("." or "..");

    private sealed record CurrentRelease(int Schema, string ClientVersion, string BuildId,
        string ReleaseDirectory, string? PreviousReleaseDirectory, string PackageSha256,
        string DataManifestId, DateTime ActivatedAtUtc);

    private sealed record ClientVersionMetadata(string ClientVersion, string BuildId, int ProtocolVersion,
        string DataManifestId, string Platform, string Channel, IReadOnlyList<string> Capabilities);
}
