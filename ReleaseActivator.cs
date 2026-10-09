using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LancerNexus.Updater;

public static class ReleaseActivator
{
    public enum StartResult { NotCurrent, Healthy, Failed }
    internal enum ActivationBoundary { ReleaseDirectoryMoved, PointerTemporaryWritten, CurrentPointerReplaced }
    private static readonly TimeSpan HealthTimeout = TimeSpan.FromMinutes(5);

    public static async Task<StartResult> TryStartCurrentAsync(UpdateManifest manifest,
        UpdatePackage clientPackage, UpdaterOptions options, CancellationToken cancellationToken)
        => await TryStartCurrentAsync(manifest, clientPackage, options, HealthTimeout, cancellationToken);

    internal static async Task<StartResult> TryStartCurrentAsync(UpdateManifest manifest,
        UpdatePackage clientPackage, UpdaterOptions options, TimeSpan healthTimeout,
        CancellationToken cancellationToken)
    {
        if (healthTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(healthTimeout));
        if (!IsCurrentVerified(manifest, clientPackage, options))
            return StartResult.NotCurrent;
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var current = TryReadCurrentRelease(Path.Combine(installRoot, "current.json"));
        var releasePath = ResolveReleasePath(installRoot, current!.ReleaseDirectory)!;
        var executableName = OperatingSystem.IsWindows() ? "lancer.exe" : "lancer";
        var executablePath = Path.Combine(releasePath, executableName);
        bool healthy;
        try { healthy = await StartAndAwaitHealthAsync(executablePath, releasePath, installRoot, healthTimeout, cancellationToken); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine($"Clientstart/Health-Handshake fehlgeschlagen: {error.Message}");
            healthy = false;
        }
        if (healthy) MarkCurrentHealthy(installRoot);
        return healthy ? StartResult.Healthy : StartResult.Failed;
    }

    public static bool IsCurrentVerified(UpdateManifest manifest, UpdatePackage clientPackage, UpdaterOptions options)
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
            !MetadataMatches(Path.Combine(releasePath, "client-version.json"), manifest) ||
            !DataPackageStager.MatchesSnapshot(releasePath, manifest, options.OptionalDataPackages))
            return false;

        var executable = Path.Combine(releasePath, OperatingSystem.IsWindows() ? "lancer.exe" : "lancer");
        if (!File.Exists(executable) || (File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0)
            return false;
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(executable);
            if ((mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0)
                return false;
        }
        return true;
    }

    public static bool RollbackCurrent(UpdaterOptions options)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var pointerPath = Path.Combine(installRoot, "current.json");
        var current = TryReadCurrentRelease(pointerPath);
        if (current?.Previous is null)
            return false;
        WriteCurrent(pointerPath, current.Previous with { Previous = null });
        return true;
    }

    public static async Task<bool> TryStartRestoredCurrentAsync(UpdaterOptions options,
        CancellationToken cancellationToken)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var current = TryReadCurrentRelease(Path.Combine(installRoot, "current.json"));
        if (current is null) return false;
        var releasePath = ResolveReleasePath(installRoot, current.ReleaseDirectory);
        if (releasePath is null || !Directory.Exists(releasePath) ||
            (File.GetAttributes(releasePath) & FileAttributes.ReparsePoint) != 0)
            return false;
        if (!MetadataIsSane(Path.Combine(releasePath, "client-version.json")))
            return false;
        var executable = Path.Combine(releasePath, OperatingSystem.IsWindows() ? "lancer.exe" : "lancer");
        if (!File.Exists(executable) || (File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0 ||
            !DataPackageStager.VerifyStoredSnapshot(releasePath))
            return false;
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(executable) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0)
            return false;
        bool healthy;
        try
        {
            var metadataPath = Path.Combine(releasePath, "client-version.json");
            healthy = UsesStartupHealthProtocol(metadataPath)
                ? await StartAndAwaitHealthAsync(executable, releasePath, installRoot, HealthTimeout, cancellationToken)
                : StartLegacyRelease(executable, releasePath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine($"Rollback-Start/Health-Handshake fehlgeschlagen: {error.Message}");
            healthy = false;
        }
        if (healthy) MarkCurrentHealthy(installRoot);
        return healthy;
    }

    public static string Activate(string stagedRelease, UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options)
        => Activate(stagedRelease, manifest, clientPackage, options, null);

    internal static string Activate(string stagedRelease, UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options, Action<ActivationBoundary>? onBoundary)
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
        onBoundary?.Invoke(ActivationBoundary.ReleaseDirectoryMoved);

        var pointerPath = Path.Combine(installRoot, "current.json");
        var previous = TryReadCurrentRelease(pointerPath);
        var pointer = new CurrentRelease(1, manifest.ClientVersion, manifest.BuildId,
            $"releases/{releaseName}", previous?.ReleaseDirectory, clientPackage.Sha256,
            manifest.DataManifestId, DateTime.UtcNow, previous is null ? null : previous with { Previous = null });
        WriteCurrent(pointerPath, pointer,
            () => onBoundary?.Invoke(ActivationBoundary.PointerTemporaryWritten));
        onBoundary?.Invoke(ActivationBoundary.CurrentPointerReplaced);
        return releasePath;
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
                current.Previous is not null && !IsSafeReleasePath(current.Previous.ReleaseDirectory) ||
                current.Previous is not null && current.PreviousReleaseDirectory != current.Previous.ReleaseDirectory ||
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
                   metadata.StartupHealthProtocolVersion >= 1 &&
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

    private static bool MetadataIsSane(string metadataPath)
    {
        try
        {
            var info = new FileInfo(metadataPath);
            if (!info.Exists || info.Length is <= 0 or > 16_384 ||
                (File.GetAttributes(metadataPath) & FileAttributes.ReparsePoint) != 0)
                return false;
            using var input = File.OpenRead(metadataPath);
            var metadata = JsonSerializer.Deserialize<ClientVersionMetadata>(input, TrustRoot.JsonOptions);
            return metadata is not null && Version.TryParse(metadata.ClientVersion, out _) &&
                   !string.IsNullOrWhiteSpace(metadata.BuildId) && metadata.ProtocolVersion > 0 &&
                   !string.IsNullOrWhiteSpace(metadata.DataManifestId) &&
                   !string.IsNullOrWhiteSpace(metadata.Platform) && !string.IsNullOrWhiteSpace(metadata.Channel) &&
                   metadata.Capabilities is not null && metadata.StartupHealthProtocolVersion >= 0;
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
        string DataManifestId, DateTime ActivatedAtUtc, CurrentRelease? Previous);

    private sealed record ClientVersionMetadata(string ClientVersion, string BuildId, int ProtocolVersion,
        string DataManifestId, string Platform, string Channel, IReadOnlyList<string> Capabilities,
        int StartupHealthProtocolVersion = 0);

    private static bool UsesStartupHealthProtocol(string metadataPath)
    {
        using var input = File.OpenRead(metadataPath);
        var metadata = JsonSerializer.Deserialize<ClientVersionMetadata>(input, TrustRoot.JsonOptions);
        return metadata?.StartupHealthProtocolVersion >= 1;
    }

    private static bool StartLegacyRelease(string executablePath, string releasePath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = executablePath,
            WorkingDirectory = releasePath,
            UseShellExecute = false
        });
        if (process is null) return false;
        Console.WriteLine($"Vorheriges gesundes LibreLancer-Release gestartet (PID {process.Id}); ohne Health-Protokoll.");
        return true;
    }

    private static async Task<bool> StartAndAwaitHealthAsync(string executablePath, string releasePath,
        string installRoot, TimeSpan healthTimeout, CancellationToken cancellationToken)
    {
        var healthDirectory = Path.Combine(installRoot, "health");
        Directory.CreateDirectory(healthDirectory);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var acknowledgementPath = Path.Combine(healthDirectory, token + ".ack");
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = executablePath,
            WorkingDirectory = releasePath,
            UseShellExecute = false,
            Environment =
            {
                ["LANCER_NEXUS_HEALTH_ACK_PATH"] = acknowledgementPath,
                ["LANCER_NEXUS_HEALTH_ACK_TOKEN"] = token
            }
        });
        if (process is null) return false;
        Console.WriteLine($"LibreLancer gestartet (PID {process.Id}); warte auf erfolgreiche Daten- und UI-Initialisierung.");
        var deadline = DateTime.UtcNow + healthTimeout;
        var acknowledged = false;
        try
        {
            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (File.Exists(acknowledgementPath))
                {
                    var info = new FileInfo(acknowledgementPath);
                    if (info.Length == token.Length)
                    {
                        var ack = await File.ReadAllBytesAsync(acknowledgementPath, cancellationToken);
                        if (CryptographicOperations.FixedTimeEquals(ack, Encoding.ASCII.GetBytes(token)))
                        {
                            acknowledged = true;
                            return true;
                        }
                    }
                }
                if (process.HasExited) return false;
                await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
            }
            return false;
        }
        finally
        {
            if (!acknowledged && !process.HasExited)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync(CancellationToken.None);
                }
                catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            }
            try
            {
                if (File.Exists(acknowledgementPath)) File.Delete(acknowledgementPath);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void MarkCurrentHealthy(string installRoot)
    {
        var pointerPath = Path.Combine(installRoot, "current.json");
        var current = TryReadCurrentRelease(pointerPath);
        if (current?.Previous is not null)
            WriteCurrent(pointerPath, current with { Previous = null });
    }

    private static void WriteCurrent(string path, CurrentRelease pointer, Action? onTemporaryWritten = null)
    {
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".current-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(output, pointer, TrustRoot.JsonOptions);
                output.Flush(flushToDisk: true);
            }
            onTemporaryWritten?.Invoke();
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }
}
