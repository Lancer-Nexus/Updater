using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LancerNexus.Updater;

public static class ReleaseActivator
{
    public enum StartResult { NotCurrent, Healthy, Failed, UpdateRequired, RepairRequired }
    internal enum ActivationBoundary { ReleaseDirectoryMoved, PointerTemporaryWritten, CurrentPointerReplaced }
    internal enum ActivationIoOperation { ReleaseDirectoryMove, CurrentPointerReplace }
    private static readonly TimeSpan HealthTimeout = TimeSpan.FromMinutes(5);

    public static async Task<StartResult> TryStartCurrentAsync(UpdateManifest manifest,
        UpdatePackage clientPackage, UpdaterOptions options, CancellationToken cancellationToken)
        => await TryStartCurrentAsync(manifest, clientPackage, options, HealthTimeout, cancellationToken, null);

    public static async Task<StartResult> TryStartCurrentAsync(UpdateManifest manifest,
        UpdatePackage clientPackage, UpdaterOptions options, CancellationToken cancellationToken,
        Func<Task>? onHealthAcknowledged)
        => await TryStartCurrentAsync(manifest, clientPackage, options, HealthTimeout, cancellationToken,
            onHealthAcknowledged);

    internal static async Task<StartResult> TryStartCurrentAsync(UpdateManifest manifest,
        UpdatePackage clientPackage, UpdaterOptions options, TimeSpan healthTimeout,
        CancellationToken cancellationToken, Func<Task>? onHealthAcknowledged = null)
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
        ClientExecutionResult execution;
        try
        {
            execution = await StartAndAwaitHealthAsync(executablePath, releasePath, installRoot,
                healthTimeout, cancellationToken, onHealthAcknowledged);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine($"Clientstart/Health-Handshake fehlgeschlagen: {error.Message}");
            return StartResult.Failed;
        }
        if (execution.ExitCode == 42) return StartResult.UpdateRequired;
        if (execution.ExitCode == 43) return StartResult.RepairRequired;
        return execution.HealthAcknowledged ? StartResult.Healthy : StartResult.Failed;
    }

    public static bool IsCurrentVerified(UpdateManifest manifest, UpdatePackage clientPackage, UpdaterOptions options)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var current = TryReadCurrentRelease(Path.Combine(installRoot, "current.json"));
        if (current is null || !MatchesReleaseTarget(current, manifest, clientPackage))
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

    public static bool IsCurrentReleaseTarget(UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options) =>
        MatchesReleaseTarget(TryReadCurrentRelease(Path.Combine(Path.GetFullPath(options.InstallRootPath), "current.json")),
            manifest, clientPackage);

    /// <summary>Restores the previous release if the active pointer still names a known-failed target.</summary>
    public static bool RollbackFailedCurrentReleaseIfNeeded(UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options)
    {
        if (!IsCurrentReleaseTarget(manifest, clientPackage, options)) return false;
        if (!RollbackCurrent(options))
            throw new InvalidOperationException("The failed active release has no previous release to restore.");
        return true;
    }

    private static bool MatchesReleaseTarget(CurrentRelease? current, UpdateManifest manifest,
        UpdatePackage clientPackage) =>
        current is not null && current.PackageSha256 == clientPackage.Sha256 &&
        current.ClientVersion == manifest.ClientVersion && current.BuildId == manifest.BuildId &&
        current.DataManifestId == manifest.DataManifestId;

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

    public static async Task<StartResult> TryStartRestoredCurrentAsync(UpdaterOptions options,
        CancellationToken cancellationToken, Func<Task>? onHealthAcknowledged = null)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var current = TryReadCurrentRelease(Path.Combine(installRoot, "current.json"));
        if (current is null) return StartResult.NotCurrent;
        var releasePath = ResolveReleasePath(installRoot, current.ReleaseDirectory);
        if (releasePath is null || !Directory.Exists(releasePath) ||
            (File.GetAttributes(releasePath) & FileAttributes.ReparsePoint) != 0)
            return StartResult.Failed;
        if (!MetadataIsSane(Path.Combine(releasePath, "client-version.json")))
            return StartResult.Failed;
        var executable = Path.Combine(releasePath, OperatingSystem.IsWindows() ? "lancer.exe" : "lancer");
        if (!File.Exists(executable) || (File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0 ||
            !DataPackageStager.VerifyStoredSnapshot(releasePath))
            return StartResult.Failed;
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(executable) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0)
            return StartResult.Failed;
        ClientExecutionResult execution;
        try
        {
            var metadataPath = Path.Combine(releasePath, "client-version.json");
            if (!UsesStartupHealthProtocol(metadataPath))
                return StartLegacyRelease(executable, releasePath) ? StartResult.Healthy : StartResult.Failed;
            execution = await StartAndAwaitHealthAsync(executable, releasePath, installRoot,
                HealthTimeout, cancellationToken, onHealthAcknowledged);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine($"Rollback-Start/Health-Handshake fehlgeschlagen: {error.Message}");
            return StartResult.Failed;
        }
        if (execution.ExitCode == 42) return StartResult.UpdateRequired;
        if (execution.ExitCode == 43) return StartResult.RepairRequired;
        return execution.HealthAcknowledged ? StartResult.Healthy : StartResult.Failed;
    }

    public static string Activate(string stagedRelease, UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options)
        => Activate(stagedRelease, manifest, clientPackage, options, null);

    internal static string Activate(string stagedRelease, UpdateManifest manifest, UpdatePackage clientPackage,
        UpdaterOptions options, Action<ActivationBoundary>? onBoundary,
        Action<ActivationIoOperation>? beforeIoOperation = null)
    {
        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var stagingRoot = Path.Combine(installRoot, "staging");
        var expectedStagingRoot = Path.GetFullPath(stagingRoot) + Path.DirectorySeparatorChar;
        var stagedPath = Path.GetFullPath(stagedRelease);
        var pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!stagedPath.StartsWith(expectedStagingRoot, pathComparison) ||
            !Directory.Exists(stagedPath) || Path.GetFileName(stagedPath).Length == 0 ||
            HasReparsePoint(installRoot, stagedPath))
            throw new InvalidOperationException("Stagingrelease liegt nicht im Installations-Stagingbereich.");

        var releasesRoot = Path.Combine(installRoot, "releases");
        Directory.CreateDirectory(releasesRoot);
        if (HasReparsePoint(installRoot, releasesRoot))
            throw new InvalidOperationException("Releaseverzeichnis enthält einen nicht erlaubten Reparse-Point.");
        var releaseName = Path.GetFileName(stagedPath);
        var releasePath = Path.Combine(releasesRoot, releaseName);
        beforeIoOperation?.Invoke(ActivationIoOperation.ReleaseDirectoryMove);
        Directory.Move(stagedPath, releasePath);
        onBoundary?.Invoke(ActivationBoundary.ReleaseDirectoryMoved);

        var pointerPath = Path.Combine(installRoot, "current.json");
        var previous = TryReadCurrentRelease(pointerPath);
        var pointer = new CurrentRelease(1, manifest.ClientVersion, manifest.BuildId,
            $"releases/{releaseName}", previous?.ReleaseDirectory, clientPackage.Sha256,
            manifest.DataManifestId, DateTime.UtcNow, previous is null ? null : previous with { Previous = null });
        WriteCurrent(pointerPath, pointer,
            () => onBoundary?.Invoke(ActivationBoundary.PointerTemporaryWritten),
            () => beforeIoOperation?.Invoke(ActivationIoOperation.CurrentPointerReplace));
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

    private static bool HasReparsePoint(string root, string path)
    {
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            return true;
        var relative = Path.GetRelativePath(root, path);
        if (relative == ".") return false;
        var current = root;
        foreach (var component in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            current = Path.Combine(current, component);
            if (!Directory.Exists(current) || (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                return true;
        }
        return false;
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

    private sealed record ClientExecutionResult(bool HealthAcknowledged, int? ExitCode);

    private static async Task<ClientExecutionResult> StartAndAwaitHealthAsync(string executablePath,
        string releasePath, string installRoot, TimeSpan healthTimeout, CancellationToken cancellationToken,
        Func<Task>? onHealthAcknowledged)
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
        if (process is null) return new(false, null);
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
                            MarkCurrentHealthy(installRoot);
                            if (onHealthAcknowledged is not null)
                                await onHealthAcknowledged();
                            break;
                        }
                    }
                }
                if (process.HasExited)
                    return new(false, process.ExitCode);
                if (acknowledged) break;
                await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
            }
            if (!acknowledged) return new(false, process.HasExited ? process.ExitCode : null);
            await process.WaitForExitAsync(cancellationToken);
            return new(true, process.ExitCode);
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

    private static void WriteCurrent(string path, CurrentRelease pointer, Action? onTemporaryWritten = null,
        Action? beforeReplace = null)
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
            beforeReplace?.Invoke();
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }
}
