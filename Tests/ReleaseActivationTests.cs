using System.Diagnostics;
using System.Text.Json;
using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class ReleaseActivationTests
{
    [Fact]
    public async Task ActivateRejectsStagingAndReleaseDirectoriesThatTraverseSymlinks()
    {
        if (OperatingSystem.IsWindows()) return;
        var root = Path.Combine(Path.GetTempPath(), $"updater-activation-symlink-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var package = new UpdatePackage("client", "1.0.0", "client.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var manifest = Manifest("1.0.0", "build-1", "data-1");
        try
        {
            var outsideStaging = Path.Combine(root, "outside-staging");
            Directory.CreateDirectory(Path.Combine(outsideStaging, "candidate"));
            await File.WriteAllTextAsync(Path.Combine(outsideStaging, "candidate", "marker"), "outside");
            Directory.CreateSymbolicLink(Path.Combine(root, "staging"), outsideStaging);

            Assert.Throws<InvalidOperationException>(() => ReleaseActivator.Activate(
                Path.Combine(root, "staging", "candidate"), manifest, package, options));
            Assert.Equal("outside", await File.ReadAllTextAsync(Path.Combine(outsideStaging, "candidate", "marker")));

            Directory.Delete(Path.Combine(root, "staging"));
            var stagingRoot = Path.Combine(root, "staging");
            Directory.CreateDirectory(stagingRoot);
            var outsideRelease = Path.Combine(root, "outside-release");
            Directory.CreateDirectory(outsideRelease);
            await File.WriteAllTextAsync(Path.Combine(outsideRelease, "marker"), "outside");
            Directory.CreateSymbolicLink(Path.Combine(stagingRoot, "candidate"), outsideRelease);

            Assert.Throws<InvalidOperationException>(() => ReleaseActivator.Activate(
                Path.Combine(stagingRoot, "candidate"), manifest, package, options));
            Assert.Equal("outside", await File.ReadAllTextAsync(Path.Combine(outsideRelease, "marker")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("ReleaseDirectoryMoved", "releases/old", "old")]
    [InlineData("PointerTemporaryWritten", "releases/old", "old")]
    [InlineData("CurrentPointerReplaced", "releases/candidate", "candidate")]
    public async Task AbruptUpdaterExitLeavesAnOldOrCompleteNewSnapshot(string boundary,
        string expectedActiveRelease, string expectedContent)
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-activation-crash-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var oldClient = new UpdatePackage("client", "1.0.0", "client-old.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var newClient = oldClient with { Version = "2.0.0", Url = "client-new.tar.zst", Sha256 = new string('b', 64) };
        var oldStage = Path.Combine(root, "staging", "old");
        var candidateStage = Path.Combine(root, "staging", "candidate");
        Directory.CreateDirectory(oldStage);
        Directory.CreateDirectory(candidateStage);
        await File.WriteAllTextAsync(Path.Combine(oldStage, "snapshot-id.txt"), "old");
        await File.WriteAllTextAsync(Path.Combine(candidateStage, "snapshot-id.txt"), "candidate");

        try
        {
            ReleaseActivator.Activate(oldStage, Manifest("1.0.0", "build-old", "data-old"), oldClient, options);

            var probeDirectory = Path.Combine(AppContext.BaseDirectory, "activation-probe");
            var probePath = Path.Combine(probeDirectory,
                OperatingSystem.IsWindows() ? "activation-crash-probe.exe" : "activation-crash-probe");
            Assert.True(File.Exists(probePath), $"Activation crash probe was not found at {probePath}.");
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(probePath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = probePath,
                UseShellExecute = false,
                ArgumentList =
                {
                    root,
                    candidateStage,
                    boundary,
                    newClient.Version,
                    "build-new",
                    "data-new",
                    newClient.Sha256
                }
            });
            Assert.NotNull(process);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(timeout.Token);

            Assert.Equal(73, process.ExitCode);
            Assert.Equal(expectedActiveRelease, ReadActiveRelease(root));
            Assert.Equal(expectedContent, await File.ReadAllTextAsync(
                Path.Combine(root, expectedActiveRelease.Replace('/', Path.DirectorySeparatorChar), "snapshot-id.txt")));
            Assert.True(Directory.Exists(Path.Combine(root, "releases", "candidate")));
            Assert.Equal("candidate", await File.ReadAllTextAsync(
                Path.Combine(root, "releases", "candidate", "snapshot-id.txt")));
            Assert.False(Directory.Exists(candidateStage));

            if (boundary == "PointerTemporaryWritten")
            {
                var temporaryPointer = Assert.Single(Directory.EnumerateFiles(root, ".current-*.tmp"));
                using var pendingPointer = JsonDocument.Parse(await File.ReadAllBytesAsync(temporaryPointer));
                Assert.Equal("releases/candidate",
                    pendingPointer.RootElement.GetProperty("releaseDirectory").GetString());

                var retryStage = Path.Combine(root, "staging", "retry");
                Directory.CreateDirectory(retryStage);
                await File.WriteAllTextAsync(Path.Combine(retryStage, "snapshot-id.txt"), "retry");
                var retryRelease = ReleaseActivator.Activate(retryStage,
                    Manifest("2.0.0", "build-retry", "data-retry"), newClient, options);
                Assert.Equal("retry", await File.ReadAllTextAsync(Path.Combine(retryRelease, "snapshot-id.txt")));
                Assert.Equal("releases/retry", ReadActiveRelease(root));
                Assert.True(File.Exists(temporaryPointer));
            }

            if (boundary == "CurrentPointerReplaced")
            {
                using var pointer = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "current.json")));
                Assert.Equal("releases/old", pointer.RootElement.GetProperty("previousReleaseDirectory").GetString());
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ReleaseDirectoryMoveIoFailureLeavesStagedCandidateAndActiveReleaseUntouched()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-activation-io-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var oldPackage = new UpdatePackage("client", "1.0.0", "client-old.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var candidatePackage = oldPackage with { Version = "2.0.0", Sha256 = new string('b', 64) };
        var oldStage = Path.Combine(root, "staging", "old");
        var candidateStage = Path.Combine(root, "staging", "candidate");
        Directory.CreateDirectory(oldStage);
        Directory.CreateDirectory(candidateStage);
        await File.WriteAllTextAsync(Path.Combine(oldStage, "marker"), "old");
        await File.WriteAllTextAsync(Path.Combine(candidateStage, "marker"), "candidate");

        try
        {
            ReleaseActivator.Activate(oldStage, Manifest("1.0.0", "build-old", "data-old"), oldPackage, options);

            var error = Assert.Throws<IOException>(() => ReleaseActivator.Activate(candidateStage,
                Manifest("2.0.0", "build-candidate", "data-candidate"), candidatePackage, options,
                onBoundary: null,
                beforeIoOperation: operation =>
                {
                    if (operation == ReleaseActivator.ActivationIoOperation.ReleaseDirectoryMove)
                        throw new IOException("Injected release directory move failure.");
                }));

            Assert.Contains("move failure", error.Message, StringComparison.Ordinal);
            Assert.Equal("releases/old", ReadActiveRelease(root));
            Assert.Equal("old", await File.ReadAllTextAsync(Path.Combine(root, "releases", "old", "marker")));
            Assert.Equal("candidate", await File.ReadAllTextAsync(Path.Combine(candidateStage, "marker")));
            Assert.False(Directory.Exists(Path.Combine(root, "releases", "candidate")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CurrentPointerReplaceIoFailurePreservesPreviousPointerAndRemovesTemporaryFile()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-pointer-io-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var oldPackage = new UpdatePackage("client", "1.0.0", "client-old.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var candidatePackage = oldPackage with { Version = "2.0.0", Sha256 = new string('b', 64) };
        var oldStage = Path.Combine(root, "staging", "old");
        var candidateStage = Path.Combine(root, "staging", "candidate");
        Directory.CreateDirectory(oldStage);
        Directory.CreateDirectory(candidateStage);
        await File.WriteAllTextAsync(Path.Combine(oldStage, "marker"), "old");
        await File.WriteAllTextAsync(Path.Combine(candidateStage, "marker"), "candidate");

        try
        {
            ReleaseActivator.Activate(oldStage, Manifest("1.0.0", "build-old", "data-old"), oldPackage, options);

            var error = Assert.Throws<IOException>(() => ReleaseActivator.Activate(candidateStage,
                Manifest("2.0.0", "build-candidate", "data-candidate"), candidatePackage, options,
                onBoundary: null,
                beforeIoOperation: operation =>
                {
                    if (operation == ReleaseActivator.ActivationIoOperation.CurrentPointerReplace)
                        throw new IOException("Injected current pointer replacement failure.");
                }));

            Assert.Contains("replacement failure", error.Message, StringComparison.Ordinal);
            Assert.Equal("releases/old", ReadActiveRelease(root));
            Assert.Equal("old", await File.ReadAllTextAsync(Path.Combine(root, "releases", "old", "marker")));
            Assert.Equal("candidate", await File.ReadAllTextAsync(Path.Combine(root, "releases", "candidate", "marker")));
            Assert.Empty(Directory.EnumerateFiles(root, ".current-*.tmp"));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FailedCandidateCrashRecoveryRestoresPreviousPointerOnlyIfCandidateIsStillActive()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-activation-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var client = new UpdatePackage("client", "1.0.0", "client.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        Directory.CreateDirectory(Path.Combine(root, "staging", "first"));
        Directory.CreateDirectory(Path.Combine(root, "staging", "second"));
        try
        {
            var previousManifest = Manifest("1.0.0", "build-1", "data-1");
            var failedManifest = Manifest("1.1.0", "build-2", "data-2");
            var failedClient = client with { Version = "1.1.0", Sha256 = new string('b', 64) };
            var first = ReleaseActivator.Activate(Path.Combine(root, "staging", "first"),
                previousManifest, client, options);
            var second = ReleaseActivator.Activate(Path.Combine(root, "staging", "second"),
                failedManifest, failedClient, options);

            Assert.True(Directory.Exists(first));
            Assert.True(Directory.Exists(second));
            Assert.True(ReleaseActivator.IsCurrentReleaseTarget(failedManifest, failedClient, options));
            Assert.True(ReleaseActivator.RollbackFailedCurrentReleaseIfNeeded(failedManifest, failedClient, options));
            Assert.False(ReleaseActivator.IsCurrentReleaseTarget(failedManifest, failedClient, options));
            using var pointer = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "current.json")));
            Assert.Equal("releases/first", pointer.RootElement.GetProperty("releaseDirectory").GetString());
            Assert.False(ReleaseActivator.RollbackFailedCurrentReleaseIfNeeded(failedManifest, failedClient, options));
            Assert.Equal("releases/first", ReadActiveRelease(root));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ProcessExitAfterFailureMarkerIsRecoveredOnNextUpdaterStartup()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-failed-start-crash-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var optionalPackages = new HashSet<string>(StringComparer.Ordinal);
        var previousPackage = new UpdatePackage("client", "1.0.0", "client-old.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var failedPackage = previousPackage with
        {
            Version = "2.0.0",
            Url = "client-failed.tar.zst",
            Sha256 = new string('b', 64)
        };
        var previousManifest = Manifest("1.0.0", "build-old", "data-old") with { Packages = [previousPackage] };
        var failedManifest = Manifest("2.0.0", "build-failed", "data-failed") with
        {
            Version = 2,
            Packages = [failedPackage]
        };

        try
        {
            var previousStage = Path.Combine(root, "staging", "old");
            var failedStage = Path.Combine(root, "staging", "failed");
            Directory.CreateDirectory(previousStage);
            Directory.CreateDirectory(failedStage);
            await File.WriteAllTextAsync(Path.Combine(previousStage, "snapshot-id.txt"), "old");
            await File.WriteAllTextAsync(Path.Combine(failedStage, "snapshot-id.txt"), "failed");
            ReleaseActivator.Activate(previousStage, previousManifest, previousPackage, options);
            ReleaseActivator.Activate(failedStage, failedManifest, failedPackage, options);

            var probePath = Path.Combine(AppContext.BaseDirectory, "activation-probe",
                OperatingSystem.IsWindows() ? "activation-crash-probe.exe" : "activation-crash-probe");
            Assert.True(File.Exists(probePath), $"Activation crash probe was not found at {probePath}.");
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(probePath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = probePath,
                UseShellExecute = false,
                ArgumentList =
                {
                    "--failed-start",
                    root,
                    failedManifest.Version.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    failedManifest.ClientVersion,
                    failedManifest.BuildId,
                    failedManifest.DataManifestId,
                    failedPackage.Sha256
                }
            });
            Assert.NotNull(process);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(timeout.Token);

            Assert.Equal(74, process.ExitCode);
            Assert.Equal("releases/failed", ReadActiveRelease(root));
            Assert.True(FailedReleaseStore.IsKnownFailure(root, failedManifest, failedPackage, optionalPackages));

            Assert.True(FailedReleaseRecovery.RecoverKnownFailedCurrent(root, failedManifest, failedPackage,
                optionalPackages, options));
            Assert.Equal("releases/old", ReadActiveRelease(root));
            Assert.True(FailedReleaseStore.IsKnownFailure(root, failedManifest, failedPackage, optionalPackages));

            Assert.True(FailedReleaseRecovery.RecoverKnownFailedCurrent(root, failedManifest, failedPackage,
                optionalPackages, options));
            Assert.Equal("releases/old", ReadActiveRelease(root));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static UpdateManifest Manifest(string version, string build, string data) => new(
        1, 1, "stable", "linux", "x64", version, "1.0.0", 1,
        DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), [])
    {
        BuildId = build,
        DataManifestId = data,
        Capabilities = []
    };

    private static string ReadActiveRelease(string installRoot)
    {
        using var pointer = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(installRoot, "current.json")));
        return pointer.RootElement.GetProperty("releaseDirectory").GetString()!;
    }
}
