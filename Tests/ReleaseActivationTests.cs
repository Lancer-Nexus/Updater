using System.Diagnostics;
using System.Text.Json;
using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class ReleaseActivationTests
{
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
    public void FailedCandidateRestoresThePreviousReleasePointerOnlyOnce()
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
            var first = ReleaseActivator.Activate(Path.Combine(root, "staging", "first"),
                Manifest("1.0.0", "build-1", "data-1"), client, options);
            var second = ReleaseActivator.Activate(Path.Combine(root, "staging", "second"),
                Manifest("1.1.0", "build-2", "data-2"), client with { Sha256 = new string('b', 64) }, options);

            Assert.True(Directory.Exists(first));
            Assert.True(Directory.Exists(second));
            Assert.True(ReleaseActivator.RollbackCurrent(options));
            using var pointer = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "current.json")));
            Assert.Equal("releases/first", pointer.RootElement.GetProperty("releaseDirectory").GetString());
            Assert.False(ReleaseActivator.RollbackCurrent(options));
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
