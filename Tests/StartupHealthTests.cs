using System.Text.Json;
using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class StartupHealthTests
{
    [Fact]
    public async Task CurrentReleaseIsHealthyOnlyAfterMatchingUiReadyAcknowledgement()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-health-{Guid.NewGuid():N}");
        var staging = Path.Combine(root, "staging", "release-one");
        Directory.CreateDirectory(staging);
        var client = new UpdatePackage("client", "1.0.0", "client.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), [client])
        {
            BuildId = "health-test",
            DataManifestId = "data-health-test",
            Capabilities = ["client_version_hello_v1"]
        };
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        try
        {
            await InstallProbeAsync(staging);
            var metadata = new
            {
                clientVersion = manifest.ClientVersion,
                buildId = manifest.BuildId,
                protocolVersion = manifest.ProtocolVersion,
                dataManifestId = manifest.DataManifestId,
                platform = "linux-x64",
                channel = manifest.Channel,
                capabilities = manifest.Capabilities,
                startupHealthProtocolVersion = 1
            };
            await File.WriteAllTextAsync(Path.Combine(staging, "client-version.json"),
                JsonSerializer.Serialize(metadata, TrustRoot.JsonOptions));
            await DataPackageStager.WriteSnapshotAsync(staging, manifest,
                new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, string>(StringComparer.Ordinal), CancellationToken.None);
            ReleaseActivator.Activate(staging, manifest, client, options);

            var result = await ReleaseActivator.TryStartCurrentAsync(
                manifest, client, options, CancellationToken.None);

            Assert.Equal(ReleaseActivator.StartResult.Healthy, result);
            using var pointer = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "current.json")));
            Assert.Equal(JsonValueKind.Null, pointer.RootElement.GetProperty("previous").ValueKind);
        }
        finally
        {
            await DeleteDirectoryAsync(root);
        }
    }

    [Theory]
    [InlineData("gateway-update-required", ReleaseActivator.StartResult.UpdateRequired)]
    [InlineData("repair-required", ReleaseActivator.StartResult.RepairRequired)]
    public async Task ClientExitRequestsAreReturnedAfterTheHealthHandshake(string marker,
        ReleaseActivator.StartResult expected)
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-client-exit-{Guid.NewGuid():N}");
        var stage = Path.Combine(root, "staging", "release");
        Directory.CreateDirectory(stage);
        var client = new UpdatePackage("client", "1.0.0", "client.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var manifest = Manifest("1.0.0", "exit-test", "exit-test-data");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        try
        {
            await InstallProbeAsync(stage);
            await File.WriteAllTextAsync(Path.Combine(stage, marker), string.Empty);
            await WriteClientMetadataAsync(stage, manifest);
            await DataPackageStager.WriteSnapshotAsync(stage, manifest,
                new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, string>(StringComparer.Ordinal), CancellationToken.None);
            ReleaseActivator.Activate(stage, manifest, client, options);

            var result = await ReleaseActivator.TryStartCurrentAsync(
                manifest, client, options, CancellationToken.None);

            Assert.Equal(expected, result);
            using var pointer = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "current.json")));
            Assert.Equal(JsonValueKind.Null, pointer.RootElement.GetProperty("previous").ValueKind);
        }
        finally
        {
            await DeleteDirectoryAsync(root);
        }
    }

    [Fact]
    public async Task FailedNewReleaseRestoresAndStartsThePreviouslyHealthyLegacyRelease()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-rollback-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var oldClient = new UpdatePackage("client", "1.0.0", "client-old.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var newClient = oldClient with { Version = "1.1.0", Url = "client-new.tar.zst", Sha256 = new string('b', 64) };
        var oldManifest = Manifest("1.0.0", "build-old", "data-old");
        var newManifest = Manifest("1.1.0", "build-new", "data-new");
        try
        {
            var oldStage = await CreateStageAsync(root, "old-stage", oldManifest, 0);
            var oldRelease = ReleaseActivator.Activate(oldStage, oldManifest, oldClient, options);
            var newStage = await CreateStageAsync(root, "new-stage", newManifest, 1, "fail-startup");
            ReleaseActivator.Activate(newStage, newManifest, newClient, options);

            var failed = await ReleaseActivator.TryStartCurrentAsync(
                newManifest, newClient, options, CancellationToken.None);
            Assert.Equal(ReleaseActivator.StartResult.Failed, failed);
            Assert.True(ReleaseActivator.RollbackCurrent(options));
            Assert.False(ReleaseActivator.IsCurrentVerified(newManifest, newClient, options));
            Assert.False(GatewayUpdatePolicy.ShouldRejectUnchangedUpdateRequest(newManifest, newClient,
                newManifest, newClient, new HashSet<string>(StringComparer.Ordinal),
                installedReleaseMatchesPreviousManifest: false));
            Assert.Equal(ReleaseActivator.StartResult.Healthy,
                await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None));

            using var pointer = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "current.json")));
            Assert.Equal(Path.GetFileName(oldRelease),
                Path.GetFileName(pointer.RootElement.GetProperty("releaseDirectory").GetString()));
        }
        finally
        {
            await DeleteDirectoryAsync(root);
        }
    }

    [Fact]
    public async Task MissingHealthAcknowledgementTimesOutRollsBackAndSuppressesTheFailedSnapshot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"updater-health-timeout-{Guid.NewGuid():N}");
        var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
            "stable", "linux", "x64", "trusted-root.json", InstallRootPath: root);
        var oldClient = new UpdatePackage("client", "1.0.0", "client-old.tar.zst", 1,
            new string('a', 64), true, "tar.zst");
        var newClient = oldClient with { Version = "1.1.0", Url = "client-new.tar.zst", Sha256 = new string('b', 64) };
        var oldManifest = Manifest("1.0.0", "build-old", "data-old");
        var newManifest = Manifest("1.1.0", "build-new", "data-new");
        var noOptionalPackages = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var oldStage = await CreateStageAsync(root, "old-stage", oldManifest, 0);
            var oldRelease = ReleaseActivator.Activate(oldStage, oldManifest, oldClient, options);
            var failedStage = await CreateStageAsync(root, "failed-stage", newManifest, 1, "no-ack");
            ReleaseActivator.Activate(failedStage, newManifest, newClient, options);

            var failed = await ReleaseActivator.TryStartCurrentAsync(newManifest, newClient, options,
                TimeSpan.FromMilliseconds(300), CancellationToken.None);

            Assert.Equal(ReleaseActivator.StartResult.Failed, failed);
            var pidFile = Assert.Single(Directory.EnumerateFiles(Path.Combine(root, "health"), "*.ack.pid"));
            var processId = int.Parse(await File.ReadAllTextAsync(pidFile));
            AssertProcessHasExited(processId);
            FailedReleaseStore.Record(root, newManifest, newClient, noOptionalPackages);
            Assert.True(FailedReleaseStore.IsKnownFailure(root, newManifest, newClient, noOptionalPackages));
            Assert.True(ReleaseActivator.RollbackCurrent(options));
            Assert.Equal(ReleaseActivator.StartResult.Healthy,
                await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None));

            using var pointer = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "current.json")));
            Assert.Equal(Path.GetFileName(oldRelease),
                Path.GetFileName(pointer.RootElement.GetProperty("releaseDirectory").GetString()));
            Assert.True(FailedReleaseStore.IsKnownFailure(root, newManifest, newClient, noOptionalPackages));
        }
        finally
        {
            await DeleteDirectoryAsync(root);
        }
    }

    private static async Task<string> CreateStageAsync(string installRoot, string name,
        UpdateManifest manifest, int healthProtocol, string? marker = null)
    {
        var stage = Path.Combine(installRoot, "staging", name);
        Directory.CreateDirectory(stage);
        await InstallProbeAsync(stage);
        if (marker is not null)
            await File.WriteAllTextAsync(Path.Combine(stage, marker), string.Empty);
        await WriteClientMetadataAsync(stage, manifest, healthProtocol);
        await DataPackageStager.WriteSnapshotAsync(stage, manifest,
            new HashSet<string>(StringComparer.Ordinal),
            new Dictionary<string, string>(StringComparer.Ordinal), CancellationToken.None);
        return stage;
    }

    private static async Task WriteClientMetadataAsync(string stage, UpdateManifest manifest, int healthProtocol = 1)
    {
        var metadata = new
        {
            clientVersion = manifest.ClientVersion,
            buildId = manifest.BuildId,
            protocolVersion = manifest.ProtocolVersion,
            dataManifestId = manifest.DataManifestId,
            platform = "linux-x64",
            channel = manifest.Channel,
            capabilities = manifest.Capabilities,
            startupHealthProtocolVersion = healthProtocol
        };
        await File.WriteAllTextAsync(Path.Combine(stage, "client-version.json"),
            JsonSerializer.Serialize(metadata, TrustRoot.JsonOptions));
    }

    private static async Task InstallProbeAsync(string stage)
    {
        var probeDirectory = Path.Combine(AppContext.BaseDirectory, "health-probe");
        Assert.True(Directory.Exists(probeDirectory), $"Health probe output was not found at {probeDirectory}.");
        foreach (var source in Directory.EnumerateFiles(probeDirectory))
        {
            var destination = Path.Combine(stage, Path.GetFileName(source));
            File.Copy(source, destination, overwrite: true);
            if (OperatingSystem.IsLinux() && Path.GetFileName(source) == "lancer")
                File.SetUnixFileMode(destination,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void AssertProcessHasExited(int processId)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(processId);
            Assert.True(process.HasExited, $"Updater left health probe process {processId} running.");
        }
        catch (ArgumentException)
        {
            // The process has already exited and its PID is no longer present.
        }
    }

    private static async Task DeleteDirectoryAsync(string path)
    {
        for (var attempt = 0; attempt < 40 && Directory.Exists(path); attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (Exception error) when (OperatingSystem.IsWindows() &&
                                          error is IOException or UnauthorizedAccessException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50));
            }
        }
        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
    }

    private static UpdateManifest Manifest(string version, string build, string data)
    {
        var client = new UpdatePackage("client", version, "client.tar.zst", 1,
            version == "1.0.0" ? new string('a', 64) : new string('b', 64), true, "tar.zst");
        return new UpdateManifest(1, 1, "stable", "linux", "x64", version, "1.0.0", 1,
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), [client])
        {
            BuildId = build,
            DataManifestId = data,
            Capabilities = ["client_version_hello_v1"]
        };
    }
}
