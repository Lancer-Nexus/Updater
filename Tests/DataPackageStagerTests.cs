using System.Security.Cryptography;
using System.Text.Json;
using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class DataPackageStagerTests
{
    [Fact]
    public async Task RequiredPackageClosureIsStagedAsOneVerifiableActiveSnapshot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-test-{Guid.NewGuid():N}");
        var release = Path.Combine(root, "staging", "release");
        var cache = Path.Combine(root, "cache");
        Directory.CreateDirectory(release);
        Directory.CreateDirectory(cache);
        try
        {
            var coreBytes = NapFixture.Create([0x43, 0x4f, 0x52, 0x45], "core.bin");
            var optionalBytes = NapFixture.Create([0x4f, 0x50, 0x54], "audio.bin");
            var corePath = WritePackage(cache, "core.nap", coreBytes);
            _ = WritePackage(cache, "optional.nap", optionalBytes);
            var core = Package("core", coreBytes, required: false, 10, 1);
            var required = Package("gameplay", new byte[] { 1, 2, 3 }, required: true, 20, 1,
                dependencies: ["core"]) with
            { Overrides = ["base-audio"] };
            var optional = Package("base-audio", optionalBytes, required: false, 15, 1);
            var voice = Package("voice", new byte[] { 9 }, required: false, 30, 1);
            var manifest = Manifest([core, required, optional, voice]);
            var selection = DataPackageStager.SelectPackages(manifest, new HashSet<string>(StringComparer.Ordinal));
            Assert.Equal(new[] { "base-audio", "core", "gameplay" }, selection.Select(x => x.Id)
                .Order(StringComparer.Ordinal).ToArray());
            Assert.Contains(DataPackageStager.SelectPackages(manifest,
                new HashSet<string>(["voice"], StringComparer.Ordinal)), x => x.Id == "voice");
            Assert.Throws<InvalidDataException>(() => DataPackageStager.SelectPackages(manifest,
                new HashSet<string>(["missing"], StringComparer.Ordinal)));

            // The fixture bytes above model already downloaded content; use their signed values.
            var requiredBytes = NapFixture.Create([1, 2, 3], "gameplay.bin");
            var requiredPath = WritePackage(cache, "gameplay.nap", requiredBytes);
            var archives = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["core"] = corePath,
                ["gameplay"] = requiredPath,
                ["base-audio"] = WritePackage(cache, "base-audio.nap", optionalBytes)
            };
            var gameplay = Package("gameplay", requiredBytes, true, 20, 1, ["core"]) with
            {
                Overrides = ["base-audio"]
            };
            var corrected = Manifest([core, gameplay, optional, voice]);
            await DataPackageStager.WriteSnapshotAsync(release, corrected,
                new HashSet<string>(StringComparer.Ordinal), archives, CancellationToken.None);

            Assert.True(DataPackageStager.MatchesSnapshot(release, corrected, new HashSet<string>(StringComparer.Ordinal)));
            using var input = File.OpenRead(Path.Combine(release, "packages", "active.json"));
            using var json = await JsonDocument.ParseAsync(input);
            Assert.Equal("data-1", json.RootElement.GetProperty("manifestId").GetString());
            Assert.Equal(3, json.RootElement.GetProperty("packages").GetArrayLength());

            var active = json.RootElement.GetProperty("packages")[0];
            var installedPath = Path.Combine(release, "packages", active.GetProperty("path").GetString()!
                .Replace('/', Path.DirectorySeparatorChar));
            await File.WriteAllBytesAsync(installedPath, [9, 9, 9, 9]);
            Assert.False(DataPackageStager.MatchesSnapshot(release, corrected,
                new HashSet<string>(StringComparer.Ordinal)));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SnapshotRejectsMissingOrUnexpectedRequiredArtifacts()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var bytes = NapFixture.Create([1, 2, 3]);
            var manifest = Manifest([Package("core", bytes, true, 10, 1)]);
            await Assert.ThrowsAsync<InvalidDataException>(() => DataPackageStager.WriteSnapshotAsync(
                root, manifest, new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, string>(), CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() => DataPackageStager.WriteSnapshotAsync(
                root, manifest, new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, string> { ["other"] = "missing.nap" }, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SnapshotRejectsFileConflictsWithoutDeclaredOverride()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-conflict-{Guid.NewGuid():N}");
        var cache = Path.Combine(root, "cache");
        Directory.CreateDirectory(cache);
        try
        {
            var baseBytes = NapFixture.Create([1], "shared/config.ini");
            var overlayBytes = NapFixture.Create([2], "shared/config.ini");
            var basePackage = Package("base", baseBytes, true, 10, 1);
            var overlayPackage = Package("overlay", overlayBytes, true, 20, 1);
            var manifest = Manifest([basePackage, overlayPackage]);
            var archives = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["base"] = WritePackage(cache, "base.nap", baseBytes),
                ["overlay"] = WritePackage(cache, "overlay.nap", overlayBytes)
            };

            await Assert.ThrowsAsync<InvalidDataException>(() => DataPackageStager.WriteSnapshotAsync(
                root, manifest, new HashSet<string>(StringComparer.Ordinal), archives, CancellationToken.None));

            Assert.False(File.Exists(Path.Combine(root, "packages", "active.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SnapshotAcceptsFileConflictsWithDeclaredHigherPriorityOverride()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-override-{Guid.NewGuid():N}");
        var cache = Path.Combine(root, "cache");
        Directory.CreateDirectory(cache);
        try
        {
            var baseBytes = NapFixture.Create([1], "shared/config.ini");
            var overlayBytes = NapFixture.Create([2], "shared/config.ini");
            var basePackage = Package("base", baseBytes, true, 10, 1);
            var overlayPackage = Package("overlay", overlayBytes, true, 20, 1) with { Overrides = ["base"] };
            var manifest = Manifest([basePackage, overlayPackage]);
            var archives = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["base"] = WritePackage(cache, "base.nap", baseBytes),
                ["overlay"] = WritePackage(cache, "overlay.nap", overlayBytes)
            };

            await DataPackageStager.WriteSnapshotAsync(
                root, manifest, new HashSet<string>(StringComparer.Ordinal), archives, CancellationToken.None);

            Assert.True(DataPackageStager.MatchesSnapshot(root, manifest, new HashSet<string>(StringComparer.Ordinal)));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SnapshotRejectsNapContentVersionThatDiffersFromSignedManifest()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-version-{Guid.NewGuid():N}");
        var cache = Path.Combine(root, "cache");
        Directory.CreateDirectory(cache);
        try
        {
            var archive = NapFixture.Create([0x41]);
            var path = WritePackage(cache, "core.nap", archive);
            var package = Package("core", archive, true, 10, 1) with { ContentVersion = 2 };
            var manifest = Manifest([package]);

            await Assert.ThrowsAsync<InvalidDataException>(() => DataPackageStager.WriteSnapshotAsync(
                root, manifest, new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, string>(StringComparer.Ordinal) { ["core"] = path },
                CancellationToken.None));
            Assert.False(File.Exists(Path.Combine(root, "packages", "active.json")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CancelledSnapshotWritePreservesThePreviouslyPublishedSnapshot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-cancel-{Guid.NewGuid():N}");
        var packagesRoot = Path.Combine(root, "packages");
        Directory.CreateDirectory(packagesRoot);
        var snapshotPath = Path.Combine(packagesRoot, "active.json");
        var previousSnapshot = "previous-snapshot"u8.ToArray();
        await File.WriteAllBytesAsync(snapshotPath, previousSnapshot);
        try
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DataPackageStager.WriteSnapshotAsync(
                root, Manifest([]), new HashSet<string>(StringComparer.Ordinal),
                new Dictionary<string, string>(StringComparer.Ordinal), cancellation.Token));

            Assert.Equal(previousSnapshot, await File.ReadAllBytesAsync(snapshotPath));
            Assert.Empty(Directory.EnumerateFiles(packagesRoot, ".active-*.tmp"));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FailureMarkerIsScopedToTheSignedManifestAndSelectedDataSnapshot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"nap-updater-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var required = Package("core", NapFixture.Create([1, 2]), true, 10, 1);
            var optional = Package("voice", NapFixture.Create([3, 4]), false, 20, 1);
            var manifest = Manifest([required, optional]);
            var client = new UpdatePackage("client", "1.0.0", "client.tar.zst", 1,
                new string('a', 64), true, "tar.zst");
            var none = new HashSet<string>(StringComparer.Ordinal);
            FailedReleaseStore.Record(root, manifest, client, none);
            Assert.True(FailedReleaseStore.IsKnownFailure(root, manifest, client, none));
            Assert.False(FailedReleaseStore.IsKnownFailure(root, manifest, client,
                new HashSet<string>(["voice"], StringComparer.Ordinal)));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static UpdatePackage Package(string id, byte[] content, bool required, int priority, int mountOrder,
        IReadOnlyList<string>? dependencies = null) =>
        new UpdatePackage(id, "1", $"packages/{id}.nap", content.Length,
            Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(), required, "nap")
        {
            ContentVersion = 1,
            Priority = priority,
            MountOrder = mountOrder,
            Dependencies = dependencies ?? [],
            Overrides = []
        };

    private static UpdateManifest Manifest(IReadOnlyList<UpdatePackage> packages) => new(
        1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
        DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddDays(1),
        [new UpdatePackage("client", "1.0.0", "client.tar.zst", 1, new string('a', 64), true, "tar.zst"), .. packages])
    {
        BuildId = "build-1",
        DataManifestId = "data-1",
        Capabilities = []
    };

    private static string WritePackage(string directory, string fileName, byte[] content)
    {
        var path = Path.Combine(directory, fileName);
        File.WriteAllBytes(path, content);
        return path;
    }
}
