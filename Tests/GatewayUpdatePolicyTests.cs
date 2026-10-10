using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class GatewayUpdatePolicyTests
{
    private static readonly IReadOnlySet<string> NoOptionalPackages = new HashSet<string>(StringComparer.Ordinal);

    [Fact]
    public void ManifestVersionAloneDoesNotCountAsAClientUpdate()
    {
        var current = Manifest(1, "client-1", "build-1", "data-1", 'a', null);
        var candidate = current with { Version = 2 };

        Assert.False(GatewayUpdatePolicy.HasUpdatedRuntimeRelease(current, current.Packages[0],
            candidate, candidate.Packages[0], NoOptionalPackages));
    }

    [Fact]
    public void UnchangedRefreshCanRecoverWhenTheInstalledReleaseDoesNotMatchTheKnownTarget()
    {
        var manifest = Manifest(3, "client-3", "build-3", "data-3", 'c', null);

        Assert.False(GatewayUpdatePolicy.ShouldRejectUnchangedUpdateRequest(manifest, manifest.Packages[0],
            manifest, manifest.Packages[0], NoOptionalPackages, installedReleaseMatchesPreviousManifest: false));
        Assert.True(GatewayUpdatePolicy.ShouldRejectUnchangedUpdateRequest(manifest, manifest.Packages[0],
            manifest, manifest.Packages[0], NoOptionalPackages, installedReleaseMatchesPreviousManifest: true));
    }

    [Theory]
    [InlineData("client-hash")]
    [InlineData("client-version")]
    [InlineData("build")]
    [InlineData("protocol")]
    [InlineData("data-manifest")]
    [InlineData("capability")]
    public void ClientRuntimeIdentityChangesPermitTheBoundedRefresh(string change)
    {
        var current = Manifest(1, "client-1", "build-1", "data-1", 'a', null);
        var candidate = change switch
        {
            "client-hash" => Manifest(2, "client-1", "build-1", "data-1", 'b', null),
            "client-version" => current with { Version = 2, ClientVersion = "1.1.0" },
            "build" => current with { Version = 2, BuildId = "build-2" },
            "protocol" => current with { Version = 2, ProtocolVersion = 2 },
            "data-manifest" => current with { Version = 2, DataManifestId = "data-2" },
            "capability" => current with { Version = 2, Capabilities = ["client_version_hello_v2"] },
            _ => throw new ArgumentOutOfRangeException(nameof(change))
        };

        Assert.True(GatewayUpdatePolicy.HasUpdatedRuntimeRelease(current, current.Packages[0],
            candidate, candidate.Packages[0], NoOptionalPackages));
    }

    [Fact]
    public void SelectedDataPackageHashChangeCountsAsAnUpdatedRuntimeRelease()
    {
        var current = Manifest(1, "client-1", "build-1", "data-1", 'a',
            new UpdatePackage("base-data", "1", "artifacts/aa/" + new string('a', 64), 32,
                new string('a', 64), true, "nap")
            { ContentVersion = 1 });
        var candidate = current with
        {
            Version = 2,
            Packages = [current.Packages[0], current.Packages[1] with { Sha256 = new string('b', 64),
                Url = "artifacts/bb/" + new string('b', 64) }]
        };

        Assert.True(GatewayUpdatePolicy.HasUpdatedRuntimeRelease(current, current.Packages[0],
            candidate, candidate.Packages[0], NoOptionalPackages));
    }

    [Theory]
    [InlineData("format")]
    [InlineData("required")]
    [InlineData("priority")]
    [InlineData("mount-order")]
    [InlineData("dependency")]
    [InlineData("override")]
    public void SelectedDataPackageRuntimeMetadataChangeCountsAsAnUpdatedRuntimeRelease(string change)
    {
        var client = new UpdatePackage("client", "1", "artifacts/client", 16, new string('a', 64), true, "tar.zst");
        var baseData = new UpdatePackage("base-data", "1", "artifacts/base", 32, new string('b', 64), true, "nap")
        {
            ContentVersion = 1,
            Priority = 0,
            MountOrder = 0
        };
        var overlay = new UpdatePackage("overlay", "1", "artifacts/overlay", 32, new string('c', 64), true, "nap")
        {
            ContentVersion = 1,
            Priority = 1,
            MountOrder = 1
        };
        var current = ManifestWithDataPackages(client, baseData, overlay);
        var changedOverlay = change switch
        {
            "format" => overlay with { Format = "other" },
            "required" => overlay with { Required = false },
            "priority" => overlay with { Priority = 2 },
            "mount-order" => overlay with { MountOrder = 2 },
            "dependency" => overlay with { Dependencies = ["base-data"] },
            "override" => overlay with { Overrides = ["base-data"] },
            _ => throw new ArgumentOutOfRangeException(nameof(change))
        };
        var candidate = current with { Version = 2, Packages = [client, baseData, changedOverlay] };

        Assert.True(GatewayUpdatePolicy.HasUpdatedRuntimeRelease(current, client, candidate, client,
            NoOptionalPackages));
    }

    private static UpdateManifest ManifestWithDataPackages(UpdatePackage client, UpdatePackage baseData,
        UpdatePackage overlay) => new(1, 1, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), [client, baseData, overlay])
        {
            BuildId = "build-1",
            DataManifestId = "data-1",
            Capabilities = ["client_version_hello_v1"]
        };

    private static UpdateManifest Manifest(long version, string clientVersion, string buildId,
        string dataManifestId, char clientHash, UpdatePackage? dataPackage)
    {
        var client = new UpdatePackage("client", clientVersion, "artifacts/" + new string(clientHash, 64),
            16, new string(clientHash, 64), true, "tar.zst");
        return new UpdateManifest(1, version, "stable", "linux", "x64", clientVersion, "1.0.0", 1,
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1),
            dataPackage is null ? [client] : [client, dataPackage])
        {
            BuildId = buildId,
            DataManifestId = dataManifestId,
            Capabilities = ["client_version_hello_v1"]
        };
    }
}
