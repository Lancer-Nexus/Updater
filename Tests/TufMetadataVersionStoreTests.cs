using System.Text.Json;
using LancerNexus.Updater;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class TufMetadataVersionStoreTests
{
    [Fact]
    public void PersistsVersionsAndRejectsRollbackOrSameVersionContentChanges()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"lancer-tuf-versions-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "metadata-versions.json");
        var root = CreateRoot();
        var accepted = Repository(2, 3, 4, 'a');
        try
        {
            Assert.Equal(new TufMetadataVersions(0, 0, 0),
                TufMetadataVersionStore.GetMinimumVersions(path, root));
            TufMetadataVersionStore.Accept(path, root, accepted);

            Assert.Equal(accepted.Versions, TufMetadataVersionStore.GetMinimumVersions(path, root));
            TufMetadataVersionStore.Accept(path, root, accepted);
            Assert.Throws<InvalidDataException>(() => TufMetadataVersionStore.Accept(path, root,
                Repository(1, 3, 4, 'b')));
            Assert.Throws<InvalidDataException>(() => TufMetadataVersionStore.Accept(path, root,
                Repository(2, 3, 4, 'b')));

            var written = JsonDocument.Parse(File.ReadAllBytes(path));
            Assert.Equal(2L, written.RootElement.GetProperty("timestamp").GetProperty("version").GetInt64());
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ResetsAffectedVersionFloorsWhenRoleKeysRotate()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"lancer-tuf-role-rotation-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "metadata-versions.json");
        var root = CreateRoot();
        try
        {
            TufMetadataVersionStore.Accept(path, root, Repository(2, 3, 4, 'a'));

            var timestampRotated = root with
            {
                TimestampRoleKeys = [Key("timestamp-replacement", 0x14)]
            };
            Assert.Equal(new TufMetadataVersions(0, 0, 4),
                TufMetadataVersionStore.GetMinimumVersions(path, timestampRotated));

            var targetsRotated = timestampRotated with
            {
                Keys = [Key("targets-replacement", 0x15)]
            };
            Assert.Equal(new TufMetadataVersions(0, 0, 0),
                TufMetadataVersionStore.GetMinimumVersions(path, targetsRotated));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CorruptPersistentStateFailsClosed()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"lancer-tuf-corrupt-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "metadata-versions.json");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(path, "not json");
            Assert.Throws<InvalidDataException>(() => TufMetadataVersionStore.GetMinimumVersions(path, CreateRoot()));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static TrustRoot CreateRoot() => new(1, 1, [Key("targets", 0x11)], 1)
    {
        TimestampRoleKeys = [Key("timestamp", 0x12)],
        TimestampRoleThreshold = 1,
        SnapshotRoleKeys = [Key("snapshot", 0x13)],
        SnapshotRoleThreshold = 1
    };

    private static TrustedKey Key(string keyId, byte seed) => new(keyId, "Ed25519",
        Convert.ToBase64String(Enumerable.Repeat(seed, 32).ToArray()));

    private static VerifiedTufRepository Repository(long timestamp, long snapshot, long targets, char digest) =>
        new(new TufMetadataVersions(timestamp, snapshot, targets), new Dictionary<string, TufTargetInfo>(),
            new string(digest, 64), new string((char)(digest + 1), 64), new string((char)(digest + 2), 64));
}
