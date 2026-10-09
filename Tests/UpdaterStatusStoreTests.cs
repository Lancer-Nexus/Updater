using System.Text.Json;
using LancerNexus.Updater;
using Xunit;

namespace Updater.Tests;

public sealed class UpdaterStatusStoreTests
{
    [Fact]
    public async Task WritesReadyStatusAsAtomicVersionedJson()
    {
        var root = Path.Combine(Path.GetTempPath(), "lancer-updater-status", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(root, "status.json");
        try
        {
            await UpdaterStatusStore.WriteAsync(path, new UpdaterStatusDocument(
                1, UpdaterOperationState.Ready, "Installation verified.", "1.2.3", true));

            using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(path));
            Assert.Equal(1, document.RootElement.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("Ready", document.RootElement.GetProperty("state").GetString());
            Assert.True(document.RootElement.GetProperty("installationVerified").GetBoolean());
            Assert.Empty(Directory.EnumerateFiles(root, "*.tmp"));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
