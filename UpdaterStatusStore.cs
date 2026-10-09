using System.Text.Json;
using System.Text.Json.Serialization;

namespace LancerNexus.Updater;

[JsonConverter(typeof(JsonStringEnumConverter<UpdaterOperationState>))]
public enum UpdaterOperationState
{
    Checking,
    Downloading,
    Staging,
    Ready,
    Failed
}

public sealed record UpdaterStatusDocument(
    int SchemaVersion,
    UpdaterOperationState State,
    string? Message,
    string? InstalledVersion,
    bool InstallationVerified,
    string? ErrorCode = null);

public static class UpdaterStatusStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter<UpdaterOperationState>() }
    };

    public static async Task WriteAsync(string? path, UpdaterStatusDocument status)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             4096, FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(output, status, JsonOptions);
                await output.FlushAsync();
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
