using System.Security.Cryptography;
using System.Text.Json;

namespace LancerNexus.Updater;

public sealed record AcceptedManifestState(
    int Schema, string Channel, string Platform, string Architecture,
    long Version, string Sha256);

public static class ManifestRollbackStore
{
    public static void Accept(string path, UpdaterOptions options, SignedManifest envelope, UpdateManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("Trusted metadata state path is required.");
        path = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        using var stateLock = new FileStream(path + ".lock", FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        var digest = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(envelope.Signed)));
        AcceptedManifestState? old = null;
        if (File.Exists(path))
        {
            try
            {
                old = JsonSerializer.Deserialize<AcceptedManifestState>(File.ReadAllBytes(path), TrustRoot.JsonOptions);
            }
            catch (JsonException error)
            {
                throw new InvalidDataException("Trusted metadata state is invalid.", error);
            }
            if (old is null || old.Schema != 1 || old.Version < 1 || old.Sha256.Length != 64 ||
                !old.Sha256.All(Uri.IsHexDigit) || old.Channel != options.Channel ||
                old.Platform != options.Platform || old.Architecture != options.Architecture)
                throw new InvalidDataException("Trusted metadata state does not match this installation.");
            if (manifest.Version < old.Version ||
                manifest.Version == old.Version && !string.Equals(digest, old.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Signed manifest rollback or version reuse detected.");
            if (manifest.Version == old.Version)
                return;
        }

        var state = new AcceptedManifestState(1, options.Channel, options.Platform,
            options.Architecture, manifest.Version, digest);
        var temporary = Path.Combine(directory, $".trusted-metadata-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(state, TrustRoot.JsonOptions));
            File.Move(temporary, path, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}
