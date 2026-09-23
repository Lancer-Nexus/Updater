using System.Net.Http.Json;

namespace LancerNexus.Updater;

public sealed record UpdateManifest(
    int Schema, string Channel, string Platform, string Architecture,
    string ClientVersion, string MinimumUpdaterVersion, int ProtocolVersion,
    DateTime GeneratedAtUtc, DateTime ExpiresAtUtc, IReadOnlyList<UpdatePackage> Packages);

public sealed record UpdatePackage(string Id, string Version, string Url, long Size, string Sha256, bool Required);

public static class ManifestClient
{
    public static async Task<UpdateManifest> LoadAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        return await client.GetFromJsonAsync<UpdateManifest>(uri, cancellationToken)
            ?? throw new InvalidDataException("Manifest ist leer.");
    }
}

public static class ManifestVerifier
{
    public static void Validate(UpdateManifest manifest, UpdaterOptions options)
    {
        var now = DateTime.UtcNow;
        if (manifest.Schema != 1 || manifest.Channel != options.Channel ||
            manifest.Platform != options.Platform || manifest.Architecture != options.Architecture)
            throw new InvalidDataException("Manifest passt nicht zur lokalen Installation.");
        if (manifest.ExpiresAtUtc <= now || manifest.ExpiresAtUtc <= manifest.GeneratedAtUtc)
            throw new InvalidDataException("Manifest ist abgelaufen oder zeitlich ungültig.");
        if (manifest.Packages.Count == 0)
            throw new InvalidDataException("Manifest enthält keine Pakete.");
        foreach (var package in manifest.Packages)
        {
            if (package.Size <= 0 || package.Sha256.Length != 64 || !package.Sha256.All(Uri.IsHexDigit) ||
                !Uri.TryCreate(package.Url, UriKind.Relative, out _) || package.Url.Contains("..", StringComparison.Ordinal))
                throw new InvalidDataException($"Paket '{package.Id}' ist ungültig.");
        }
    }
}
