using System.Security.Cryptography;

namespace LancerNexus.Updater;

public static class ArtifactDownloader
{
    private const long MaximumArtifactSize = 16L * 1024 * 1024 * 1024;

    public static async Task<string> DownloadVerifiedAsync(
        UpdatePackage package, UpdaterOptions options, CancellationToken cancellationToken)
    {
        if (package.Size is <= 0 or > MaximumArtifactSize || package.Sha256.Length != 64 ||
            !package.Sha256.All(Uri.IsHexDigit))
            throw new InvalidDataException("Paketgröße oder SHA-256 ist ungültig.");

        var baseUri = options.EffectiveArtifactBaseUri;
        if (!baseUri.IsAbsoluteUri || baseUri.Scheme != Uri.UriSchemeHttps || !baseUri.AbsolutePath.EndsWith('/') ||
            !string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment) ||
            !Uri.TryCreate(package.Url, UriKind.Relative, out var relativeUrl))
            throw new InvalidOperationException("Konfigurierte Artefakt-Basis oder Paket-URL ist ungültig.");

        var artifactUri = new Uri(baseUri, relativeUrl);
        if (artifactUri.Scheme != Uri.UriSchemeHttps || artifactUri.UserInfo.Length != 0 ||
            !string.Equals(artifactUri.IdnHost, baseUri.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            artifactUri.Port != baseUri.Port || !artifactUri.AbsolutePath.StartsWith(baseUri.AbsolutePath, StringComparison.Ordinal))
            throw new InvalidDataException("Paket-URL verlässt die konfigurierte Artefaktquelle.");

        var cacheDirectory = Path.GetFullPath(options.CachePath);
        Directory.CreateDirectory(cacheDirectory);
        var finalPath = Path.Combine(cacheDirectory, package.Sha256.ToLowerInvariant() + ".package");
        if (File.Exists(finalPath) && await MatchesAsync(finalPath, package, cancellationToken))
            return finalPath;

        var temporaryPath = Path.Combine(cacheDirectory, $".{package.Sha256}.{Guid.NewGuid():N}.part");
        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(10) };
            using var response = await client.GetAsync(artifactUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
                throw new HttpRequestException($"Artefaktdownload antwortete mit HTTP {(int)response.StatusCode}.");
            if (response.Content.Headers.ContentLength is long contentLength && contentLength != package.Size)
                throw new InvalidDataException("Artefaktgröße stimmt nicht mit dem signierten Manifest überein.");

            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[128 * 1024];
            long total = 0;
            int read;
            while ((read = await input.ReadAsync(buffer, cancellationToken)) != 0)
            {
                total += read;
                if (total > package.Size)
                    throw new InvalidDataException("Artefakt überschreitet die signierte Größe.");
                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            await output.FlushAsync(cancellationToken);
            if (total != package.Size || !CryptographicOperations.FixedTimeEquals(
                    hash.GetHashAndReset(), Convert.FromHexString(package.Sha256)))
                throw new InvalidDataException("Artefaktgröße oder SHA-256 stimmt nicht mit dem signierten Manifest überein.");

            File.Move(temporaryPath, finalPath, overwrite: true);
            return finalPath;
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private static async Task<bool> MatchesAsync(string path, UpdatePackage package, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.Length != package.Size)
            return false;
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(package.Sha256));
    }
}
