using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace LancerNexus.Updater;

public static class ArtifactDownloader
{
    private const long MaximumArtifactSize = 16L * 1024 * 1024 * 1024;

    public static Task<string> DownloadVerifiedAsync(
        UpdatePackage package, UpdaterOptions options, CancellationToken cancellationToken) =>
        DownloadVerifiedAsync(package, options, cancellationToken, null);

    internal static async Task<string> DownloadVerifiedAsync(
        UpdatePackage package, UpdaterOptions options, CancellationToken cancellationToken,
        HttpMessageHandler? testHandler)
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
        var digest = package.Sha256.ToLowerInvariant();
        var finalPath = Path.Combine(cacheDirectory, digest + ".package");
        var partialPath = Path.Combine(cacheDirectory, "." + digest + ".part");
        await using var artifactLock = await AcquireArtifactLockAsync(
            Path.Combine(cacheDirectory, "." + digest + ".lock"), cancellationToken);

        if (File.Exists(finalPath) && await MatchesAsync(finalPath, package, cancellationToken))
            return finalPath;

        if (File.Exists(partialPath))
        {
            var partialInfo = new FileInfo(partialPath);
            if (partialInfo.Length > package.Size)
                File.Delete(partialPath);
            else if (partialInfo.Length == package.Size)
            {
                if (await MatchesAsync(partialPath, package, cancellationToken))
                {
                    File.Move(partialPath, finalPath, overwrite: true);
                    return finalPath;
                }
                File.Delete(partialPath);
            }
        }

        var offset = File.Exists(partialPath) ? new FileInfo(partialPath).Length : 0;
        DiskSpaceGuard.EnsureAvailable(cacheDirectory, package.Size - offset);
        using var handler = testHandler ?? new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler, disposeHandler: testHandler is null)
        {
            Timeout = TimeSpan.FromMinutes(10)
        };
        using var request = new HttpRequestMessage(HttpMethod.Get, artifactUri);
        if (offset > 0)
            request.Headers.Range = new RangeHeaderValue(offset, null);

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var append = ValidateResponse(response, offset, package.Size);
        if (!append)
            offset = 0;

        await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (var output = new FileStream(partialPath,
                         append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.None,
                         128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough))
        {
            var buffer = new byte[128 * 1024];
            int read;
            while ((read = await input.ReadAsync(buffer, cancellationToken)) != 0)
            {
                if (output.Length + read > package.Size)
                {
                    await output.DisposeAsync();
                    File.Delete(partialPath);
                    throw new InvalidDataException("Artefakt überschreitet die signierte Größe.");
                }
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            await output.FlushAsync(cancellationToken);
            output.Flush(flushToDisk: true);
        }

        var completedLength = new FileInfo(partialPath).Length;
        if (completedLength < package.Size)
            throw new IOException("Artefaktdownload wurde vor der signierten Dateigröße unterbrochen; Teilinhalt bleibt für die Fortsetzung erhalten.");
        if (completedLength > package.Size)
        {
            File.Delete(partialPath);
            throw new InvalidDataException("Artefakt überschreitet die signierte Größe.");
        }
        if (!await MatchesAsync(partialPath, package, cancellationToken))
        {
            File.Delete(partialPath);
            throw new InvalidDataException("Artefakt-SHA-256 stimmt nicht mit dem signierten Manifest überein.");
        }

        File.Move(partialPath, finalPath, overwrite: true);
        return finalPath;
    }

    private static bool ValidateResponse(HttpResponseMessage response, long offset, long expectedSize)
    {
        if (offset > 0 && response.StatusCode == HttpStatusCode.OK)
        {
            ValidateContentLength(response, expectedSize);
            return false;
        }

        if (offset == 0 && response.StatusCode == HttpStatusCode.OK)
        {
            ValidateContentLength(response, expectedSize);
            return false;
        }

        if (response.StatusCode != HttpStatusCode.PartialContent || response.Content.Headers.ContentRange is not { } range ||
            !string.Equals(range.Unit, "bytes", StringComparison.OrdinalIgnoreCase) ||
            range.From != offset || range.To is null || range.To < offset || range.Length != expectedSize)
            throw new InvalidDataException("Downloadserver lieferte einen ungültigen oder nicht passenden Bytebereich.");

        var expectedRangeLength = checked(range.To.Value - offset + 1);
        if (response.Content.Headers.ContentLength is long contentLength && contentLength != expectedRangeLength)
            throw new InvalidDataException("Länge des gelieferten Bytebereichs ist ungültig.");
        return true;
    }

    private static void ValidateContentLength(HttpResponseMessage response, long expected)
    {
        if (response.Content.Headers.ContentLength is long actual && actual != expected)
            throw new InvalidDataException("Artefaktgröße stimmt nicht mit dem signierten Manifest überein.");
    }

    private static async Task<FileStream> AcquireArtifactLockAsync(string lockPath, CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None,
                    1, FileOptions.DeleteOnClose);
            }
            catch (IOException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }
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
