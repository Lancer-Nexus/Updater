using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace LancerNexus.Updater;

public sealed record UpdateManifest(
    int Schema, long Version, string Channel, string Platform, string Architecture,
    string ClientVersion, string MinimumUpdaterVersion, int ProtocolVersion,
    DateTime GeneratedAtUtc, DateTime ExpiresAtUtc, IReadOnlyList<UpdatePackage> Packages)
{
    public string BuildId { get; init; } = "";
    public string DataManifestId { get; init; } = "";
    public IReadOnlyList<string> Capabilities { get; init; } = [];
}

public sealed record UpdatePackage(
    string Id, string Version, string Url, long Size, string Sha256, bool Required, string Format = "");
public sealed record ManifestSignature(string KeyId, string Algorithm, string Value);
public sealed record SignedManifest(string Signed, IReadOnlyList<ManifestSignature> Signatures);
public sealed record TrustedKey(string KeyId, string Algorithm, string PublicKey);

// Distributed with the bootstrapper through a trusted channel; never fetched from the manifest URL.
public sealed record TrustRoot(int Schema, int Threshold, IReadOnlyList<TrustedKey> Keys, long MinimumManifestVersion)
{
    public static TrustRoot Load(string path) =>
        JsonSerializer.Deserialize<TrustRoot>(File.ReadAllBytes(path), JsonOptions)
        ?? throw new InvalidDataException("Trust root ist leer.");

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}

public static class ManifestClient
{
    public static async Task<SignedManifest> LoadAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Manifest URL muss HTTPS verwenden.");
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        const int maximumBytes = 2_097_152;
        if (response.Content.Headers.ContentLength > maximumBytes)
            throw new InvalidDataException("Signiertes Manifest ist zu groß.");
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int count;
        while ((count = await source.ReadAsync(chunk, cancellationToken)) != 0)
        {
            if (buffer.Length + count > maximumBytes)
                throw new InvalidDataException("Signiertes Manifest ist zu groß.");
            buffer.Write(chunk, 0, count);
        }
        buffer.Position = 0;
        return await JsonSerializer.DeserializeAsync<SignedManifest>(buffer, TrustRoot.JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("Signiertes Manifest ist leer.");
    }
}

public static class ManifestVerifier
{
    public static UpdateManifest Validate(SignedManifest envelope, TrustRoot root, UpdaterOptions options, DateTime nowUtc)
    {
        if (root.Schema != 1 || root.Threshold < 1 || root.Keys is null || root.Threshold > root.Keys.Count ||
            root.MinimumManifestVersion < 1 || root.Keys.Any(k => string.IsNullOrWhiteSpace(k.KeyId) ||
                k.Algorithm != "Ed25519" || string.IsNullOrWhiteSpace(k.PublicKey)) ||
            root.Keys.Select(k => k.KeyId).Distinct(StringComparer.Ordinal).Count() != root.Keys.Count)
            throw new InvalidDataException("Trust root ist ungültig.");
        if (envelope.Signatures is null || string.IsNullOrWhiteSpace(envelope.Signed))
            throw new InvalidDataException("Manifest-Signatur fehlt.");

        byte[] payload;
        try { payload = Convert.FromBase64String(envelope.Signed); }
        catch (FormatException error) { throw new InvalidDataException("Manifest-Payload ist ungültig.", error); }
        if (payload.Length is 0 or > 1_048_576)
            throw new InvalidDataException("Manifest-Payload ist zu groß oder leer.");

        var validKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signature in envelope.Signatures)
        {
            var key = root.Keys.FirstOrDefault(k => k.KeyId == signature.KeyId && k.Algorithm == "Ed25519");
            if (key is null || signature.Algorithm != "Ed25519" || validKeys.Contains(key.KeyId))
                continue;
            try
            {
                var publicKey = Convert.FromBase64String(key.PublicKey);
                var signatureBytes = Convert.FromBase64String(signature.Value);
                if (publicKey.Length != 32 || signatureBytes.Length != 64)
                    throw new InvalidDataException("Ed25519-Schlüssel oder Signatur hat eine falsche Länge.");
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
                verifier.BlockUpdate(payload, 0, payload.Length);
                if (verifier.VerifySignature(signatureBytes))
                    validKeys.Add(key.KeyId);
            }
            catch (FormatException error) { throw new InvalidDataException("Ed25519-Wert ist ungültig.", error); }
        }
        if (validKeys.Count < root.Threshold)
            throw new InvalidDataException("Manifest-Signaturschwelle nicht erreicht.");

        UpdateManifest manifest;
        try { manifest = JsonSerializer.Deserialize<UpdateManifest>(payload, TrustRoot.JsonOptions)
            ?? throw new InvalidDataException("Manifest ist leer."); }
        catch (JsonException error) { throw new InvalidDataException("Manifest-Payload ist kein gültiges JSON.", error); }
        if (manifest.Schema != 1 || manifest.Version < root.MinimumManifestVersion ||
            manifest.Channel != options.Channel || manifest.Platform != options.Platform ||
            manifest.Architecture != options.Architecture)
            throw new InvalidDataException("Manifest passt nicht zur lokalen Installation oder ist ein Rollback.");
        if (manifest.GeneratedAtUtc.Kind != DateTimeKind.Utc || manifest.ExpiresAtUtc.Kind != DateTimeKind.Utc ||
            manifest.GeneratedAtUtc > nowUtc || manifest.ExpiresAtUtc <= nowUtc ||
            manifest.ExpiresAtUtc <= manifest.GeneratedAtUtc)
            throw new InvalidDataException("Manifest ist abgelaufen oder zeitlich ungültig.");
        if (!Version.TryParse(manifest.ClientVersion, out _) ||
            string.IsNullOrWhiteSpace(manifest.MinimumUpdaterVersion) ||
            string.IsNullOrWhiteSpace(manifest.BuildId) || string.IsNullOrWhiteSpace(manifest.DataManifestId) ||
            manifest.BuildId.Length > 128 || manifest.DataManifestId.Length > 128 ||
            manifest.ProtocolVersion < 1 || manifest.Capabilities is null || manifest.Capabilities.Count > 128 ||
            manifest.Capabilities.Any(c => string.IsNullOrWhiteSpace(c) || c.Length > 128) ||
            manifest.Packages is null || manifest.Packages.Count == 0 ||
            !manifest.Packages.Any(p => p.Required && p.Id == "client"))
            throw new InvalidDataException("Manifest enthält keine gültige Clientversion oder Pflichtpakete.");
        var runningVersion = typeof(ManifestVerifier).Assembly.GetName().Version ?? new Version(0, 0);
        if (!Version.TryParse(manifest.MinimumUpdaterVersion, out var minimumUpdaterVersion) ||
            minimumUpdaterVersion > runningVersion)
            throw new InvalidDataException("Updater-Version ist für dieses Manifest zu alt.");
        foreach (var package in manifest.Packages)
        {
            if (string.IsNullOrWhiteSpace(package.Id) || string.IsNullOrWhiteSpace(package.Version) ||
            package.Size <= 0 || package.Sha256?.Length != 64 || !package.Sha256.All(Uri.IsHexDigit) ||
                package.Format != "tar.zst" ||
                !Uri.TryCreate(package.Url, UriKind.Relative, out var relative) ||
                package.Url.StartsWith('/') || package.Url.StartsWith('\\') ||
                package.Url.Contains('\\') || package.Url.Contains('?') || package.Url.Contains('#') ||
                relative.OriginalString.Split('/').Any(segment => segment is "" or "." or ".." ||
                    segment.Contains('%', StringComparison.Ordinal)))
                throw new InvalidDataException($"Paket '{package.Id}' ist ungültig.");
        }
        if (manifest.Packages.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() != manifest.Packages.Count)
            throw new InvalidDataException("Manifest enthält doppelte Paket-IDs.");
        return manifest;
    }
}
