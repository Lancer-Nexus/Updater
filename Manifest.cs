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
    string Id, string Version, string Url, long Size, string Sha256, bool Required, string Format = "")
{
    public ulong? ContentVersion { get; init; }
    public int Priority { get; init; }
    public int MountOrder { get; init; }
    public IReadOnlyList<string> Dependencies { get; init; } = [];
    public IReadOnlyList<string> Overrides { get; init; } = [];
}
public sealed record ManifestSignature(string KeyId, string Algorithm, string Value);
public sealed record SignedManifest(string Signed, IReadOnlyList<ManifestSignature> Signatures);
public sealed record TrustedKey(string KeyId, string Algorithm, string PublicKey);

// Distributed with the bootstrapper through a trusted channel; never fetched from the manifest URL.
public sealed record TrustRoot(int Schema, int Threshold, IReadOnlyList<TrustedKey> Keys, long MinimumManifestVersion)
{
    public long RootVersion { get; init; }
    public DateTime RootExpiresAtUtc { get; init; } = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc);
    public IReadOnlyList<TrustedKey>? RootRoleKeys { get; init; }
    public int RootRoleThreshold { get; init; }
    public IReadOnlyList<TrustedKey>? TimestampRoleKeys { get; init; }
    public int TimestampRoleThreshold { get; init; }
    public IReadOnlyList<TrustedKey>? SnapshotRoleKeys { get; init; }
    public int SnapshotRoleThreshold { get; init; }
    public bool ConsistentSnapshot { get; init; }

    public static TrustRoot Load(string path) =>
        JsonSerializer.Deserialize<TrustRoot>(File.ReadAllBytes(path), JsonOptions)
        ?? throw new InvalidDataException("Trust root ist leer.");

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}

public static class ManifestClient
{
    public static async Task<SignedManifest> LoadAsync(Uri uri, CancellationToken cancellationToken)
        => await LoadAsync(uri, cancellationToken, null);

    internal static async Task<SignedManifest> LoadAsync(
        Uri uri, CancellationToken cancellationToken, HttpMessageHandler? testHandler)
    {
        var bytes = await LoadBytesAsync(uri, cancellationToken, testHandler, "Signiertes Manifest");
        try
        {
            return JsonSerializer.Deserialize<SignedManifest>(bytes, TrustRoot.JsonOptions)
                ?? throw new InvalidDataException("Signiertes Manifest ist leer.");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Signiertes Manifest ist kein gültiges JSON.", error);
        }
    }

    public static Task<byte[]> LoadTufMetadataBytesAsync(Uri uri, CancellationToken cancellationToken) =>
        LoadTufMetadataBytesAsync(uri, cancellationToken, null);

    internal static Task<byte[]> LoadTufMetadataBytesAsync(Uri uri, CancellationToken cancellationToken,
        HttpMessageHandler? testHandler) => LoadBytesAsync(uri, cancellationToken, testHandler, "TUF metadata");

    public static Task<byte[]> LoadBytesAsync(Uri uri, CancellationToken cancellationToken) =>
        LoadBytesAsync(uri, cancellationToken, null, "Signiertes Manifest");

    internal static Task<byte[]> LoadBytesAsync(Uri uri, CancellationToken cancellationToken,
        HttpMessageHandler? testHandler) => LoadBytesAsync(uri, cancellationToken, testHandler, "Signiertes Manifest");

    private static async Task<byte[]> LoadBytesAsync(Uri uri, CancellationToken cancellationToken,
        HttpMessageHandler? testHandler, string description)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException($"{description} URL muss HTTPS verwenden.");
        using var handler = testHandler ?? new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler, disposeHandler: testHandler is null)
        { Timeout = TimeSpan.FromSeconds(30) };
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        const int maximumBytes = 2_097_152;
        if (response.Content.Headers.ContentLength > maximumBytes)
            throw new InvalidDataException($"{description} überschreitet 2 MiB.");
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int count;
        while ((count = await source.ReadAsync(chunk, cancellationToken)) != 0)
        {
            if (buffer.Length + count > maximumBytes)
                throw new InvalidDataException($"{description} überschreitet 2 MiB.");
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    public static async Task<byte[]?> LoadRootMetadataAsync(Uri uri, CancellationToken cancellationToken) =>
        await LoadRootMetadataAsync(uri, cancellationToken, null);

    internal static async Task<byte[]?> LoadRootMetadataAsync(
        Uri uri, CancellationToken cancellationToken, HttpMessageHandler? testHandler)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("TUF root metadata URL muss HTTPS verwenden.");
        using var handler = testHandler ?? new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler, disposeHandler: testHandler is null)
        { Timeout = TimeSpan.FromSeconds(30) };
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        const int maximumBytes = 64 * 1024;
        if (response.Content.Headers.ContentLength > maximumBytes)
            throw new InvalidDataException("TUF root metadata exceeds its size limit.");
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int count;
        while ((count = await source.ReadAsync(chunk, cancellationToken)) != 0)
        {
            if (buffer.Length + count > maximumBytes)
                throw new InvalidDataException("TUF root metadata exceeds its size limit.");
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }
}

public static class ManifestVerifier
{
    public static UpdateManifest Validate(SignedManifest envelope, TrustRoot root, UpdaterOptions options, DateTime nowUtc)
    {
        ValidateTrustRoot(root);
        if (envelope.Signatures is null || string.IsNullOrWhiteSpace(envelope.Signed))
            throw new InvalidDataException("Manifest-Signatur fehlt.");

        byte[] payload;
        try { payload = Convert.FromBase64String(envelope.Signed); }
        catch (FormatException error) { throw new InvalidDataException("Manifest-Payload ist ungültig.", error); }
        if (payload.Length is 0 or > 1_048_576)
            throw new InvalidDataException("Manifest-Payload ist zu groß oder leer.");

        UpdateManifest manifest;
        try
        {
            var canonicalPayload = ManifestCanonicalizer.Canonicalize(payload);
            if (!payload.AsSpan().SequenceEqual(canonicalPayload))
                throw new InvalidDataException("Manifest-Payload ist nicht RFC 8785 kanonisiert.");
            manifest = JsonSerializer.Deserialize<UpdateManifest>(payload, TrustRoot.JsonOptions)
                ?? throw new InvalidDataException("Manifest ist leer.");
        }
        catch (JsonException error) { throw new InvalidDataException("Manifest-Payload ist kein gültiges JSON.", error); }

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
            if (string.IsNullOrWhiteSpace(package.Id) || package.Id.Length > 96 ||
                package.Id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) ||
                string.IsNullOrWhiteSpace(package.Version) ||
            package.Size <= 0 || package.Sha256?.Length != 64 || !package.Sha256.All(Uri.IsHexDigit) ||
                (package.Id == "client" ? package.Format != "tar.zst" :
                    package.Format != "nap" || !package.ContentVersion.HasValue ||
                    package.Dependencies is null || package.Overrides is null) ||
                !Uri.TryCreate(package.Url, UriKind.Relative, out var relative) ||
                package.Url.StartsWith('/') || package.Url.StartsWith('\\') ||
                package.Url.Contains('\\') || package.Url.Contains('?') || package.Url.Contains('#') ||
                relative.OriginalString.Split('/').Any(segment => segment is "" or "." or ".." ||
                    segment.Contains('%', StringComparison.Ordinal)))
                throw new InvalidDataException($"Paket '{package.Id}' ist ungültig.");
        }
        if (manifest.Packages.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() != manifest.Packages.Count)
            throw new InvalidDataException("Manifest enthält doppelte Paket-IDs.");
        var dataPackages = manifest.Packages.Where(p => p.Id != "client").ToArray();
        var dataIds = dataPackages.Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
        if (dataPackages.GroupBy(p => (p.Priority, p.MountOrder)).Any(g => g.Count() > 1))
            throw new InvalidDataException("NAP-Pakete benötigen je Priorität eine eindeutige Mount-Reihenfolge.");
        foreach (var package in dataPackages)
        {
            if (package.Dependencies.Any(id => !dataIds.Contains(id) || id == package.Id) ||
                package.Overrides.Any(id => !dataIds.Contains(id) || id == package.Id) ||
                package.Dependencies.Distinct(StringComparer.Ordinal).Count() != package.Dependencies.Count ||
                package.Overrides.Distinct(StringComparer.Ordinal).Count() != package.Overrides.Count)
                throw new InvalidDataException($"NAP-Paket '{package.Id}' hat ungültige Abhängigkeiten oder Overrides.");
        }
        var visit = new Dictionary<string, byte>(StringComparer.Ordinal);
        var byId = dataPackages.ToDictionary(p => p.Id, StringComparer.Ordinal);
        int CompareMountOrder(UpdatePackage left, UpdatePackage right)
        {
            var comparison = left.Priority.CompareTo(right.Priority);
            if (comparison == 0) comparison = left.MountOrder.CompareTo(right.MountOrder);
            return comparison == 0 ? StringComparer.Ordinal.Compare(left.Id, right.Id) : comparison;
        }
        foreach (var package in dataPackages)
            foreach (var prerequisiteId in package.Dependencies.Concat(package.Overrides))
                if (CompareMountOrder(byId[prerequisiteId], package) >= 0)
                    throw new InvalidDataException($"NAP-Paket '{prerequisiteId}' muss vor '{package.Id}' gemountet werden.");
        bool HasDependencyCycle(string id)
        {
            if (visit.TryGetValue(id, out var state)) return state == 1;
            visit[id] = 1;
            foreach (var dependency in byId[id].Dependencies)
                if (HasDependencyCycle(dependency)) return true;
            visit[id] = 2;
            return false;
        }
        if (dataIds.Any(HasDependencyCycle))
            throw new InvalidDataException("NAP-Paketabhängigkeiten enthalten einen Zyklus.");
        return manifest;
    }

    internal static void ValidateTrustRoot(TrustRoot root)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (root.Schema != 1 || root.MinimumManifestVersion < 1 || root.RootVersion < 0 ||
            root.RootExpiresAtUtc.Kind != DateTimeKind.Utc || root.Keys is null ||
            root.RootRoleKeys is null && root.RootRoleThreshold != 0 ||
            root.RootRoleKeys is not null && (root.RootRoleThreshold < 1 || root.RootRoleThreshold > root.RootRoleKeys.Count))
            throw new InvalidDataException("Trust root ist ungültig.");
        ValidateKeySet(root.Keys, root.Threshold);
        if (root.RootRoleKeys is { } rootKeys) ValidateKeySet(rootKeys, root.RootRoleThreshold);
        if ((root.TimestampRoleKeys is null) != (root.TimestampRoleThreshold == 0) ||
            (root.SnapshotRoleKeys is null) != (root.SnapshotRoleThreshold == 0))
            throw new InvalidDataException("Trust root role keys and thresholds must be configured together.");
        if (root.TimestampRoleKeys is { } timestampKeys) ValidateKeySet(timestampKeys, root.TimestampRoleThreshold);
        if (root.SnapshotRoleKeys is { } snapshotKeys) ValidateKeySet(snapshotKeys, root.SnapshotRoleThreshold);
    }

    private static void ValidateKeySet(IReadOnlyList<TrustedKey> keys, int threshold)
    {
        if (threshold < 1 || threshold > keys.Count || keys.Any(key => key is null ||
                string.IsNullOrWhiteSpace(key.KeyId) || key.Algorithm != "Ed25519" || key.PublicKey is not { Length: 44 }) ||
            keys.Select(key => key.KeyId).Distinct(StringComparer.Ordinal).Count() != keys.Count)
            throw new InvalidDataException("Trust root ist ungültig.");
        var publicKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            byte[] publicKey;
            try { publicKey = Convert.FromBase64String(key.PublicKey); }
            catch (FormatException error)
            {
                throw new InvalidDataException("Trust root enthält einen ungültigen Ed25519-Schlüssel.", error);
            }
            var canonicalPublicKey = Convert.ToBase64String(publicKey);
            if (publicKey.Length != 32 || !string.Equals(canonicalPublicKey, key.PublicKey, StringComparison.Ordinal) ||
                !publicKeys.Add(canonicalPublicKey))
                throw new InvalidDataException("Trust root enthält einen ungültigen oder doppelten Ed25519-Schlüssel.");
        }
    }
}
