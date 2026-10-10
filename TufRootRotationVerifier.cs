using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace LancerNexus.Updater;

public sealed record TufRootSignature(
    [property: JsonPropertyName("keyid")] string KeyId,
    [property: JsonPropertyName("sig")] string Value);

public sealed record TufRootChainState(int Schema, IReadOnlyList<string> Updates);

/// <summary>Validates one TUF root transition using both predecessor and successor root thresholds.</summary>
public static class TufRootRotationVerifier
{
    private const int MaximumRootBytes = 64 * 1024;
    private const int MaximumRootKeys = 64;
    private const int MaximumSignatures = 64;
    private const int MaximumRootUpdates = 64;
    private const int MaximumRootStateBytes = 8 * 1024 * 1024;

    public static async Task<TrustRoot> UpdateChainAsync(TrustRoot bootstrapRoot, string statePath,
        Func<long, CancellationToken, Task<byte[]?>> fetchVersion, DateTime updateStartedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bootstrapRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(fetchVersion);
        ManifestVerifier.ValidateTrustRoot(bootstrapRoot);
        if (updateStartedAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("TUF update start time must be UTC.", nameof(updateStartedAtUtc));

        var fullStatePath = Path.GetFullPath(statePath);
        var stateDirectory = Path.GetDirectoryName(fullStatePath)!;
        Directory.CreateDirectory(stateDirectory);
        using var stateLock = new FileStream(fullStatePath + ".lock", FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);

        var updates = new List<string>();
        var currentRoot = bootstrapRoot;
        if (File.Exists(fullStatePath))
        {
            var stateInfo = new FileInfo(fullStatePath);
            if (stateInfo.Length is <= 0 or > MaximumRootStateBytes)
                throw new InvalidDataException("Persisted TUF root chain is empty or exceeds its size limit.");
            TufRootChainState state;
            try
            {
                state = JsonSerializer.Deserialize<TufRootChainState>(await File.ReadAllBytesAsync(fullStatePath, cancellationToken),
                    TrustRoot.JsonOptions) ?? throw new InvalidDataException("Persisted TUF root chain is empty.");
            }
            catch (JsonException error)
            {
                throw new InvalidDataException("Persisted TUF root chain is invalid.", error);
            }
            if (state.Schema != 1 || state.Updates is null || state.Updates.Count > MaximumRootUpdates)
                throw new InvalidDataException("Persisted TUF root chain has an unsupported schema or length.");
            foreach (var update in state.Updates)
            {
                byte[] bytes;
                try { bytes = Convert.FromBase64String(update); }
                catch (FormatException error) { throw new InvalidDataException("Persisted TUF root chain entry is invalid.", error); }
                currentRoot = VerifySuccessor(bytes, currentRoot);
                updates.Add(update);
            }
        }

        while (updates.Count < MaximumRootUpdates)
        {
            var nextVersion = checked(currentRoot.RootVersion + 1);
            var bytes = await fetchVersion(nextVersion, cancellationToken);
            if (bytes is null) break;
            currentRoot = VerifySuccessor(bytes, currentRoot);
            updates.Add(Convert.ToBase64String(bytes));
            await PersistStateAsync(fullStatePath, updates, cancellationToken);
        }

        if (updates.Count == MaximumRootUpdates)
        {
            var nextVersion = checked(currentRoot.RootVersion + 1);
            if (await fetchVersion(nextVersion, cancellationToken) is not null)
                throw new InvalidDataException("TUF root chain exceeds the maximum update count.");
        }
        EnsureCurrent(currentRoot, updateStartedAtUtc);
        return currentRoot;
    }

    public static TrustRoot VerifySuccessor(ReadOnlyMemory<byte> envelopeBytes, TrustRoot currentRoot)
    {
        ArgumentNullException.ThrowIfNull(currentRoot);
        ManifestVerifier.ValidateTrustRoot(currentRoot);
        if (envelopeBytes.Length is 0 or > MaximumRootBytes)
            throw new InvalidDataException("TUF root metadata is empty or exceeds its size limit.");

        try
        {
            using var document = JsonDocument.Parse(envelopeBytes);
            var envelope = document.RootElement;
            if (envelope.ValueKind != JsonValueKind.Object ||
                !envelope.TryGetProperty("signed", out var signed) || signed.ValueKind != JsonValueKind.Object ||
                !envelope.TryGetProperty("signatures", out var signaturesElement) ||
                signaturesElement.ValueKind != JsonValueKind.Array || signaturesElement.GetArrayLength() is < 1 or > MaximumSignatures)
                throw new InvalidDataException("TUF root envelope is malformed.");

            _ = ManifestCanonicalizer.Canonicalize(envelopeBytes.ToArray());

            var canonicalSigned = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
            var successor = ParseRoot(signed);
            if (successor.Version != checked(currentRoot.RootVersion + 1))
                throw new InvalidDataException("TUF root version is not the immediate successor.");

            var signatures = signaturesElement.EnumerateArray().Select(element =>
            {
                if (element.ValueKind != JsonValueKind.Object ||
                    !element.TryGetProperty("keyid", out var keyIdElement) || keyIdElement.ValueKind != JsonValueKind.String ||
                    !element.TryGetProperty("sig", out var signatureElement) || signatureElement.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("TUF root signature entry is malformed.");
                return new TufRootSignature(keyIdElement.GetString()!, signatureElement.GetString()!);
            }).ToArray();
            if (signatures.Select(signature => signature.KeyId).Distinct(StringComparer.Ordinal).Count() != signatures.Length)
                throw new InvalidDataException("TUF root contains duplicate signature key IDs.");

            var oldKeys = currentRoot.RootRoleKeys ?? currentRoot.Keys;
            var oldThreshold = currentRoot.RootRoleThreshold > 0 ? currentRoot.RootRoleThreshold : currentRoot.Threshold;
            if (!VerifyThreshold(canonicalSigned, signatures, oldKeys, oldThreshold) ||
                !VerifyThreshold(canonicalSigned, signatures, successor.RootRoleKeys, successor.RootRoleThreshold))
                throw new InvalidDataException("TUF root transition does not meet both root signature thresholds.");

            return currentRoot with
            {
                Keys = successor.TargetsRoleKeys,
                Threshold = successor.TargetsRoleThreshold,
                RootVersion = successor.Version,
                RootExpiresAtUtc = successor.ExpiresAtUtc,
                RootRoleKeys = successor.RootRoleKeys,
                RootRoleThreshold = successor.RootRoleThreshold,
                TimestampRoleKeys = successor.TimestampRoleKeys,
                TimestampRoleThreshold = successor.TimestampRoleThreshold,
                SnapshotRoleKeys = successor.SnapshotRoleKeys,
                SnapshotRoleThreshold = successor.SnapshotRoleThreshold,
                ConsistentSnapshot = successor.ConsistentSnapshot
            };
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("TUF root metadata JSON is invalid.", error);
        }
        catch (OverflowException error)
        {
            throw new InvalidDataException("TUF root version is out of range.", error);
        }
    }

    public static void EnsureCurrent(TrustRoot root, DateTime updateStartedAtUtc)
    {
        if (updateStartedAtUtc.Kind != DateTimeKind.Utc || root.RootExpiresAtUtc.Kind != DateTimeKind.Utc ||
            root.RootExpiresAtUtc <= updateStartedAtUtc)
            throw new InvalidDataException("Trusted TUF root metadata is expired or has invalid timestamps.");
    }

    private static async Task PersistStateAsync(string path, IReadOnlyList<string> updates,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new TufRootChainState(1, updates.ToArray()),
            TrustRoot.JsonOptions);
        if (bytes.Length > MaximumRootStateBytes)
            throw new InvalidDataException("Persisted TUF root chain exceeds its size limit.");
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static ParsedRoot ParseRoot(JsonElement signed)
    {
        if (RequiredString(signed, "_type") != "root" || RequiredString(signed, "spec_version") != "1.0.36" ||
            !signed.TryGetProperty("consistent_snapshot", out var consistentSnapshotElement) ||
            consistentSnapshotElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            !signed.TryGetProperty("version", out var versionElement) || !versionElement.TryGetInt64(out var version) || version < 1 ||
            !signed.TryGetProperty("expires", out var expiresElement) || expiresElement.ValueKind != JsonValueKind.String ||
            !DateTimeOffset.TryParseExact(expiresElement.GetString(), "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expires) ||
            expires.Offset != TimeSpan.Zero || !signed.TryGetProperty("keys", out var keysElement) ||
            keysElement.ValueKind != JsonValueKind.Object || !signed.TryGetProperty("roles", out var rolesElement) ||
            rolesElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("TUF root metadata fields are invalid or unsupported.");

        var keys = new Dictionary<string, TrustedKey>(StringComparer.Ordinal);
        var keyBytes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in keysElement.EnumerateObject())
        {
            if (keys.Count >= MaximumRootKeys || property.Name.Length != 64 || !property.Name.All(Uri.IsHexDigit) ||
                property.Value.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("TUF root key map is invalid.");
            var keyId = property.Name.ToLowerInvariant();
            var key = property.Value;
            if (RequiredString(key, "keytype") != "ed25519" || RequiredString(key, "scheme") != "ed25519" ||
                !key.TryGetProperty("keyval", out var keyValue) || keyValue.ValueKind != JsonValueKind.Object ||
                RequiredString(keyValue, "public") is not { Length: 64 } publicHex)
                throw new InvalidDataException("TUF root contains an unsupported key.");
            byte[] publicKey;
            try { publicKey = Convert.FromHexString(publicHex); }
            catch (FormatException error) { throw new InvalidDataException("TUF root public key is malformed.", error); }
            var keyDigest = Convert.ToHexString(SHA256.HashData(
                ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(property.Value)))).ToLowerInvariant();
            if (publicKey.Length != 32 || keyDigest != keyId || !keyBytes.Add(Convert.ToHexString(publicKey)))
                throw new InvalidDataException("TUF root key ID is incorrect or public key is duplicated.");
            keys.Add(keyId, new TrustedKey(keyId, "Ed25519", Convert.ToBase64String(publicKey)));
        }

        var roles = new Dictionary<string, ParsedRole>(StringComparer.Ordinal);
        foreach (var roleName in new[] { "root", "timestamp", "snapshot", "targets" })
        {
            if (!rolesElement.TryGetProperty(roleName, out var roleElement) || roleElement.ValueKind != JsonValueKind.Object ||
                !roleElement.TryGetProperty("keyids", out var idsElement) || idsElement.ValueKind != JsonValueKind.Array ||
                !roleElement.TryGetProperty("threshold", out var thresholdElement) ||
                !thresholdElement.TryGetInt32(out var threshold))
                throw new InvalidDataException($"TUF root is missing the {roleName} role.");
            var ids = idsElement.EnumerateArray().Select(id => id.ValueKind == JsonValueKind.String
                ? id.GetString()!
                : throw new InvalidDataException($"TUF {roleName} key ID is invalid.")).ToArray();
            if (ids.Length is < 1 or > MaximumRootKeys || ids.Distinct(StringComparer.Ordinal).Count() != ids.Length ||
                threshold < 1 || threshold > ids.Length || ids.Any(id => !keys.ContainsKey(id)))
                throw new InvalidDataException($"TUF {roleName} role threshold or key list is invalid.");
            roles.Add(roleName, new ParsedRole(ids.Select(id => keys[id]).ToArray(), threshold));
        }

        return new ParsedRoot(version, expires.UtcDateTime, roles["root"].Keys, roles["root"].Threshold,
            roles["targets"].Keys, roles["targets"].Threshold,
            roles["timestamp"].Keys, roles["timestamp"].Threshold,
            roles["snapshot"].Keys, roles["snapshot"].Threshold,
            consistentSnapshotElement.GetBoolean());
    }

    private static bool VerifyThreshold(byte[] payload, IReadOnlyList<TufRootSignature> signatures,
        IReadOnlyList<TrustedKey> keys, int threshold)
    {
        var trusted = keys.ToDictionary(key => key.KeyId, StringComparer.Ordinal);
        var verified = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signature in signatures)
        {
            if (!trusted.TryGetValue(signature.KeyId, out var key) || key.Algorithm != "Ed25519") continue;
            byte[] publicKey;
            byte[] signatureBytes;
            try
            {
                publicKey = Convert.FromBase64String(key.PublicKey);
                signatureBytes = Convert.FromHexString(signature.Value);
            }
            catch (FormatException) { continue; }
            if (publicKey.Length != 32 || signatureBytes.Length != 64) continue;
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.BlockUpdate(payload, 0, payload.Length);
            if (verifier.VerifySignature(signatureBytes)) verified.Add(signature.KeyId);
        }
        return verified.Count >= threshold;
    }

    private static string RequiredString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()!
            : throw new InvalidDataException($"TUF root field '{propertyName}' is invalid.");

    private sealed record ParsedRoot(long Version, DateTime ExpiresAtUtc,
        IReadOnlyList<TrustedKey> RootRoleKeys, int RootRoleThreshold,
        IReadOnlyList<TrustedKey> TargetsRoleKeys, int TargetsRoleThreshold,
        IReadOnlyList<TrustedKey> TimestampRoleKeys, int TimestampRoleThreshold,
        IReadOnlyList<TrustedKey> SnapshotRoleKeys, int SnapshotRoleThreshold,
        bool ConsistentSnapshot);

    private sealed record ParsedRole(IReadOnlyList<TrustedKey> Keys, int Threshold);
}
