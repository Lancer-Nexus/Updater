using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LancerNexus.Updater;

internal sealed record TufDelegatedRole(string Name, IReadOnlyList<TrustedKey> Keys, int Threshold,
    IReadOnlyList<string>? Paths, IReadOnlyList<string>? PathHashPrefixes, bool Terminating)
{
    public bool Matches(string targetPath)
    {
        if (Paths is not null && !Paths.Any(pattern => TufDelegationVerifier.PathMatches(pattern, targetPath)))
            return false;
        if (PathHashPrefixes is null) return true;
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(targetPath)));
        return PathHashPrefixes.Any(prefix => digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>Parses delegated target roles and enforces their target path scopes.</summary>
internal static class TufDelegationVerifier
{
    private const int MaximumDelegatedKeys = 128;
    private const int MaximumDelegatedRoles = 128;
    private const int MaximumRoleKeys = 64;
    private const int MaximumRoleSelectors = 256;

    public static IReadOnlyList<TufDelegatedRole> ReadRoles(JsonElement signed)
    {
        if (!signed.TryGetProperty("delegations", out var delegations)) return [];
        if (delegations.ValueKind != JsonValueKind.Object ||
            !delegations.TryGetProperty("keys", out var keyMap) || keyMap.ValueKind != JsonValueKind.Object ||
            !delegations.TryGetProperty("roles", out var roles) || roles.ValueKind != JsonValueKind.Array ||
            roles.GetArrayLength() > MaximumDelegatedRoles)
            throw new InvalidDataException("TUF delegations object is malformed or exceeds its role limit.");

        var keys = ReadKeys(keyMap);
        var result = new List<TufDelegatedRole>(roles.GetArrayLength());
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in roles.EnumerateArray())
        {
            if (role.ValueKind != JsonValueKind.Object ||
                !role.TryGetProperty("name", out var nameElement) || nameElement.ValueKind != JsonValueKind.String ||
                !role.TryGetProperty("keyids", out var keyIdsElement) || keyIdsElement.ValueKind != JsonValueKind.Array ||
                !role.TryGetProperty("threshold", out var thresholdElement) || !thresholdElement.TryGetInt32(out var threshold) ||
                !role.TryGetProperty("terminating", out var terminatingElement) ||
                terminatingElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new InvalidDataException("TUF delegated role entry is malformed.");

            var name = nameElement.GetString()!;
            if (!IsValidRoleName(name) || !names.Add(name))
                throw new InvalidDataException("TUF delegated role name is unsafe or duplicated.");
            var keyIds = keyIdsElement.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String
                ? item.GetString()!
                : throw new InvalidDataException("TUF delegated role key ID is malformed.")).ToArray();
            if (keyIds.Length is < 1 or > MaximumRoleKeys || keyIds.Distinct(StringComparer.Ordinal).Count() != keyIds.Length ||
                threshold < 1 || threshold > keyIds.Length || keyIds.Any(id => !keys.ContainsKey(id)))
                throw new InvalidDataException("TUF delegated role threshold or key list is invalid.");

            var paths = ReadSelectors(role, "paths", ValidatePathPattern);
            var prefixes = ReadSelectors(role, "path_hash_prefixes", ValidateHashPrefix);
            if (paths is not null && prefixes is not null)
                throw new InvalidDataException("TUF delegated role cannot declare both paths and path_hash_prefixes.");
            result.Add(new TufDelegatedRole(name, keyIds.Select(id => keys[id]).ToArray(), threshold,
                paths, prefixes, terminatingElement.GetBoolean()));
        }
        return result;
    }

    public static bool IsValidRoleName(string name) => name is { Length: > 0 and <= 256 } &&
        !name.StartsWith('/') && !name.EndsWith('/') && !name.Contains('\\') && !name.Contains(':') &&
        !name.Contains('%') && name.Split('/').All(segment => segment.Length > 0 && segment is not ("." or "..") &&
            segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')) &&
        (name.Contains('/') || name is not ("root" or "timestamp" or "snapshot" or "targets" or "mirrors"));

    public static string RoleTrustFingerprint(string parentTrustSha256, TufDelegatedRole role)
    {
        var trust = new
        {
            Parent = parentTrustSha256,
            role.Name,
            role.Threshold,
            Keys = role.Keys.OrderBy(key => key.KeyId, StringComparer.Ordinal)
                .Select(key => new { key.KeyId, key.Algorithm, key.PublicKey }).ToArray()
        };
        return Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(trust, TrustRoot.JsonOptions))).ToLowerInvariant();
    }

    public static string TrustFingerprint(IReadOnlyList<TrustedKey> keys, int threshold)
    {
        var trust = new
        {
            Threshold = threshold,
            Keys = keys.OrderBy(key => key.KeyId, StringComparer.Ordinal)
                .Select(key => new { key.KeyId, key.Algorithm, key.PublicKey }).ToArray()
        };
        return Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(trust, TrustRoot.JsonOptions))).ToLowerInvariant();
    }

    public static bool PathMatches(string pattern, string path)
    {
        var patternParts = pattern.Split('/');
        var pathParts = path.Split('/');
        if (patternParts.Length != pathParts.Length) return false;
        for (var part = 0; part < patternParts.Length; part++)
        {
            var patternSegment = patternParts[part];
            var pathSegment = pathParts[part];
            var previous = new bool[pathSegment.Length + 1];
            previous[0] = true;
            foreach (var token in patternSegment)
            {
                var next = new bool[pathSegment.Length + 1];
                if (token == '*')
                {
                    next[0] = previous[0];
                    for (var i = 1; i < next.Length; i++) next[i] = previous[i] || next[i - 1];
                }
                else
                {
                    for (var i = 1; i < next.Length; i++)
                        next[i] = previous[i - 1] && (token == '?' || token == pathSegment[i - 1]);
                }
                previous = next;
            }
            if (!previous[pathSegment.Length]) return false;
        }
        return true;
    }

    private static Dictionary<string, TrustedKey> ReadKeys(JsonElement keyMap)
    {
        var result = new Dictionary<string, TrustedKey>(StringComparer.Ordinal);
        var publicKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in keyMap.EnumerateObject())
        {
            if (result.Count >= MaximumDelegatedKeys || property.Name.Length != 64 || !property.Name.All(Uri.IsHexDigit) ||
                property.Value.ValueKind != JsonValueKind.Object ||
                RequiredString(property.Value, "keytype") != "ed25519" ||
                RequiredString(property.Value, "scheme") != "ed25519" ||
                !property.Value.TryGetProperty("keyval", out var keyValue) || keyValue.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("TUF delegated key is malformed or unsupported.");

            var publicHex = RequiredString(keyValue, "public");
            byte[] publicKey;
            try { publicKey = Convert.FromHexString(publicHex); }
            catch (FormatException error) { throw new InvalidDataException("TUF delegated public key is malformed.", error); }
            var keyId = property.Name.ToLowerInvariant();
            var computedKeyId = Convert.ToHexString(SHA256.HashData(
                ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(property.Value))))
                .ToLowerInvariant();
            if (publicKey.Length != 32 || computedKeyId != keyId || !publicKeys.Add(Convert.ToHexString(publicKey)))
                throw new InvalidDataException("TUF delegated key ID is incorrect or public key is duplicated.");
            if (!result.TryAdd(keyId, new TrustedKey(keyId, "Ed25519", Convert.ToBase64String(publicKey))))
                throw new InvalidDataException("TUF delegated key map contains a duplicate key ID.");
        }
        return result;
    }

    private static string[]? ReadSelectors(JsonElement role, string propertyName, Action<string> validate)
    {
        if (!role.TryGetProperty(propertyName, out var selectors)) return null;
        if (selectors.ValueKind != JsonValueKind.Array || selectors.GetArrayLength() is < 1 or > MaximumRoleSelectors)
            throw new InvalidDataException($"TUF delegated role {propertyName} is empty or exceeds its limit.");
        var result = selectors.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String
            ? item.GetString()!
            : throw new InvalidDataException($"TUF delegated role {propertyName} entry is malformed.")).ToArray();
        foreach (var value in result) validate(value);
        if (result.Distinct(StringComparer.Ordinal).Count() != result.Length)
            throw new InvalidDataException($"TUF delegated role {propertyName} contains duplicates.");
        return result;
    }

    private static void ValidatePathPattern(string value)
    {
        if (value is not { Length: > 0 and <= 1024 } || value.StartsWith('/') || value.Contains('\\') ||
            value.Contains(':') || value.Contains('%') || value.Contains('#') || value.Contains('[') || value.Contains(']') ||
            value.Split('/').Any(segment => segment is "" or "." or ".."))
            throw new InvalidDataException("TUF delegated path pattern is unsafe or unsupported.");
    }

    private static void ValidateHashPrefix(string value)
    {
        if (value is not { Length: > 0 and <= 64 } || !value.All(Uri.IsHexDigit))
            throw new InvalidDataException("TUF delegated path hash prefix is invalid.");
    }

    private static string RequiredString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()!
            : throw new InvalidDataException($"TUF delegated key field '{propertyName}' is invalid.");
}
