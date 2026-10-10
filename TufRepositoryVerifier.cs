using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text.Json;

namespace LancerNexus.Updater;

public sealed record TufDelegatedMetadataReceipt(long Version, string Sha256, string TrustSha256);
public sealed record TufMetadataVersions(long Timestamp, long Snapshot, long Targets)
{
    public IReadOnlyDictionary<string, TufDelegatedMetadataReceipt> DelegatedRoles { get; init; } =
        new Dictionary<string, TufDelegatedMetadataReceipt>(StringComparer.Ordinal);

    public bool Equals(TufMetadataVersions? other) => other is not null && Timestamp == other.Timestamp &&
        Snapshot == other.Snapshot && Targets == other.Targets && DelegatedRoles.Count == other.DelegatedRoles.Count &&
        DelegatedRoles.All(entry => other.DelegatedRoles.TryGetValue(entry.Key, out var receipt) &&
                                    receipt == entry.Value);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Timestamp);
        hash.Add(Snapshot);
        hash.Add(Targets);
        foreach (var entry in DelegatedRoles.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            hash.Add(entry.Key, StringComparer.Ordinal);
            hash.Add(entry.Value);
        }
        return hash.ToHashCode();
    }
}
public sealed record TufTargetInfo(long Length, string Sha256);
public sealed record VerifiedTufRepository(TufMetadataVersions Versions,
    IReadOnlyDictionary<string, TufTargetInfo> Targets, string TimestampSha256,
    string SnapshotSha256, string TargetsSha256)
{
    public IReadOnlyDictionary<string, TufDelegatedMetadataReceipt> DelegatedRoles { get; init; } =
        new Dictionary<string, TufDelegatedMetadataReceipt>(StringComparer.Ordinal);
}

/// <summary>
/// Verifies the top-level timestamp -> snapshot -> targets chain used by the Updater.
/// This POUF requires SHA-256 and lengths on metadata references and does not allow delegations.
/// </summary>
public static class TufRepositoryVerifier
{
    private const int MaximumMetadataLength = 2 * 1024 * 1024;

    public static VerifiedTufRepository Verify(TrustRoot root, ReadOnlyMemory<byte> timestampBytes,
        ReadOnlyMemory<byte> snapshotBytes, ReadOnlyMemory<byte> targetsBytes, DateTime updateStartedAtUtc,
        TufMetadataVersions minimumVersions)
        => VerifyCore(root, timestampBytes, snapshotBytes, targetsBytes, updateStartedAtUtc,
            minimumVersions, allowDelegations: false);

    internal static VerifiedTufRepository VerifyWithDelegations(TrustRoot root,
        ReadOnlyMemory<byte> timestampBytes, ReadOnlyMemory<byte> snapshotBytes,
        ReadOnlyMemory<byte> targetsBytes, DateTime updateStartedAtUtc, TufMetadataVersions minimumVersions)
        => VerifyCore(root, timestampBytes, snapshotBytes, targetsBytes, updateStartedAtUtc,
            minimumVersions, allowDelegations: true);

    /// <summary>Verifies every delegated role supplied by a repository publisher.</summary>
    public static VerifiedTufRepository VerifyAllDelegations(TrustRoot root,
        ReadOnlyMemory<byte> timestampBytes, ReadOnlyMemory<byte> snapshotBytes,
        ReadOnlyMemory<byte> targetsBytes, IReadOnlyDictionary<string, byte[]> delegatedMetadata,
        DateTime updateStartedAtUtc, TufMetadataVersions minimumVersions)
    {
        ArgumentNullException.ThrowIfNull(delegatedMetadata);
        var repository = VerifyWithDelegations(root, timestampBytes, snapshotBytes, targetsBytes,
            updateStartedAtUtc, minimumVersions);
        var snapshot = TufMetadataVerifier.Verify(snapshotBytes, "snapshot", root.SnapshotRoleKeys!,
            root.SnapshotRoleThreshold, minimumVersions.Snapshot, updateStartedAtUtc);
        var topTargets = TufMetadataVerifier.Verify(targetsBytes, "targets", root.Keys, root.Threshold,
            minimumVersions.Targets, updateStartedAtUtc);
        var receipts = new Dictionary<string, TufDelegatedMetadataReceipt>(StringComparer.Ordinal);
        var visited = new Dictionary<string, string>(StringComparer.Ordinal);
        var delegatedRoles = new Dictionary<string, VerifiedTufMetadata>(StringComparer.Ordinal);
        var topTrust = TufDelegationVerifier.TrustFingerprint(root.Keys, root.Threshold);
        long delegatedMetadataBytes = 0;

        void Visit(VerifiedTufMetadata parent, string parentTrust, IReadOnlyList<TufDelegatedRole> scopes,
            int depth)
        {
            if (depth > 16)
                throw new InvalidDataException("TUF delegated role depth exceeds its limit.");
            foreach (var role in TufDelegationVerifier.ReadRoles(parent.Signed))
            {
                var trust = TufDelegationVerifier.RoleTrustFingerprint(parentTrust, role);
                if (visited.TryGetValue(role.Name, out var oldTrust))
                {
                    if (oldTrust != trust)
                        throw new InvalidDataException("TUF delegated role name has conflicting trust definitions.");
                    continue;
                }
                if (visited.Count >= 128)
                    throw new InvalidDataException("TUF delegated role count exceeds its limit.");
                visited.Add(role.Name, trust);
                var reference = GetDelegatedMetadataReference(snapshot, role.Name);
                if (!delegatedMetadata.TryGetValue(role.Name, out var bytes))
                    throw new InvalidDataException($"TUF delegated metadata '{role.Name}' was not supplied.");
                delegatedMetadataBytes = checked(delegatedMetadataBytes + bytes.LongLength);
                if (delegatedMetadataBytes > 16 * 1024 * 1024)
                    throw new InvalidDataException("TUF delegated metadata exceeds its aggregate size limit.");
                VerifyReferencedMetadata(bytes, reference, role.Name);
                var minimumVersion = minimumVersions.DelegatedRoles.TryGetValue(role.Name, out var previous) &&
                                    previous.TrustSha256 == trust ? previous.Version : 0;
                var metadata = TufMetadataVerifier.Verify(bytes, role.Name, role.Keys, role.Threshold,
                    minimumVersion, updateStartedAtUtc, delegatedTargetsRole: true);
                if (metadata.Version != reference.Version)
                    throw new InvalidDataException($"TUF delegated role {role.Name} version does not match snapshot.");
                var nestedScopes = scopes.Append(role).ToArray();
                var targets = ReadTargets(metadata.Signed);
                foreach (var target in targets)
                {
                    if (nestedScopes.Any(scope => !scope.Matches(target.Key)))
                        throw new InvalidDataException("TUF delegated targets metadata declares a path outside its delegated scope.");
                }
                var digest = Sha256(bytes);
                receipts.Add(role.Name, new TufDelegatedMetadataReceipt(metadata.Version, digest, trust));
                delegatedRoles.Add(role.Name, metadata);
                Visit(metadata, trust, nestedScopes, depth + 1);
            }
        }

        Visit(topTargets, topTrust, [], 0);
        if (delegatedMetadata.Keys.Any(name => !visited.ContainsKey(name)))
            throw new InvalidDataException("TUF publisher received delegated metadata that the signed metadata does not reference.");
        var targetPaths = new HashSet<string>(repository.Targets.Keys, StringComparer.Ordinal);
        foreach (var metadata in delegatedRoles.Values)
            targetPaths.UnionWith(ReadTargets(metadata.Signed).Keys);
        var effectiveTargets = new Dictionary<string, TufTargetInfo>(repository.Targets, StringComparer.Ordinal);
        TufTargetInfo? Resolve(VerifiedTufMetadata parent, IReadOnlyList<TufDelegatedRole> scopes,
            string path, int depth)
        {
            if (depth > 16) throw new InvalidDataException("TUF delegated role depth exceeds its limit.");
            if (ReadTargets(parent.Signed).TryGetValue(path, out var direct)) return direct;
            foreach (var role in TufDelegationVerifier.ReadRoles(parent.Signed))
            {
                if (!role.Matches(path) || scopes.Any(scope => !scope.Matches(path))) continue;
                var child = delegatedRoles[role.Name];
                if (ReadTargets(child.Signed).TryGetValue(path, out direct)) return direct;
                var nested = Resolve(child, scopes.Append(role).ToArray(), path, depth + 1);
                if (nested is not null) return nested;
                if (role.Terminating) return null;
            }
            return null;
        }
        foreach (var path in targetPaths)
        {
            if (effectiveTargets.ContainsKey(path)) continue;
            var resolved = Resolve(topTargets, [], path, 0);
            if (resolved is not null) effectiveTargets.Add(path, resolved);
        }
        var roleVersions = repository.Versions with { DelegatedRoles = receipts };
        return repository with
        {
            Targets = effectiveTargets.ToFrozenDictionary(StringComparer.Ordinal),
            Versions = roleVersions,
            DelegatedRoles = receipts
        };
    }

    private static VerifiedTufRepository VerifyCore(TrustRoot root, ReadOnlyMemory<byte> timestampBytes,
        ReadOnlyMemory<byte> snapshotBytes, ReadOnlyMemory<byte> targetsBytes, DateTime updateStartedAtUtc,
        TufMetadataVersions minimumVersions, bool allowDelegations)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(minimumVersions);
        ManifestVerifier.ValidateTrustRoot(root);
        TufRootRotationVerifier.EnsureCurrent(root, updateStartedAtUtc);
        if (minimumVersions.Timestamp < 0 || minimumVersions.Snapshot < 0 || minimumVersions.Targets < 0)
            throw new ArgumentOutOfRangeException(nameof(minimumVersions));
        if (root.TimestampRoleKeys is null || root.SnapshotRoleKeys is null)
            throw new InvalidDataException("Trusted root does not provide timestamp and snapshot roles.");

        var timestamp = TufMetadataVerifier.Verify(timestampBytes, "timestamp", root.TimestampRoleKeys,
            root.TimestampRoleThreshold, minimumVersions.Timestamp, updateStartedAtUtc);
        var snapshotReference = ReadMetadataReference(timestamp.Signed, "snapshot.json");
        VerifyReferencedMetadata(snapshotBytes.Span, snapshotReference, "snapshot");

        var snapshot = TufMetadataVerifier.Verify(snapshotBytes, "snapshot", root.SnapshotRoleKeys,
            root.SnapshotRoleThreshold, minimumVersions.Snapshot, updateStartedAtUtc);
        if (snapshot.Version != snapshotReference.Version)
            throw new InvalidDataException("Snapshot version does not match trusted timestamp metadata.");
        var targetsReference = ReadMetadataReference(snapshot.Signed, "targets.json", allowAdditional: true);
        VerifyReferencedMetadata(targetsBytes.Span, targetsReference, "targets");

        var targets = TufMetadataVerifier.Verify(targetsBytes, "targets", root.Keys,
            root.Threshold, minimumVersions.Targets, updateStartedAtUtc);
        if (targets.Version != targetsReference.Version)
            throw new InvalidDataException("Targets version does not match trusted snapshot metadata.");
        if (!allowDelegations && targets.Signed.TryGetProperty("delegations", out _))
            throw new InvalidDataException("Delegated TUF targets roles are not supported by this Updater profile.");

        return new VerifiedTufRepository(new TufMetadataVersions(timestamp.Version, snapshot.Version, targets.Version),
            ReadTargets(targets.Signed), Sha256(timestampBytes.Span), Sha256(snapshotBytes.Span),
            Sha256(targetsBytes.Span));
    }

    public static void VerifyTargetBytes(VerifiedTufRepository repository, string targetPath,
        ReadOnlySpan<byte> targetBytes)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ValidateTargetPath(targetPath);
        if (!repository.Targets.TryGetValue(targetPath, out var target))
            throw new InvalidDataException("Requested file is not declared by trusted TUF targets metadata.");
        if (targetBytes.Length != target.Length ||
            !string.Equals(Convert.ToHexString(SHA256.HashData(targetBytes)).ToLowerInvariant(), target.Sha256,
                StringComparison.Ordinal))
            throw new InvalidDataException("Downloaded target does not match its trusted TUF length and SHA-256.");
    }

    public static void VerifyTargetMetadata(VerifiedTufRepository repository, string targetPath,
        long length, string sha256)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ValidateTargetPath(targetPath);
        if (length < 0 || sha256.Length != 64 || !sha256.All(Uri.IsHexDigit) ||
            !repository.Targets.TryGetValue(targetPath, out var target) || target.Length != length ||
            !string.Equals(target.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Target size or SHA-256 does not match trusted TUF targets metadata.");
    }

    public static long GetReferencedMetadataVersion(VerifiedTufMetadata parent, string childRole)
    {
        ArgumentNullException.ThrowIfNull(parent);
        var metadataPath = MetadataPath(parent.Role, childRole);
        return ReadMetadataReference(parent.Signed, metadataPath, allowAdditional: parent.Role == "snapshot").Version;
    }

    public static void VerifyReferencedMetadataBytes(VerifiedTufMetadata parent, string childRole,
        ReadOnlySpan<byte> childBytes)
    {
        ArgumentNullException.ThrowIfNull(parent);
        var metadataPath = MetadataPath(parent.Role, childRole);
        VerifyReferencedMetadata(childBytes,
            ReadMetadataReference(parent.Signed, metadataPath, allowAdditional: parent.Role == "snapshot"), childRole);
    }

    internal static MetadataReference GetDelegatedMetadataReference(VerifiedTufMetadata snapshot, string roleName)
    {
        if (snapshot.Role != "snapshot" || !TufDelegationVerifier.IsValidRoleName(roleName))
            throw new ArgumentException("Delegated metadata reference request is invalid.", nameof(roleName));
        return ReadMetadataReference(snapshot.Signed, roleName + ".json", allowAdditional: true);
    }

    private static string MetadataPath(string parentRole, string childRole) => (parentRole, childRole) switch
    {
        ("timestamp", "snapshot") => "snapshot.json",
        ("snapshot", "targets") => "targets.json",
        ("snapshot", _) when TufDelegationVerifier.IsValidRoleName(childRole) => childRole + ".json",
        _ => throw new ArgumentException("Unsupported TUF metadata role reference.", nameof(childRole))
    };

    private static MetadataReference ReadMetadataReference(JsonElement signed, string metadataPath,
        bool allowAdditional = false)
    {
        if (!signed.TryGetProperty("meta", out var meta) || meta.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("TUF metadata role has no meta object.");
        MetadataReference? result = null;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in meta.EnumerateObject())
        {
            if (!names.Add(item.Name))
                throw new InvalidDataException("TUF metadata contains duplicate metadata references.");
            var reference = ReadMetadataReferenceInfo(item.Value);
            if (item.Name == metadataPath)
            {
                if (result is not null)
                    throw new InvalidDataException("TUF metadata contains a duplicate role reference.");
                result = reference;
            }
            else if (!allowAdditional || !IsSnapshotMetadataPath(item.Name))
                throw new InvalidDataException("TUF metadata references unsupported roles.");
        }
        return result ?? throw new InvalidDataException($"TUF metadata role does not reference {metadataPath}.");
    }

    private static bool IsSnapshotMetadataPath(string path) => path == "targets.json" ||
        path.EndsWith(".json", StringComparison.Ordinal) &&
        TufDelegationVerifier.IsValidRoleName(path[..^".json".Length]);

    private static MetadataReference ReadMetadataReferenceInfo(JsonElement info)
    {
        if (info.ValueKind != JsonValueKind.Object ||
            !info.TryGetProperty("version", out var versionElement) || !versionElement.TryGetInt64(out var version) || version < 1 ||
            !info.TryGetProperty("length", out var lengthElement) || !lengthElement.TryGetInt64(out var length) ||
            length is <= 0 or > MaximumMetadataLength ||
            !info.TryGetProperty("hashes", out var hashes) || hashes.ValueKind != JsonValueKind.Object ||
            !hashes.TryGetProperty("sha256", out var hashElement) || hashElement.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("TUF metadata reference requires a positive version, bounded length and SHA-256.");
        var hash = hashElement.GetString()!;
        if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
            throw new InvalidDataException("TUF metadata reference SHA-256 is invalid.");
        return new MetadataReference(version, length, hash.ToLowerInvariant());
    }

    private static void VerifyReferencedMetadata(ReadOnlySpan<byte> bytes, MetadataReference reference, string role)
    {
        if (bytes.Length != reference.Length || bytes.Length > MaximumMetadataLength ||
            !string.Equals(Sha256(bytes), reference.Sha256,
                StringComparison.Ordinal))
            throw new InvalidDataException($"Downloaded TUF {role} metadata does not match its signed length and SHA-256.");
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    internal static IReadOnlyDictionary<string, TufTargetInfo> ReadTargets(JsonElement signed)
    {
        if (!signed.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("TUF targets metadata has no targets object.");
        var result = new Dictionary<string, TufTargetInfo>(StringComparer.Ordinal);
        foreach (var target in targets.EnumerateObject())
        {
            ValidateTargetPath(target.Name);
            if (!result.TryAdd(target.Name, ReadTargetInfo(target.Value)))
                throw new InvalidDataException("TUF targets metadata contains a duplicate target path.");
        }
        return result.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static TufTargetInfo ReadTargetInfo(JsonElement info)
    {
        if (info.ValueKind != JsonValueKind.Object ||
            !info.TryGetProperty("length", out var lengthElement) || !lengthElement.TryGetInt64(out var length) || length < 0 ||
            !info.TryGetProperty("hashes", out var hashes) || hashes.ValueKind != JsonValueKind.Object ||
            !hashes.TryGetProperty("sha256", out var hashElement) || hashElement.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("TUF target requires a positive length and SHA-256.");
        var hash = hashElement.GetString()!;
        if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
            throw new InvalidDataException("TUF target SHA-256 is invalid.");
        return new TufTargetInfo(length, hash.ToLowerInvariant());
    }

    internal static void ValidateTargetPath(string path)
    {
        if (path is not { Length: > 0 and <= 1024 } || path.StartsWith('/') || path.StartsWith('\\') ||
            path.Contains('\\') || path.Contains(':') || path.Contains('%') || path.Contains('?') || path.Contains('#') ||
            path.Split('/').Any(segment => segment is "" or "." or ".."))
            throw new InvalidDataException("TUF target path is not a safe relative target name.");
    }

    internal sealed record MetadataReference(long Version, long Length, string Sha256);
}
