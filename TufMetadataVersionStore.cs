using System.Security.Cryptography;
using System.Text.Json;

namespace LancerNexus.Updater;

/// <summary>Durably retains verified top-level TUF role versions and exact metadata digests.</summary>
public static class TufMetadataVersionStore
{
    private const int MaximumStateBytes = 64 * 1024;

    public static TufMetadataVersions GetMinimumVersions(string path, TrustRoot root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(root);
        ManifestVerifier.ValidateTrustRoot(root);
        EnsureRoleTrustIsConfigured(root);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        using var stateLock = new FileStream(fullPath + ".lock", FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        var stored = ReadState(fullPath);
        var effective = ApplyCurrentRoleTrust(stored, root);
        return new TufMetadataVersions(effective.Timestamp.Version, effective.Snapshot.Version,
            effective.Targets.Version)
        {
            DelegatedRoles = effective.DelegatedRoles
        };
    }

    public static void Accept(string path, TrustRoot root, VerifiedTufRepository repository)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(repository);
        ManifestVerifier.ValidateTrustRoot(root);
        EnsureRoleTrustIsConfigured(root);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        using var stateLock = new FileStream(fullPath + ".lock", FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);

        var stored = ApplyCurrentRoleTrust(ReadState(fullPath), root);
        var timestamp = AcceptReceipt(stored.Timestamp, repository.Versions.Timestamp,
            repository.TimestampSha256, "timestamp");
        var snapshot = AcceptReceipt(stored.Snapshot, repository.Versions.Snapshot,
            repository.SnapshotSha256, "snapshot");
        var targets = AcceptReceipt(stored.Targets, repository.Versions.Targets,
            repository.TargetsSha256, "targets");
        var delegated = new Dictionary<string, TufDelegatedMetadataReceipt>(stored.DelegatedRoles,
            StringComparer.Ordinal);
        foreach (var (roleName, receipt) in repository.DelegatedRoles)
        {
            if (!TufDelegationVerifier.IsValidRoleName(roleName) || !ValidFingerprint(receipt.TrustSha256))
                throw new InvalidDataException("Verified delegated TUF role receipt is invalid.");
            var previous = delegated.TryGetValue(roleName, out var storedReceipt) &&
                           storedReceipt.TrustSha256 == receipt.TrustSha256
                ? storedReceipt
                : new TufDelegatedMetadataReceipt(0, "", receipt.TrustSha256);
            var accepted = AcceptDelegatedReceipt(previous, receipt, roleName);
            delegated[roleName] = accepted;
        }
        if (delegated.Count > 1024)
            throw new InvalidDataException("Persisted TUF delegated role state exceeds its role limit.");
        var state = new TufMetadataVersionState(1, RoleFingerprint(root.TimestampRoleKeys!, root.TimestampRoleThreshold),
            RoleFingerprint(root.SnapshotRoleKeys!, root.SnapshotRoleThreshold),
            RoleFingerprint(root.Keys, root.Threshold), timestamp, snapshot, targets)
        {
            DelegatedRoles = delegated
        };
        Persist(fullPath, directory, state);
    }

    private static TufMetadataVersionState ReadState(string path)
    {
        if (!File.Exists(path))
            return TufMetadataVersionState.Empty;
        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumStateBytes)
            throw new InvalidDataException("Persisted TUF metadata version state is empty or too large.");
        TufMetadataVersionState state;
        try
        {
            state = JsonSerializer.Deserialize<TufMetadataVersionState>(File.ReadAllBytes(path), TrustRoot.JsonOptions)
                ?? throw new InvalidDataException("Persisted TUF metadata version state is empty.");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Persisted TUF metadata version state is invalid.", error);
        }
        if (state.Schema != 1 || !ValidFingerprint(state.TimestampTrustSha256) ||
            !ValidFingerprint(state.SnapshotTrustSha256) || !ValidFingerprint(state.TargetsTrustSha256))
            throw new InvalidDataException("Persisted TUF metadata version state has an unsupported schema or trust fingerprint.");
        ValidateReceipt(state.Timestamp, "timestamp");
        ValidateReceipt(state.Snapshot, "snapshot");
        ValidateReceipt(state.Targets, "targets");
        if (state.DelegatedRoles is null || state.DelegatedRoles.Count > 1024 ||
            state.DelegatedRoles.Any(entry => !TufDelegationVerifier.IsValidRoleName(entry.Key) ||
                                               entry.Value is null || entry.Value.Version < 0 ||
                                               entry.Value.Version == 0 && entry.Value.Sha256 != "" ||
                                               entry.Value.Version > 0 && !ValidFingerprint(entry.Value.Sha256) ||
                                               !ValidFingerprint(entry.Value.TrustSha256)))
            throw new InvalidDataException("Persisted TUF delegated role receipts are invalid.");
        return state;
    }

    private static TufMetadataVersionState ApplyCurrentRoleTrust(TufMetadataVersionState state, TrustRoot root)
    {
        var timestampTrust = RoleFingerprint(root.TimestampRoleKeys!, root.TimestampRoleThreshold);
        var snapshotTrust = RoleFingerprint(root.SnapshotRoleKeys!, root.SnapshotRoleThreshold);
        var targetsTrust = RoleFingerprint(root.Keys, root.Threshold);
        var timestampOrSnapshotChanged = state.TimestampTrustSha256 != timestampTrust ||
                                         state.SnapshotTrustSha256 != snapshotTrust;
        var targetsChanged = state.TargetsTrustSha256 != targetsTrust;

        // TUF requires both timestamp and snapshot state to be discarded when either role is rotated.
        return new TufMetadataVersionState(1, timestampTrust, snapshotTrust, targetsTrust,
            timestampOrSnapshotChanged ? TufMetadataReceipt.Empty : state.Timestamp,
            timestampOrSnapshotChanged ? TufMetadataReceipt.Empty : state.Snapshot,
            targetsChanged ? TufMetadataReceipt.Empty : state.Targets)
        {
            DelegatedRoles = targetsChanged
                ? new Dictionary<string, TufDelegatedMetadataReceipt>(StringComparer.Ordinal)
                : state.DelegatedRoles
        };
    }

    private static void EnsureRoleTrustIsConfigured(TrustRoot root)
    {
        if (root.TimestampRoleKeys is null || root.SnapshotRoleKeys is null)
            throw new InvalidDataException("Trusted root does not provide timestamp and snapshot roles.");
    }

    private static TufMetadataReceipt AcceptReceipt(TufMetadataReceipt previous, long version,
        string digest, string role)
    {
        var candidate = new TufMetadataReceipt(version, digest.ToLowerInvariant());
        ValidateReceipt(candidate, role);
        if (version < previous.Version ||
            version == previous.Version && !string.Equals(candidate.Sha256, previous.Sha256, StringComparison.Ordinal))
            throw new InvalidDataException($"TUF {role} metadata rollback or same-version content change detected.");
        return candidate;
    }

    private static TufDelegatedMetadataReceipt AcceptDelegatedReceipt(TufDelegatedMetadataReceipt previous,
        TufDelegatedMetadataReceipt candidate, string role)
    {
        if (candidate.Version < previous.Version ||
            candidate.Version == previous.Version && previous.Version > 0 &&
            !string.Equals(candidate.Sha256, previous.Sha256, StringComparison.Ordinal))
            throw new InvalidDataException($"TUF delegated role {role} metadata rollback or same-version content change detected.");
        return candidate;
    }

    private static void ValidateReceipt(TufMetadataReceipt receipt, string role)
    {
        if (receipt is null || receipt.Version < 0 ||
            receipt.Version == 0 && receipt.Sha256 != "" ||
            receipt.Version > 0 && !ValidFingerprint(receipt.Sha256))
            throw new InvalidDataException($"Persisted TUF {role} metadata receipt is invalid.");
    }

    private static string RoleFingerprint(IReadOnlyList<TrustedKey> keys, int threshold)
    {
        var role = new
        {
            Threshold = threshold,
            Keys = keys.OrderBy(key => key.KeyId, StringComparer.Ordinal)
                .Select(key => new { key.KeyId, key.Algorithm, key.PublicKey }).ToArray()
        };
        return Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(role, TrustRoot.JsonOptions))).ToLowerInvariant();
    }

    private static bool ValidFingerprint(string value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static void Persist(string path, string directory, TufMetadataVersionState state)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, TrustRoot.JsonOptions);
        if (bytes.Length > MaximumStateBytes)
            throw new InvalidDataException("TUF metadata version state exceeds its size limit.");
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private sealed record TufMetadataVersionState(int Schema, string TimestampTrustSha256,
        string SnapshotTrustSha256, string TargetsTrustSha256, TufMetadataReceipt Timestamp,
        TufMetadataReceipt Snapshot, TufMetadataReceipt Targets)
    {
        public Dictionary<string, TufDelegatedMetadataReceipt> DelegatedRoles { get; init; } =
            new(StringComparer.Ordinal);

        public static TufMetadataVersionState Empty { get; } = new(1, new string('0', 64),
            new string('0', 64), new string('0', 64), TufMetadataReceipt.Empty,
            TufMetadataReceipt.Empty, TufMetadataReceipt.Empty);
    }

    private sealed record TufMetadataReceipt(long Version, string Sha256)
    {
        public static TufMetadataReceipt Empty { get; } = new(0, "");
    }
}
