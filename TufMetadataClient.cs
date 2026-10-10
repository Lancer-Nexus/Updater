namespace LancerNexus.Updater;

/// <summary>Fetches and verifies a TUF metadata chain and requested delegated targets.</summary>
public static class TufMetadataClient
{
    public static Task<VerifiedTufRepository> LoadAsync(Uri metadataBaseUri, TrustRoot trustRoot,
        DateTime updateStartedAtUtc, TufMetadataVersions minimumVersions,
        CancellationToken cancellationToken = default) =>
        LoadAsync(metadataBaseUri, trustRoot, updateStartedAtUtc, minimumVersions,
            ManifestClient.LoadTufMetadataBytesAsync, cancellationToken);

    public static Task<VerifiedTufRepository> LoadAsync(Uri metadataBaseUri, TrustRoot trustRoot,
        DateTime updateStartedAtUtc, TufMetadataVersions minimumVersions,
        IReadOnlyCollection<string> requestedTargetPaths, CancellationToken cancellationToken = default) =>
        LoadAsync(metadataBaseUri, trustRoot, updateStartedAtUtc, minimumVersions,
            ManifestClient.LoadTufMetadataBytesAsync, cancellationToken, requestedTargetPaths);

    internal static async Task<VerifiedTufRepository> LoadAsync(Uri metadataBaseUri, TrustRoot trustRoot,
        DateTime updateStartedAtUtc, TufMetadataVersions minimumVersions,
        Func<Uri, CancellationToken, Task<byte[]>> fetchMetadata, CancellationToken cancellationToken,
        IReadOnlyCollection<string>? requestedTargetPaths = null)
    {
        ArgumentNullException.ThrowIfNull(metadataBaseUri);
        ArgumentNullException.ThrowIfNull(trustRoot);
        ArgumentNullException.ThrowIfNull(minimumVersions);
        ArgumentNullException.ThrowIfNull(fetchMetadata);
        if (!metadataBaseUri.IsAbsoluteUri || metadataBaseUri.Scheme != Uri.UriSchemeHttps ||
            !metadataBaseUri.AbsolutePath.EndsWith("/", StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(metadataBaseUri.Query) || !string.IsNullOrEmpty(metadataBaseUri.Fragment))
            throw new InvalidOperationException("TUF metadata base must be an HTTPS URL with a trailing '/'.");
        if (trustRoot.TimestampRoleKeys is null || trustRoot.SnapshotRoleKeys is null)
            throw new InvalidDataException("Trusted root does not provide timestamp and snapshot roles.");

        var timestampBytes = await FetchAsync(metadataBaseUri, "timestamp.json", fetchMetadata, cancellationToken);
        var timestamp = TufMetadataVerifier.Verify(timestampBytes, "timestamp", trustRoot.TimestampRoleKeys,
            trustRoot.TimestampRoleThreshold, minimumVersions.Timestamp, updateStartedAtUtc);
        var snapshotVersion = TufRepositoryVerifier.GetReferencedMetadataVersion(timestamp, "snapshot");
        var snapshotFile = MetadataFileName("snapshot", snapshotVersion, trustRoot.ConsistentSnapshot);
        var snapshotBytes = await FetchAsync(metadataBaseUri, snapshotFile, fetchMetadata, cancellationToken);
        TufRepositoryVerifier.VerifyReferencedMetadataBytes(timestamp, "snapshot", snapshotBytes);

        var snapshot = TufMetadataVerifier.Verify(snapshotBytes, "snapshot", trustRoot.SnapshotRoleKeys,
            trustRoot.SnapshotRoleThreshold, minimumVersions.Snapshot, updateStartedAtUtc);
        var targetsVersion = TufRepositoryVerifier.GetReferencedMetadataVersion(snapshot, "targets");
        var targetsFile = MetadataFileName("targets", targetsVersion, trustRoot.ConsistentSnapshot);
        var targetsBytes = await FetchAsync(metadataBaseUri, targetsFile, fetchMetadata, cancellationToken);
        TufRepositoryVerifier.VerifyReferencedMetadataBytes(snapshot, "targets", targetsBytes);

        var repository = TufRepositoryVerifier.VerifyWithDelegations(trustRoot, timestampBytes, snapshotBytes,
            targetsBytes, updateStartedAtUtc, minimumVersions);
        var topTargets = TufMetadataVerifier.Verify(targetsBytes, "targets", trustRoot.Keys,
            trustRoot.Threshold, minimumVersions.Targets, updateStartedAtUtc);
        var delegatedRoles = TufDelegationVerifier.ReadRoles(topTargets.Signed);
        foreach (var role in delegatedRoles)
            _ = TufRepositoryVerifier.GetDelegatedMetadataReference(snapshot, role.Name);
        var targetPaths = ValidateRequestedPaths(requestedTargetPaths);
        if (delegatedRoles.Count > 0 && targetPaths.Length == 0)
            throw new InvalidDataException("Requested target paths are required when TUF delegations are present.");

        if (targetPaths.Length == 0) return repository;

        var resolvedTargets = new Dictionary<string, TufTargetInfo>(repository.Targets, StringComparer.Ordinal);
        var roleReceipts = new Dictionary<string, TufDelegatedMetadataReceipt>(StringComparer.Ordinal);
        var resolver = new DelegatedTargetsResolver(metadataBaseUri, trustRoot, snapshot, minimumVersions,
            updateStartedAtUtc, fetchMetadata, cancellationToken, roleReceipts);
        var topTrust = TufDelegationVerifier.TrustFingerprint(trustRoot.Keys, trustRoot.Threshold);
        foreach (var targetPath in targetPaths)
        {
            if (resolvedTargets.ContainsKey(targetPath)) continue;
            var resolved = await resolver.FindAsync(topTargets, topTrust, [], targetPath,
                new Dictionary<string, string>(StringComparer.Ordinal), 0);
            if (resolved is null)
                throw new InvalidDataException($"Requested target '{targetPath}' is not declared by trusted TUF targets metadata.");
            resolvedTargets.Add(targetPath, resolved);
        }

        var roleMap = new Dictionary<string, TufDelegatedMetadataReceipt>(roleReceipts, StringComparer.Ordinal);
        var versions = repository.Versions with { DelegatedRoles = roleMap };
        return repository with { Targets = resolvedTargets, Versions = versions, DelegatedRoles = roleMap };
    }

    public static string MetadataFileName(string role, long version, bool consistentSnapshot)
    {
        if (role == "timestamp") return "timestamp.json";
        if (version < 1 || role is not ("snapshot" or "targets") && !TufDelegationVerifier.IsValidRoleName(role))
            throw new ArgumentException("TUF metadata role or version is invalid.", nameof(role));
        return consistentSnapshot ? $"{version}.{role}.json" : $"{role}.json";
    }

    private static string[] ValidateRequestedPaths(IReadOnlyCollection<string>? paths)
    {
        if (paths is null) return [];
        if (paths.Count > 512)
            throw new InvalidDataException("TUF requested target count exceeds its limit.");
        var result = paths.Distinct(StringComparer.Ordinal).ToArray();
        foreach (var path in result) TufRepositoryVerifier.ValidateTargetPath(path);
        return result;
    }

    private static async Task<byte[]> FetchAsync(Uri metadataBaseUri, string fileName,
        Func<Uri, CancellationToken, Task<byte[]>> fetchMetadata, CancellationToken cancellationToken)
    {
        var uri = new Uri(metadataBaseUri, fileName);
        if (uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 ||
            !string.Equals(uri.IdnHost, metadataBaseUri.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            uri.Port != metadataBaseUri.Port || !uri.AbsolutePath.StartsWith(metadataBaseUri.AbsolutePath,
                StringComparison.Ordinal))
            throw new InvalidDataException("TUF metadata URL escaped its configured HTTPS base.");
        return await fetchMetadata(uri, cancellationToken);
    }

    private sealed class DelegatedTargetsResolver(Uri metadataBaseUri, TrustRoot trustRoot,
        VerifiedTufMetadata snapshot, TufMetadataVersions minimumVersions, DateTime updateStartedAtUtc,
        Func<Uri, CancellationToken, Task<byte[]>> fetchMetadata, CancellationToken cancellationToken,
        IDictionary<string, TufDelegatedMetadataReceipt> receipts)
    {
        private const int MaximumDelegatedRoles = 128;
        private const int MaximumDelegationDepth = 16;
        private const int MaximumDelegatedMetadataBytes = 16 * 1024 * 1024;
        private readonly Dictionary<string, CachedRole> cache = new(StringComparer.Ordinal);
        private long delegatedMetadataBytes;

        public async Task<TufTargetInfo?> FindAsync(VerifiedTufMetadata parent, string parentTrust,
            IReadOnlyList<TufDelegatedRole> parentScopes, string targetPath,
            IDictionary<string, string> visited, int depth)
        {
            if (depth > MaximumDelegationDepth)
                throw new InvalidDataException("TUF delegated role depth exceeds its limit.");
            var parentTargets = TufRepositoryVerifier.ReadTargets(parent.Signed);
            if (parentTargets.TryGetValue(targetPath, out var direct)) return direct;

            var roles = TufDelegationVerifier.ReadRoles(parent.Signed);
            foreach (var role in roles)
                _ = TufRepositoryVerifier.GetDelegatedMetadataReference(snapshot, role.Name);

            foreach (var role in roles)
            {
                if (!role.Matches(targetPath) || parentScopes.Any(scope => !scope.Matches(targetPath))) continue;
                var trustFingerprint = TufDelegationVerifier.RoleTrustFingerprint(parentTrust, role);
                if (visited.TryGetValue(role.Name, out var previousTrust))
                {
                    if (previousTrust != trustFingerprint)
                        throw new InvalidDataException("TUF delegated role name has conflicting trust definitions.");
                    continue;
                }
                visited.Add(role.Name, trustFingerprint);
                var loaded = await LoadRoleAsync(parentTrust, role, parentScopes);
                if (loaded.Targets.TryGetValue(targetPath, out direct)) return direct;

                var scopes = parentScopes.Append(role).ToArray();
                var nested = await FindAsync(loaded.Metadata, loaded.TrustSha256, scopes,
                    targetPath, visited, depth + 1);
                if (nested is not null) return nested;
                if (role.Terminating) return null;
            }
            return null;
        }

        private async Task<CachedRole> LoadRoleAsync(string parentTrust, TufDelegatedRole role,
            IReadOnlyList<TufDelegatedRole> parentScopes)
        {
            var trustFingerprint = TufDelegationVerifier.RoleTrustFingerprint(parentTrust, role);
            var reference = TufRepositoryVerifier.GetDelegatedMetadataReference(snapshot, role.Name);
            if (cache.TryGetValue(role.Name, out var cached))
            {
                if (cached.TrustSha256 != trustFingerprint || cached.Metadata.Version != reference.Version ||
                    cached.Sha256 != reference.Sha256)
                    throw new InvalidDataException("TUF delegated role name resolves to conflicting trusted metadata.");
                ValidateTargetScopes(cached.Targets, parentScopes.Append(role));
                return cached;
            }
            if (cache.Count >= MaximumDelegatedRoles)
                throw new InvalidDataException("TUF delegated role count exceeds its limit.");

            var minimumVersion = minimumVersions.DelegatedRoles.TryGetValue(role.Name, out var previous) &&
                                 previous.TrustSha256 == trustFingerprint
                ? previous.Version
                : 0;
            var fileName = MetadataFileName(role.Name, reference.Version, trustRoot.ConsistentSnapshot);
            var bytes = await FetchAsync(metadataBaseUri, fileName, fetchMetadata, cancellationToken);
            delegatedMetadataBytes = checked(delegatedMetadataBytes + bytes.LongLength);
            if (delegatedMetadataBytes > MaximumDelegatedMetadataBytes)
                throw new InvalidDataException("TUF delegated metadata exceeds its aggregate size limit.");
            TufRepositoryVerifier.VerifyReferencedMetadataBytes(snapshot, role.Name, bytes);
            var metadata = TufMetadataVerifier.Verify(bytes, role.Name, role.Keys, role.Threshold,
                minimumVersion, updateStartedAtUtc, delegatedTargetsRole: true);
            if (metadata.Version != reference.Version)
                throw new InvalidDataException($"TUF delegated role {role.Name} version does not match snapshot.");

            var targets = TufRepositoryVerifier.ReadTargets(metadata.Signed);
            ValidateTargetScopes(targets, parentScopes.Append(role));
            foreach (var child in TufDelegationVerifier.ReadRoles(metadata.Signed))
                _ = TufRepositoryVerifier.GetDelegatedMetadataReference(snapshot, child.Name);

            var digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
            var loaded = new CachedRole(metadata, targets, digest, trustFingerprint);
            cache.Add(role.Name, loaded);
            receipts[role.Name] = new TufDelegatedMetadataReceipt(metadata.Version, digest, trustFingerprint);
            return loaded;
        }

        private static void ValidateTargetScopes(IReadOnlyDictionary<string, TufTargetInfo> targets,
            IEnumerable<TufDelegatedRole> scopes)
        {
            var selectors = scopes.ToArray();
            if (targets.Keys.Any(path => selectors.Any(scope => !scope.Matches(path))))
                throw new InvalidDataException("TUF delegated targets metadata declares a path outside its delegated scope.");
        }

        private sealed record CachedRole(VerifiedTufMetadata Metadata,
            IReadOnlyDictionary<string, TufTargetInfo> Targets, string Sha256, string TrustSha256);
    }
}
