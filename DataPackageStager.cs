using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LancerNexus.Updater;

public static class DataPackageStager
{
    public static bool VerifyStoredSnapshot(string releaseDirectory)
    {
        try
        {
            var packagesRoot = Path.Combine(Path.GetFullPath(releaseDirectory), "packages");
            var snapshotPath = Path.Combine(packagesRoot, "active.json");
            if (!Directory.Exists(packagesRoot)) return true; // Legacy healthy release using loose DATA.
            var info = new FileInfo(snapshotPath);
            if (!info.Exists || info.Length is <= 0 or > 4 * 1024 * 1024 ||
                HasReparsePoint(packagesRoot, snapshotPath))
                return false;
            using var input = File.OpenRead(snapshotPath);
            var snapshot = JsonSerializer.Deserialize<ActiveSnapshot>(input, TrustRoot.JsonOptions);
            if (snapshot is null || snapshot.SchemaVersion != 1 || string.IsNullOrWhiteSpace(snapshot.ManifestId) ||
                snapshot.ManifestId.Length > 128 || snapshot.Packages is null || snapshot.Packages.Count > 1024)
                return false;
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var package in snapshot.Packages)
            {
                if (package is null || string.IsNullOrWhiteSpace(package.Id) || package.Id.Length > 96 ||
                    package.Id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) ||
                    !ids.Add(package.Id) || package.Size <= 0 || package.Sha256 is null ||
                    package.Sha256.Length != 64 ||
                    !package.Sha256.All(Uri.IsHexDigit) || package.Dependencies is null || package.Overrides is null ||
                    !IsSafeRelativePackagePath(package.Path))
                    return false;
                var packagePath = Path.GetFullPath(Path.Combine(packagesRoot,
                    package.Path.Replace('/', Path.DirectorySeparatorChar)));
                var relative = Path.GetRelativePath(packagesRoot, packagePath);
                if (Path.IsPathRooted(relative) || relative == ".." ||
                    relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                    !File.Exists(packagePath) || HasReparsePoint(packagesRoot, packagePath))
                    return false;
                var packageInfo = new FileInfo(packagePath);
                if (packageInfo.Length != package.Size) return false;
                using var packageStream = File.OpenRead(packagePath);
                var digest = SHA256.HashData(packageStream);
                if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(package.Sha256)))
                    return false;
            }
            return true;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    public static bool MatchesSnapshot(string releaseDirectory, UpdateManifest manifest,
        IReadOnlySet<string> optionalPackageIds)
    {
        try
        {
            var packagesRoot = Path.Combine(Path.GetFullPath(releaseDirectory), "packages");
            var snapshotPath = Path.Combine(packagesRoot, "active.json");
            var info = new FileInfo(snapshotPath);
            if (!info.Exists || info.Length is <= 0 or > 4 * 1024 * 1024 ||
                HasReparsePoint(packagesRoot, snapshotPath))
                return false;
            using var input = File.OpenRead(snapshotPath);
            var snapshot = JsonSerializer.Deserialize<ActiveSnapshot>(input, TrustRoot.JsonOptions);
            if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.ManifestId != manifest.DataManifestId ||
                snapshot.Packages is null)
                return false;
            var expected = SelectPackages(manifest, optionalPackageIds).ToDictionary(p => p.Id, StringComparer.Ordinal);
            if (snapshot.Packages.Count != expected.Count) return false;
            foreach (var installed in snapshot.Packages)
            {
                if (installed is null || installed.Dependencies is null || installed.Overrides is null ||
                    !expected.TryGetValue(installed.Id, out var package) ||
                    installed.Size != package.Size ||
                    !string.Equals(installed.Sha256, package.Sha256, StringComparison.OrdinalIgnoreCase) ||
                    installed.Required != package.Required || installed.Version != package.ContentVersion ||
                    installed.Priority != package.Priority || installed.MountOrder != package.MountOrder ||
                    !installed.Dependencies.SequenceEqual(package.Dependencies, StringComparer.Ordinal) ||
                    !installed.Overrides.SequenceEqual(package.Overrides, StringComparer.Ordinal) ||
                    !IsSafeRelativePackagePath(installed.Path))
                    return false;
                var packagePath = Path.GetFullPath(Path.Combine(packagesRoot,
                    installed.Path.Replace('/', Path.DirectorySeparatorChar)));
                var relative = Path.GetRelativePath(packagesRoot, packagePath);
                if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                    Path.IsPathRooted(relative) || !File.Exists(packagePath) || HasReparsePoint(packagesRoot, packagePath))
                    return false;
                var file = new FileInfo(packagePath);
                if (file.Length != package.Size)
                    return false;
                using var packageStream = File.OpenRead(packagePath);
                var digest = SHA256.HashData(packageStream);
                if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(package.Sha256)))
                    return false;
            }
            return true;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    public static IReadOnlyList<UpdatePackage> SelectPackages(UpdateManifest manifest,
        IReadOnlySet<string> optionalPackageIds)
    {
        var packages = manifest.Packages.Where(p => p.Id != "client")
            .ToDictionary(p => p.Id, StringComparer.Ordinal);
        foreach (var id in optionalPackageIds)
            if (!packages.TryGetValue(id, out var package) || package.Required)
                throw new InvalidDataException($"Optionale Paket-ID '{id}' ist unbekannt oder als Pflichtpaket markiert.");
        var selected = new HashSet<string>(StringComparer.Ordinal);
        void AddWithDependencies(string id)
        {
            if (!selected.Add(id)) return;
            foreach (var related in packages[id].Dependencies.Concat(packages[id].Overrides))
                AddWithDependencies(related);
        }
        foreach (var package in packages.Values.Where(p => p.Required))
            AddWithDependencies(package.Id);
        foreach (var id in optionalPackageIds)
            AddWithDependencies(id);
        return selected.Select(id => packages[id]).ToArray();
    }

    public static string SelectionFingerprint(UpdateManifest manifest, IReadOnlySet<string> optionalPackageIds)
    {
        var canonical = string.Join("\n", SelectPackages(manifest, optionalPackageIds)
            .OrderBy(p => p.Id, StringComparer.Ordinal)
            .Select(p => $"{p.Id}\0{p.Sha256.ToLowerInvariant()}"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public static async Task WriteSnapshotAsync(string stagedRelease, UpdateManifest manifest,
        IReadOnlySet<string> optionalPackageIds,
        IReadOnlyDictionary<string, string> verifiedArchives, CancellationToken cancellationToken)
    {
        var selected = SelectPackages(manifest, optionalPackageIds);
        var selectedIds = selected.Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
        if (verifiedArchives.Count != selectedIds.Count || verifiedArchives.Keys.Any(id => !selectedIds.Contains(id)))
            throw new InvalidDataException("Verifizierte NAP-Artefakte entsprechen nicht dem erforderlichen Snapshot.");

        var packagesRoot = Path.Combine(Path.GetFullPath(stagedRelease), "packages");
        var contentRoot = Path.Combine(packagesRoot, "content");
        Directory.CreateDirectory(contentRoot);
        var activePackages = new List<ActivePackage>(selected.Count);
        var effectivePaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in selected.OrderBy(p => p.Priority).ThenBy(p => p.MountOrder).ThenBy(p => p.Id, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = Path.GetFullPath(verifiedArchives[package.Id]);
            var fileName = $"{package.Sha256.ToLowerInvariant()}.nap";
            var destination = Path.Combine(contentRoot, fileName);
            if (File.Exists(destination))
                await VerifyFileAsync(destination, package, cancellationToken);
            else
            {
                DiskSpaceGuard.EnsureAvailable(contentRoot, package.Size);
                await CopyVerifiedAsync(source, destination, package, cancellationToken);
            }
            var napMetadata = NapPackageVerifier.VerifyFile(destination);
            if (package.ContentVersion != napMetadata.ContentVersion)
                throw new InvalidDataException($"NAP-Paket '{package.Id}' hat eine andere Content-Version als das signierte Manifest.");
            foreach (var path in napMetadata.EntryPaths)
            {
                if (effectivePaths.TryGetValue(path, out var previousPackage) &&
                    !package.Overrides.Contains(previousPackage, StringComparer.Ordinal))
                    throw new InvalidDataException(
                        $"NAP-Paket '{package.Id}' kollidiert mit '{previousPackage}' bei '{path}' ohne deklariertes Override.");
                effectivePaths[path] = package.Id;
            }
            activePackages.Add(new ActivePackage(package.Id, $"content/{fileName}", package.Size,
                package.Sha256.ToLowerInvariant(), package.Required, package.ContentVersion,
                package.Priority, package.MountOrder, package.Dependencies, package.Overrides));
        }

        var snapshot = new ActiveSnapshot(1, manifest.DataManifestId, activePackages);
        var snapshotPath = Path.Combine(packagesRoot, "active.json");
        var temporaryPath = Path.Combine(packagesRoot, $".active-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var snapshotFile = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(snapshotFile, snapshot, TrustRoot.JsonOptions, cancellationToken);
                await snapshotFile.FlushAsync(cancellationToken);
                snapshotFile.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, snapshotPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private sealed record ActiveSnapshot(int SchemaVersion, string ManifestId, IReadOnlyList<ActivePackage> Packages);
    private sealed record ActivePackage(string Id, string Path, long Size, string Sha256, bool Required,
        ulong? Version, int Priority, int MountOrder, IReadOnlyList<string> Dependencies,
        IReadOnlyList<string> Overrides);

    private static async Task CopyVerifiedAsync(string sourcePath, string destinationPath,
        UpdatePackage package, CancellationToken cancellationToken)
    {
        var temporaryPath = destinationPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            await using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
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
                    throw new InvalidDataException($"NAP-Paket '{package.Id}' überschreitet seine signierte Größe.");
                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            await output.FlushAsync(cancellationToken);
            output.Flush(flushToDisk: true);
            await output.DisposeAsync();
            if (total != package.Size || !CryptographicOperations.FixedTimeEquals(
                    hash.GetHashAndReset(), Convert.FromHexString(package.Sha256)))
                throw new InvalidDataException($"NAP-Paket '{package.Id}' änderte sich nach dem Download.");
            File.Move(temporaryPath, destinationPath);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static async Task VerifyFileAsync(string path, UpdatePackage package, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.Length != package.Size)
            throw new InvalidDataException($"NAP-Paket '{package.Id}' kollidiert mit einem anderen Paketdigest.");
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var digest = await SHA256.HashDataAsync(input, cancellationToken);
        if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(package.Sha256)))
            throw new InvalidDataException($"NAP-Paket '{package.Id}' kollidiert mit einem anderen Paketdigest.");
    }

    private static bool IsSafeRelativePackagePath(string? path) =>
        !string.IsNullOrWhiteSpace(path) && !Path.IsPathRooted(path) && !path.Contains('\\') &&
        !path.Contains(':') && !path.Contains('\0') &&
        path.Split('/').All(component => component.Length != 0 && component is not ("." or ".."));

    private static bool HasReparsePoint(string root, string path)
    {
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            return true;
        var relative = Path.GetRelativePath(root, path);
        var current = root;
        foreach (var component in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            current = Path.Combine(current, component);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                return true;
        }
        return false;
    }
}
