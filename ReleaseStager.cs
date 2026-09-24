using System.Formats.Tar;
using System.Text.Json;
using ZstdSharp;

namespace LancerNexus.Updater;

public static class ReleaseStager
{
    private const int MaximumEntries = 100_000;
    private const long MaximumExpandedBytes = 24L * 1024 * 1024 * 1024;
    private static readonly UnixFileMode SafeFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite |
        UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    public static async Task<string> StageClientAsync(
        UpdateManifest manifest, UpdatePackage package, string verifiedArchivePath,
        UpdaterOptions options, CancellationToken cancellationToken)
    {
        if (package.Id != "client")
            throw new InvalidDataException("Nur das Clientpaket kann als Release gestaged werden.");

        var installRoot = Path.GetFullPath(options.InstallRootPath);
        var stagingRoot = Path.Combine(installRoot, "staging");
        Directory.CreateDirectory(stagingRoot);
        var releaseName = $"{package.Sha256[..16].ToLowerInvariant()}-{Guid.NewGuid():N}";
        var stageDirectory = Path.Combine(stagingRoot, releaseName);
        Directory.CreateDirectory(stageDirectory);
        try
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(stageDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (package.Format != "tar.zst")
                throw new InvalidDataException("Clientpaketformat wird vom Stager nicht unterstützt.");
            await ExtractTarZstdAsync(verifiedArchivePath, stageDirectory, cancellationToken);

            var metadata = new ClientVersionMetadata(
                manifest.ClientVersion, manifest.BuildId, manifest.ProtocolVersion,
                manifest.DataManifestId, $"{manifest.Platform}-{manifest.Architecture}",
                manifest.Channel, manifest.Capabilities);
            await using var metadataFile = new FileStream(Path.Combine(stageDirectory, "client-version.json"),
                FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
            await JsonSerializer.SerializeAsync(metadataFile, metadata, TrustRoot.JsonOptions, cancellationToken);
            await metadataFile.FlushAsync(cancellationToken);
            var executableName = OperatingSystem.IsWindows() ? "lancer.exe" : "lancer";
            var executablePath = Path.Combine(stageDirectory, executableName);
            if (!File.Exists(executablePath) || (File.GetAttributes(executablePath) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Clientrelease enthält keine sichere LibreLancer-Programmdatei.");
            if (!OperatingSystem.IsWindows())
            {
                var mode = File.GetUnixFileMode(executablePath);
                if ((mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0)
                    throw new InvalidDataException("LibreLancer-Programmdatei ist nicht ausführbar.");
            }
            return stageDirectory;
        }
        catch
        {
            Directory.Delete(stageDirectory, recursive: true);
            throw;
        }
    }

    private static async Task ExtractTarZstdAsync(string archivePath, string destination, CancellationToken cancellationToken)
    {
        await using var source = File.OpenRead(archivePath);
        using var zstd = new DecompressionStream(source);
        using var reader = new TarReader(zstd, leaveOpen: false);
        var guard = new ExtractionGuard(destination);
        TarEntry? entry;
        while ((entry = reader.GetNextEntry(copyData: false)) is not null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.EntryType is not (TarEntryType.Directory or TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                throw new InvalidDataException("TAR enthält einen Link oder einen nicht unterstützten Dateityp.");
            var isDirectory = entry.EntryType == TarEntryType.Directory;
            var length = isDirectory ? 0 : entry.Length;
            var (path, relativePath) = guard.Accept(entry.Name, isDirectory, length);
            if (isDirectory)
            {
                Directory.CreateDirectory(path);
                if (relativePath.Length != 0 && !OperatingSystem.IsWindows())
                    File.SetUnixFileMode(path, SafeFileMode);
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (entry.DataStream is null)
                throw new InvalidDataException("TAR-Dateieintrag enthält keine Daten.");
            await CopyBoundedAsync(entry.DataStream, output, length, cancellationToken);
            if (!OperatingSystem.IsWindows())
            {
                var mode = entry.Mode & SafeFileMode;
                if ((mode & UnixFileMode.UserRead) == 0)
                    mode |= UnixFileMode.UserRead;
                File.SetUnixFileMode(path, mode);
            }
        }
        guard.Complete();
    }

    private static async Task CopyBoundedAsync(Stream source, Stream destination, long expectedLength,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        long copied = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) != 0)
        {
            copied += read;
            if (copied > expectedLength)
                throw new InvalidDataException("Archiveeintrag überschreitet seine deklarierte Größe.");
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        if (copied != expectedLength)
            throw new InvalidDataException("Archiveintrag ist kürzer als deklariert.");
    }

    private sealed class ExtractionGuard
    {
        private readonly string root;
        private readonly HashSet<string> entries = new(StringComparer.OrdinalIgnoreCase);
        private string? archiveRoot;
        private int count;
        private int files;
        private long expandedBytes;

        public ExtractionGuard(string root) => this.root = Path.GetFullPath(root);

        public (string Path, string RelativePath) Accept(string rawName, bool isDirectory, long length)
        {
            if (++count > MaximumEntries || length < 0 || length > MaximumExpandedBytes - expandedBytes)
                throw new InvalidDataException("Archiv überschreitet Anzahl- oder Größenlimits.");
            expandedBytes += length;
            if (string.IsNullOrEmpty(rawName) || rawName.Contains('\\') || rawName.Contains(':') || rawName.Contains('\0') ||
                rawName.StartsWith('/') || rawName.StartsWith("//", StringComparison.Ordinal))
                throw new InvalidDataException("Archiv enthält einen unsicheren Pfad.");
            var normalized = isDirectory ? rawName.TrimEnd('/') : rawName;
            var segments = normalized.Split('/');
            if (segments.Length == 1 && isDirectory && segments[0].Length != 0 &&
                segments[0] is not ("." or "..") && !segments[0].EndsWith('.') && !segments[0].EndsWith(' '))
            {
                if (archiveRoot is null)
                    archiveRoot = segments[0];
                if (!string.Equals(archiveRoot, segments[0], StringComparison.Ordinal) || !entries.Add("."))
                    throw new InvalidDataException("Archiv enthält mehrere oder doppelte Stammordner.");
                return (root, "");
            }
            if (segments.Length < 2 || segments.Any(s => s.Length == 0 || s is "." or ".." ||
                    s.EndsWith('.') || s.EndsWith(' ')))
                throw new InvalidDataException("Archiv muss genau einen gemeinsamen Versionsordner enthalten.");
            if (archiveRoot is null)
                archiveRoot = segments[0];
            if (!string.Equals(archiveRoot, segments[0], StringComparison.Ordinal))
                throw new InvalidDataException("Archiv enthält mehr als einen Stammordner.");
            var relative = string.Join(Path.DirectorySeparatorChar, segments.Skip(1));
            if (relative.Length == 0)
                throw new InvalidDataException("Leerer Archivpfad.");
            var fullPath = Path.GetFullPath(Path.Combine(root, relative));
            if (!fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidDataException("Archivpfad verlässt das Staging-Verzeichnis.");
            if (!entries.Add(relative))
                throw new InvalidDataException("Archiv enthält doppelte Pfade.");
            if (!isDirectory)
                files++;
            return (fullPath, relative);
        }

        public void Complete()
        {
            if (count == 0 || files == 0 || archiveRoot is null)
                throw new InvalidDataException("Clientarchiv ist leer.");
        }
    }

    private sealed record ClientVersionMetadata(
        string ClientVersion, string BuildId, int ProtocolVersion, string DataManifestId,
        string Platform, string Channel, IReadOnlyList<string> Capabilities);
}
