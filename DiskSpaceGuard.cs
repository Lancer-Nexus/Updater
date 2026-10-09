namespace LancerNexus.Updater;

internal static class DiskSpaceGuard
{
    public static void EnsureAvailable(string path, long requiredBytes) =>
        EnsureAvailable(path, requiredBytes, GetAvailableBytes);

    internal static void EnsureAvailable(string path, long requiredBytes, Func<string, long> availableBytes)
    {
        if (requiredBytes < 0) throw new ArgumentOutOfRangeException(nameof(requiredBytes));
        ArgumentNullException.ThrowIfNull(availableBytes);
        var available = availableBytes(Path.GetFullPath(path));
        if (available < requiredBytes)
            throw new IOException($"Nicht genügend freier Speicherplatz: {requiredBytes} Byte benötigt, {available} Byte verfügbar.");
    }

    private static long GetAvailableBytes(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        DriveInfo? matchingDrive = null;
        var longestRootLength = -1;
        foreach (var drive in DriveInfo.GetDrives())
        {
            var root = Path.GetFullPath(drive.Name);
            var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar)
                ? root
                : root + Path.DirectorySeparatorChar;
            if ((string.Equals(fullPath, root.TrimEnd(Path.DirectorySeparatorChar), comparison) ||
                 fullPath.StartsWith(rootPrefix, comparison)) && root.Length > longestRootLength)
            {
                matchingDrive = drive;
                longestRootLength = root.Length;
            }
        }
        return matchingDrive?.AvailableFreeSpace ??
               throw new IOException("Das Zielvolume für die Speicherplatzprüfung ist nicht bestimmbar.");
    }
}
