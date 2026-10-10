namespace LancerNexus.Updater;

/// <summary>Coordinates durable failed-release suppression with pointer rollback and restart recovery.</summary>
public static class FailedReleaseRecovery
{
    public static bool RecoverKnownFailedCurrent(string installRoot, UpdateManifest manifest,
        UpdatePackage clientPackage, IReadOnlySet<string> optionalPackageIds, UpdaterOptions options)
    {
        if (!FailedReleaseStore.IsKnownFailure(installRoot, manifest, clientPackage, optionalPackageIds))
            return false;

        ReleaseActivator.RollbackFailedCurrentReleaseIfNeeded(manifest, clientPackage, options);
        return true;
    }

    public static void RecordFailureAndRollback(string installRoot, UpdateManifest manifest,
        UpdatePackage clientPackage, IReadOnlySet<string> optionalPackageIds, UpdaterOptions options) =>
        RecordFailureAndRollback(installRoot, manifest, clientPackage, optionalPackageIds, options, null);

    internal static void RecordFailureAndRollback(string installRoot, UpdateManifest manifest,
        UpdatePackage clientPackage, IReadOnlySet<string> optionalPackageIds, UpdaterOptions options,
        Action? afterFailureMarkerPersisted)
    {
        try { FailedReleaseStore.Record(installRoot, manifest, clientPackage, optionalPackageIds); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Fehlerstatus konnte nicht gespeichert werden: {error.Message}");
        }

        afterFailureMarkerPersisted?.Invoke();
        if (!ReleaseActivator.RollbackCurrent(options))
            throw new InvalidOperationException("Clientstart fehlgeschlagen und es gibt kein startbares gesundes Vorgängerrelease.");
    }
}
