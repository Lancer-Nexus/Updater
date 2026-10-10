using LancerNexus.Updater;

if (args.Length == 2 && args[0] == "--lock-check")
{
    try
    {
        using var updaterRunLock = UpdaterRunLock.Acquire(args[1]);
        return 0;
    }
    catch (InvalidOperationException)
    {
        return 74;
    }
}

if (args.Length == 7 && args[0] == "--failed-start")
{
    var failedInstallRoot = args[1];
    if (!long.TryParse(args[2], out var failedManifestVersion)) return 2;
    var failedClientVersion = args[3];
    var failedBuildId = args[4];
    var failedDataManifestId = args[5];
    var failedPackageHash = args[6];
    var failedPackage = new UpdatePackage("client", failedClientVersion, "client.tar.zst", 1,
        failedPackageHash, true, "tar.zst");
    var failedManifest = new UpdateManifest(1, failedManifestVersion, "stable", "linux", "x64", failedClientVersion,
        "1.0.0", 1, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), [failedPackage])
    {
        BuildId = failedBuildId,
        DataManifestId = failedDataManifestId,
        Capabilities = []
    };
    var failedOptions = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
        "stable", "linux", "x64", "trusted-root.json", InstallRootPath: failedInstallRoot);

    FailedReleaseRecovery.RecordFailureAndRollback(failedInstallRoot, failedManifest, failedPackage,
        new HashSet<string>(StringComparer.Ordinal), failedOptions, () => Environment.Exit(74));
    return 0;
}

if (args.Length != 7)
    return 2;

var installRoot = args[0];
var stagedRelease = args[1];
var boundaryName = args[2];
var clientVersion = args[3];
var buildId = args[4];
var dataManifestId = args[5];
var packageHash = args[6];
if (!Enum.TryParse<ReleaseActivator.ActivationBoundary>(boundaryName, out var requestedBoundary))
    return 2;

var package = new UpdatePackage("client", clientVersion, "client.tar.zst", 1, packageHash, true, "tar.zst");
var manifest = new UpdateManifest(1, 1, "stable", "linux", "x64", clientVersion, "1.0.0", 1,
    DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddHours(1), [package])
{
    BuildId = buildId,
    DataManifestId = dataManifestId,
    Capabilities = []
};
var options = new UpdaterOptions(new Uri("https://updates.example.test/manifest"),
    "stable", "linux", "x64", "trusted-root.json", InstallRootPath: installRoot);

ReleaseActivator.Activate(stagedRelease, manifest, package, options, boundary =>
{
    if (boundary == requestedBoundary)
        Environment.Exit(73);
});
return 0;
