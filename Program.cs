using LancerNexus.Updater;

if (args.Length == 3 && args[0] == "canonicalize-manifest")
{
    var input = new FileInfo(args[1]);
    if (!input.Exists || input.Length is <= 0 or > 1_048_576)
        throw new InvalidDataException("Manifestdatei ist leer, fehlt oder überschreitet 1 MiB.");
    var canonical = ManifestCanonicalizer.Canonicalize(await File.ReadAllBytesAsync(input.FullName));
    await File.WriteAllBytesAsync(args[2], canonical);
    Console.WriteLine($"Kanonische Manifestbytes geschrieben: {args[2]}");
    return;
}

var statusPath = Environment.GetEnvironmentVariable("LANCER_NEXUS_STATUS_FILE");
try
{
    await RunUpdaterAsync(args, statusPath);
}
catch (Exception error)
{
    await UpdaterStatusStore.WriteAsync(statusPath, new UpdaterStatusDocument(
        1, UpdaterOperationState.Failed, "Update operation failed.", null, false, error.GetType().Name));
    throw;
}

static async Task RunUpdaterAsync(string[] args, string? statusPath)
{
    var prepareOnly = args.Contains("--prepare-only", StringComparer.Ordinal);
    var startCurrentOnly = args.Contains("--start-current", StringComparer.Ordinal);
    if (prepareOnly && startCurrentOnly)
        throw new ArgumentException("Updater modes are mutually exclusive.");

    await UpdaterStatusStore.WriteAsync(statusPath, new UpdaterStatusDocument(
        1, UpdaterOperationState.Checking, "Checking signed release metadata.", null, false));
    var options = UpdaterOptions.FromEnvironment(args);
    using var updaterRunLock = UpdaterRunLock.Acquire(options.InstallRootPath);
    var envelope = await ManifestClient.LoadAsync(options.ManifestUri, CancellationToken.None);
    var trustRoot = TrustRoot.Load(options.TrustRootPath);
    var manifest = ManifestVerifier.Validate(envelope, trustRoot, options, DateTime.UtcNow);
    ManifestRollbackStore.Accept(options.StatePath, options, envelope, manifest);
    Console.WriteLine($"Manifest {manifest.ClientVersion} für {manifest.Platform}/{manifest.Architecture} ist gültig.");

    var clientPackage = manifest.Packages.Single(p => p.Id == "client");
    if (FailedReleaseStore.IsKnownFailure(options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages))
    {
        Console.Error.WriteLine("Dieses Release ist bereits fehlgeschlagen; es wird nicht erneut aktiviert.");
        if (!prepareOnly && await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None))
        {
            await WriteReadyAsync(statusPath, null, "Restored healthy release started.");
            return;
        }
        throw new InvalidOperationException("Das zuletzt gesunde Clientrelease konnte nicht gestartet werden.");
    }

    if (prepareOnly)
    {
        if (ReleaseActivator.IsCurrentVerified(manifest, clientPackage, options))
        {
            FailedReleaseStore.Clear(options.InstallRootPath);
            await WriteReadyAsync(statusPath, manifest.ClientVersion);
            return;
        }
    }
    else
    {
        var currentStart = await ReleaseActivator.TryStartCurrentAsync(
            manifest, clientPackage, options, CancellationToken.None);
        if (currentStart == ReleaseActivator.StartResult.Healthy)
        {
            FailedReleaseStore.Clear(options.InstallRootPath);
            await WriteReadyAsync(statusPath, manifest.ClientVersion);
            return;
        }
        if (currentStart == ReleaseActivator.StartResult.Failed)
        {
            RecordFailureSafely(options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages);
            if (ReleaseActivator.RollbackCurrent(options) &&
                await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None))
            {
                await WriteReadyAsync(statusPath, null, "Restored healthy release started.");
                return;
            }
            throw new InvalidOperationException("Clientstart fehlgeschlagen und es gibt kein startbares gesundes Vorgängerrelease.");
        }
        if (startCurrentOnly)
            throw new InvalidOperationException("There is no verified current release matching the signed manifest.");
    }

    await UpdaterStatusStore.WriteAsync(statusPath, new UpdaterStatusDocument(
        1, UpdaterOperationState.Downloading, "Downloading and verifying signed packages.", manifest.ClientVersion, false));
    var dataPackages = DataPackageStager.SelectPackages(manifest, options.OptionalDataPackages);
    var selectedPackages = dataPackages.Append(clientPackage).ToArray();
    string? verifiedClientArchive = null;
    var verifiedDataArchives = new Dictionary<string, string>(StringComparer.Ordinal);
    foreach (var package in selectedPackages)
    {
        var path = await ArtifactDownloader.DownloadVerifiedAsync(package, options, CancellationToken.None);
        if (package.Id == clientPackage.Id)
            verifiedClientArchive = path;
        else
            verifiedDataArchives.Add(package.Id, path);
        Console.WriteLine($"Paket {package.Id} {package.Version} geprüft und gecacht: {path}");
    }

    await UpdaterStatusStore.WriteAsync(statusPath, new UpdaterStatusDocument(
        1, UpdaterOperationState.Staging, "Installing the verified release snapshot.", manifest.ClientVersion, false));
    var stagedRelease = await ReleaseStager.StageClientAsync(
        manifest, clientPackage, verifiedClientArchive ?? throw new InvalidOperationException("Clientpaket wurde nicht geladen."),
        options, CancellationToken.None);
    try
    {
        await DataPackageStager.WriteSnapshotAsync(stagedRelease, manifest, options.OptionalDataPackages,
            verifiedDataArchives, CancellationToken.None);
    }
    catch
    {
        if (Directory.Exists(stagedRelease)) Directory.Delete(stagedRelease, recursive: true);
        throw;
    }
    var activeRelease = ReleaseActivator.Activate(stagedRelease, manifest, clientPackage, options);
    Console.WriteLine($"Clientrelease wurde atomar aktiviert: {activeRelease}");
    if (prepareOnly)
    {
        if (!ReleaseActivator.IsCurrentVerified(manifest, clientPackage, options))
            throw new InvalidDataException("The activated release did not pass installation verification.");
        await WriteReadyAsync(statusPath, manifest.ClientVersion);
        return;
    }

    var activatedStart = await ReleaseActivator.TryStartCurrentAsync(
        manifest, clientPackage, options, CancellationToken.None);
    if (activatedStart == ReleaseActivator.StartResult.Healthy)
    {
        FailedReleaseStore.Clear(options.InstallRootPath);
        await WriteReadyAsync(statusPath, manifest.ClientVersion);
        return;
    }
    RecordFailureSafely(options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages);
    if (ReleaseActivator.RollbackCurrent(options) &&
        await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None))
    {
        await WriteReadyAsync(statusPath, null, "Restored healthy release started.");
        return;
    }
    throw new InvalidOperationException("Aktiviertes Release wurde nicht gesund; Rollback auf das Vorgängerrelease ist fehlgeschlagen.");
}

static Task WriteReadyAsync(string? statusPath, string? installedVersion, string message = "Installation verified.") =>
    UpdaterStatusStore.WriteAsync(statusPath,
        new UpdaterStatusDocument(1, UpdaterOperationState.Ready, message, installedVersion, true));

static void RecordFailureSafely(string installRoot, UpdateManifest manifest, UpdatePackage package,
    IReadOnlySet<string> optionalPackageIds)
{
    try { FailedReleaseStore.Record(installRoot, manifest, package, optionalPackageIds); }
    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"Fehlerstatus konnte nicht gespeichert werden: {error.Message}");
    }
}
