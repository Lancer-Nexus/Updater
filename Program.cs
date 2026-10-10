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
    var updateStartedAtUtc = DateTime.UtcNow;
    var bootstrapRoot = TrustRoot.Load(options.TrustRootPath);
    Task<byte[]?> FetchRootVersionAsync(long version, CancellationToken cancellationToken) =>
        ManifestClient.LoadRootMetadataAsync(new Uri(options.EffectiveRootMetadataBaseUri, version.ToString()), cancellationToken);
    Task<TrustRoot> RefreshTrustRootAsync() => TufRootRotationVerifier.UpdateChainAsync(
        bootstrapRoot, options.RootChainStatePath, FetchRootVersionAsync, updateStartedAtUtc, CancellationToken.None);
    var trustRoot = bootstrapRoot;
    async Task<VerifiedUpdateMetadata> LoadVerifiedReleaseMetadataAsync()
    {
        trustRoot = await RefreshTrustRootAsync();
        return await UpdateMetadataLoader.LoadAsync(options, trustRoot, updateStartedAtUtc,
            CancellationToken.None);
    }

    var releaseMetadata = await LoadVerifiedReleaseMetadataAsync();
    var envelope = releaseMetadata.Envelope;
    var manifest = releaseMetadata.Manifest;
    var clientPackage = manifest.Packages.Single(p => p.Id == "client");
    var updateRetries = 0;
    var repairRetries = 0;
    Console.WriteLine($"Manifest {manifest.ClientVersion} für {manifest.Platform}/{manifest.Architecture} ist gültig.");
    if (prepareOnly)
    {
        if (ReleaseActivator.IsCurrentVerified(manifest, clientPackage, options))
        {
            await WriteReadyAsync(statusPath, manifest.ClientVersion);
            return;
        }
    }

    Task PublishRunningStatusAsync() => WriteReadyAsync(statusPath, manifest.ClientVersion,
        "Client started; waiting for exit and Gateway update requests.");

    var failedRelease = FailedReleaseStore.IsKnownFailure(
        options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages);
    var startResult = ReleaseActivator.StartResult.NotCurrent;
    var startedRestoredRelease = false;
    if (!prepareOnly)
    {
        if (failedRelease)
            FailedReleaseRecovery.RecoverKnownFailedCurrent(options.InstallRootPath, manifest, clientPackage,
                options.OptionalDataPackages, options);
        startResult = failedRelease
            ? await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None,
                () => WriteReadyAsync(statusPath, null, "Restored release is running."))
            : await ReleaseActivator.TryStartCurrentAsync(manifest, clientPackage, options,
                CancellationToken.None, PublishRunningStatusAsync);
        startedRestoredRelease = failedRelease;
        if (failedRelease && startResult == ReleaseActivator.StartResult.Failed)
            throw new InvalidOperationException("The failed release is suppressed and no healthy previous release could start.");
    }

    while (true)
    {
        if (startResult == ReleaseActivator.StartResult.Healthy)
        {
            if (!startedRestoredRelease)
                FailedReleaseStore.Clear(options.InstallRootPath);
            await WriteReadyAsync(statusPath, manifest.ClientVersion);
            return;
        }

        if (startResult == ReleaseActivator.StartResult.Failed)
        {
            FailedReleaseRecovery.RecordFailureAndRollback(options.InstallRootPath, manifest, clientPackage,
                options.OptionalDataPackages, options);
            startResult = await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None,
                () => WriteReadyAsync(statusPath, null, "Restored release is running."));
            startedRestoredRelease = true;
            if (startResult == ReleaseActivator.StartResult.Healthy)
            {
                await WriteReadyAsync(statusPath, null, "Restored healthy release started.");
                return;
            }
            if (startResult is not (ReleaseActivator.StartResult.UpdateRequired or ReleaseActivator.StartResult.RepairRequired))
                throw new InvalidOperationException("Clientstart fehlgeschlagen und das Vorgängerrelease konnte nicht gestartet werden.");
        }

        if (startResult == ReleaseActivator.StartResult.UpdateRequired)
        {
            if (updateRetries >= 3)
                throw new InvalidOperationException("Gateway requested an update repeatedly; retry limit reached.");
            updateRetries++;
            await UpdaterStatusStore.WriteAsync(statusPath, new UpdaterStatusDocument(
                1, UpdaterOperationState.Checking, "Gateway requested an update; refreshing signed release metadata.",
                manifest.ClientVersion, false, "GatewayUpdateRequired"));
            var previousManifest = manifest;
            var previousClient = clientPackage;
            var installedReleaseMatchesPreviousManifest =
                ReleaseActivator.IsCurrentVerified(previousManifest, previousClient, options);
            releaseMetadata = await LoadVerifiedReleaseMetadataAsync();
            envelope = releaseMetadata.Envelope;
            manifest = releaseMetadata.Manifest;
            clientPackage = manifest.Packages.Single(p => p.Id == "client");
            if (GatewayUpdatePolicy.ShouldRejectUnchangedUpdateRequest(previousManifest, previousClient,
                    manifest, clientPackage, options.OptionalDataPackages, installedReleaseMatchesPreviousManifest))
                throw new InvalidOperationException("Gateway requires an update, but refreshed signed metadata does not change the installed runtime release.");
            Console.WriteLine($"Gateway-Update erkannt; neues signiertes Clientrelease {manifest.ClientVersion} wird vorbereitet.");
            startResult = ReleaseActivator.StartResult.NotCurrent;
            startedRestoredRelease = false;
            continue;
        }

        if (startResult == ReleaseActivator.StartResult.RepairRequired)
        {
            if (repairRetries >= 1)
                throw new InvalidOperationException("Gateway requested repair repeatedly; repair retry limit reached.");
            repairRetries++;
            startResult = ReleaseActivator.StartResult.NotCurrent;
            startedRestoredRelease = false;
        }

        if (startResult != ReleaseActivator.StartResult.NotCurrent)
            throw new InvalidOperationException("Updater entered an invalid client start state.");
        if (startCurrentOnly && updateRetries == 0 && repairRetries == 0)
            throw new InvalidOperationException("There is no verified current release matching the signed manifest.");
        if (FailedReleaseStore.IsKnownFailure(options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages))
            throw new InvalidOperationException("This signed release is already recorded as failed and will not be activated again.");

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

        startResult = await ReleaseActivator.TryStartCurrentAsync(manifest, clientPackage, options,
            CancellationToken.None, PublishRunningStatusAsync);
        startedRestoredRelease = false;
    }
}

static Task WriteReadyAsync(string? statusPath, string? installedVersion, string message = "Installation verified.") =>
    UpdaterStatusStore.WriteAsync(statusPath,
        new UpdaterStatusDocument(1, UpdaterOperationState.Ready, message, installedVersion, true));
