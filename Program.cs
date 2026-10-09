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
    if (await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None))
        return;
    throw new InvalidOperationException("Das zuletzt gesunde Clientrelease konnte nicht gestartet werden.");
}

var currentStart = await ReleaseActivator.TryStartCurrentAsync(
    manifest, clientPackage, options, CancellationToken.None);
if (currentStart == ReleaseActivator.StartResult.Healthy)
{
    FailedReleaseStore.Clear(options.InstallRootPath);
    return;
}
if (currentStart == ReleaseActivator.StartResult.Failed)
{
    RecordFailureSafely(options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages);
    if (ReleaseActivator.RollbackCurrent(options) &&
        await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None))
        return;
    throw new InvalidOperationException("Clientstart fehlgeschlagen und es gibt kein startbares gesundes Vorgängerrelease.");
}

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
var activatedStart = await ReleaseActivator.TryStartCurrentAsync(
    manifest, clientPackage, options, CancellationToken.None);
if (activatedStart == ReleaseActivator.StartResult.Healthy)
{
    FailedReleaseStore.Clear(options.InstallRootPath);
    return;
}
RecordFailureSafely(options.InstallRootPath, manifest, clientPackage, options.OptionalDataPackages);
if (ReleaseActivator.RollbackCurrent(options) &&
    await ReleaseActivator.TryStartRestoredCurrentAsync(options, CancellationToken.None))
    return;
throw new InvalidOperationException("Aktiviertes Release wurde nicht gesund; Rollback auf das Vorgängerrelease ist fehlgeschlagen.");

static void RecordFailureSafely(string installRoot, UpdateManifest manifest, UpdatePackage package,
    IReadOnlySet<string> optionalPackageIds)
{
    try { FailedReleaseStore.Record(installRoot, manifest, package, optionalPackageIds); }
    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"Fehlerstatus konnte nicht gespeichert werden: {error.Message}");
    }
}
