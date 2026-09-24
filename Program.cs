using LancerNexus.Updater;

var options = UpdaterOptions.FromEnvironment(args);
var envelope = await ManifestClient.LoadAsync(options.ManifestUri, CancellationToken.None);
var trustRoot = TrustRoot.Load(options.TrustRootPath);
var manifest = ManifestVerifier.Validate(envelope, trustRoot, options, DateTime.UtcNow);
ManifestRollbackStore.Accept(options.StatePath, options, envelope, manifest);
Console.WriteLine($"Manifest {manifest.ClientVersion} für {manifest.Platform}/{manifest.Architecture} ist gültig.");
if (manifest.Packages.Any(p => p.Required && p.Id != "client"))
    throw new InvalidOperationException("Pflicht-Datenpakete sind noch nicht installierbar; die aktive Version bleibt unverändert.");

var clientPackage = manifest.Packages.Single(p => p.Id == "client");
string? verifiedClientArchive = null;
foreach (var package in manifest.Packages.Where(p => p.Required))
{
    var path = await ArtifactDownloader.DownloadVerifiedAsync(package, options, CancellationToken.None);
    Console.WriteLine($"Pflichtpaket {package.Id} {package.Version} geprüft und gecacht: {path}");
    if (package.Id == clientPackage.Id)
        verifiedClientArchive = path;
}
if (ReleaseActivator.TryStartCurrent(manifest, clientPackage, options))
    return;

var stagedRelease = await ReleaseStager.StageClientAsync(
    manifest, clientPackage, verifiedClientArchive ?? throw new InvalidOperationException("Clientpaket wurde nicht geladen."),
    options, CancellationToken.None);
var activeRelease = ReleaseActivator.Activate(stagedRelease, manifest, clientPackage, options);
Console.WriteLine($"Clientrelease wurde atomar aktiviert: {activeRelease}");
if (!ReleaseActivator.TryStartCurrent(manifest, clientPackage, options))
    throw new InvalidOperationException("Aktiviertes Clientrelease ist unvollständig oder kann nicht gestartet werden.");
