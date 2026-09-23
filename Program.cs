using LancerNexus.Updater;

var options = UpdaterOptions.FromEnvironment(args);
var manifest = await ManifestClient.LoadAsync(options.ManifestUri, CancellationToken.None);
ManifestVerifier.Validate(manifest, options);
Console.WriteLine($"Manifest {manifest.ClientVersion} für {manifest.Platform}/{manifest.Architecture} ist gültig.");
Console.WriteLine("Download/Installation sind im nächsten Schritt vorgesehen.");
