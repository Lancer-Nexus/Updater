namespace LancerNexus.Updater;

public sealed record UpdaterOptions(
    Uri ManifestUri, string Channel, string Platform, string Architecture,
    string TrustRootPath, string StatePath = "", Uri? ArtifactBaseUri = null,
    string CachePath = "", string InstallRootPath = "")
{
    public IReadOnlySet<string> OptionalDataPackages { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    public Uri EffectiveArtifactBaseUri => ArtifactBaseUri ?? new Uri(ManifestUri.GetLeftPart(UriPartial.Authority) + "/v1/");

    public static UpdaterOptions FromEnvironment(string[] args)
    {
        var raw = Environment.GetEnvironmentVariable("LANCER_NEXUS_MANIFEST_URL") ??
                  (args.FirstOrDefault(argument => !argument.StartsWith("--", StringComparison.Ordinal)) ??
                   "https://downloads.example.net/v1/channels/stable/manifest");
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Manifest URL muss HTTPS verwenden.");
        var channel = Environment.GetEnvironmentVariable("LANCER_NEXUS_CHANNEL") ?? "stable";
        var platform = Environment.GetEnvironmentVariable("LANCER_NEXUS_PLATFORM") ?? "linux";
        var architecture = Environment.GetEnvironmentVariable("LANCER_NEXUS_ARCHITECTURE") ?? "x64";
        if (channel is not ("stable" or "beta" or "nightly" or "internal") ||
            platform is not ("linux" or "win") || architecture is not ("x64" or "arm64"))
            throw new InvalidOperationException("Channel, Plattform oder Architektur ist ungültig.");
        var artifactBaseRaw = Environment.GetEnvironmentVariable("LANCER_NEXUS_ARTIFACT_BASE_URL");
        var artifactBase = artifactBaseRaw is null
            ? new Uri(uri.GetLeftPart(UriPartial.Authority) + "/v1/")
            : Uri.TryCreate(artifactBaseRaw, UriKind.Absolute, out var configuredBase) &&
              configuredBase.Scheme == Uri.UriSchemeHttps && configuredBase.AbsolutePath.EndsWith('/') &&
              string.IsNullOrEmpty(configuredBase.Query) && string.IsNullOrEmpty(configuredBase.Fragment)
                ? configuredBase
                : throw new InvalidOperationException("Artefakt-Basis muss eine HTTPS-URL mit abschließendem '/' sein.");
        var optionalPackages = (Environment.GetEnvironmentVariable("LANCER_NEXUS_OPTIONAL_PACKAGES") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);
        if (optionalPackages.Any(id => id.Length > 96 ||
                id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))))
            throw new InvalidOperationException("Die Liste optionaler Datenpakete enthält eine ungültige Paket-ID.");
        return new UpdaterOptions(uri, channel, platform, architecture,
            Environment.GetEnvironmentVariable("LANCER_NEXUS_TRUST_ROOT") ?? "trusted-root.json",
            Environment.GetEnvironmentVariable("LANCER_NEXUS_METADATA_STATE") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "lancer-nexus", $"trusted-metadata-{channel}-{platform}-{architecture}.json"),
            artifactBase,
            Environment.GetEnvironmentVariable("LANCER_NEXUS_PACKAGE_CACHE") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "lancer-nexus", "packages"),
            Environment.GetEnvironmentVariable("LANCER_NEXUS_INSTALL_ROOT") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LancerNexus"))
        {
            OptionalDataPackages = optionalPackages
        };
    }
}
