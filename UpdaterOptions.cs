namespace LancerNexus.Updater;

public sealed record UpdaterOptions(Uri ManifestUri, string Channel, string Platform, string Architecture)
{
    public static UpdaterOptions FromEnvironment(string[] args)
    {
        var raw = Environment.GetEnvironmentVariable("LANCER_NEXUS_MANIFEST_URL") ??
                  (args.Length > 0 ? args[0] : "https://downloads.example.net/v1/channels/stable/manifest");
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Manifest URL muss HTTPS verwenden.");
        return new UpdaterOptions(uri,
            Environment.GetEnvironmentVariable("LANCER_NEXUS_CHANNEL") ?? "stable",
            Environment.GetEnvironmentVariable("LANCER_NEXUS_PLATFORM") ?? "linux",
            Environment.GetEnvironmentVariable("LANCER_NEXUS_ARCHITECTURE") ?? "x64");
    }
}
