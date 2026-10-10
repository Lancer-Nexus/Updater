using System.Text.Json;

namespace LancerNexus.Updater;

public sealed record VerifiedUpdateMetadata(SignedManifest Envelope, UpdateManifest Manifest,
    VerifiedTufRepository TufRepository);

/// <summary>Loads a TUF-authenticated manifest and binds every manifest package to trusted targets metadata.</summary>
public static class UpdateMetadataLoader
{
    public static Task<VerifiedUpdateMetadata> LoadAsync(UpdaterOptions options, TrustRoot trustRoot,
        DateTime updateStartedAtUtc, CancellationToken cancellationToken = default) =>
        LoadAsync(options, trustRoot, updateStartedAtUtc, ManifestClient.LoadBytesAsync,
            ManifestClient.LoadTufMetadataBytesAsync, cancellationToken);

    internal static async Task<VerifiedUpdateMetadata> LoadAsync(UpdaterOptions options, TrustRoot trustRoot,
        DateTime updateStartedAtUtc, Func<Uri, CancellationToken, Task<byte[]>> fetchManifest,
        Func<Uri, CancellationToken, Task<byte[]>> fetchMetadata, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(trustRoot);
        ArgumentNullException.ThrowIfNull(fetchManifest);
        ArgumentNullException.ThrowIfNull(fetchMetadata);
        if (updateStartedAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Update start time must be UTC.", nameof(updateStartedAtUtc));

        var manifestBytes = await fetchManifest(options.ManifestUri, cancellationToken);
        SignedManifest envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<SignedManifest>(manifestBytes, TrustRoot.JsonOptions)
                ?? throw new InvalidDataException("TUF-bound manifest is empty.");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("TUF-bound manifest is invalid JSON.", error);
        }

        var manifest = ManifestVerifier.Validate(envelope, trustRoot, options, updateStartedAtUtc);
        var manifestTargetPath = $"{options.Channel}/{options.Platform}-{options.Architecture}.json";
        var targetPaths = new[] { manifestTargetPath }.Concat(manifest.Packages.Select(package => package.Url))
            .Distinct(StringComparer.Ordinal).ToArray();
        var minimumVersions = TufMetadataVersionStore.GetMinimumVersions(options.TufMetadataStatePath, trustRoot);
        var repository = await TufMetadataClient.LoadAsync(options.EffectiveTufMetadataBaseUri,
            trustRoot, updateStartedAtUtc, minimumVersions, fetchMetadata, cancellationToken, targetPaths);
        TufRepositoryVerifier.VerifyTargetBytes(repository, manifestTargetPath, manifestBytes);

        foreach (var package in manifest.Packages)
            TufRepositoryVerifier.VerifyTargetMetadata(repository, package.Url, package.Size, package.Sha256);

        // Advance durable floors only after the fetched manifest and all of its package descriptors
        // are bound to the verified targets role.
        TufMetadataVersionStore.Accept(options.TufMetadataStatePath, trustRoot, repository);
        ManifestRollbackStore.Accept(options.StatePath, options, envelope, manifest);
        return new VerifiedUpdateMetadata(envelope, manifest, repository);
    }
}
