namespace LancerNexus.Updater;

internal static class GatewayUpdatePolicy
{
    public static bool ShouldRejectUnchangedUpdateRequest(UpdateManifest previousManifest,
        UpdatePackage previousClient, UpdateManifest refreshedManifest, UpdatePackage refreshedClient,
        IReadOnlySet<string> optionalPackages, bool installedReleaseMatchesPreviousManifest) =>
        installedReleaseMatchesPreviousManifest &&
        !HasUpdatedRuntimeRelease(previousManifest, previousClient, refreshedManifest, refreshedClient, optionalPackages);

    public static bool HasUpdatedRuntimeRelease(UpdateManifest currentManifest, UpdatePackage currentClient,
        UpdateManifest candidateManifest, UpdatePackage candidateClient, IReadOnlySet<string> optionalPackages)
    {
        if (!currentClient.Sha256.Equals(candidateClient.Sha256, StringComparison.OrdinalIgnoreCase) ||
            currentClient.Version != candidateClient.Version || currentClient.Size != candidateClient.Size ||
            currentClient.Format != candidateClient.Format ||
            currentManifest.ClientVersion != candidateManifest.ClientVersion ||
            currentManifest.BuildId != candidateManifest.BuildId ||
            currentManifest.ProtocolVersion != candidateManifest.ProtocolVersion ||
            currentManifest.DataManifestId != candidateManifest.DataManifestId ||
            !currentManifest.Capabilities.Order(StringComparer.Ordinal)
                .SequenceEqual(candidateManifest.Capabilities.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            return true;

        var currentData = DataPackageStager.SelectPackages(currentManifest, optionalPackages)
            .OrderBy(package => package.Id, StringComparer.Ordinal).ToArray();
        var candidateData = DataPackageStager.SelectPackages(candidateManifest, optionalPackages)
            .OrderBy(package => package.Id, StringComparer.Ordinal).ToArray();
        return currentData.Length != candidateData.Length || currentData.Zip(candidateData).Any(pair =>
            pair.First.Id != pair.Second.Id || pair.First.Version != pair.Second.Version ||
            pair.First.Format != pair.Second.Format || pair.First.Required != pair.Second.Required ||
            pair.First.ContentVersion != pair.Second.ContentVersion || pair.First.Size != pair.Second.Size ||
            !pair.First.Sha256.Equals(pair.Second.Sha256, StringComparison.OrdinalIgnoreCase) ||
            pair.First.Priority != pair.Second.Priority || pair.First.MountOrder != pair.Second.MountOrder ||
            !pair.First.Dependencies.SequenceEqual(pair.Second.Dependencies, StringComparer.Ordinal) ||
            !pair.First.Overrides.SequenceEqual(pair.Second.Overrides, StringComparer.Ordinal));
    }
}
