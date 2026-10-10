using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class TufRepositoryVerifierTests
{
    private static readonly DateTime Now = new(2026, 10, 10, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void VerifiesRoleBindingsAndReturnsTargets()
    {
        var repository = BuildRepository();

        var verified = TufRepositoryVerifier.Verify(repository.Root, repository.Timestamp,
            repository.Snapshot, repository.Targets, Now, new TufMetadataVersions(1, 2, 3));

        Assert.Equal(new TufMetadataVersions(2, 3, 4), verified.Versions);
        Assert.Equal(repository.TargetLength, verified.Targets["manifests/stable/linux-x64.json"].Length);
        Assert.Equal(repository.TargetSha256, verified.Targets["manifests/stable/linux-x64.json"].Sha256);
        TufRepositoryVerifier.VerifyTargetBytes(verified, "manifests/stable/linux-x64.json",
            "signed-manifest-bytes"u8);
        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.VerifyTargetBytes(verified,
            "manifests/stable/linux-x64.json", "changed"u8));
        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.VerifyTargetBytes(verified,
            "unknown-target", "signed-manifest-bytes"u8));
    }

    [Fact]
    public void AcceptsADeclaredEmptyTarget()
    {
        var repository = BuildRepository(targetBytes: []);
        var verified = TufRepositoryVerifier.Verify(repository.Root, repository.Timestamp,
            repository.Snapshot, repository.Targets, Now, new TufMetadataVersions(0, 0, 0));

        Assert.Equal(0, verified.Targets["manifests/stable/linux-x64.json"].Length);
        TufRepositoryVerifier.VerifyTargetBytes(verified, "manifests/stable/linux-x64.json", []);
        TufRepositoryVerifier.VerifyTargetMetadata(verified, "manifests/stable/linux-x64.json", 0,
            Convert.ToHexString(SHA256.HashData([])).ToLowerInvariant());
    }

    [Fact]
    public void RejectsMismatchedMetadataBytesAndRoleVersions()
    {
        var repository = BuildRepository();
        var alteredSnapshot = repository.Snapshot.ToArray();
        alteredSnapshot[^1] ^= 0x01;
        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.Verify(repository.Root,
            repository.Timestamp, alteredSnapshot, repository.Targets, Now, new TufMetadataVersions(0, 0, 0)));

        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.Verify(repository.Root,
            repository.Timestamp, repository.Snapshot, repository.Targets, Now, new TufMetadataVersions(3, 4, 5)));

        var badSnapshotRepository = BuildRepository(snapshotTargetsVersion: 5);
        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.Verify(badSnapshotRepository.Root,
            badSnapshotRepository.Timestamp, badSnapshotRepository.Snapshot, badSnapshotRepository.Targets,
            Now, new TufMetadataVersions(0, 0, 0)));
    }

    [Fact]
    public void RejectsUnsafeTargetPathsAndDelegations()
    {
        var unsafePath = BuildRepository(targetPath: "../client.tar.zst");
        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.Verify(unsafePath.Root,
            unsafePath.Timestamp, unsafePath.Snapshot, unsafePath.Targets, Now, new TufMetadataVersions(0, 0, 0)));

        var delegated = BuildRepository(withDelegations: true);
        Assert.Throws<InvalidDataException>(() => TufRepositoryVerifier.Verify(delegated.Root,
            delegated.Timestamp, delegated.Snapshot, delegated.Targets, Now, new TufMetadataVersions(0, 0, 0)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TufMetadataClientFetchesRolesByVerifiedReferences(bool consistentSnapshot)
    {
        var repository = BuildRepository();
        var root = repository.Root with { ConsistentSnapshot = consistentSnapshot };
        var requested = new List<string>();
        Task<byte[]> Fetch(Uri uri, CancellationToken _)
        {
            requested.Add(uri.AbsolutePath);
            return Task.FromResult(Path.GetFileName(uri.AbsolutePath) switch
            {
                "timestamp.json" => repository.Timestamp,
                "3.snapshot.json" or "snapshot.json" => repository.Snapshot,
                "4.targets.json" or "targets.json" => repository.Targets,
                _ => throw new InvalidOperationException($"Unexpected metadata request: {uri}")
            });
        }

        var verified = await TufMetadataClient.LoadAsync(new Uri("https://updates.example.test/v1/metadata/"),
            root, Now, new TufMetadataVersions(2, 3, 4), Fetch, CancellationToken.None);

        Assert.Equal(new TufMetadataVersions(2, 3, 4), verified.Versions);
        Assert.Equal(new[]
        {
            "/v1/metadata/timestamp.json",
            consistentSnapshot ? "/v1/metadata/3.snapshot.json" : "/v1/metadata/snapshot.json",
            consistentSnapshot ? "/v1/metadata/4.targets.json" : "/v1/metadata/targets.json"
        }, requested);
    }

    [Fact]
    public async Task TufMetadataClientChecksTimestampBindingBeforeFetchingTargets()
    {
        var repository = BuildRepository();
        var requested = new List<string>();
        Task<byte[]> Fetch(Uri uri, CancellationToken _)
        {
            requested.Add(uri.AbsolutePath);
            return Task.FromResult(Path.GetFileName(uri.AbsolutePath) == "timestamp.json"
                ? repository.Timestamp
                : repository.Snapshot.Concat(new byte[] { 0x00 }).ToArray());
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => TufMetadataClient.LoadAsync(
            new Uri("https://updates.example.test/v1/metadata/"), repository.Root, Now,
            new TufMetadataVersions(0, 0, 0), Fetch, CancellationToken.None));

        Assert.Equal(2, requested.Count);
    }

    private static RepositoryFixture BuildRepository(string targetPath = "manifests/stable/linux-x64.json",
        long? snapshotTargetsVersion = null, bool withDelegations = false, byte[]? targetBytes = null)
    {
        var timestampSigner = Signer(0x51);
        var snapshotSigner = Signer(0x52);
        var targetsSigner = Signer(0x53);
        targetBytes ??= "signed-manifest-bytes"u8.ToArray();
        var targetDigest = Convert.ToHexString(SHA256.HashData(targetBytes)).ToLowerInvariant();
        var target = new JsonObject
        {
            ["length"] = targetBytes.Length,
            ["hashes"] = new JsonObject { ["sha256"] = targetDigest }
        };
        var targetsSigned = new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 4,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject { [targetPath] = target }
        };
        if (withDelegations) targetsSigned["delegations"] = new JsonObject();
        var targets = SignMetadata(targetsSigned, targetsSigner);

        var snapshotSigned = new JsonObject
        {
            ["_type"] = "snapshot",
            ["spec_version"] = "1.0.36",
            ["version"] = 3,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject
            {
                ["targets.json"] = MetadataInfo(snapshotTargetsVersion ?? 4, targets)
            }
        };
        var snapshot = SignMetadata(snapshotSigned, snapshotSigner);
        var timestampSigned = new JsonObject
        {
            ["_type"] = "timestamp",
            ["spec_version"] = "1.0.36",
            ["version"] = 2,
            ["expires"] = Now.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject { ["snapshot.json"] = MetadataInfo(3, snapshot) }
        };
        var timestamp = SignMetadata(timestampSigned, timestampSigner);

        var root = new TrustRoot(1, 1, [targetsSigner.TrustedKey], 1)
        {
            TimestampRoleKeys = [timestampSigner.TrustedKey],
            TimestampRoleThreshold = 1,
            SnapshotRoleKeys = [snapshotSigner.TrustedKey],
            SnapshotRoleThreshold = 1
        };
        return new RepositoryFixture(root, timestamp, snapshot, targets, targetBytes.Length, targetDigest);
    }

    private static JsonObject MetadataInfo(long version, byte[] bytes) => new()
    {
        ["version"] = version,
        ["length"] = bytes.Length,
        ["hashes"] = new JsonObject { ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() }
    };

    private static byte[] SignMetadata(JsonObject signed, SignerFixture signer)
    {
        var payload = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
        var ed25519 = new Ed25519Signer();
        ed25519.Init(true, signer.PrivateKey);
        ed25519.BlockUpdate(payload, 0, payload.Length);
        var envelope = new JsonObject
        {
            ["signed"] = signed,
            ["signatures"] = new JsonArray(new JsonObject
            {
                ["keyid"] = signer.TrustedKey.KeyId,
                ["sig"] = Convert.ToHexString(ed25519.GenerateSignature()).ToLowerInvariant()
            })
        };
        return JsonSerializer.SerializeToUtf8Bytes(envelope);
    }

    private static SignerFixture Signer(byte seed)
    {
        var privateKey = new Ed25519PrivateKeyParameters(Enumerable.Repeat(seed, 32).ToArray(), 0);
        var publicKey = privateKey.GeneratePublicKey().GetEncoded();
        var keyObject = new JsonObject
        {
            ["keytype"] = "ed25519",
            ["scheme"] = "ed25519",
            ["keyval"] = new JsonObject { ["public"] = Convert.ToHexString(publicKey).ToLowerInvariant() }
        };
        var keyId = Convert.ToHexString(SHA256.HashData(
            ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(keyObject)))).ToLowerInvariant();
        return new SignerFixture(privateKey, new TrustedKey(keyId, "Ed25519", Convert.ToBase64String(publicKey)));
    }

    private sealed record SignerFixture(Ed25519PrivateKeyParameters PrivateKey, TrustedKey TrustedKey);
    private sealed record RepositoryFixture(TrustRoot Root, byte[] Timestamp, byte[] Snapshot, byte[] Targets,
        int TargetLength, string TargetSha256);
}
