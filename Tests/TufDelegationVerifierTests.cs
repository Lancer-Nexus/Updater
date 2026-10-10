using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class TufDelegationVerifierTests
{
    private static readonly DateTime Now = new(2026, 10, 10, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void ParsesPathAndHashPrefixDelegationsAndAppliesPathGlobsBySegment()
    {
        var (keyObject, keyId, key) = CreateKey(0x27);
        var roles = ReadRoles(new JsonObject
        {
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject { [keyId] = keyObject.DeepClone() },
                ["roles"] = new JsonArray(
                    Role("linux", keyId, paths: ["packages/linux-?.tar.zst"]),
                    Role("hash-bin", keyId, pathHashPrefixes: ["A1B2"]))
            }
        });

        Assert.Equal(2, roles.Count);
        Assert.True(roles[0].Matches("packages/linux-1.tar.zst"));
        Assert.False(roles[0].Matches("packages/linux-10.tar.zst"));
        Assert.False(roles[0].Matches("packages/sub/linux-1.tar.zst"));
        Assert.Equal(key, Assert.Single(roles[0].Keys));
        Assert.Equal(1, roles[0].Threshold);
        Assert.True(roles[0].Terminating);
        Assert.Equal(keyId, roles[1].Keys[0].KeyId);
    }

    [Fact]
    public void AcceptsAnEmptyDelegationSetWhenAllDelegationsHaveBeenRevoked()
    {
        var roles = ReadRoles(new JsonObject
        {
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject(),
                ["roles"] = new JsonArray()
            }
        });

        Assert.Empty(roles);
    }

    [Fact]
    public void RejectsMalformedDelegationKeysRolesAndSelectors()
    {
        var (keyObject, keyId, _) = CreateKey(0x28);
        Assert.Throws<InvalidDataException>(() => ReadRoles(new JsonObject
        {
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject { [keyId] = keyObject.DeepClone() },
                ["roles"] = new JsonArray(Role("../escape", keyId))
            }
        }));
        Assert.Throws<InvalidDataException>(() => ReadRoles(new JsonObject
        {
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject { [keyId] = keyObject.DeepClone() },
                ["roles"] = new JsonArray(Role("targets/linux", keyId,
                    paths: ["packages/*"], pathHashPrefixes: ["ab"]))
            }
        }));
        Assert.Throws<InvalidDataException>(() => ReadRoles(new JsonObject
        {
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject { [keyId] = keyObject.DeepClone() },
                ["roles"] = new JsonArray(Role("targets", keyId, paths: ["../outside"]))
            }
        }));
    }

    [Fact]
    public void VerifiesDelegatedTargetsEnvelopeUsingItsDelegatedKeyAndName()
    {
        var (_, _, trustedKey, signer) = CreateSigner(0x29);
        var signed = new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 7,
            ["expires"] = Now.AddHours(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject()
        };
        var bytes = SignMetadata(signed, trustedKey, signer);
        var verified = TufMetadataVerifier.Verify(bytes, "targets/linux", [trustedKey], 1, 7, Now,
            delegatedTargetsRole: true);

        Assert.Equal("targets/linux", verified.Role);
        Assert.Equal(7, verified.Version);
        Assert.Throws<ArgumentException>(() => TufMetadataVerifier.Verify(bytes, "../targets", [trustedKey], 1,
            0, Now, delegatedTargetsRole: true));
        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(bytes, "timestamp", [trustedKey], 1,
            0, Now));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MetadataClientFetchesAndVerifiesDelegatedTargets(bool consistentSnapshot)
    {
        var repository = BuildDelegatedRepository();
        var root = repository.Root with { ConsistentSnapshot = consistentSnapshot };
        var fetched = new List<string>();
        Task<byte[]> Fetch(Uri uri, CancellationToken _)
        {
            fetched.Add(uri.AbsolutePath);
            return Task.FromResult(Path.GetFileName(uri.AbsolutePath) switch
            {
                "timestamp.json" => repository.Timestamp,
                "3.snapshot.json" or "snapshot.json" => repository.Snapshot,
                "4.targets.json" or "targets.json" => repository.Targets,
                "7.content.json" or "content.json" => repository.DelegatedTargets,
                _ => throw new InvalidOperationException($"Unexpected TUF metadata request: {uri}")
            });
        }

        var verified = await TufMetadataClient.LoadAsync(new Uri("https://updates.example.test/v1/metadata/"),
            root, Now, new TufMetadataVersions(0, 0, 0), Fetch, CancellationToken.None,
            ["manifests/stable/linux-x64.json", "artifacts/client.tar.zst"]);

        Assert.Equal(repository.ManifestSha256, verified.Targets["manifests/stable/linux-x64.json"].Sha256);
        Assert.Equal(repository.PackageSha256, verified.Targets["artifacts/client.tar.zst"].Sha256);
        Assert.Equal(7, verified.DelegatedRoles["content"].Version);
        Assert.Contains(consistentSnapshot ? "/v1/metadata/7.content.json" : "/v1/metadata/content.json",
            fetched);

        var stateDirectory = Path.Combine(Path.GetTempPath(), "tuf-delegated-state-" + Guid.NewGuid().ToString("N"));
        var statePath = Path.Combine(stateDirectory, "metadata.json");
        try
        {
            TufMetadataVersionStore.Accept(statePath, root, verified);
            var floors = TufMetadataVersionStore.GetMinimumVersions(statePath, root);
            Assert.Equal(7, floors.DelegatedRoles["content"].Version);
            await Assert.ThrowsAsync<InvalidDataException>(() => TufMetadataClient.LoadAsync(
                new Uri("https://updates.example.test/v1/metadata/"), root, Now,
                floors with
                {
                    DelegatedRoles = new Dictionary<string, TufDelegatedMetadataReceipt>(StringComparer.Ordinal)
                    {
                        ["content"] = floors.DelegatedRoles["content"] with { Version = 8 }
                    }
                }, Fetch, CancellationToken.None, ["manifests/stable/linux-x64.json"]));
        }
        finally
        {
            if (Directory.Exists(stateDirectory)) Directory.Delete(stateDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task MetadataClientRejectsDelegatedTargetsOutsideTheirDeclaredScope()
    {
        var repository = BuildDelegatedRepository(["manifests/*"]);
        Task<byte[]> Fetch(Uri uri, CancellationToken _) => Task.FromResult(Path.GetFileName(uri.AbsolutePath) switch
        {
            "timestamp.json" => repository.Timestamp,
            "3.snapshot.json" or "snapshot.json" => repository.Snapshot,
            "4.targets.json" or "targets.json" => repository.Targets,
            "7.content.json" or "content.json" => repository.DelegatedTargets,
            _ => throw new InvalidOperationException($"Unexpected TUF metadata request: {uri}")
        });

        await Assert.ThrowsAsync<InvalidDataException>(() => TufMetadataClient.LoadAsync(
            new Uri("https://updates.example.test/v1/metadata/"), repository.Root, Now,
            new TufMetadataVersions(0, 0, 0), Fetch, CancellationToken.None,
            ["manifests/stable/linux-x64.json"]));
    }

    private static IReadOnlyList<TufDelegatedRole> ReadRoles(JsonObject signed) =>
        TufDelegationVerifier.ReadRoles(JsonDocument.Parse(signed.ToJsonString()).RootElement);

    private static JsonObject Role(string name, string keyId, string[]? paths = null,
        string[]? pathHashPrefixes = null)
    {
        var role = new JsonObject
        {
            ["name"] = name,
            ["keyids"] = new JsonArray(JsonValue.Create(keyId)),
            ["threshold"] = 1,
            ["terminating"] = true
        };
        if (paths is not null) role["paths"] = JsonSerializer.SerializeToNode(paths);
        if (pathHashPrefixes is not null)
            role["path_hash_prefixes"] = JsonSerializer.SerializeToNode(pathHashPrefixes);
        return role;
    }

    private static (JsonObject KeyObject, string KeyId, TrustedKey TrustedKey) CreateKey(byte seed)
    {
        var (keyObject, keyId, key, _) = CreateSigner(seed);
        return (keyObject, keyId, key);
    }

    private static (JsonObject KeyObject, string KeyId, TrustedKey TrustedKey,
        Ed25519PrivateKeyParameters Signer) CreateSigner(byte seed)
    {
        var signer = new Ed25519PrivateKeyParameters(Enumerable.Repeat(seed, 32).ToArray(), 0);
        var publicKey = signer.GeneratePublicKey().GetEncoded();
        var keyObject = new JsonObject
        {
            ["keytype"] = "ed25519",
            ["scheme"] = "ed25519",
            ["keyval"] = new JsonObject { ["public"] = Convert.ToHexString(publicKey).ToLowerInvariant() }
        };
        var keyId = Convert.ToHexString(SHA256.HashData(ManifestCanonicalizer.Canonicalize(
            JsonSerializer.SerializeToUtf8Bytes(keyObject)))).ToLowerInvariant();
        return (keyObject, keyId, new TrustedKey(keyId, "Ed25519", Convert.ToBase64String(publicKey)), signer);
    }

    private static byte[] SignMetadata(JsonObject signed, TrustedKey key,
        Ed25519PrivateKeyParameters signer)
    {
        var payload = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
        var ed25519 = new Ed25519Signer();
        ed25519.Init(true, signer);
        ed25519.BlockUpdate(payload, 0, payload.Length);
        return JsonSerializer.SerializeToUtf8Bytes(new JsonObject
        {
            ["signed"] = signed,
            ["signatures"] = new JsonArray(new JsonObject
            {
                ["keyid"] = key.KeyId,
                ["sig"] = Convert.ToHexString(ed25519.GenerateSignature()).ToLowerInvariant()
            })
        });
    }

    private static DelegatedRepositoryFixture BuildDelegatedRepository(string[]? paths = null)
    {
        var timestampSigner = CreateSigner(0x31);
        var snapshotSigner = CreateSigner(0x32);
        var targetsSigner = CreateSigner(0x33);
        var delegatedSigner = CreateSigner(0x34);
        var manifest = "signed manifest payload"u8.ToArray();
        var package = "signed package bytes"u8.ToArray();
        var delegatedSigned = new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 7,
            ["expires"] = Now.AddDays(2).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject
            {
                ["manifests/stable/linux-x64.json"] = TargetInfo(manifest),
                ["artifacts/client.tar.zst"] = TargetInfo(package)
            }
        };
        var delegatedBytes = SignMetadata(delegatedSigned, delegatedSigner.TrustedKey, delegatedSigner.Signer);

        var delegatedRole = new JsonObject
        {
            ["name"] = "content",
            ["keyids"] = new JsonArray(JsonValue.Create(delegatedSigner.TrustedKey.KeyId)),
            ["threshold"] = 1,
            ["terminating"] = true
        };
        if (paths is not null) delegatedRole["paths"] = JsonSerializer.SerializeToNode(paths);
        var targetsSigned = new JsonObject
        {
            ["_type"] = "targets",
            ["spec_version"] = "1.0.36",
            ["version"] = 4,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["targets"] = new JsonObject(),
            ["delegations"] = new JsonObject
            {
                ["keys"] = new JsonObject
                {
                    [delegatedSigner.TrustedKey.KeyId] = delegatedSigner.KeyObject.DeepClone()
                },
                ["roles"] = new JsonArray(delegatedRole)
            }
        };
        var targetsBytes = SignMetadata(targetsSigned, targetsSigner.TrustedKey, targetsSigner.Signer);
        var snapshotSigned = new JsonObject
        {
            ["_type"] = "snapshot",
            ["spec_version"] = "1.0.36",
            ["version"] = 3,
            ["expires"] = Now.AddDays(3).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject
            {
                ["targets.json"] = MetadataInfo(4, targetsBytes),
                ["content.json"] = MetadataInfo(7, delegatedBytes)
            }
        };
        var snapshotBytes = SignMetadata(snapshotSigned, snapshotSigner.TrustedKey, snapshotSigner.Signer);
        var timestampSigned = new JsonObject
        {
            ["_type"] = "timestamp",
            ["spec_version"] = "1.0.36",
            ["version"] = 2,
            ["expires"] = Now.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["meta"] = new JsonObject { ["snapshot.json"] = MetadataInfo(3, snapshotBytes) }
        };
        var timestampBytes = SignMetadata(timestampSigned, timestampSigner.TrustedKey, timestampSigner.Signer);
        var root = new TrustRoot(1, 1, [targetsSigner.TrustedKey], 1)
        {
            TimestampRoleKeys = [timestampSigner.TrustedKey],
            TimestampRoleThreshold = 1,
            SnapshotRoleKeys = [snapshotSigner.TrustedKey],
            SnapshotRoleThreshold = 1
        };
        return new DelegatedRepositoryFixture(root, timestampBytes, snapshotBytes, targetsBytes, delegatedBytes,
            Convert.ToHexString(SHA256.HashData(manifest)).ToLowerInvariant(),
            Convert.ToHexString(SHA256.HashData(package)).ToLowerInvariant());
    }

    private static JsonObject TargetInfo(byte[] bytes) => new()
    {
        ["length"] = bytes.Length,
        ["hashes"] = new JsonObject
        {
            ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()
        }
    };

    private static JsonObject MetadataInfo(long version, byte[] bytes) => new()
    {
        ["version"] = version,
        ["length"] = bytes.Length,
        ["hashes"] = new JsonObject
        {
            ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()
        }
    };

    private sealed record DelegatedRepositoryFixture(TrustRoot Root, byte[] Timestamp, byte[] Snapshot,
        byte[] Targets, byte[] DelegatedTargets, string ManifestSha256, string PackageSha256);
}
