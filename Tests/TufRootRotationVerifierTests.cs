using System.Security.Cryptography;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class TufRootRotationVerifierTests
{
    private static readonly DateTime Now = new(2026, 10, 10, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void SuccessorRequiresOldAndNewRootThresholdsAndAdvancesTargetRole()
    {
        var oldKeys = new[] { Signer(1), Signer(2) };
        var newRootKeys = new[] { Signer(3), Signer(4) };
        var targetKeys = new[] { Signer(5) };
        var current = BootstrapRoot(oldKeys, threshold: 2);
        var envelope = BuildRoot(1, oldKeys, newRootKeys, targetKeys, oldThreshold: 2, newThreshold: 2);

        var updated = TufRootRotationVerifier.VerifySuccessor(envelope, current);

        Assert.Equal(1, updated.RootVersion);
        Assert.Equal(2, updated.RootRoleThreshold);
        Assert.Equal(1, updated.Threshold);
        Assert.Equal(targetKeys[0].KeyId, updated.Keys[0].KeyId);
        Assert.Equal(targetKeys[0].KeyId, updated.TimestampRoleKeys![0].KeyId);
        Assert.Equal(1, updated.TimestampRoleThreshold);
        Assert.Equal(targetKeys[0].KeyId, updated.SnapshotRoleKeys![0].KeyId);
        Assert.Equal(1, updated.SnapshotRoleThreshold);
        Assert.True(updated.ConsistentSnapshot);
        TufRootRotationVerifier.EnsureCurrent(updated, Now);
    }

    [Fact]
    public void SuccessorRejectsMissingEitherThresholdAndVersionGaps()
    {
        var oldKeys = new[] { Signer(1), Signer(2) };
        var newRootKeys = new[] { Signer(3), Signer(4) };
        var targetKeys = new[] { Signer(5) };
        var current = BootstrapRoot(oldKeys, threshold: 2);

        Assert.Throws<InvalidDataException>(() => TufRootRotationVerifier.VerifySuccessor(
            BuildRoot(1, oldKeys[..1], newRootKeys, targetKeys, oldThreshold: 2, newThreshold: 2), current));
        Assert.Throws<InvalidDataException>(() => TufRootRotationVerifier.VerifySuccessor(
            BuildRoot(1, oldKeys, newRootKeys[..1], targetKeys, oldThreshold: 2, newThreshold: 2), current));
        Assert.Throws<InvalidDataException>(() => TufRootRotationVerifier.VerifySuccessor(
            BuildRoot(2, oldKeys, newRootKeys, targetKeys, oldThreshold: 2, newThreshold: 2), current));

        var aliasedBootstrap = current with
        {
            Keys = [oldKeys[0].TrustedKey, oldKeys[0].TrustedKey with { KeyId = "bootstrap-alias" }]
        };
        Assert.Throws<InvalidDataException>(() => TufRootRotationVerifier.VerifySuccessor(
            BuildRoot(1, oldKeys, newRootKeys, targetKeys, oldThreshold: 2, newThreshold: 2), aliasedBootstrap));
    }

    [Fact]
    public void SuccessorRejectsExpiredRootAndIncorrectKeyIds()
    {
        var oldKeys = new[] { Signer(1), Signer(2) };
        var newRootKeys = new[] { Signer(3), Signer(4) };
        var targetKeys = new[] { Signer(5) };
        var current = BootstrapRoot(oldKeys, threshold: 2);

        var expired = TufRootRotationVerifier.VerifySuccessor(
            BuildRoot(1, oldKeys, newRootKeys, targetKeys, 2, 2, expires: Now.AddSeconds(-1)), current);
        Assert.Throws<InvalidDataException>(() => TufRootRotationVerifier.EnsureCurrent(expired, Now));

        var wrongKeyId = BuildRoot(1, oldKeys, newRootKeys, targetKeys, 2, 2, corruptKeyId: true);
        Assert.Throws<InvalidDataException>(() => TufRootRotationVerifier.VerifySuccessor(wrongKeyId, current));
    }

    [Fact]
    public async Task RootChainPersistsAndRevalidatesFromTheBootstrapRoot()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"lancer-tuf-root-{Guid.NewGuid():N}");
        var statePath = Path.Combine(directory, "root-chain.json");
        var oldKeys = new[] { Signer(1), Signer(2) };
        var newRootKeys = new[] { Signer(3), Signer(4) };
        var targetKeys = new[] { Signer(5) };
        var bootstrap = BootstrapRoot(oldKeys, threshold: 2);
        var rootOne = BuildRoot(1, oldKeys, newRootKeys, targetKeys, 2, 2);
        try
        {
            var accepted = await TufRootRotationVerifier.UpdateChainAsync(bootstrap, statePath,
                (version, _) => Task.FromResult<byte[]?>(version == 1 ? rootOne : null), Now);
            Assert.Equal(1, accepted.RootVersion);
            Assert.True(File.Exists(statePath));

            var restored = await TufRootRotationVerifier.UpdateChainAsync(bootstrap, statePath,
                (version, _) =>
                {
                    Assert.Equal(2, version);
                    return Task.FromResult<byte[]?>(null);
                }, Now);
            Assert.Equal(accepted.RootVersion, restored.RootVersion);
            Assert.Equal(accepted.Keys.Select(key => key.KeyId), restored.Keys.Select(key => key.KeyId));

            var state = JsonSerializer.Deserialize<TufRootChainState>(await File.ReadAllBytesAsync(statePath),
                TrustRoot.JsonOptions)!;
            await File.WriteAllTextAsync(statePath, JsonSerializer.Serialize(
                state with { Updates = [Convert.ToBase64String("tampered"u8.ToArray())] }, TrustRoot.JsonOptions));
            await Assert.ThrowsAsync<InvalidDataException>(() => TufRootRotationVerifier.UpdateChainAsync(
                bootstrap, statePath, (_, _) => Task.FromResult<byte[]?>(null), Now));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RootMetadataClientReturnsNotFoundAndRejectsRedirects()
    {
        var notFound = new TestHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        Assert.Null(await ManifestClient.LoadRootMetadataAsync(
            new Uri("https://updates.example.test/v1/metadata/root/1"), CancellationToken.None, notFound));

        var redirect = new TestHandler(_ => new HttpResponseMessage(HttpStatusCode.Redirect)
        { Headers = { Location = new Uri("https://evil.example.test/root.json") } });
        await Assert.ThrowsAsync<HttpRequestException>(() => ManifestClient.LoadRootMetadataAsync(
            new Uri("https://updates.example.test/v1/metadata/root/1"), CancellationToken.None, redirect));
    }

    private static TrustRoot BootstrapRoot(IReadOnlyList<SignerFixture> signers, int threshold) =>
        new(1, threshold, signers.Select(signer => signer.TrustedKey).ToArray(), 1);

    private static byte[] BuildRoot(long version, IReadOnlyList<SignerFixture> oldSigners,
        IReadOnlyList<SignerFixture> newRootSigners, IReadOnlyList<SignerFixture> targetSigners,
        int oldThreshold, int newThreshold, DateTime? expires = null, bool corruptKeyId = false)
    {
        var allSigners = newRootSigners.Concat(targetSigners).DistinctBy(signer => signer.KeyId).ToArray();
        var keys = new JsonObject();
        foreach (var signer in allSigners)
        {
            var keyObject = signer.TufKey.DeepClone();
            keys[signer.KeyId] = keyObject;
        }
        var rootIds = newRootSigners.Select(signer => signer.KeyId).ToArray();
        var targetIds = targetSigners.Select(signer => signer.KeyId).ToArray();
        if (corruptKeyId)
        {
            var original = keys.First();
            var value = original.Value!.DeepClone();
            keys.Remove(original.Key);
            keys[original.Key[..^1] + (original.Key[^1] == '0' ? "1" : "0")] = value;
        }

        var signed = new JsonObject
        {
            ["_type"] = "root",
            ["spec_version"] = "1.0.36",
            ["consistent_snapshot"] = true,
            ["version"] = version,
            ["expires"] = (expires ?? Now.AddDays(30)).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["keys"] = keys,
            ["roles"] = new JsonObject
            {
                ["root"] = Role(rootIds, newThreshold),
                ["timestamp"] = Role(targetIds, 1),
                ["snapshot"] = Role(targetIds, 1),
                ["targets"] = Role(targetIds, 1)
            }
        };
        var payload = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
        var signatures = oldSigners.Select(signer => Sign(signer, payload, signer.TrustedKey.KeyId))
            .Concat(newRootSigners.Select(signer => Sign(signer, payload, signer.KeyId))).ToArray();
        var envelope = new JsonObject
        {
            ["signed"] = signed,
            ["signatures"] = new JsonArray(signatures.Select(signature => (JsonNode?)new JsonObject
            {
                ["keyid"] = signature.KeyId,
                ["sig"] = signature.Value
            }).ToArray())
        };
        return JsonSerializer.SerializeToUtf8Bytes(envelope);
    }

    private static JsonObject Role(IEnumerable<string> ids, int threshold) => new()
    {
        ["keyids"] = new JsonArray(ids.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()),
        ["threshold"] = threshold
    };

    private static TufRootSignature Sign(SignerFixture signer, byte[] payload, string keyId)
    {
        var signature = new Ed25519Signer();
        signature.Init(true, signer.PrivateKey);
        signature.BlockUpdate(payload, 0, payload.Length);
        return new TufRootSignature(keyId, Convert.ToHexString(signature.GenerateSignature()).ToLowerInvariant());
    }

    private static SignerFixture Signer(byte seed)
    {
        var privateKey = new Ed25519PrivateKeyParameters(Enumerable.Repeat(seed, 32).ToArray(), 0);
        var publicKey = privateKey.GeneratePublicKey().GetEncoded();
        var key = new JsonObject
        {
            ["keytype"] = "ed25519",
            ["scheme"] = "ed25519",
            ["keyval"] = new JsonObject { ["public"] = Convert.ToHexString(publicKey).ToLowerInvariant() }
        };
        var keyId = Convert.ToHexString(SHA256.HashData(
            ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(key)))).ToLowerInvariant();
        return new SignerFixture(privateKey, keyId, key,
            new TrustedKey($"bootstrap-{seed}", "Ed25519", Convert.ToBase64String(publicKey)));
    }

    private sealed record SignerFixture(Ed25519PrivateKeyParameters PrivateKey, string KeyId,
        JsonObject TufKey, TrustedKey TrustedKey);

    private sealed class TestHandler(Func<HttpRequestMessage, HttpResponseMessage> createResponse) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(createResponse(request));
    }
}
