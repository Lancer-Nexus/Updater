using System.Text.Json;
using System.Text;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class ManifestVerifierTests
{
    private static readonly DateTime Now = new(2026, 9, 23, 12, 0, 0, DateTimeKind.Utc);
    private static readonly UpdaterOptions Options = new(
        new Uri("https://downloads.example.net/manifest"), "stable", "linux", "x64", "trusted-root.json");

    [Fact]
    public void PersistedVersionRejectsOldAndEquivocatedManifests()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"lancer-nexus-test-{Guid.NewGuid():N}");
        var path = Path.Combine(folder, "trusted-metadata.json");
        try
        {
            var (accepted, root) = SignedManifestFor(TestManifest(), 1);
            var verified = ManifestVerifier.Validate(accepted, root, Options, Now);
            ManifestRollbackStore.Accept(path, Options, accepted, verified);
            ManifestRollbackStore.Accept(path, Options, accepted, verified);

            var (older, olderRoot) = SignedManifestFor(TestManifest() with { Version = 6 }, 1);
            var olderVerified = ManifestVerifier.Validate(older, olderRoot, Options, Now);
            Assert.Throws<InvalidDataException>(() =>
                ManifestRollbackStore.Accept(path, Options, older, olderVerified));

            var (reused, reusedRoot) = SignedManifestFor(TestManifest() with { ClientVersion = "1.0.1" }, 1);
            var reusedVerified = ManifestVerifier.Validate(reused, reusedRoot, Options, Now);
            Assert.Throws<InvalidDataException>(() =>
                ManifestRollbackStore.Accept(path, Options, reused, reusedVerified));
        }
        finally
        {
            if (Directory.Exists(folder))
                Directory.Delete(folder, true);
        }
    }

    [Fact]
    public void ValidThresholdManifestIsAccepted()
    {
        var (envelope, root) = SignedManifestFor(TestManifest(), 2);
        Assert.Equal("1.0.0", ManifestVerifier.Validate(envelope, root, Options, Now).ClientVersion);
    }

    [Fact]
    public void ManifestCanonicalizationSortsKeysAndUsesCanonicalStringEscapes()
    {
        var input = Encoding.UTF8.GetBytes("{\"z\":1,\"a\":\"\\n/é\",\"b\":true}");
        var canonical = ManifestCanonicalizer.Canonicalize(input);

        Assert.Equal("{\"a\":\"\\n/é\",\"b\":true,\"z\":1}", Encoding.UTF8.GetString(canonical));
        Assert.Throws<InvalidDataException>(() => ManifestCanonicalizer.Canonicalize(
            Encoding.UTF8.GetBytes("{\"n\":9007199254740992}")));
        Assert.Throws<InvalidDataException>(() => ManifestCanonicalizer.Canonicalize(
            Encoding.UTF8.GetBytes("{\"n\":1.0}")));
        Assert.Throws<InvalidDataException>(() => ManifestCanonicalizer.Canonicalize(
            Encoding.UTF8.GetBytes("\"\\uD800\"")));
        Assert.Throws<InvalidDataException>(() => ManifestCanonicalizer.Canonicalize(
            Encoding.UTF8.GetBytes("{\"\\uD800\":1}")));
    }

    [Fact]
    public void NoncanonicalAndDuplicatePropertyManifestsAreRejected()
    {
        var (envelope, root) = SignedManifestFor(TestManifest(), 1);
        var payload = Convert.FromBase64String(envelope.Signed);
        var noncanonical = new SignedManifest(Convert.ToBase64String([.. Encoding.UTF8.GetBytes(" "), .. payload]),
            envelope.Signatures);
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(noncanonical, root, Options, Now));

        var duplicateProperties = Encoding.UTF8.GetBytes("{\"a\":1,\"a\":1}");
        Assert.Throws<InvalidDataException>(() => ManifestCanonicalizer.Canonicalize(duplicateProperties));
    }

    [Fact]
    public void TamperingExpiryRollbackAndWrongPlatformAreRejected()
    {
        var (envelope, root) = SignedManifestFor(TestManifest(), 1);
        var tampered = envelope with
        {
            Signed = Convert.ToBase64String(ManifestCanonicalizer.Serialize(
            TestManifest() with { ClientVersion = "9.9.9" }))
        };
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(tampered, root, Options, Now));
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(envelope,
            root with { MinimumManifestVersion = 8 }, Options, Now));
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(envelope, root,
            Options with { Platform = "windows" }, Now));
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(envelope, root, Options, Now.AddDays(2)));
    }

    [Fact]
    public void InsufficientDistinctSignaturesAndUnsafeUrlAreRejected()
    {
        var (envelope, root) = SignedManifestFor(TestManifest(), 2);
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(
            envelope with { Signatures = [envelope.Signatures[0], envelope.Signatures[0]] },
            root, Options, Now));
        var unsafeManifest = TestManifest() with
        {
            Packages = [new UpdatePackage("client", "1.0.0", "../evil.tar.zst", 1,
                new string('a', 64), true, "tar.zst")]
        };
        var (unsafeEnvelope, unsafeRoot) = SignedManifestFor(unsafeManifest, 1);
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(unsafeEnvelope, unsafeRoot, Options, Now));
    }

    [Fact]
    public void TrustRootCannotCountOnePublicKeyUnderMultipleIdsTowardThreshold()
    {
        var (envelope, root) = SignedManifestFor(TestManifest(), 1);
        var originalSignature = envelope.Signatures[0];
        var aliasedRoot = root with
        {
            Threshold = 2,
            Keys = [root.Keys[0], root.Keys[0] with { KeyId = "release-alias" }]
        };
        var aliasedEnvelope = envelope with
        {
            Signatures = [originalSignature, originalSignature with { KeyId = "release-alias" }]
        };

        Assert.Throws<InvalidDataException>(() =>
            ManifestVerifier.Validate(aliasedEnvelope, aliasedRoot, Options, Now));
    }

    [Fact]
    public void SignedManifestAcceptsNapPackagesAndRejectsInvalidDependencyGraph()
    {
        var bytes = new byte[] { 1, 2, 3 };
        var dataPackage = new UpdatePackage("core", "1", "packages/core.nap", bytes.Length,
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant(), true, "nap")
        {
            ContentVersion = 1,
            Priority = 100,
            MountOrder = 1
        };
        var manifest = TestManifest() with { Packages = [TestManifest().Packages[0], dataPackage] };
        var (envelope, root) = SignedManifestFor(manifest, 1);
        Assert.Equal("core", ManifestVerifier.Validate(envelope, root, Options, Now).Packages[1].Id);

        var cyclic = dataPackage with { Dependencies = ["core"] };
        var cyclicManifest = manifest with { Packages = [manifest.Packages[0], cyclic] };
        var (cyclicEnvelope, cyclicRoot) = SignedManifestFor(cyclicManifest, 1);
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(cyclicEnvelope, cyclicRoot, Options, Now));

        var invalidFormat = dataPackage with { Format = "tar.zst" };
        var invalidManifest = manifest with { Packages = [manifest.Packages[0], invalidFormat] };
        var (invalidEnvelope, invalidRoot) = SignedManifestFor(invalidManifest, 1);
        Assert.Throws<InvalidDataException>(() => ManifestVerifier.Validate(invalidEnvelope, invalidRoot, Options, Now));
    }

    private static UpdateManifest TestManifest() => new(
        1, 7, "stable", "linux", "x64", "1.0.0", "1.0.0", 1,
        Now.AddHours(-1), Now.AddDays(1),
        [new UpdatePackage("client", "1.0.0", "artifacts/sha256/aa/file.tar.zst",
            100, new string('a', 64), true, "tar.zst")])
    {
        BuildId = "20260923.1",
        DataManifestId = "data-2026-09-22",
        Capabilities = ["client_version_hello_v1"]
    };

    private static (SignedManifest Envelope, TrustRoot Root) SignedManifestFor(UpdateManifest manifest, int threshold)
    {
        var payload = ManifestCanonicalizer.Serialize(manifest);
        var keys = new List<TrustedKey>();
        var signatures = new List<ManifestSignature>();
        for (var i = 0; i < 2; i++)
        {
            var privateKey = new Ed25519PrivateKeyParameters(
                Enumerable.Repeat((byte)(i + 1), 32).ToArray(), 0);
            keys.Add(new TrustedKey($"release-{i}", "Ed25519",
                Convert.ToBase64String(privateKey.GeneratePublicKey().GetEncoded())));
            var signer = new Ed25519Signer();
            signer.Init(true, privateKey);
            signer.BlockUpdate(payload, 0, payload.Length);
            signatures.Add(new ManifestSignature($"release-{i}", "Ed25519",
                Convert.ToBase64String(signer.GenerateSignature())));
        }
        return (new SignedManifest(Convert.ToBase64String(payload), signatures),
            new TrustRoot(1, threshold, keys, 1));
    }
}
