using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using LancerNexus.Updater;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace LancerNexus.Updater.Tests;

public sealed class TufMetadataVerifierTests
{
    private static readonly DateTime Now = new(2026, 10, 10, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData("timestamp")]
    [InlineData("snapshot")]
    [InlineData("targets")]
    public void VerifiesRoleSignatureVersionAndExpiry(string role)
    {
        var signer = CreateSigner(0x41);
        var envelope = BuildMetadata(role, 2, signer);

        var verified = TufMetadataVerifier.Verify(envelope, role, [signer.TrustedKey], 1, 1, Now);

        Assert.Equal(role, verified.Role);
        Assert.Equal(2, verified.Version);
        Assert.Equal(Now.AddDays(2), verified.ExpiresAtUtc);
        Assert.Equal("metadata-test", verified.Signed.GetProperty("custom").GetString());
    }

    [Fact]
    public void RejectsWrongRoleExpiredMetadataAndMetadataRollback()
    {
        var signer = CreateSigner(0x42);
        var timestamp = BuildMetadata("timestamp", 2, signer);

        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(
            timestamp, "snapshot", [signer.TrustedKey], 1, 1, Now));
        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(
            BuildMetadata("timestamp", 2, signer, Now), "timestamp", [signer.TrustedKey], 1, 1, Now));
        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(
            BuildMetadata("timestamp", 2, signer), "timestamp", [signer.TrustedKey], 1, 3, Now));
        Assert.Equal(2, TufMetadataVerifier.Verify(BuildMetadata("timestamp", 2, signer),
            "timestamp", [signer.TrustedKey], 1, 2, Now).Version);
        Assert.Throws<ArgumentException>(() => TufMetadataVerifier.Verify(
            BuildMetadata("timestamp", 2, signer), "timestamp", [signer.TrustedKey], 1, 0,
            DateTime.SpecifyKind(Now, DateTimeKind.Local)));
    }

    [Fact]
    public void RejectsInvalidThresholdDuplicateSignaturesAndAliasedKeys()
    {
        var first = CreateSigner(0x43);
        var second = CreateSigner(0x44);
        var oneSignature = BuildMetadata("targets", 3, first);

        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(
            oneSignature, "targets", [first.TrustedKey, second.TrustedKey], 2, 0, Now));
        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(
            BuildMetadata("targets", 3, first, duplicateSignature: true), "targets", [first.TrustedKey], 1, 0, Now));
        Assert.Throws<InvalidDataException>(() => TufMetadataVerifier.Verify(
            oneSignature, "targets", [first.TrustedKey, first.TrustedKey with { KeyId = new string('0', 64) }], 1, 0, Now));
    }

    private static byte[] BuildMetadata(string role, long version, SignerFixture signer,
        DateTime? expires = null, bool duplicateSignature = false)
    {
        var signed = new JsonObject
        {
            ["_type"] = role,
            ["spec_version"] = "1.0.36",
            ["version"] = version,
            ["expires"] = (expires ?? Now.AddDays(2)).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["custom"] = "metadata-test"
        };
        var canonicalSigned = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
        var signature = new Ed25519Signer();
        signature.Init(true, signer.PrivateKey);
        signature.BlockUpdate(canonicalSigned, 0, canonicalSigned.Length);
        var signatureValue = Convert.ToHexString(signature.GenerateSignature()).ToLowerInvariant();
        var signatureObject = new JsonObject { ["keyid"] = signer.TrustedKey.KeyId, ["sig"] = signatureValue };
        var signatures = duplicateSignature
            ? new JsonArray(signatureObject.DeepClone(), signatureObject.DeepClone())
            : new JsonArray(signatureObject);
        return JsonSerializer.SerializeToUtf8Bytes(new JsonObject { ["signed"] = signed, ["signatures"] = signatures });
    }

    private static SignerFixture CreateSigner(byte seed)
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
}
