using System.Globalization;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace LancerNexus.Updater;

public sealed record VerifiedTufMetadata(string Role, long Version, DateTime ExpiresAtUtc, JsonElement Signed);

/// <summary>Verifies signed top-level TUF metadata using keys delegated by the current trusted root.</summary>
public static class TufMetadataVerifier
{
    private const int MaximumMetadataBytes = 2 * 1024 * 1024;
    private const int MaximumSignatures = 64;

    /// <param name="minimumVersion">Inclusive lower bound. Callers retaining a version receipt must also compare the envelope digest when versions are equal.</param>
    public static VerifiedTufMetadata Verify(ReadOnlyMemory<byte> envelopeBytes, string role,
        IReadOnlyList<TrustedKey> trustedKeys, int threshold, long minimumVersion, DateTime updateStartedAtUtc,
        bool delegatedTargetsRole = false)
    {
        if (delegatedTargetsRole
                ? !TufDelegationVerifier.IsValidRoleName(role)
                : role is not ("timestamp" or "snapshot" or "targets"))
            throw new ArgumentException("TUF metadata role name is invalid or unsupported.", nameof(role));
        ArgumentNullException.ThrowIfNull(trustedKeys);
        if (envelopeBytes.Length is 0 or > MaximumMetadataBytes)
            throw new InvalidDataException("TUF metadata is empty or exceeds its size limit.");
        if (updateStartedAtUtc.Kind != DateTimeKind.Utc || minimumVersion < 0 || threshold < 1 ||
            threshold > trustedKeys.Count || trustedKeys.Count is < 1 or > MaximumSignatures)
            throw new ArgumentException("TUF metadata verification policy is invalid.");
        ValidateTrustedKeys(trustedKeys);

        try
        {
            using var document = JsonDocument.Parse(envelopeBytes);
            var envelope = document.RootElement;
            if (envelope.ValueKind != JsonValueKind.Object ||
                !envelope.TryGetProperty("signed", out var signed) || signed.ValueKind != JsonValueKind.Object ||
                !envelope.TryGetProperty("signatures", out var signaturesElement) ||
                signaturesElement.ValueKind != JsonValueKind.Array ||
                signaturesElement.GetArrayLength() is < 1 or > MaximumSignatures)
                throw new InvalidDataException("TUF metadata envelope is malformed.");

            if (!signed.TryGetProperty("_type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String ||
                typeElement.GetString() != (delegatedTargetsRole ? "targets" : role) ||
                !signed.TryGetProperty("spec_version", out var specElement) || specElement.ValueKind != JsonValueKind.String ||
                !IsSupportedSpecVersion(specElement.GetString()) ||
                !signed.TryGetProperty("version", out var versionElement) || !versionElement.TryGetInt64(out var version) ||
                version < 1 || version < minimumVersion ||
                !signed.TryGetProperty("expires", out var expiresElement) || expiresElement.ValueKind != JsonValueKind.String ||
                !DateTimeOffset.TryParseExact(expiresElement.GetString(), "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expires) ||
                expires.Offset != TimeSpan.Zero || expires.UtcDateTime <= updateStartedAtUtc)
                throw new InvalidDataException($"TUF {role} metadata type, version, specification or expiry is invalid.");

            var signatures = signaturesElement.EnumerateArray().Select(ReadSignature).ToArray();
            if (signatures.Select(signature => signature.KeyId).Distinct(StringComparer.Ordinal).Count() != signatures.Length)
                throw new InvalidDataException($"TUF {role} metadata contains duplicate signature key IDs.");
            var canonicalSigned = ManifestCanonicalizer.Canonicalize(JsonSerializer.SerializeToUtf8Bytes(signed));
            if (!VerifyThreshold(canonicalSigned, signatures, trustedKeys, threshold))
                throw new InvalidDataException($"TUF {role} metadata signature threshold was not met.");

            return new VerifiedTufMetadata(role, version, expires.UtcDateTime, signed.Clone());
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("TUF metadata JSON is invalid.", error);
        }
    }

    private static TufRootSignature ReadSignature(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty("keyid", out var keyId) || keyId.ValueKind != JsonValueKind.String ||
            !element.TryGetProperty("sig", out var signature) || signature.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("TUF metadata signature entry is malformed.");
        return new TufRootSignature(keyId.GetString()!, signature.GetString()!);
    }

    private static bool IsSupportedSpecVersion(string? value) => value is not null &&
        Version.TryParse(value, out var version) && version.Major == 1 && version.Minor == 0;

    private static void ValidateTrustedKeys(IReadOnlyList<TrustedKey> trustedKeys)
    {
        if (trustedKeys.Any(key => key is null || key.Algorithm != "Ed25519" || key.KeyId is not { Length: 64 } ||
                !key.KeyId.All(Uri.IsHexDigit) || key.PublicKey is not { Length: 44 }) ||
            trustedKeys.Select(key => key.KeyId).Distinct(StringComparer.Ordinal).Count() != trustedKeys.Count)
            throw new InvalidDataException("TUF role trust keys are invalid.");
        var publicKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in trustedKeys)
        {
            byte[] bytes;
            try { bytes = Convert.FromBase64String(key.PublicKey); }
            catch (FormatException error) { throw new InvalidDataException("TUF role contains an invalid public key.", error); }
            var canonical = Convert.ToBase64String(bytes);
            if (bytes.Length != 32 || canonical != key.PublicKey || !publicKeys.Add(canonical))
                throw new InvalidDataException("TUF role contains a duplicate or invalid public key.");
        }
    }

    private static bool VerifyThreshold(byte[] payload, IReadOnlyList<TufRootSignature> signatures,
        IReadOnlyList<TrustedKey> trustedKeys, int threshold)
    {
        var trusted = trustedKeys.ToDictionary(key => key.KeyId, StringComparer.Ordinal);
        var verified = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signature in signatures)
        {
            if (!trusted.TryGetValue(signature.KeyId, out var key)) continue;
            byte[] signatureBytes;
            try { signatureBytes = Convert.FromHexString(signature.Value); }
            catch (FormatException) { continue; }
            if (signatureBytes.Length != 64) continue;
            var publicKey = Convert.FromBase64String(key.PublicKey);
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.BlockUpdate(payload, 0, payload.Length);
            if (verifier.VerifySignature(signatureBytes)) verified.Add(signature.KeyId);
        }
        return verified.Count >= threshold;
    }
}
