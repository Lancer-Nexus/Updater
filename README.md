# Lancer Nexus Updater

The Updater is the cross-platform Windows/Linux bootstrapper for the Lancer Nexus Client.

## Responsibilities

- Check signed update manifests before starting the client
- Download and resume client and game-data packages
- Verify signatures, hashes, sizes and compatibility
- Install releases atomically with rollback support
- Repair missing or corrupted game data
- Keep the running client binary untouched during updates
- Start the correct client version after validation

The updater must remain independent from the game client so it can repair or replace a broken client installation.

## Current verification runtime

The .NET 10 console entry point loads an HTTPS manifest from `LANCER_NEXUS_MANIFEST_URL` (or its first argument). Redirects and responses over 2 MiB are rejected. `LANCER_NEXUS_TRUST_ROOT` names a local, trusted JSON file (default `trusted-root.json`) provisioned with the bootstrapper through a trusted channel. The updater never downloads this root from the manifest URL. Private release keys never belong here.

The downloaded JSON is `{"signed":"<base64 of RFC 8785 canonical UTF-8 manifest bytes>","signatures":[{"keyId":"release-1","algorithm":"Ed25519","value":"<base64 signature>"}]}`. Object properties use RFC 8785 ordering and string escaping; the current manifest schema permits safe integer numbers only. The Updater rejects noncanonical payloads, duplicate properties and numbers outside the interoperable integer range before signature verification. Signatures cover the canonical `signed` bytes. The local root has `schema`, `threshold`, `keys` (each with `keyId`, `algorithm`, `publicKey` as base64 raw 32-byte Ed25519 key) and `minimumManifestVersion`. Distinct trusted keys must meet the threshold. The signed manifest has a monotonic `version` in addition to the fields in the cluster plan; the root's minimum version is a rollback floor. Release tooling must raise that floor when a new trust root is provisioned.

Release tooling can canonicalize a prepared manifest before signing it:

```bash
dotnet Updater.dll canonicalize-manifest manifest.json manifest.canonical.json
```

Sign the exact bytes in `manifest.canonical.json`; then base64-encode those same bytes for the envelope's `signed` field.

The verifier checks signature threshold, schema, version floor, channel, platform, architecture, UTC issue/expiry, updater minimum version, required client package and package size/hash/relative URL fields before returning a manifest. The signed manifest also supplies `buildId`, `dataManifestId` and `capabilities`, which are required inputs for the client's `ClientVersionHello`; these values must not be inferred from local or unsigned configuration. After verification, `LANCER_NEXUS_METADATA_STATE` (default: a per-user `lancer-nexus/trusted-metadata-<channel>-<platform>-<architecture>.json` file) atomically records the highest accepted version and payload hash. Lower versions and different payloads reusing that version fail closed. Concurrent updater processes serialize access to this state.

Required artifacts are streamed from `LANCER_NEXUS_ARTIFACT_BASE_URL` (default: the manifest host at `/v1/`) with redirects disabled. Package URLs must stay under that configured HTTPS base. Downloads are bounded by the signed size and written to a digest-specific `.part` file. After interruption the next run requests the remaining byte range; the server's `Content-Range` and total size are checked, and the completed file is promoted only after its complete SHA-256 matches. A per-digest exclusive lock prevents concurrent updater processes from corrupting the same partial. Insufficient free space is rejected before network transfer; extraction and data-package staging check their target volumes as well. `LANCER_NEXUS_PACKAGE_CACHE` selects the per-user cache directory. Existing hash-named cache entries are revalidated before reuse. The signed client package uses `format: "tar.zst"`; signed game-data packages use `format: "nap"` and include a content version, mount priority/order, dependencies and overrides. Set `LANCER_NEXUS_OPTIONAL_PACKAGES` to a comma-separated list of optional package IDs; required packages, selected optional packages, and their dependency/override closure are activated together. The client stager uses a managed Zstandard decoder with bounded TAR extraction, rejects links, special files, traversal, duplicate paths and archives beyond 100,000 entries or 24 GiB expanded size, writes `client-version.json` from signed handshake fields, and verifies that the platform's `lancer` executable exists and is runnable. Required and selected NAP packages are copied into the same staged release, then listed in `packages/active.json`; before that snapshot is written, the Updater validates each archive's NAP V1 header, section bounds, index hash, canonical paths, chunk references, decompressed chunk hashes and complete file hashes, and matches the header content version to the signed manifest. An exclusive install-root `updater.lock` serializes updater processes for the same installation. Activation moves the complete client and data snapshot under `releases/` and atomically replaces `current.json`. On later starts the updater revalidates each active package's size and SHA-256 before directly launching the selected `lancer` executable without a shell. New releases declare startup-health protocol version 1 and the Client acknowledges after game data and its first UI state load; the Updater waits up to five minutes, kills an unacknowledged process, restores the previous healthy release pointer and records the failed package selection to prevent reactivation loops. A prior release without this protocol is trusted as the already-activated fallback and launched directly. Automated health-timeout tests cover process termination and previous-pointer restoration on Linux; the same native probe tests are configured for Windows CI, whose result and Windows game runtime are still pending. Abrupt child-process exits after the release move, after flushing the temporary pointer, and after atomically replacing the pointer are tested. A retry succeeds with the stale temporary file left by the interrupted write.

This is a TUF-inspired signed targets role with a pinned trust root. Full TUF root rotation and timestamp/snapshot roles remain pending. Signed client and data package staging, required and selected-optional dependency closure, NAP V1 structural/content validation, activation, health acknowledgement and one-generation rollback are implemented. Deterministic interrupted-download and insufficient-space tests pass; real disk-full behavior, activation-boundary process interruption, the Windows CI result and Windows game runtime remain unverified.

Run the verifier tests with `dotnet test Tests/Updater.Tests.csproj -c Release`.
