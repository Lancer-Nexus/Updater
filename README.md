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

The downloaded JSON is `{"signed":"<base64 of exact UTF-8 manifest bytes>","signatures":[{"keyId":"release-1","algorithm":"Ed25519","value":"<base64 signature>"}]}`. Signatures cover the decoded `signed` bytes exactly. The local root has `schema`, `threshold`, `keys` (each with `keyId`, `algorithm`, `publicKey` as base64 raw 32-byte Ed25519 key) and `minimumManifestVersion`. Distinct trusted keys must meet the threshold. The signed manifest has a monotonic `version` in addition to the fields in the cluster plan; the root's minimum version is a rollback floor. Release tooling must raise that floor when a new trust root is provisioned.

The verifier checks signature threshold, schema, version floor, channel, platform, architecture, UTC issue/expiry, updater minimum version, required client package and package size/hash/relative URL fields before returning a manifest. The signed manifest also supplies `buildId`, `dataManifestId` and `capabilities`, which are required inputs for the client's `ClientVersionHello`; these values must not be inferred from local or unsigned configuration. After verification, `LANCER_NEXUS_METADATA_STATE` (default: a per-user `lancer-nexus/trusted-metadata-<channel>-<platform>-<architecture>.json` file) atomically records the highest accepted version and payload hash. Lower versions and different payloads reusing that version fail closed. Concurrent updater processes serialize access to this state.

Required artifacts are streamed from `LANCER_NEXUS_ARTIFACT_BASE_URL` (default: the manifest host at `/v1/`) with redirects disabled. Package URLs must stay under that configured HTTPS base. Each response is bounded by the signed size, hashed while streaming to a temporary cache file, and atomically renamed only after exact size and SHA-256 checks pass. `LANCER_NEXUS_PACKAGE_CACHE` selects the per-user cache directory. Existing hash-named cache entries are revalidated before reuse. The manifest must sign `format: "tar.zst"` for every package. BuildLL emits one-root-directory Zstandard-compressed TAR packages on Windows and Linux. The client stager uses a managed Zstandard decoder with bounded TAR extraction, rejects links, special files, traversal, duplicate paths and archives beyond 100,000 entries or 24 GiB expanded size, writes `client-version.json` from signed handshake fields, and verifies that the platform's `lancer` executable exists and is runnable. A verified client-only release is moved into `releases/`, and `current.json` is atomically replaced with the new release pointer and prior pointer target. On later starts the updater revalidates the downloaded package, checks the current pointer and local handshake metadata, then launches only the selected `lancer` executable directly without a shell. Required non-client packages fail closed before activation until their data placement is implemented. Automatic rollback after a failed process startup and startup health confirmation remain pending.

This is a TUF-inspired signed targets role with a pinned trust root. Full TUF root rotation and timestamp/snapshot roles remain pending. Client-only staging, activation and process start are implemented; automatic rollback after a failed startup/health check and installation of required data packages remain pending.

Run the verifier tests with `dotnet test Tests/Updater.Tests.csproj -c Release`.
