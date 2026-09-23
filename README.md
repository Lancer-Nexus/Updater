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

## Skeleton runtime

The .NET 10 console entry point loads an HTTPS manifest from `LANCER_NEXUS_MANIFEST_URL` (or its first argument), validates schema, channel, platform, architecture, expiry, package size/hash fields and rejects absolute/path-traversal package URLs. Artifact download, Ed25519/TUF signature verification, staging, atomic activation, rollback and client startup are deliberately the next implementation milestones; private release keys never belong here.
