# AGENTS.md – Lancer Nexus Updater

## Mission

Provide a secure and recoverable Windows/Linux bootstrapper for client and game-data updates.

## Rules

- Verify signed metadata before trusting any artifact URL.
- Verify size and SHA-256 before activation.
- Never overwrite the currently running client or updater.
- Use staging directories, atomic activation and rollback.
- Reject path traversal, unsafe archive entries and unexpected file types.
- Keep private signing keys out of the updater and repository.
- Keep the trusted root local to the bootstrapper and advance the persistent accepted-manifest version only after signature and policy verification.
- Use the pinned root threshold and BouncyCastle Ed25519 verification; release signing remains an offline or protected publishing operation.
- Accept only signed `tar.zst` package formats and use the pinned managed Zstandard decoder with strict TAR entry and expanded-size limits.
- Do not require administrator privileges for per-user installations.
- Do not start the client when required data packages are missing or invalid.
- Keep `--start-current` supervising the Client after UI-ready; exit code 42 refreshes signed metadata and permits restart only when runtime identity changes, with a bounded retry count. Exit code 43 permits one repair pass. Never infer these signals from console text.
- Keep logs useful but free of tokens, credentials and personal data.

## Verification

Test interrupted downloads, corrupted archives, expired manifests, invalid signatures, downgrade attempts, insufficient disk space, locked files, repair mode and failed client startup.
