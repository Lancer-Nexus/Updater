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
- Do not require administrator privileges for per-user installations.
- Do not start the client when required data packages are missing or invalid.
- Keep logs useful but free of tokens, credentials and personal data.

## Verification

Test interrupted downloads, corrupted archives, expired manifests, invalid signatures, downgrade attempts, insufficient disk space, locked files, repair mode and failed client startup.
