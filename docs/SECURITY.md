# Security requirements

These requirements apply before implementing real network functionality.

## Profile credentials

- Store credentials separately from ordinary profile metadata.
- On Windows, use Windows Credential Manager through the keyring integration.
- Never log raw share links or credential-bearing configuration.
- Do not return passwords, UUIDs, or tokens to the React profile list.
- Keep only an allowlist of non-secret transport options in the profile index.
- Treat unsupported options explicitly; do not silently claim an imported link is fully supported by an engine.

## Preflight mode

- Must not enable TUN or packet interception.
- Must not change Windows system proxy settings.
- Must not route unrelated device traffic.
- Must use temporary, scoped runtime configuration and loopback-only listeners where possible.
- Must stop every child process and remove temporary resources on every exit path.
- Must fail closed: uncertain cleanup blocks normal connection startup.

## Process supervision

- The Rust supervisor owns all engine process handles.
- Child processes must not be detached.
- Shutdown must have bounded graceful and forced termination phases.
- Process identity and exit status must be verified before declaring cleanup complete.

## Secrets and diagnostics

- Redact passwords, tokens, UUIDs, private keys, and authentication headers.
- Never write credential-bearing JSON into ordinary application settings or logs.
- Profile secrets are currently stored through the Windows Credential Manager.
- Engine configuration files containing credentials must be temporary, access-restricted, and removed after process exit.

## Supply chain

- Pin engine versions and verify downloaded binaries with published checksums/signatures where available.
- Review each engine's license and redistribution terms before bundling.
- Keep third-party notices and source links with release artifacts.
- Never download or execute an engine binary merely because a profile references it.
