# Security requirements

These requirements apply before implementing real network functionality.

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

## Credentials and logs

- Never log raw profile URLs or credential-bearing configuration.
- Redact passwords, tokens, UUIDs, private keys, and authentication headers.
- Do not store secrets in plaintext JSON settings.
- Review Windows-protected storage integration before adding persistent credentials.

## Supply chain

- Pin engine versions and verify downloaded binaries with published checksums/signatures where available.
- Review each engine's license and redistribution terms before bundling.
- Keep third-party notices and source links with release artifacts.
- Do not download or execute an engine binary merely because a profile references it.
