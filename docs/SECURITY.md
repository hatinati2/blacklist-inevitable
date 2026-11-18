# Security requirements and current implementation

The application currently implements profile storage and isolated sing-box preflight probes. It does not yet implement a normal VPN connection, device-wide traffic routing, TUN, Wintun, packet capture, or Windows system-proxy integration.

## Profile credentials

- Store credentials separately from ordinary profile metadata.
- On Windows, use Windows Credential Manager through the keyring integration.
- Never log raw share links or credential-bearing configuration.
- Do not return passwords, UUIDs, or tokens to the React profile list.
- Keep only an allowlist of non-secret transport options in the profile index.
- Treat unsupported options explicitly; do not silently claim an imported link is fully supported by an engine.

The current profile store uses Windows Credential Manager for credentials and keeps secrets out of the profile-list response. The sing-box adapter retrieves credentials only when constructing a temporary configuration.

## Preflight isolation

Current implementation:

- The preflight sing-box SOCKS inbound binds to `127.0.0.1`.
- The request client connects through that local SOCKS proxy using remote DNS.
- The preflight path does not enable TUN / Wintun, packet interception, Windows system proxy settings, or device-wide traffic routing.
- Temporary probe configurations are created in unique per-run directories and removed in the normal cleanup path.
- The normal request path asks the temporary child to stop and waits for its exit with a bounded timeout.
- Child processes use kill-on-drop, and a temporary-directory Drop guard attempts fallback file cleanup if the command future is dropped.

Remaining requirements:

- Verify child termination, listener release, and file cleanup on success, failure, timeout, user cancellation, and application shutdown on Windows.
- Add an application-wide runtime health state so a future normal Connect is blocked whenever cleanup cannot be confirmed.
- Add explicit access-control hardening for credential-bearing temporary files where needed.
- Keep preflight isolated from all normal connection and device-routing state.

The current Drop fallback is not equivalent to an application-wide supervisor that confirms process exit after every cancellation or app-shutdown path.

## Process supervision

Before normal connection functionality is implemented:

- The Rust supervisor must own all engine process handles.
- Child processes must not be detached.
- Shutdown must have bounded graceful and forced termination phases.
- Process identity and exit status must be verified before declaring cleanup complete.
- Connect, Disconnect, cancellation, crash recovery, and app shutdown must be serialized through one Rust-owned state machine.
- Uncertain cleanup must fail closed and block the next normal connection.

## Secrets and diagnostics

- Redact passwords, tokens, UUIDs, private keys, and authentication headers.
- Never write credential-bearing JSON into ordinary application settings or logs.
- Profile secrets are currently stored through Windows Credential Manager.
- Engine configuration files contain credentials during preflight; they are temporary and removed by the probe cleanup path. Explicit per-file ACL hardening is not yet implemented.
- Engine validation diagnostics are sanitized before being returned to the UI.

## Supply chain and third-party code

- The Windows AMD64 sing-box 1.14.4 archive is fetched from the official upstream GitHub release and checked against a pinned SHA-256 digest before extraction. The download and uncompressed executable are each limited to 128 MiB, and the executable's reported version is checked after extraction and whenever the app reports the engine as installed.
- The current download flow verifies the pinned archive digest; it does not perform a separate upstream signature-verification step.
- The sing-box executable is downloaded on demand and is not bundled in the app installer.
- A third-party notice is written beside the installed executable.
- Real Delay workers are detached from the invoking Tauri command so closing the invoking window or cancelling that command does not abort the worker before its normal child-process and temporary-directory cleanup. A process-wide supervisor that confirms child termination during application shutdown remains a release requirement.
- Complete license, notice, redistribution, signing, and release review remains a release gate.
- Never download or execute an engine binary merely because a profile references it.
