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

Credential deletion failures are reported. If the OS credential store refuses deletion after the metadata write, the profile metadata is restored on a best-effort basis so the user can retry removal. If that restoration also fails, the UI reloads the durable profile list and reports that an orphaned credential may remain. Profile list writes and mutations are serialized by an application-wide lock.

## Preflight isolation

Current implementation:

- The preflight sing-box SOCKS inbound binds to `127.0.0.1`.
- The request client connects through that local SOCKS proxy using remote DNS.
- The preflight path does not enable TUN / Wintun, packet interception, Windows system proxy settings, or device-wide traffic routing.
- Temporary probe configurations are created in unique per-run directories and removed in the normal cleanup path.
- The normal request path asks the temporary child to stop and waits for its exit with a bounded timeout.
- Child processes use kill-on-drop, and a temporary-directory Drop guard attempts fallback file cleanup if the command future is dropped.

Current graceful-shutdown supervision:

- Real Delay, explicit config-validation, engine installation, and installed-version status commands register operation leases with an application-scoped Rust supervisor.
- New supervised engine operations are rejected after shutdown begins.
- Tauri exit is deferred while active Real Delay operations cancel their HTTP probe, stop and wait for the sing-box child, and remove temporary probe files.
- Config validation remains bounded by a 15-second timeout. If process termination or config-file cleanup is uncertain, the in-memory runtime health flag is set to unsafe and later engine operations are blocked for the rest of that app session.
- Temporary config and probe-directory Drop guards make a final synchronous cleanup attempt.

Remaining requirements:

- Verify child termination, listener release, and file cleanup on success, failure, timeout, user cancellation, graceful app shutdown, and forced termination on Windows.
- Add Windows Job Object ownership and startup recovery so stale child processes are handled after hard crashes or power loss.
- Add explicit access-control hardening for credential-bearing temporary files where needed.
- Keep preflight isolated from all normal connection and device-routing state.

## Process supervision

Before normal connection functionality is implemented:

- Extend the current preflight supervisor into a connection-runtime owner for all engine process handles.
- Child processes must not be detached; shutdown and cancellation must await process exit.
- Windows Job Object ownership and startup recovery must cover forced termination and hard crashes.
- Connect, Disconnect, cancellation, crash recovery, and app shutdown must be serialized through one Rust-owned state machine.
- Uncertain cleanup must fail closed and block the next normal connection, including after an application restart.

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
