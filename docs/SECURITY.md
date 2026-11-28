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
- The preflight root and each per-run directory are created with a protected, explicit owner/DACL. Existing roots are accepted only when their effective owner and complete DACL match the expected descriptor; reparse-point directories and unexpected ACLs fail closed.
- Credential-bearing config files are created with `CREATE_NEW` and an explicit protected DACL in the same `CreateFileW` call. The handle's owner/DACL is verified before the first credential byte is written. A failed ACL check blocks config creation and engine startup.
- On Windows, the protected DACL grants full control only to the current user SID, LocalSystem, and Builtin Administrators; directory ACEs are inheritable by children. The DACL is protected from inheriting broad parent permissions. The same primitive uses owner-only POSIX directory/file modes on Unix test hosts.
- The normal request path asks the temporary child to stop and waits for its exit with a bounded timeout.
- Child processes use kill-on-drop, and a temporary-directory Drop guard attempts fallback file cleanup if the command future is dropped.

Current process supervision:

- Real Delay, explicit config-validation, engine installation, and installed-version status commands register operation leases with an application-scoped Rust supervisor.
- New supervised engine operations are rejected after shutdown begins.
- Tauri exit is deferred while active Real Delay operations cancel their HTTP probe, stop and wait for the sing-box child, and remove temporary probe files.
- Config validation remains bounded by a 15-second timeout. If process termination or config-file cleanup is uncertain, the in-memory runtime health flag is set to unsafe and later engine operations are blocked for the rest of that app session.
- Temporary config and probe-directory Drop guards make a final synchronous cleanup attempt.
- On Windows, during Tauri setup the desktop application itself joins the supervisor's Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, after initial Tauri/WebView helper processes are initialized but before the app event loop can dispatch engine commands. Those existing UI helpers remain outside the engine Job Object. Windows automatically associates later children created by a process in a Job Object with that Job Object unless breakaway is explicitly allowed/requested; this app does not enable breakaway. Engine commands remain `CREATE_SUSPENDED`; before resuming the initial thread, the supervisor verifies membership in this exact Job Object and explicitly assigns only if inheritance did not establish membership.
- If thread discovery, Job Object initialization, process assignment, or thread resume fails, engine work is blocked; the child is terminated and awaited before the operation returns. The child cannot run its own code before Job Object membership is established.
- Because the application itself is already in the Job Object before engine child creation, a child inherits membership at the instant it is created. Closing the app's final Job Object handle terminates inherited children even if the app crashes before its post-spawn verification call. If the application cannot be assigned to the Job Object (including unsupported outer-job constraints), cleanup health is marked unsafe and all engine operations remain blocked.
- If runtime cleanup becomes uncertain, the UI displays an explicit safety warning and disables engine installation, config validation, and Real Delay instead of presenting the engine as merely uninstalled.

Remaining requirements:

- Keep the Windows app-process Job Object inheritance and per-instance isolation regression tests enabled (issue #24).
- Verify child termination, listener release, and file cleanup on success, failure, timeout, user cancellation, graceful app shutdown, and app-level forced termination on Windows.
- Production engine operations start blocked and are enabled only after Tauri setup confirms that the application joined its kill-on-close Job Object. If attachment fails, keep runtime cleanup unhealthy and block every engine operation; do not fall back to an uncontained spawn.
- Complete real Windows 10/11 acceptance with a second standard-user SID: verify it cannot list/read the preflight root, per-run directories, or live config files while the app identity can. The hosted CI harness uses a second-user impersonated token and native file opens, but hosted CI and same-user unit tests do not replace device acceptance.
- Keep preflight isolated from all normal connection and device-routing state.

## Process supervision

Before normal connection functionality is implemented:

- Extend the current preflight supervisor into a connection-runtime owner for all engine process handles.
- Child processes must not be detached; shutdown and cancellation must await process exit.
- The application joins its kill-on-close Job Object before creating child processes; Windows child-process inheritance provides containment at creation. Engine children remain suspended until membership in this exact Job Object is verified and their initial thread is resumed.
- Connect, Disconnect, cancellation, crash recovery, and app shutdown must be serialized through one Rust-owned state machine.
- Uncertain cleanup must fail closed and block the next normal connection, including after an application restart.

## Secrets and diagnostics

- Redact passwords, tokens, UUIDs, private keys, and authentication headers.
- Never write credential-bearing JSON into ordinary application settings or logs.
- Profile secrets are currently stored through Windows Credential Manager.
- Engine configuration files contain credentials during preflight. Their parent directories and files now receive protected ACLs at creation, and the file ACL is verified before credentials are written. Cleanup remains necessary but is no longer the only protection while a probe is active. The real second-user SID denial test on supported Windows 10/11 remains a release acceptance requirement.
- Engine validation diagnostics are sanitized before being returned to the UI.

## Supply chain and third-party code

- The Windows AMD64 sing-box 1.14.4 archive is fetched from the official upstream GitHub release and checked against a pinned SHA-256 digest before extraction. The download and uncompressed executable are each limited to 128 MiB, and the executable's reported version is checked after extraction and whenever the app reports the engine as installed.
- The current download flow verifies the pinned archive digest; it does not perform a separate upstream signature-verification step.
- The sing-box executable is downloaded on demand and is not bundled in the app installer.
- A third-party notice is written beside the installed executable.
- Real Delay workers are detached from the invoking Tauri command so closing the invoking window or cancelling that command does not abort the worker before cleanup. The process-wide supervisor waits for graceful cleanup, while the Windows Job Object provides kill-on-close containment for assigned children.
- Complete license, notice, redistribution, signing, and release review remains a release gate.
- Never download or execute an engine binary merely because a profile references it.
