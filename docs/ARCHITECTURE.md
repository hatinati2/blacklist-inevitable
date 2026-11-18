# Architecture

## Target shape

```text
React UI
  │ Tauri commands/events
  ▼
Rust application services
  ├── Profile service (import, normalize, validate, redact)
  ├── Engine supervisor (process ownership, health, shutdown)
  ├── Preflight coordinator (isolated per-node probes)
  ├── Connection coordinator (exclusive real-connection lifecycle)
  └── Platform boundary (Windows proxy/TUN integration; disabled during preflight)
        │
        ├── sing-box adapter
        ├── Xray-core adapter
        └── Mihomo adapter
```

The current code implements only the desktop shell, a status command, and engine target metadata. The boxes above are the intended separation of responsibilities, not claims of completed functionality.

## Engine adapters

Each adapter must declare its capabilities explicitly. Protocols, transport settings, DNS behavior, routing features, and configuration semantics are not assumed to be interchangeable across engines. Unsupported configuration must produce a clear validation error; it must never be silently dropped during conversion.

Engine binaries will be selected and version-pinned deliberately. Redistribution, notices, and license obligations must be reviewed before any binary is bundled.

## Preflight isolation invariant

Preflight and normal connection are separate runtime modes with separate coordinators:

- Preflight may create temporary loopback listeners and child processes for node probes.
- Preflight must not enable TUN, alter system proxy settings, or capture device traffic.
- The supervisor owns every child process and records its process identity.
- Temporary files and listeners are removed on success, error, cancellation, and application shutdown.
- If process termination or cleanup cannot be verified, the application must refuse to start the normal connection and expose a recoverable error state.

## Connection lifecycle

The future connection coordinator will own a single explicit state machine. UI state is informational; Rust is the source of truth. Connect, disconnect, cancellation, and shutdown operations must be serialized so that a second start cannot race with cleanup from a prior run.

## Secrets and diagnostics

Profile credentials must not be written to ordinary logs. Persistent secret storage must use Windows-protected storage rather than plaintext application settings. Diagnostic output should redact passwords, UUIDs, tokens, private keys, and credential-bearing URLs.
