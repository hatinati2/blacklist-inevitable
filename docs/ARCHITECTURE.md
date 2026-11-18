# Architecture

## Current implementation

The current Windows application contains these working code paths:

```text
React / TypeScript UI
  │ Tauri commands
  ▼
Rust application services
  ├── Profile import and normalization
  ├── Profile metadata store + Windows Credential Manager
  ├── TCP endpoint diagnostic (TCP-capable profiles only)
  ├── sing-box installer (pinned version + SHA-256 check)
  └── sing-box preflight
        ├── per-profile outbound config generation
        ├── native sing-box config validation
        ├── temporary loopback-only SOCKS inbound
        └── HTTPS 204 request through the selected outbound
```

Only the sing-box preflight adapter is implemented. Xray-core and Mihomo are planned adapters, not functional integrations.

## Engine adapter boundary

Each adapter must declare capabilities explicitly. Protocols, transport settings, DNS behavior, routing features, and configuration semantics are not assumed to be interchangeable across engines. Unsupported configuration must produce a clear error; it must never be silently dropped during conversion.

The current sing-box adapter maps a defined subset of VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC options. Unknown source options are recorded by name during import and cause the adapter to reject the profile until those options are explicitly supported. A successful native config check proves only that sing-box accepts the generated configuration; it does not prove remote reachability or successful authentication.

The Windows AMD64 sing-box 1.14.4 archive is downloaded on demand and checked against a pinned SHA-256 digest before extraction. The app also checks the executable's reported version. The executable is not bundled in the application installer. License and release review remains outstanding.

## Preflight isolation

The current preflight path uses a temporary engine process and a loopback SOCKS inbound bound to `127.0.0.1`. The HTTP client connects to that inbound using SOCKS5 remote DNS (`socks5h`) and sends the request through the selected sing-box outbound. The primary and fallback endpoints must return HTTP 204; redirects are not followed.

The current preflight path does not enable TUN, Wintun, packet capture, a Windows system proxy, or normal device traffic routing. The basic TCP endpoint diagnostic is a separate direct TCP connection and must never be labelled Real Delay.

The Real Delay implementation currently uses fixed endpoints and fixed timeouts. The UI does not yet provide a configurable test URL or timeout.

## Process ownership and remaining lifecycle work

The Real Delay function owns the temporary sing-box child process during the normal request path, requests termination, waits for exit with a bounded timeout, and removes the unique temporary directory. The child is configured with kill-on-drop, and a directory guard attempts synchronous file cleanup when the command future is dropped.

This is not yet a complete application-wide process supervisor. In particular, cancellation and app-shutdown paths do not yet have a shared runtime health state that proves child termination and blocks a future normal Connect. The application has no normal Connect / Disconnect coordinator yet. These are release-blocking requirements before implementing device-wide traffic routing.

## Secrets and diagnostics

Profile credentials are stored separately from ordinary profile metadata using Windows Credential Manager through the keyring integration. Credentials are retrieved only when the engine adapter needs to create a temporary configuration. Engine diagnostics are redacted before they are returned to the UI. Temporary engine configuration contains credentials and must be removed after the probe.

## Future normal connection architecture

Normal connection must be added as a separate runtime mode, not by reusing the preflight proxy process. A future connection coordinator will own an explicit state machine for Connect, Disconnect, cancellation, crash recovery, and application shutdown. UI state is informational; Rust must remain the source of truth.

The normal connection path may add Windows TUN / proxy integration only after preflight lifecycle and cleanup are independently verified. If a prior process cannot be confirmed stopped, normal connection startup must fail closed.
