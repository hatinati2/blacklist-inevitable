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

The current sing-box adapter maps a defined subset of VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, and a bounded subset of Naive HTTPS / QUIC options. Unknown source options are recorded by name during import and cause the adapter to reject the profile until those options are explicitly supported. A successful native config check proves only that sing-box accepts the generated configuration; it does not prove remote reachability or successful authentication.

The Windows AMD64 sing-box 1.14.4 archive is downloaded on demand and checked against a pinned SHA-256 digest before extraction. The installer stages and activates `sing-box.exe` and the required Naive `libcronet.dll` together in a versioned installation directory. The app also checks the executable's reported version. The executable is not bundled in the application installer. License and release review remains outstanding.

## Preflight isolation

The current preflight path uses a temporary engine process and a loopback SOCKS inbound bound to `127.0.0.1`. The HTTP client connects to that inbound using SOCKS5 remote DNS (`socks5h`) and sends the request through the selected sing-box outbound. The primary and fallback endpoints must return HTTP 204; redirects are not followed.

The current preflight path does not enable TUN, Wintun, packet capture, a Windows system proxy, or normal device traffic routing. The basic TCP endpoint diagnostic is a separate direct TCP connection and must never be labelled Real Delay.

The Real Delay implementation currently uses fixed endpoints and fixed timeouts. The UI does not yet provide a configurable test URL or timeout.

## Process ownership and remaining lifecycle work

Real Delay, explicit config validation, engine installation, and installed-version status probes acquire leases from an application-scoped process supervisor. The supervisor rejects new engine operations after shutdown starts, signals active Real Delay workers, and waits for registered operations to release their leases before the Tauri app exits. A Real Delay worker responds to shutdown by cancelling the proxied request, stopping its sing-box child, waiting for process exit, and removing its unique temporary directory. Config validation is bounded; a timeout or unconfirmed cleanup marks the in-memory runtime health state as unsafe.

Temporary config-validation files and probe directories also have synchronous Drop guards. A failed final cleanup marks the supervisor unhealthy, and further engine operations are rejected for the remainder of that app session. The app's `ExitRequested` event is deferred until supervised operations finish their cleanup path.

This is a graceful-shutdown supervisor for the currently implemented preflight operations, with Windows process containment for children after assignment. At startup the supervisor creates an app-owned Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; each sing-box child is assigned immediately after spawn. When the final job handle closes, Windows terminates processes still assigned to that job, including after an unexpected app exit. If job creation or child assignment fails, engine work fails closed; an uncontained child is killed and awaited, and runtime health is marked unsafe. Assignment occurs immediately after process creation rather than atomically with it, so a narrow pre-assignment crash window remains. Startup recovery for that edge case and app-level forced-termination tests remain release gates. The health gate is still in-memory. The application still has no normal Connect / Disconnect coordinator.

## Secrets and diagnostics

Profile credentials are stored separately from ordinary profile metadata using Windows Credential Manager through the keyring integration. Credentials are retrieved only when the engine adapter needs to create a temporary configuration. Engine diagnostics are redacted before they are returned to the UI. Temporary engine configuration contains credentials and must be removed after the probe.

## Future normal connection architecture

Normal connection must be added as a separate runtime mode, not by reusing the preflight proxy process. A future connection coordinator will own an explicit state machine for Connect, Disconnect, cancellation, crash recovery, and application shutdown. UI state is informational; Rust must remain the source of truth.

The normal connection path may add Windows TUN / proxy integration only after preflight lifecycle and cleanup are independently verified. If a prior process cannot be confirmed stopped, normal connection startup must fail closed.
