# blacklist-inevitable

A Windows-first desktop app for importing proxy profiles and testing them before a future connection workflow. The current build implements **profile management and sing-box preflight testing**; it is not yet a traffic-routing VPN client.

## Current implementation

- Import one share link per line: VLESS, VMess Base64 JSON, Trojan, Shadowsocks SIP002, Hysteria2 / hy2, TUIC, and Naive HTTPS / QUIC.
- Keep profile metadata separate from credentials. On Windows, credentials are stored through Windows Credential Manager.
- Preserve the names of unknown source options without retaining their values. The sing-box adapter refuses profiles with options it cannot map instead of silently dropping settings.
- Download and install the pinned Windows AMD64 sing-box 1.14.4 release. The downloaded archive is checked against a pinned SHA-256 digest, the executable and required `libcronet.dll` are extracted together into a versioned installation directory, and the executable's reported version is checked.
- Generate an isolated sing-box outbound configuration for each supported profile and run the native `sing-box check`.
- Measure **Real Delay** by sending an HTTPS request through a temporary, loopback-only SOCKS5 proxy backed by that profile's sing-box outbound. The test accepts HTTP 204 only, disallows redirects, and uses a fallback 204 endpoint.
- Configure and persist the primary/fallback HTTPS probe URLs and request timeout in the application settings. The timeout is bounded to 2–30 seconds (9 seconds by default); endpoint URLs cannot contain embedded credentials or fragments.
- Keep the basic TCP endpoint check separate. It is only a TCP connection diagnostic and is not Real Delay.
- Supervise Real Delay and explicit config-validation operations; on graceful app exit, cancel active probes, stop and wait for their sing-box child process, and finish temporary-file cleanup before exiting.

Real Delay probe endpoints and request timeout can be changed in the UI and are saved in application data. Xray-core and Mihomo are target engines only; their adapters are not implemented yet.
On Windows, during Tauri setup the application joins its own Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, after the initial Tauri/WebView helper processes have been initialized but before the app event loop can dispatch engine commands. Those existing UI helpers remain outside the engine Job Object. Windows automatically gives later child processes membership in their parent's Job Object at process creation, so each engine child is already contained before it can run or before the app can crash. Engine children are still created with their initial thread suspended; the supervisor verifies membership in this specific Job Object (and assigns them while still suspended only as a fallback) before resuming the thread. Production engine work starts blocked and is enabled only after Tauri setup confirms that the app process joined the Job Object. If attachment, membership verification, or safe thread resume fails, engine work remains blocked and the child is terminated. This removes the create-to-assignment orphan window; a Windows integration test also checks that closing one app instance's Job Object does not terminate another instance's child. The runtime cleanup-health gate remains in-memory.

## Not implemented

- Normal Connect / Disconnect and device traffic routing.
- TUN, Wintun, packet capture, or Windows system-proxy integration.
- Privileged Windows VPN agent/service and authenticated local IPC.
- Xray-core and Mihomo adapters.
- Mieru profiles (the upstream sing-box 1.14.4 adapter does not implement Mieru).
- Subscription URL, Clash YAML, sing-box JSON, or plugin-based Shadowsocks import.
- Android support.

The preflight code path does not enable TUN or change Windows system proxy settings. That is not a claim that normal VPN connection functionality exists.

## Windows build and verification

The GitHub Actions workflow on `main` runs Rust formatting checks, Rust tests, Rust compilation checks, the frontend build, and the Windows NSIS installer build. The CI workflow also performs a silent install, launches the app and checks that its process stays alive, then silently uninstalls it on an ephemeral GitHub Windows runner. This catches basic packaging and lifecycle failures, but does **not** replace upgrade testing, clean-machine verification on a user-controlled Windows device, or network smoke tests.

- [Windows build workflow](https://github.com/hatinati2/blacklist-inevitable/actions/workflows/windows.yml)
- [Repository](https://github.com/hatinati2/blacklist-inevitable)

For local development, install Node.js 22, Rust stable with the MSVC target, Microsoft C++ Build Tools, and WebView2 Runtime:

```powershell
npm install
npm run tauri -- dev
```

Build the Windows installer:

```powershell
npm run tauri -- build
```

## Repository map

- `src/` — React / TypeScript desktop UI
- `src-tauri/` — Rust application, profile store, and engine adapters
- `docs/ARCHITECTURE.md` — architecture and runtime boundaries
- `docs/PROFILE_IMPORT.md` — import, credential, and test behavior
- `docs/REAL_DELAY_SPEC.md` — Real Delay semantics and remaining acceptance requirements
- `docs/ROADMAP.md` — staged delivery and release gates
- `docs/REFERENCE_CLIENTS.md` — lessons and license boundaries from Karing, v2rayN, v2rayNG, and Hiddify
- `docs/SECURITY.md` — security invariants and current limitations

## Third-party engine

sing-box is downloaded from its upstream release rather than bundled in this repository. The app writes a third-party notice beside the installed executable. The upstream project is licensed under GPL-3.0-or-later and has additional naming / association language; a complete license, notice, redistribution, and release review remains a Windows release gate. The current installer does not bundle the sing-box executable.
