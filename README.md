# blacklist-inevitable

A Windows-first desktop app for importing proxy profiles and testing them before a future connection workflow. The current build implements **profile management and sing-box preflight testing**; it is not yet a traffic-routing VPN client.

## Current implementation

- Import one share link per line: VLESS, VMess Base64 JSON, Trojan, Shadowsocks SIP002, Hysteria2 / hy2, and TUIC.
- Keep profile metadata separate from credentials. On Windows, credentials are stored through Windows Credential Manager.
- Preserve the names of unknown source options without retaining their values. The sing-box adapter refuses profiles with options it cannot map instead of silently dropping settings.
- Download and install the pinned Windows AMD64 sing-box 1.14.4 release. The downloaded archive is checked against a pinned SHA-256 digest, the executable is extracted, and its reported version is checked.
- Generate an isolated sing-box outbound configuration for each supported profile and run the native `sing-box check`.
- Measure **Real Delay** by sending an HTTPS request through a temporary, loopback-only SOCKS5 proxy backed by that profile's sing-box outbound. The test accepts HTTP 204 only, disallows redirects, and uses a fallback 204 endpoint.
- Keep the basic TCP endpoint check separate. It is only a TCP connection diagnostic and is not Real Delay.

Real Delay is currently implemented with fixed probe endpoints and timeouts. Xray-core and Mihomo are target engines only; their adapters are not implemented yet.

## Not implemented

- Normal Connect / Disconnect and device traffic routing.
- TUN, Wintun, packet capture, or Windows system-proxy integration.
- Xray-core and Mihomo adapters.
- Subscription URL, Clash YAML, sing-box JSON, or plugin-based Shadowsocks import.
- Android support.

The preflight code path does not enable TUN or change Windows system proxy settings. That is not a claim that normal VPN connection functionality exists.

## Windows build and verification

The GitHub Actions workflow on `main` runs Rust formatting checks, Rust tests, Rust compilation checks, the frontend build, and the Windows NSIS installer build. A successful CI build confirms compilation and packaging on the GitHub Windows runner; it does **not** replace installation, upgrade, uninstall, or network smoke tests on a clean Windows machine.

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
- `docs/SECURITY.md` — security invariants and current limitations

## Third-party engine

sing-box is downloaded from its upstream release rather than bundled in this repository. The app writes a third-party notice beside the installed executable. The upstream project is licensed under GPL-3.0-or-later and has additional naming / association language; a complete license, notice, redistribution, and release review remains a Windows release gate. The current installer does not bundle the sing-box executable.
