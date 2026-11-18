# blacklist-inevitable

A Windows-first, multi-engine proxy/VPN desktop client focused on safe server preflight testing and predictable connection lifecycle management.

> **Status: foundation only.** This repository currently contains the desktop shell and project scaffolding. It is not yet a working VPN client: profile parsing, engine process management, node probing, TUN/system-proxy integration, and traffic routing are not implemented.

## Product decisions

- **First platform:** Windows. Android work starts only after the Windows release has been built and smoke-tested.
- **Stack:** Tauri 2, React, TypeScript, and Rust.
- **Engine targets:** sing-box, Xray-core, and Mihomo, integrated incrementally behind explicit adapters.
- **Priority:** balanced — stability, useful features, and a straightforward interface.

## Non-negotiable preflight safety

The future **Test servers** operation has two mandatory, separate checks for every supported node:

1. **Config validation:** generate the selected engine's configuration and run that engine's native config checker (for the first engine, `sing-box check`). Invalid configurations must be rejected with a useful error before a delay measurement starts.
2. **Real delay:** launch a temporary, per-node engine process with a loopback-only local proxy, send a real HTTP(S) request through that node to a configurable 204 test URL, and measure the request round-trip time. A TCP handshake time is not a real-delay result.

Neither check may enable TUN, change the Windows system proxy, or route unrelated device traffic. The runner must own and stop every temporary child process and remove all temporary configuration files. If cleanup cannot be confirmed, normal connection startup must remain blocked until the runtime is reconciled.

The current TCP endpoint check is only a separate diagnostic. It is not config validation and it is not the promised Real Delay feature.

## Windows development

Install Node.js LTS, Rust stable with the MSVC target, Microsoft C++ Build Tools, and WebView2 Runtime.

```powershell
npm install
npm run tauri -- dev
```

Build the Windows installer:

```powershell
npm run tauri -- build
```

## Repository map

- `src/` — React/TypeScript desktop UI
- `src-tauri/` — Rust application shell and engine boundary
- `docs/ARCHITECTURE.md` — component boundaries and safety invariants
- `docs/ROADMAP.md` — staged delivery plan
- `docs/SECURITY.md` — security and cleanup requirements
- `.github/workflows/windows.yml` — Windows build pipeline

No third-party engine binaries are bundled at this stage. Their licenses and redistribution obligations must be reviewed before packaging them.
