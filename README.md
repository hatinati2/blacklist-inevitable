# blacklist-inevitable

A Windows-first, multi-engine proxy/VPN desktop client focused on safe server preflight testing and predictable connection lifecycle management.

> **Status: foundation only.** This repository currently contains the desktop shell and project scaffolding. It is not yet a working VPN client: profile parsing, engine process management, node probing, TUN/system-proxy integration, and traffic routing are not implemented.

## Product decisions

- **First platform:** Windows. Android work starts only after the Windows release has been built and smoke-tested.
- **Stack:** Tauri 2, React, TypeScript, and Rust.
- **Engine targets:** sing-box, Xray-core, and Mihomo, integrated incrementally behind explicit adapters.
- **Priority:** balanced — stability, useful features, and a straightforward interface.

## Non-negotiable preflight safety

The future **Test servers** operation must be isolated from the real connection path. It must not enable TUN, change the Windows system proxy, or route ordinary device traffic. It must create temporary probe-only runtime state, test nodes independently, report latency and failure reasons, and clean up every child process and temporary resource. If cleanup cannot be confirmed, normal connection startup must remain blocked until the runtime is reconciled.

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
