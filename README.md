# blacklist-inevitable

A Windows-first, multi-engine proxy/VPN desktop client focused on safe server preflight testing and predictable connection lifecycle management.

> **Project status:** early foundation. The current repository is a development scaffold, not a working VPN client. Engine processes, profile parsing, server testing, and traffic routing are not implemented yet.

## Product direction

- **Platform:** Windows first. Android is explicitly out of scope until the Windows release is built and smoke-tested.
- **Architecture:** Tauri 2, React, TypeScript, and Rust.
- **Engine strategy:** adapter-based integration for sing-box, Xray-core, and Mihomo, added incrementally after compatibility and licensing review.
- **Priority:** balanced — stability, practical features, and straightforward UX.

## Core safety requirement

The future **Test servers** workflow must run independently of the real connection path. It must not enable TUN, alter the system proxy, or route normal device traffic. It should start only the minimum isolated engine process required for a probe, report per-node latency and errors, and always clean up its temporary resources. A cleanup failure must prevent a normal connection from starting until the state is reconciled.

## Development

Prerequisites for Windows development:

- Node.js LTS and npm
- Rust stable toolchain with the MSVC target
- Microsoft C++ Build Tools
- WebView2 Runtime

Commands:

```powershell
npm install
npm run tauri dev
```

Build a Windows installer:

```powershell
npm run tauri build
```

## Current scope

The initial foundation establishes the desktop shell, engine boundary, project documentation, and a Windows CI build workflow. It does not bundle engine binaries or implement real proxy/VPN functionality.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).
