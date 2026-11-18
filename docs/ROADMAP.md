# Roadmap

Windows is the first platform. Android work starts only after the Windows release has been installed and smoke-tested on a clean machine.

## M0 — Repository and desktop foundation

- [x] Initialize repository and document product constraints.
- [x] Add Tauri 2 + React + TypeScript shell.
- [x] Add Rust status command and engine target boundary.
- [x] Add Windows CI build workflow.
- [x] Build a Windows NSIS installer in GitHub Actions.

## M1 — Profiles and basic endpoint checks

- [x] Define a normalized profile model.
- [x] Import VLESS, VMess, Trojan, Shadowsocks SIP002, Hysteria2, and TUIC share links.
- [x] Keep credentials in Windows Credential Manager, separate from profile metadata.
- [x] Add local profile listing and removal.
- [x] Add bounded TCP endpoint checks for TCP-capable profiles.
- [ ] Expand fixture coverage for real-world share-link variants and unsupported-option warnings.
- [ ] Test persistence and credential deletion on a clean Windows machine.

## M2 — First engine integration and preflight (sing-box)

- [x] Pin sing-box 1.14.4 for Windows AMD64 and verify the downloaded archive with a pinned SHA-256 digest.
- [x] Download, inspect, extract, and version-check the engine executable before installing it.
- [x] Generate an isolated outbound configuration for each profile supported by the adapter.
- [x] Run the native `sing-box check -c` validation before a delay probe.
- [x] Implement Real Delay as an HTTP(S) request through the selected node's temporary loopback SOCKS5 proxy; accept HTTP 204 only and disable redirects.
- [x] Add a primary and fallback 204 endpoint, bounded request timeouts, and a maximum of four concurrent engine processes.
- [x] Sort successful results by measured Real Delay and keep failures / unsupported profiles visible.
- [x] Keep TCP reachability as a separately labelled diagnostic.
- [x] Keep the current preflight code path free of TUN and Windows system-proxy changes.
- [ ] Add configurable probe URLs and timeout settings.
- [x] Add an application-scoped supervisor for Real Delay and config-validation operations; defer graceful app exit until registered operations finish cleanup.
- [x] Cancel active Real Delay workers on graceful app shutdown, stop and await their sing-box child process, and reject new engine work once shutdown begins.
- [x] Add an in-memory cleanup-health gate that blocks subsequent engine operations in the current app session when cleanup is uncertain.
- [x] Add Windows Job Object ownership with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; assign each engine child immediately after spawn so Windows terminates assigned processes when the app's final job handle closes.
- [x] Add a Windows unit test confirming that closing the final Job Object handle terminates an assigned child.
- [x] Surface an unhealthy runtime-cleanup state in the UI and disable engine actions while cleanup is uncertain.
- [x] Prevent engine code from executing before Windows Job Object verification by creating each engine child suspended, verifying membership, then resuming its sole initial thread.
- [x] Attach the desktop application itself to its kill-on-close Job Object during Tauri setup, after initial UI helpers are initialized but before engine commands can run, so later children inherit containment at process creation; fail closed if the app cannot join.
- [x] Add a Windows integration test for inherited child membership and per-instance Job Object isolation, closing the pre-assignment orphan window.
- [ ] Verify file cleanup, child-process exit, and listener release under success, failure, timeout, cancellation, graceful shutdown, and app-level forced termination on Windows.
- [ ] Run protocol-aware preflight tests against controlled VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC test servers.

## M3 — Multi-engine adapters

- [ ] Add Xray-core adapter and explicitly map supported capabilities.
- [ ] Add Mihomo adapter and explicitly map supported capabilities.
- [ ] Report unsupported configuration rather than silently dropping fields.
- [ ] Add cross-engine fixture tests so the same imported profile is only advertised as supported where its semantics are preserved.

## M4 — Normal connection lifecycle

- [ ] Add an explicit Rust-owned Connect / Disconnect state machine.
- [ ] Add Windows platform integration only for the normal connection path.
- [ ] Test repeated connect / disconnect, crashes, sleep / resume, and shutdown.
- [ ] Block normal Connect if prior runtime cleanup is uncertain.
- [ ] Verify DNS handling and traffic routing without leaking traffic outside the selected tunnel.

## M5 — Windows release gate

- [x] Build the Windows NSIS installer in CI and upload it as a workflow artifact.
- [ ] Install, upgrade, launch, and uninstall on a clean Windows machine.
- [ ] Run end-to-end preflight against controlled test profiles on Windows.
- [ ] Run real connection smoke tests after M4 is implemented, including DNS and traffic routing.
- [ ] Review licenses, third-party notices, signing, and release artifact integrity.
- [ ] Publish a Windows release only after all required gates pass.

## M6 — Android

Android planning and implementation start only after M5 is complete and the Windows release is verified.
