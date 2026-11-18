# Roadmap

The scope is Windows first. Android work starts only after the Windows build has been installed and smoke-tested.

## M0 — Repository and desktop foundation

- [x] Initialize repository and document product constraints.
- [x] Add Tauri 2 + React + TypeScript shell.
- [x] Add Rust status command and engine target boundary.
- [x] Add Windows CI build workflow.
- [x] Confirm Windows installer build in GitHub Actions.

## M1 — Profiles and basic endpoint checks

- [x] Define a normalized profile model.
- [x] Import VLESS, VMess, Trojan, Shadowsocks SIP002, Hysteria2, and TUIC share links.
- [x] Keep credentials in Windows Credential Manager, separate from profile metadata.
- [x] Add local profile listing and removal.
- [x] Add bounded TCP endpoint checks for TCP-capable profiles.
- [ ] Add fixture coverage for real-world share-link variants and unsupported-option warnings.
- [ ] Test persistence and credential deletion on a clean Windows machine.

## M2 — First engine integration (sing-box)

- [ ] Pin a sing-box release after platform, feature, and license review.
- [ ] Add verified engine installation/update flow; never execute an unverified binary.
- [ ] Generate one isolated outbound config per imported node.
- [ ] Run the native `sing-box check` command and report valid/invalid plus actionable errors.
- [ ] Add a process supervisor with bounded logs and deterministic shutdown.
- [ ] Add **Real Delay**: HTTP(S) request through the selected node's temporary local proxy.
- [ ] Measure request round-trip time, not TCP connect time; keep TCP reachability as a separately labelled diagnostic.
- [ ] Add configurable test URL, timeout, bounded concurrency, and a fallback URL.
- [ ] Prove preflight never enables TUN or mutates Windows system proxy settings.
- [ ] Verify cleanup on success, failure, timeout, cancellation, and application shutdown.

## M3 — Multi-engine adapters

- [ ] Add Xray-core adapter and explicitly map supported capabilities.
- [ ] Add Mihomo adapter and explicitly map supported capabilities.
- [ ] Report unsupported configuration rather than silently dropping fields.
- [ ] Add UDP-aware probes for Hysteria2 and TUIC.

## M4 — Real connection lifecycle

- [ ] Add an explicit connect/disconnect state machine.
- [ ] Add Windows platform integration only for the normal connection path.
- [ ] Test repeated connect/disconnect, crashes, sleep/resume, and shutdown.
- [ ] Block normal connect if prior runtime cleanup is uncertain.

## M5 — Windows release gate

- [ ] Build NSIS installer on Windows CI.
- [ ] Test installation, upgrade, uninstall, and clean-machine startup.
- [ ] Run protocol-aware preflight tests against controlled test profiles.
- [ ] Run real connection smoke tests, including DNS and traffic routing.
- [ ] Review licenses, notices, signing, and release artifacts.
- [ ] Publish a Windows release only after all required gates pass.

## M6 — Android

Android planning and implementation start only after M5 is complete and the Windows release is verified.
