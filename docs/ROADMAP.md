# Roadmap

The scope is Windows first. Android remains out of scope until the Windows build and smoke-test gate has passed.

## M0 — Repository and desktop foundation

- [x] Initialize repository and document product constraints.
- [x] Add Tauri 2 + React + TypeScript shell.
- [x] Add Rust status command and engine target boundary.
- [x] Add Windows CI build workflow.
- [ ] Confirm CI build on GitHub Actions and fix any platform issues.

## M1 — Profiles and storage

- [ ] Define a normalized profile model and validation errors.
- [ ] Implement import for the first agreed profile formats.
- [ ] Add local profile list, editing, duplicate detection, and safe export.
- [ ] Redact secrets in logs and use protected storage where needed.

## M2 — First engine integration

- [ ] Select and pin the first engine version after compatibility review.
- [ ] Implement executable discovery and checksum/version verification.
- [ ] Implement configuration generation and engine-native validation.
- [ ] Add process supervision, bounded logs, and deterministic shutdown.

## M3 — Isolated server preflight

- [ ] Build a probe-only runtime with no TUN and no system-proxy mutation.
- [ ] Test every supported node with configurable timeout and concurrency.
- [ ] Return latency, reachability, and actionable failure details.
- [ ] Verify cleanup on success, timeout, crash, and user cancellation.
- [ ] Block normal connect whenever cleanup status is uncertain.

## M4 — Real connection lifecycle

- [ ] Add explicit connect/disconnect state machine.
- [ ] Add platform integration only for the normal connection path.
- [ ] Test repeated connect/disconnect, crashes, sleep/resume, and shutdown.
- [ ] Add safe recovery after interrupted sessions.

## M5 — Windows release gate

- [ ] Build NSIS installer on Windows CI.
- [ ] Test install, upgrade, uninstall, and clean-machine startup.
- [ ] Run preflight and connection smoke tests against controlled test profiles.
- [ ] Review licenses, notices, signing, and release artifacts.
- [ ] Publish a Windows release only after the above gates pass.

## M6 — Android

Android planning and implementation start only after M5 is completed and the Windows release is verified.
