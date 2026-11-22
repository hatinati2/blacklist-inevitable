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
- [x] Import VLESS, VMess, Trojan, Shadowsocks SIP002, Hysteria2, TUIC, and Naive HTTPS / QUIC share links.
- [x] Keep credentials in Windows Credential Manager, separate from profile metadata.
- [x] Add local profile listing and removal.
- [x] Add bounded TCP endpoint checks for TCP-capable profiles.
- [ ] Expand fixture coverage for real-world share-link variants and unsupported-option warnings.
- [ ] Test persistence and credential deletion on a clean Windows machine.

## M2 — First engine integration and preflight (sing-box)

- [x] Import Naive HTTPS / QUIC links, map the supported outbound fields, and install the required official Windows `libcronet.dll` beside sing-box.

- [x] Pin sing-box 1.14.4 for Windows AMD64 and verify the downloaded archive with a pinned SHA-256 digest.
- [x] Download, inspect, extract, and version-check the engine executable before installing it.
- [x] Generate an isolated outbound configuration for each profile supported by the adapter.
- [x] Run the native `sing-box check -c` validation before a delay probe.
- [x] Implement Real Delay as an HTTP(S) request through the selected node's temporary loopback SOCKS5 proxy; accept HTTP 204 only and disable redirects.
- [x] Add a primary and fallback 204 endpoint, bounded request timeouts, and a maximum of four concurrent engine processes.
- [x] Sort successful results by measured Real Delay and keep failures / unsupported profiles visible.
- [x] Keep TCP reachability as a separately labelled diagnostic.
- [x] Keep the current preflight code path free of TUN and Windows system-proxy changes.
- [x] Add configurable HTTPS probe URLs and bounded timeout settings (2–30 seconds).
- [x] Add an application-scoped supervisor for Real Delay and config-validation operations; defer graceful app exit until registered operations finish cleanup.
- [x] Cancel active Real Delay workers on graceful app shutdown, stop and await their sing-box child process, and reject new engine work once shutdown begins.
- [x] Add an in-memory cleanup-health gate that blocks subsequent engine operations in the current app session when cleanup is uncertain.
- [x] Add Windows Job Object ownership with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; attach the application during Tauri setup so engine children inherit containment at process creation, then verify membership while each child's initial thread is suspended.
- [x] Add a Windows unit test confirming that closing the final Job Object handle terminates an assigned child.
- [x] Surface an unhealthy runtime-cleanup state in the UI and disable engine actions while cleanup is uncertain.
- [x] Prevent engine code from executing before Windows Job Object verification by creating each engine child suspended, verifying membership, then resuming its sole initial thread.
- [x] Attach the desktop application itself to its kill-on-close Job Object during Tauri setup, after initial UI helpers are initialized but before engine commands can run, so later children inherit containment at process creation; fail closed if the app cannot join.
- [x] Add a Windows integration test for inherited child membership and per-instance Job Object isolation, closing the pre-assignment orphan window.
- [ ] Verify file cleanup, child-process exit, and listener release under success, failure, timeout, cancellation, graceful shutdown, and app-level forced termination on Windows.
- [ ] Run protocol-aware preflight tests against controlled VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, and Naive test servers.

## M3 — Multi-engine adapters

- [ ] Add Xray-core adapter and explicitly map supported capabilities.
- [ ] Add Mihomo adapter and explicitly map supported capabilities.
- [ ] Report unsupported configuration rather than silently dropping fields.
- [ ] Add cross-engine fixture tests so the same imported profile is only advertised as supported where its semantics are preserved.

## Windows protocol compatibility backlog

- [x] Add a bounded Naive HTTPS / QUIC share-link importer and sing-box outbound mapping for Windows.
- [ ] Evaluate Mieru profile/config import and sing-box mapping for the Windows release; do not assume a share-link URI format.
- [ ] Run controlled-server Naive authentication tests, including both HTTPS and QUIC modes, before claiming end-to-end protocol compatibility.
- [ ] For Mieru, verify upstream engine support, canonical config format, credential isolation, transport semantics, and controlled-server behavior before implementation.
- [ ] Keep unsupported fields visible by name and reject profiles that cannot be represented without semantic loss.

Naive import/config mapping is implemented for a bounded subset; remote authentication tests remain open. Mieru is a future Windows compatibility target and is not currently supported. Android and other OS work remains blocked until the Windows release gate is complete.

## M4 — Normal connection lifecycle

- [x] Add bounded length-prefixed Agent IPC, per-connection replay protection, a local-only Windows named-pipe listener with a protected DACL and caller SID/session checks, a read-only desktop status client, and fail-closed SCM PID plus installed-image-path verification before sending requests. A pinned production publisher thumbprint remains required before credential handoff.
- [x] Add a versioned, bounded, non-secret Windows Agent recovery journal with monotonic checkpoints; load it at service startup and fail closed on missing/unsafe/corrupt or unresolved state. Actual OS resource reconciliation and rollback remain open.
- [x] Add read-only OS recovery observers for process creation identity, TUN interface GUID and IPv4/IPv6 unicast addresses with prefix lengths, IPv4/IPv6 routes with stable NET_LUID, and complete persistent WFP provider/sublayer filter inventory. These probes do not yet perform reconciliation or rollback.
- [ ] Add a faithful dual-stack/profile-aware DNS journal model and read-only observer, including per-stack name servers, profile name servers, adapter suffix/search settings, supplemental search lists, and DNS-over-HTTPS server properties; keep recovery Unknown when Windows returns unsupported or incomplete settings.
- [ ] Add an explicit Rust-owned Connect / Disconnect state machine.
- [ ] Add Windows platform integration only for the normal connection path.
- [x] Install a narrowly scoped LocalSystem Agent service through the per-machine signed-package lifecycle, with matching Authenticode signer checks and protected service data ACLs.
- [x] Verify the connected named-pipe server PID against the running Service Control Manager Agent PID and require its executable image to resolve to the installed Agent beside the desktop app before sending requests.
- [ ] Add authenticated one-shot profile/credential handoff over IPC only after the server identity gate above is independently validated on supported Windows versions.
- [x] Define destination-based Global and Rule routing; generate Iran-aware Direct rules from geosite-ir/geoip-ir, with foreign traffic using the VPN outbound by default.
- [ ] Add a Rule/Global mode selector, rule-list management, protected rule-set cache/download, and user-editable domain/IP exceptions to the Windows UI and Agent.
- [x] Define Windows split-tunnel policy modes (Full Tunnel, Direct Only, Include Selected, Exclude Selected, and per-app Custom VPN/Direct/Block) and map them to sing-box process-path route rules.
- [ ] Add the split-tunnel policy editor and persistent settings in the Windows UI; enforce process-path matching and DNS behavior in the privileged agent.
- [x] Test signed install/start/status-query/uninstall and unsigned no-service behavior in Windows CI.
- [ ] Test upgrade, UAC denial, service crash/recovery, server identity verification, and UI-agent authorization on clean Windows 10/11 machines.
- [ ] Test repeated connect / disconnect, crashes, sleep / resume, and shutdown.
- [ ] Block normal Connect if prior runtime cleanup is uncertain.
- [ ] Verify DNS handling and traffic routing without leaking traffic outside the selected tunnel.
- [ ] Implement Agent-owned WFP physical-egress kill switch independent of sing-box's dynamic strict-route filters; retain protection across engine failure and define Agent-crash/reboot persistence and recovery.
- [ ] Implement encrypted VPN-endpoint DNS bootstrap with no system-DNS/plaintext fallback; keep in-session DoH on the VPN path.
- [ ] Add a Strict Privacy mode that forbids incompatible Direct destination and per-app bypass exceptions; clearly label other modes that intentionally permit physical egress.
- [ ] Verify IPv4/IPv6 routing, DNS/DoT/DoQ/DoH, local discovery and all non-tunnel egress with Windows 10/11 physical-adapter packet captures across connect/disconnect/crash/recovery/network-change cases.

## M5 — Windows release gate

- [x] Build the Windows NSIS installer in CI and upload it as a workflow artifact.
- [ ] Install, upgrade, launch, and uninstall on a clean Windows machine.
- [ ] Run end-to-end preflight against controlled test profiles on Windows.
- [ ] Run real connection smoke tests after M4 is implemented, including DNS and traffic routing.
- [ ] Review licenses, third-party notices, signing, and release artifact integrity.
- [ ] Publish a Windows release only after all required gates pass.

## M6 — Android

Android planning and implementation start only after M5 is complete and the Windows release is verified.
