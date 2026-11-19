# Windows VPN connection design

## Purpose and scope

This document defines the implementation boundary for the first real VPN release. Windows is the only target for this phase. Android and other operating systems must not be started until the Windows release gate is complete.

The current sing-box preflight implementation is not reused as the normal VPN session. Preflight remains an isolated profile-validation and Real Delay feature. The first operational VPN path will use the existing sing-box engine integration, subject to the release and licensing review.

## User-visible behavior

The Windows MVP must provide:
- Clear Disconnected / Connecting / Connected / Disconnecting / Error states.
- Connect and Disconnect actions for one selected supported profile.
- A truthful indication of whether the tunnel and required routes/DNS configuration are active.
- A safe failure state if the tunnel cannot be established or cleanup cannot be confirmed.
- No success indication merely because the sing-box process started.

The initial release should prioritize a reliable full-device tunnel. Split tunneling and per-app routing are out of scope unless separately designed and tested.

## Rust-owned session state machine

The Rust backend is the sole authority for session state. The frontend displays snapshots and submits commands; it must not independently infer that a connection is active.

Proposed states:
1. Disconnected
2. Preparing — validate profile and credentials, check runtime health, prepare TUN/network resources.
3. StartingEngine — start the normal-mode engine process under process supervision.
4. ConfiguringNetwork — configure interface addresses, routes, DNS, and required firewall policy.
5. Connected — verify the tunnel is usable and the intended traffic path is active.
6. Disconnecting — stop accepting new session work, stop engine, restore network state, release resources.
7. Error — report a sanitized error and whether cleanup is confirmed.

Transitions must be serialized. Duplicate Connect requests, Disconnect during preparation, app shutdown during connection, and profile changes during a session must have explicit behavior. A new Connect is rejected while a previous session is active or cleanup is uncertain.

## Resource ownership and rollback

A single Rust connection coordinator owns:
- The engine child process and its Windows Job Object containment.
- The TUN adapter/interface handle.
- Routes and interface configuration created for this session.
- DNS configuration created for this session.
- Firewall rules or kill-switch state created for this session.
- A durable session/recovery record sufficient to identify resources after an app crash.

Every successful network mutation must have a corresponding recorded rollback action. Setup is transactional: if any later step fails, already-created resources are rolled back in reverse order. Disconnect is idempotent and must tolerate partially configured sessions.

Do not blindly restore a machine-wide setting to a guessed default. Record the previous state and restore only resources owned by this session. If restoration cannot be verified, mark runtime cleanup unhealthy, block another Connect, and provide recovery diagnostics.

## Privileged Windows agent

The UI must remain unelevated. The normal VPN session is planned to run through a narrowly scoped Windows background agent that owns the TUN interface, routes, DNS, firewall policy, and long-lived engine process. The agent communicates with the desktop app over authenticated local IPC (prefer a Windows named pipe with a restrictive DACL and caller-token verification). It must expose a fixed operation allowlist, not a generic shell/process-spawn interface.

The desktop process and service run under potentially different Windows security identities, so the agent must not assume it can directly read the user's Credential Manager. The preferred MVP design is a one-shot credential handoff over the authenticated IPC channel, with credentials held in memory and only temporary restrictive-ACL engine config files where required. Durable session recovery data must never contain profile secrets.

See [WINDOWS_AGENT_DESIGN.md](WINDOWS_AGENT_DESIGN.md) for the service boundary, credential handoff, authorization, transaction, recovery, and verification requirements.

## Windows tunnel and routing

The implementation must select and document a supported Windows TUN/Wintun integration before coding the production path. Evaluate maintenance status, redistribution/licensing, signing requirements, architecture support, and clean-machine installation behavior of the selected driver/runtime.

The normal connection path must:
- Create or open a dedicated tunnel interface.
- Assign interface addressing and MTU deliberately.
- Route intended device traffic through the tunnel.
- Preserve only minimum routes required to keep the VPN server reachable outside the tunnel.
- Avoid route loops and accidental loss of the control connection.
- Detect interface removal, engine exit, and route/DNS drift.
- Restore only network state owned by the session on disconnect or failure.

The preflight path must never create this interface or modify routes.

## DNS and leak prevention

DNS is part of the tunnel design, not a follow-up cosmetic feature.

Before declaring Connected, verify that:
- DNS requests use the configured resolver path through the tunnel.
- IPv4 and IPv6 behavior is explicit; unsupported paths must be disabled or handled rather than silently leaking.
- The system does not fall back to an unintended physical-interface resolver while the VPN claims to protect traffic.
- DNS configuration is restored on disconnect.
- Failure to enforce the expected DNS policy prevents a successful Connected state.

A kill-switch/firewall policy must be designed with explicit behavior for startup, connected, disconnecting, engine crash, and app crash. Do not claim leak protection until packet-level Windows tests verify it.

## Process lifecycle and crash recovery

Reuse existing application-owned Job Object containment as a foundation, but extend supervision from short preflight operations to a long-lived session process.

Required cases include:
- Normal Connect and Disconnect.
- Engine exits unexpectedly while connected.
- User requests Disconnect during startup.
- App exits while connected.
- Forced app termination or system restart.
- Sleep/resume and network-interface changes.
- Failure to stop the engine or restore routes/DNS.

On startup, detect stale session state and reconcile it with actual Windows interfaces, routes, DNS, firewall rules, and process state. Never trust a persisted Connected flag without verifying the machine's actual network state. Recovery must be idempotent and fail closed when ownership or restoration cannot be confirmed.

## Security and diagnostics

- Credentials remain in Windows Credential Manager and must not be copied into ordinary settings or logs.
- Engine configuration files are credential-bearing temporary resources with restrictive Windows ACLs and deterministic cleanup.
- UI diagnostics must redact passwords, UUIDs, tokens, private keys, and authentication headers.
- Engine downloads remain pinned and hash-verified; release signing and third-party license review remain required.
- No connection command may start an uncontained engine process.

## Verification gates

The Windows connection implementation is not complete until automated and manual tests cover:
1. Successful tunnel establishment and verified traffic through the selected profile.
2. Traffic cannot escape through the physical interface when the configured kill-switch policy is active.
3. DNS requests follow the intended tunnel resolver path for IPv4 and IPv6.
4. Failed authentication, unreachable server, invalid config, and engine crash.
5. Connect cancellation and repeated Connect/Disconnect.
6. App graceful exit, forced termination, and restart recovery.
7. Route/DNS restoration after normal disconnect and every injected failure.
8. Clean-machine installation, upgrade, uninstall, and driver/runtime lifecycle.

CI installer smoke tests alone are not sufficient evidence for these networking gates.

## Protocol and engine compatibility policy

The first Windows connection implementation should use the existing sing-box adapter and advertise only protocol/option combinations that are explicitly mapped and verified. Xray-core and Mihomo remain separate engine-adapter work; do not silently translate unsupported options.

NaiveProxy (naive) is now supported for a bounded subset of v2rayN-style HTTPS and QUIC share links and sing-box 1.14.4 outbound fields. This includes staging the required official Windows `libcronet.dll` beside the engine. Controlled-server authentication tests remain required before claiming full protocol compatibility. Mieru remains a future compatibility target: current Hiddify/Karing variants can rely on modified sing-box cores, so that is not proof that upstream sing-box 1.14.4 supports it. Verify canonical configuration format, credential fields, TLS/transport semantics, engine support, and licensing before implementation. Mieru may need configuration-file import rather than assuming a share URI. Preserve unknown fields by name and reject configurations whose semantics cannot be represented without loss.

## Out of scope for this phase

- Android, macOS, and Linux implementation.
- Split tunneling and per-application routing.
- Subscription and bulk remote configuration formats unless separately scoped.
- Claims of production leak protection before packet-level Windows verification.
