# Windows privileged VPN agent design

## Why a separate agent

The Tauri/React desktop process should remain a normal, unelevated user process. A normal VPN session needs Windows privileges to create a tunnel interface and manage routes, DNS, and firewall policy. The UI should request narrowly scoped operations from a small Windows agent rather than run the entire desktop application as Administrator.

This design is informed by Hiddify's documented Windows/Linux split between an unprivileged UI/core client and an elevated background service. It is an architectural reference only: no Hiddify source code, binary, protocol, name, or UI asset is copied.

## Proposed process boundary

Unelevated Tauri UI:
- Profile store and Credential Manager access in the current user context.
- Displays authoritative connection snapshots from the agent.
- Sends explicit Connect, Disconnect, and status requests.

Authenticated local IPC over a Windows named pipe.

Elevated Windows VPN Agent service:
- Validates caller identity and request schema.
- Owns the Rust connection state machine.
- Owns the sing-box process and its Job Object.
- Owns TUN, routes, DNS, and session firewall policy.
- Performs startup recovery and rollback.

Official pinned sing-box engine:
- Normal-session TUN inbound.
- Explicitly mapped profile outbound.
- DNS and routing rules.

The service boundary is a security boundary, not a second UI. The agent exposes a small fixed RPC surface; it must not accept arbitrary command lines, executable paths, arbitrary filesystem paths, or unrestricted engine JSON from the desktop process.

## Installation and elevation

- The main desktop UI must not require an Administrator manifest.
- Install, upgrade, repair, and uninstall of the agent are separate privileged operations with a visible UAC consent prompt.
- Use a small, signed service installer/bootstrapper and verify its version/hash before replacing an existing service.
- UAC denial or failure to install/start the agent leaves the app disconnected and reports a clear recoverable error.
- Agent upgrades must stop and drain the old engine session, preserve or safely recover network state, replace the agent atomically, and then start the new version.
- The agent is registered under a stable service identity and runs with only the Windows privileges required for its network operations. The final service account/token model must be validated on clean Windows 10/11 machines; do not guess at LocalSystem vs a dedicated service account without testing driver, interface, routing, and user-session requirements.

## Local IPC security

Prefer a Windows named pipe over an unauthenticated localhost TCP/gRPC port.

Required controls:
- A restrictive pipe DACL: the active interactive user SID, SYSTEM, and Administrators only, with no broad Users/Everyone access.
- Reject remote clients; bind the pipe to the local machine.
- Verify the connected client's token and user/session identity on every new connection.
- Use a per-install or per-user protected secret only as an additional authentication factor, not as a substitute for the pipe ACL and caller-token check.
- Apply message size limits, timeouts, request IDs, and strict serde/schema validation.
- Permit only explicit operations such as GetStatus, Connect(profile_id), Disconnect, GetDiagnostics, and narrowly scoped recovery. Never expose a generic process-spawn or shell command.
- Rate-limit repeated start/stop and failed authentication attempts.
- Redact secrets from agent logs and return sanitized error codes/details to the UI.

The agent must re-check authorization for each RPC, not just when a channel is first opened. It must not trust caller-supplied profile data or a profile ID without resolving and validating it against the current user's profile store/credential access policy.

## IPC framing and duplicate-request handling

The shared Rust Agent protocol defines a bounded byte-stream frame for the future named-pipe transport:

- Four-byte unsigned little-endian payload length followed by one UTF-8 JSON request.
- Payload length is checked before allocation and is limited to 128 KiB.
- The reader consumes exactly one header and one payload; malformed, truncated, oversized, or otherwise invalid messages fail closed.
- A per-authenticated-connection replay guard rejects request IDs already accepted on that connection. It retains at most 4,096 IDs and requires the listener to close the connection when the budget is exhausted rather than evicting old IDs.

The named-pipe listener must authenticate the peer before creating the guard and retain it until the connection closes. This guard is not a substitute for the pipe DACL, local-only pipe configuration, or Windows caller-token/session verification, and it does not persist across service restarts or separate connections. The actual named-pipe server/client, ACL provisioning, token checks, timeouts, and credential handoff are not implemented by the framing module.

## Credential handoff

Windows Credential Manager is scoped to a user. A privileged service running under another security identity cannot be assumed to read the desktop user's credentials directly.

Before implementation, choose and test one explicit handoff design:
1. The unelevated UI retrieves only the selected profile's credentials from Credential Manager and sends them through the authenticated named pipe for one Connect request; or
2. The agent runs under a compatible per-user elevated token and accesses that user's credential store itself.

For the first Windows MVP, prefer one-shot handoff over copying the desktop user's entire credential store to the service. The agent validates the request, holds secrets in memory only where possible, and writes credential-bearing sing-box configuration only into a unique temporary directory with a restrictive DACL. The config and directory must be deleted after Disconnect, failed startup, timeout, cancellation, service shutdown, or crash recovery. No raw share URL, password, UUID, token, or private key is written to ordinary logs or durable session state.

If service isolation requires a durable protected secret for IPC, store only the control secret in a service-owned directory with ACLs limited to the service identity and Administrators; never store profile credentials there.

## Agent-owned connection runtime

The agent is the sole owner of the normal-session state machine:
- Disconnected
- Preparing
- StartingEngine
- ConfiguringNetwork
- Connected
- Disconnecting
- Recovering
- Error (with cleanup health)

The agent owns:
- Long-lived sing-box child process and kill-on-close Job Object.
- TUN interface identity and handles.
- Routes and interface metrics created for this session.
- Per-interface DNS configuration and DNS policy.
- Firewall/kill-switch rules, if enabled.
- A durable, non-secret recovery journal describing the network resources owned by the session.

Use the official pinned sing-box 1.14.4 TUN inbound as the first implementation candidate; its inbound TUN documentation supports Windows. The pinned engine depends on `sing-tun`; at the exact sing-tun revision used by sing-box 1.14.4, architecture-specific Wintun DLL bytes are embedded into the Go binary with `go:embed` and loaded from memory through its memory-module loader. Do not ship a second independently downloaded `wintun.dll` beside the engine by default. However, creating a Wintun adapter still invokes the Wintun API and may install/manage its kernel driver; this is an elevated OS operation that must be tested on clean machines and through upgrade/uninstall. The implementation evidence is visible in [sing-box v1.14.4 go.mod](https://github.com/SagerNet/sing-box/blob/v1.14.4/go.mod), [sing-tun Wintun embed code](https://github.com/SagerNet/sing-tun/blob/040db71fcd33196f1d15708b91eb61e9dc6ab8dd/internal/wintun/dll_windows_amd64.go), and [sing-tun Windows adapter](https://github.com/SagerNet/sing-tun/blob/040db71fcd33196f1d15708b91eb61e9dc6ab8dd/tun_windows.go).

The first Windows tests must also verify how sing-box strict routing creates and releases its dynamic Windows Filtering Platform (WFP) filters/session, and that those filters are removed after normal disconnect, engine crash, agent crash, and system restart. TUN teardown and WFP resource cleanup must be included in the agent's recovery journal and release tests.

The initial config should explicitly evaluate and test:

- auto_route enabled to put the default route through the TUN.
- strict_route enabled on Windows to prevent DNS leak from ordinary multihomed DNS resolution; with dns_mode=hijack, sing-box documents that port 53 traffic leaving through non-TUN interfaces is blocked.
- dns_mode set explicitly to hijack rather than relying on a default.
- dns_address omitted initially unless a custom design is required; in 1.14.4, an unset value is derived from the TUN address list and automatically hijacked into the sing-box DNS module. If dns_address is explicitly set, the config must also add an explicit hijack-dns route action.
- route.auto_detect_interface or a tested route.default_interface selection to prevent the engine's own outbound and VPN-server connection from looping back into the TUN.
- A DNS module with explicit resolver servers and final resolver; any encrypted DNS server's detour and domain bootstrap must be verified so DNS resolution itself uses the intended tunnel route.

Do not copy a sample TUN address pair or MTU blindly. Choose addresses/MTU for this product, check for collisions with local routes, and test IPv4 and IPv6 routing separately. Use only the Wintun implementation already embedded by the pinned official sing-box build unless a documented compatibility failure demonstrates that another driver is required. Do not introduce a second engine or a second tunnel driver merely because another client bundles one.

These field semantics are taken from the official sing-box 1.14.4 TUN, DNS, DNS-server, route, and dial documentation.

## Connect transaction and rollback

Connect is a transaction with explicit checkpoints:

1. Authenticate the UI caller; validate profile ID and capability.
2. Resolve the selected profile and its credentials; reject unmapped protocol options.
3. Resolve all IP addresses for the VPN server and preserve the narrowest physical route needed to reach it outside the tunnel.
4. Create a unique session ID and write a non-secret recovery journal before network mutation.
5. Generate a TUN-mode sing-box config in a restrictive temporary directory.
6. Validate the config with the pinned engine.
7. Start the engine suspended; verify Job Object membership; resume only after containment is confirmed.
8. Wait for the TUN interface to appear and verify interface identity/address/MTU.
9. Apply routes and DNS in a recorded, reversible order.
10. Apply the agreed leak-prevention policy.
11. Run packet-level routing and DNS checks; transition to Connected only when all required checks succeed.

Every successful mutation is journaled with its exact resource identity and its previous state. If any later step fails, roll back in reverse order. Disconnect is idempotent. A failed rollback marks the runtime unhealthy and blocks subsequent Connect attempts.

Do not restore a guessed default DNS server or route. Restore only settings and resources created or changed by this session, using the recorded previous values and verifying restoration.

## Fail-closed DNS and traffic leak protection

Leak prevention is a release-blocking security requirement. The detailed threat model, routing-mode semantics, Agent-owned WFP kill-switch requirements, DNS bootstrap rules, and Windows packet-capture matrix are maintained in [WINDOWS_LEAK_PREVENTION.md](WINDOWS_LEAK_PREVENTION.md).

Important distinction: sing-box's Windows `strict_route` with `dns_mode: hijack` protects ordinary port-53 DNS from leaving non-TUN interfaces. It is not a complete all-protocol, Agent-owned kill switch. The pinned sing-tun Windows implementation uses a dynamic WFP session for its strict-route filters; the session is closed with the TUN. The Agent therefore needs an independent egress policy whose protection survives engine failure and whose service-crash/reboot behavior is explicitly tested.

Do not report Connected until the Agent-owned egress policy, IPv4/IPv6 routes, TUN DNS configuration, encrypted resolver and leak probes have all been verified. If rollback is uncertain, retain the physical-egress block and fail closed.

## DNS and traffic safety

- Treat DNS as part of the tunnel, not as an optional later feature.
- Use the exact Windows behavior of the pinned sing-box version's TUN inbound dns_mode, dns_address, auto_route, and strict_route fields; test IPv4 and IPv6 separately.
- Ensure the VPN server endpoint itself retains a physical route to avoid routing loops.
- Explicitly decide how IPv6 behaves when the selected node or DNS path does not support it.
- Do not show Connected before the intended routes and DNS path have been verified.
- A kill-switch must have explicit start/connect/disconnect/crash semantics. Never claim leak protection until packet captures demonstrate that traffic and DNS cannot escape through the physical adapter under the configured policy.

## Agent lifecycle and recovery policy

The first Windows MVP should use a conservative default:
- A deliberate user Disconnect restores all owned network settings and stops the engine.
- An orderly app exit requests Disconnect and waits for the agent to confirm cleanup.
- If the UI crashes or its authenticated heartbeat disappears, the agent detects the orphaned session and performs safe Disconnect/rollback. Keeping a tunnel alive after the UI exits can be introduced later as a separate explicit user option.
- If the agent or engine crashes, the next agent start reconciles the journal with actual process, interface, route, DNS, and firewall state before accepting Connect.
- On system restart, recovery is idempotent and must not trust a stale persisted Connected flag.
- If state ownership or restoration cannot be confirmed, keep the app disconnected, mark cleanup unhealthy, and provide a recovery action/diagnostic rather than silently overwriting user network settings.

## Verification matrix

The agent and normal VPN path are not ready for release until tests cover:
- Install, upgrade, repair, UAC denial, service start/stop, uninstall, and clean-machine ACLs.
- Named-pipe caller identity, unauthorized user denial, remote connection rejection, malformed/oversized messages, and replay attempts.
- Successful Connect/Disconnect, duplicate requests, cancellation during each setup checkpoint, and rollback after each injected failure.
- Engine crash, agent crash, UI crash, forced process termination, Windows restart, sleep/resume, network changes, and stale journal recovery.
- Route preservation for the VPN endpoint, IPv4/IPv6 traffic routing, DNS behavior, and physical-adapter packet captures.
- Credential redaction, temporary config DACLs, deterministic deletion, and no orphaned processes, listeners, routes, interfaces, or firewall rules.

CI installer smoke tests cannot replace these Windows networking and privilege-boundary tests.


## Mieru sidecar adapter (future Windows compatibility)

The official Mieru client supports Windows and documents a JSON client config plus a local SOCKS5 listener. It is a separate Go client/server implementation, not an outbound in upstream sing-box 1.14.4. If Mieru is added, prefer a separately supervised client binary rather than adopting a modified sing-box fork solely for this protocol.

A candidate flow is: the agent creates a unique restrictive-ACL Mieru JSON config with the user's credential material, sets the child's `MIERU_CONFIG_JSON_FILE` environment variable to that file, starts the Mieru client under its process supervisor, waits for its loopback SOCKS5 listener, and points the sing-box selected-session route at that local SOCKS5 outbound. Upstream `pkg/appctl/client.go` explicitly supports `MIERU_CONFIG_JSON_FILE` and `MIERU_CONFIG_FILE` to override the default user config path, which offers a concrete per-session isolation path. This must be validated for UDP ASSOCIATE as well as TCP, process shutdown and orphan recovery, and config-file persistence/cleanup. Do not use the default persistent Mieru user config for per-session secrets.

The official Mieru client guide describes JSON config fields for username/password, server IP/domain, TCP/UDP port bindings, MTU, multiplexing, handshake mode, SOCKS5 port, and start/stop/test CLI commands: https://github.com/enfein/mieru/blob/main/docs/client-install.md. The project is GPL-3.0: https://github.com/enfein/mieru/blob/main/LICENSE. This is a candidate integration, not implemented support or a claim that any arbitrary Mieru subscription URL is accepted.
