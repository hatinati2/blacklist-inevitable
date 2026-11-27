# Windows DNS and traffic leak prevention

## Release priority

This document defines a release-blocking security requirement for the privileged Windows VPN Agent. The objective is to prevent unintended user-data egress over physical adapters, including DNS, when the tunnel is starting, connected, changing networks, failing, disconnecting, or recovering.

Do not advertise "zero leaks" as an absolute guarantee. A meaningful release claim must name the tested Windows builds, selected routing mode, allowed control-plane exceptions, threat model, and packet-capture evidence. Any intentional Direct route is an explicit egress exception, not a leak-free tunnel.

## Current protections in the generated TUN config

The current Rust TUN config generator sets:

- `auto_route: true` to direct default routes to the TUN.
- `strict_route: true` on Windows.
- `dns_mode: hijack` explicitly.
- No explicit `dns_address`, allowing sing-box 1.14.4 to derive TUN DNS addresses from the configured IPv4/IPv6 interface addresses and automatically route those addresses to the DNS module.
- A DoH resolver with a numeric server IP, TLS enabled and an explicit TLS server name. This avoids resolving the resolver hostname through the system DNS path.
- The DoH server detours through the selected VPN outbound in normal modes.
- `route.auto_detect_interface: true` to keep sing-box outbound connections on the physical default interface and avoid routing the VPN server connection back into the TUN.

These settings are configuration generation only. The application still has no implemented normal Connect/Disconnect path, TUN session, privileged route/DNS transaction, or live Windows packet verification.

Pinned sing-box 1.14.4 TUN documentation states that on Windows, `dns_mode: hijack` together with `strict_route` blocks port 53 traffic using interfaces other than the TUN. When `dns_address` is omitted, sing-box derives addresses from the first IPv4/IPv6 TUN addresses and automatically applies the DNS hijack action. If `dns_address` is explicitly configured, the configuration must add a matching `hijack-dns` route action:
- https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/inbound/tun.md

The pinned DNS-over-HTTPS server accepts a numeric server address and TLS server name; the HTTPS DNS transport must use the intended VPN detour:
- https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/dns/server/https.md

The route `auto_detect_interface` setting binds outbound connections to the default NIC to prevent routing loops under TUN:
- https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/route/index.md

## Important limitation: strict_route is not the Agent kill switch

The exact `sing-tun` revision used by sing-box 1.14.4 is `040db71fcd33196f1d15708b91eb61e9dc6ab8dd`, as pinned in the sing-box v1.14.4 `go.mod`:
- https://github.com/SagerNet/sing-box/blob/v1.14.4/go.mod

Its Windows TUN implementation opens a WFP dynamic session for strict routing. In DNS hijack mode, that implementation installs WFP blocks for remote port 53 on IPv4 and IPv6 connect layers, allows the TUN interface, and permits the sing-box process to establish its own outbound connections. The dynamic WFP session is closed when the TUN is closed. These strict-route filters are not a durable, Agent-owned block-all-user-traffic policy:
- https://github.com/SagerNet/sing-tun/blob/040db71fcd33196f1d15708b91eb61e9dc6ab8dd/tun_windows.go

Therefore:
- Keep `strict_route` and DNS hijack enabled; they are important protections.
- Do not claim that they alone block every protocol from using a physical adapter.
- Do not rely on sing-box's dynamic WFP session to protect traffic after the engine or Agent exits.
- Implement a separate Agent-owned fail-closed egress policy and verify its exact behavior on Windows.

## Required Agent-owned egress policy

The WFP backend now has a narrowly scoped cleanup primitive for persistent filters:
- It accepts only stable filter GUIDs recorded in the recovery journal.
- It verifies the persistent provider and sublayer through read-only BFE lookups; missing or mismatched namespace state is an error, never proof of cleanup.
- It looks up each exact journaled filter GUID directly and verifies provider, sublayer, layer, persistent flag, and live BFE filter ID before deletion. It does not enumerate or select unrelated filters.
- Inside one WFP transaction, it re-reads each exact GUID and re-verifies the complete ownership identity before deleting by GUID.
- After commit, it independently verifies every requested GUID is absent; after abort, it verifies the original live identities remain present.
- A key is treated as already absent only when the ownership namespace is verified and the exact GUID lookup returns the documented filter-not-found status. Legacy records without stable filter GUIDs are not deleted automatically.
- The operation does not remove the provider/sublayer and is not called by startup recovery, Connect, Disconnect or Recover.

This is a cleanup building block, not an active kill switch. No physical-egress filters are installed by this method during normal application operation, and it does not establish crash/reboot protection or packet-level leak prevention.

The Agent must own a WFP policy independently of sing-box's dynamic WFP session.

1. Resolve and pin the active VPN endpoint address set and exact transport ports before the tunnel. Preserve only the narrow physical route and WFP allow rule required for those endpoint connections.
2. Install and verify physical-interface egress protection before changing the default route. The policy must prevent user-data traffic from escaping the TUN while allowing only documented control-plane traffic such as the active VPN endpoint and narrowly scoped network-control protocols required to keep the link operational.
3. Record every WFP provider, sublayer, filter identity and prior state in the non-secret recovery journal before/after the corresponding mutation.
4. Keep protection active if sing-box fails to start, the TUN adapter does not appear, route/DNS setup fails, health checks fail, or cleanup is uncertain.
5. If sing-box crashes while the Agent is alive, the Agent must retain its own egress block until it has completed safe rollback or the user explicitly selects a documented disconnected state.
6. Define service-crash and system-restart behavior. A WFP dynamic session owned only by the Agent is not sufficient if its termination removes the protection. Use a tested persistent/recovery design so that a service crash or reboot cannot silently return user traffic to an unrestricted physical route.
7. Remove the block last, and only after engine exit, route/DNS restoration, TUN teardown and all owned WFP cleanup have been independently verified.
8. If the Agent cannot prove that a resource is owned or safely restorable, it must fail closed and provide a recovery action rather than deleting unknown filters or restoring guessed network settings.

Do not use a broad "block all" rule without carefully scoped exceptions for the VPN endpoint and essential link-control traffic. Preserve and test DHCP, ARP, IPv6 neighbor discovery and other required local control-plane behavior explicitly. Do not permit arbitrary DNS or application traffic as a workaround.

## DNS policy

### Session DNS
- Keep `dns_mode: hijack`, `strict_route: true`, and `auto_route: true` in the supported Windows TUN profile.
- Leave `dns_address` unset while relying on sing-box's derived TUN DNS addresses. If a later design supplies it explicitly, add and test the corresponding `hijack-dns` route action.
- Use a DoH server with a numeric bootstrap IP, TLS hostname validation and a selected VPN outbound detour.
- Do not add a plaintext DNS fallback server. If the encrypted resolver is unavailable, resolution fails; it must not silently fall back to a physical-interface resolver.
- Route ordinary UDP/TCP port 53 to the internal DNS handling path and verify that physical-interface port 53 is blocked for both address families.
- Explicitly decide whether DoT and DoQ are blocked or forced through the VPN. Test TCP/UDP 853 and common DoQ ports (including UDP 784 and 8853); port-53 hijacking does not cover these protocols.
- Generic DoH over TCP/QUIC 443 cannot reliably be identified by port alone. In Strict Privacy mode, all user application traffic must therefore use the VPN path; do not permit process-based or destination-based Direct exceptions that could move embedded DoH to a physical interface.
- Define behavior for Windows DNS Client, multihomed DNS, NRPT, Windows system DoH, browser DoH, cached answers, resolver cache flush, mDNS, LLMNR, NetBIOS name service and local discovery.
- Strict Privacy mode should disable or tightly constrain local discovery protocols where they expose device names or queries onto the local network. LAN use-cases may be exposed as an explicit, separately labelled exception.

### VPN endpoint bootstrap
A profile whose server is a hostname needs an address before TUN startup. The Agent must not use ordinary Windows system DNS as a silent fallback.

- Prefer a configured bootstrap resolver addressed by a numeric IP and authenticated with TLS/DoH SNI, or require a literal server IP.
- If bootstrap DoH is unavailable or certificate validation fails, abort Connect. Never downgrade to UDP/TCP port 53.
- Document that this initial encrypted bootstrap request is outside the not-yet-created tunnel and is visible to the chosen bootstrap resolver; the physical ISP should see only the encrypted connection to that resolver, not the DNS question.
- Once the tunnel is verified, all subsequent application DNS must use the in-tunnel encrypted resolver.
- The Agent must keep the VPN endpoint's physical route narrow and update it safely after network changes or endpoint re-resolution.

### DNS semantics by routing mode
- Full Tunnel / Strict Privacy: all user-data traffic, including application-embedded DoH, uses the VPN; DNS uses the encrypted in-tunnel resolver. No Direct application/destination exception is compatible with the strict guarantee.
- Rule mode: explicit Iranian/private Direct destinations are intentional physical egress exceptions. DNS transport itself must remain on the selected encrypted resolver/VPN path. If Strict Privacy is enabled, these Direct exceptions must be disabled or rejected.
- Per-app Direct/Exclude and DirectOnly: these modes intentionally permit physical egress and must never be labelled as no-leak modes. DNS must still use an encrypted resolver with no plaintext fallback; show which resolver path is used.
- If a user selects a policy that requires direct traffic, explain that it intentionally weakens the no-physical-egress guarantee.

## IPv4, IPv6 and other traffic

- Install and verify default routes for both IPv4 and IPv6 before reporting Connected.
- If the upstream node or path cannot carry IPv6, install a tested IPv6 block on physical adapters before connecting; never allow IPv6 to fall back directly.
- Keep the VPN endpoint's physical route outside the TUN to avoid recursion. No other external destination may be excluded from the tunnel in Strict Privacy mode.
- Route TCP, UDP, QUIC, ICMP/ICMPv6 and WebRTC/STUN through the selected policy. Test raw sockets and applications that bind to a physical interface.
- Explicitly decide how mDNS, LLMNR, NetBIOS, SSDP and other multicast/broadcast discovery protocols behave. Do not assume the ordinary default route catches local multicast.
- A deliberate Direct route is a product policy choice; it is not hidden or accidental. Strict Privacy mode must make incompatible split-tunnel and destination-bypass policies unavailable.

## Connect / Disconnect transaction ordering

1. Validate the profile and reject unsupported protocol options before network mutation.
2. Resolve the VPN endpoint using the encrypted bootstrap path; do not fall back to system DNS.
3. Create a session ID and persist the recovery journal.
4. Install Agent-owned WFP physical-egress protections and verify the filters.
5. Generate and validate the sing-box TUN config.
6. Start sing-box under Job Object containment and verify process identity.
7. Wait for the TUN interface to appear and verify its GUID, interface index, IPv4/IPv6 addresses and MTU.
8. Verify TUN DNS configuration and in-tunnel encrypted resolver reachability.
9. Apply recorded routes and any narrowly scoped endpoint route.
10. Verify IPv4/IPv6 default routes and the expected DNS path; run leak probes.
11. Show Connected only after all required checks pass.

On any failure, reverse only the mutations recorded by this session. Keep the egress block active until engine/TUN/network cleanup and state restoration have been verified. Disconnect is idempotent and removes the kill switch last.

## Windows packet-capture acceptance tests

Run on clean Windows 10 and Windows 11 machines. Capture simultaneously on every physical adapter and the TUN adapter. Automated assertions must identify interfaces, destination addresses, protocols and ports.

Cover:
- Connect bootstrap, tunnel start, steady state, reconnect, explicit disconnect and recovery.
- sing-box crash, Agent crash, forced Agent termination, service restart, application crash, Windows restart, sleep/resume, DHCP renew, Wi-Fi/Ethernet switch and VPN endpoint IP changes.
- IPv4 and IPv6 UDP/TCP port 53.
- DoT TCP/UDP 853 and DoQ UDP 784/853/8853.
- Windows DNS Client, multihomed DNS, NRPT, system DoH, browser DoH and custom DoH over TCP/QUIC 443.
- WebRTC/STUN, UDP/QUIC, TCP, ICMP/ICMPv6, multicast, mDNS, LLMNR, NetBIOS and SSDP.
- Full Tunnel, Rule, DirectOnly, Include Selected, Exclude Selected and Custom application policy, recording intentional physical egress separately from leakage.

Acceptance for Strict Privacy mode: no user-data packet exits a physical adapter except the narrow, documented VPN/bootstrap/link-control allowlist. The kill switch remains effective through engine failure and Agent restart. A failed or unconfirmed rollback keeps the block active and prevents Connected/reconnect.

CI config validation and installer smoke tests do not replace these packet-level Windows tests.
