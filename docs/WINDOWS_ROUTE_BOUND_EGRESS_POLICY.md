# Route-bound Windows egress policy snapshot

## Status

`WindowsEgressSnapshot::capture` composes the read-only interface, route, and network-change primitives. It is a plan-building step only: it does not install WFP filters, change routes or DNS, mutate interface state, or start sing-box. It is not wired into normal Agent Connect.

## Capture sequence

1. Subscribe to IPv4/IPv6 route and IP-interface changes.
2. Record the current network generation.
3. Enumerate conservative physical-hardware candidates with stable NET_LUID and current index.
4. Resolve every numeric VPN endpoint independently using the Windows-selected best route.
5. Re-read the selected interface and require its fresh LUID/index and hardware flags to match the candidate inventory.
6. Compile a WFP intent plan that blocks all four ALE/OUTBOUND_TRANSPORT layers on every candidate physical interface, but permits each endpoint tuple only on the one interface selected for that endpoint.
7. Re-check the network generation; discard the entire snapshot if any observed change occurred during capture.

The snapshot retains the notification subscriptions. Its accessors call `ensure_current`; any route or interface notification invalidates the plan and requires complete rediscovery and re-resolution. The WFP install path accepts the snapshot and re-checks freshness after persisting stable filter intent, before opening the BFE transaction, and immediately before commit.

## Why exact endpoint-to-interface permits matter

An unbound policy that adds every VPN endpoint exception to every physical adapter is broader than the Windows route lookup. With two NICs, endpoint A may route through NIC 1 and endpoint B through NIC 2; the route-bound plan permits A only on NIC 1 and B only on NIC 2, while retaining block filters on both NICs. It rejects missing/duplicate endpoint bindings, unknown endpoints, and stale/mismatched LUID/index pairs.

## Windows acceptance coverage

The disposable Windows CI runner also exercises the compiled route-bound plan against live BFE with two synthetic physical-interface identities and separate IPv4/IPv6 endpoint bindings. The rollback-only test adds each filter, reads back its interface LUID, endpoint tuple, action and layer, deletes by key, then aborts without leaving packet policy installed. A second acceptance probe runs as the restricted Agent service SID: it commits the 12 route-bound filters using TEST-NET destinations and nonexistent interface identities, reloads the durable journal, removes the exact keys, confirms idempotent absence, and removes the journal. This validates the WFP and recovery path, not real packet routing or production network protection.

## Encrypted endpoint preparation

The Windows-only `WindowsEgressSnapshot::capture_for_server` entry point accepts a hostname, explicit non-zero port, and engine-derived TCP/UDP protocol. It performs numeric-address DoH bootstrap with no system-DNS fallback, maps each resolved A/AAAA address to the exact supplied transport tuple, and immediately captures current physical route bindings. The endpoint count is capped at the WFP policy limit. The API deliberately does not infer transport semantics from a profile label.

The initial DoH request occurs before snapshot capture and before any tunnel exists. A successful snapshot is preparation data only; it does not install policy, mutate routes/DNS, or authorize Connected state.

## Consistency boundary

The recovery journal now has an explicit `egressProtected` phase. The Agent may record that phase only after the route-bound WFP filter transaction commits, every exact filter identity is read back successfully, and the snapshot generation is still current. The connection state machine separately requires `InstallingEgressProtection` → `EgressProtected` before `StartingEngine`; an uncertain WFP commit/read-back or journal checkpoint must keep engine startup blocked.

This is a state/journal barrier, not the full Connect transaction. The current Agent IPC still rejects Connect and Disconnect. It does not configure routes or DNS, start sing-box, prove link-control exceptions, or establish a verified tunnel.

The epoch is a point-in-time invalidation guard, not a route lock. A route can still change after a final generation check and before or immediately after a WFP commit. The commit caller must retain the snapshot, treat invalidation as failed preparation, keep the engine stopped, and leave the durable WFP intent journal for exact recovery. A future connection state machine must serialize route/DNS/WFP/engine state and reconcile it on crash/reboot.

## Remaining security gates

- DNS bootstrap must resolve hostnames through an encrypted, pinned bootstrap path and produce the complete numeric endpoint set before capture.
- Network compartment and route-selection behavior must be tested on Windows 10/11 across Wi-Fi/Ethernet, multi-NIC, IPv4/IPv6, reconnect, sleep/resume, and VPN/tunnel adapter cases.
- Network-control, multicast/broadcast, local-discovery, and required system traffic still need an explicit policy.
- Run physical-adapter packet captures for all traffic classes and crash/reboot cases before release acceptance.
- Keep Connect disabled; this is not yet a complete kill switch.

## Engine-derived endpoint preparation

The profile-based preparation entry point builds the strict sing-box outbound config before deriving the remote TCP/UDP tuple set. It includes both protocols for Shadowsocks, uses the generated Naive QUIC setting, handles Hysteria2/TUIC as UDP, and treats VLESS/VMess/Trojan as TCP unless the emitted sing-box transport is QUIC. The DoH resolver maps each returned numeric address to all of those exact tuples in one bounded set, then resolves Windows routes. Unknown engine configuration shapes fail closed. This still produces only a route-bound plan; it does not install WFP policy or start the tunnel.
