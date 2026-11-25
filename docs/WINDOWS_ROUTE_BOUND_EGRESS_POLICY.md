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

## Consistency boundary

The epoch is a point-in-time invalidation guard, not a route lock. A route can still change after a final generation check and before or immediately after a WFP commit. The commit caller must retain the snapshot, treat invalidation as failed preparation, keep the engine stopped, and leave the durable WFP intent journal for exact recovery. A future connection state machine must serialize route/DNS/WFP/engine state and reconcile it on crash/reboot.

## Remaining security gates

- DNS bootstrap must resolve hostnames through an encrypted, pinned bootstrap path and produce the complete numeric endpoint set before capture.
- Network compartment and route-selection behavior must be tested on Windows 10/11 across Wi-Fi/Ethernet, multi-NIC, IPv4/IPv6, reconnect, sleep/resume, and VPN/tunnel adapter cases.
- Network-control, multicast/broadcast, local-discovery, and required system traffic still need an explicit policy.
- Run physical-adapter packet captures for all traffic classes and crash/reboot cases before release acceptance.
- Keep Connect disabled; this is not yet a complete kill switch.
