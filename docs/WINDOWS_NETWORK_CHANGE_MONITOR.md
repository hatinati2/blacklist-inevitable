# Windows route and IP-interface change monitor

## Status

`windows_network_change::NetworkChangeMonitor` is a read-only invalidation primitive. It does not modify routes, DNS, WFP, interfaces, or traffic and is not wired into Agent Connect. It tracks notifications for both IPv4 and IPv6 route and IP-interface changes.

## Registration and callback behavior

The monitor registers `NotifyRouteChange2(AF_UNSPEC, ...)` and `NotifyIpInterfaceChange(AF_UNSPEC, ...)`. Both registrations must succeed before a caller takes its initial `NetworkEpoch`. If either registration fails, any successful earlier registration is cancelled and monitor creation fails closed. Starting or stopping a monitor also advances the generation, so snapshots cannot be reused across a period when no notifications were being observed.

The callbacks are intentionally minimal: they do not allocate, acquire locks, retain or dereference OS-owned row pointers, or call cancellation APIs. Each callback only increments a process-wide atomic generation. If the 64-bit generation would wrap, the monitor becomes permanently invalid rather than permitting an ABA match.

A caller should:
1. Start and retain the monitor for the entire lifetime of any route-dependent operation.
2. Take a generation snapshot after registration succeeds.
3. Discover hardware interfaces and resolve every numeric VPN endpoint to the Windows-selected egress interface.
4. Re-check the generation immediately before a future WFP/route/DNS transaction; any mismatch requires re-discovery and re-resolution.
5. Explicitly call `shutdown` from a non-callback thread, and treat cancellation failure as an unsafe cleanup condition.

Microsoft documents that `AF_UNSPEC` registers for both IPv4 and IPv6, callbacks are serialized, and the row pointers are owned by the OS. It also documents that `CancelMibChangeNotify2` must not be called from the notification callback thread because that can deadlock:
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2

## Consistency and recovery boundary

The generation is a point-in-time invalidation token, not a lock on the Windows routing table. A route/interface change can occur after the final check and before a WFP commit. The future connection transaction must serialize route updates, endpoint resolution, WFP commit, DNS/engine startup, and generation validation; any notification during preparation must abort and roll back before permitting traffic.

Notifications do not persist across reboot. The Agent must re-register on startup, enumerate current interfaces/routes, reconcile its durable journal, and keep Connect disabled until state is trustworthy.
