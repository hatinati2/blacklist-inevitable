# Windows VPN endpoint route-to-interface resolution

## Status

The Rust module `windows_route::resolve_vpn_endpoint_egress` is read-only. It is not wired into Agent Connect, does not install WFP filters, and does not change routes, DNS, interface state, or traffic. It provides a point-in-time correlation between each numeric VPN endpoint and the physical adapter Windows currently selects for that destination.

## Resolution method

For each validated numeric IPv4 or IPv6 endpoint, the implementation calls IP Helper `GetBestInterfaceEx`, which returns the interface index with the best route to that destination for either address family. It then calls `GetIfEntry2` with that index to obtain the current `MIB_IF_ROW2` record and stable `NET_LUID`.

Microsoft API references:
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2

The route result is accepted only when the fresh interface record still has hardware and connector flags, is not a filter or endpoint interface, is not a known logical interface type, and its exact LUID/index pair exists in the earlier physical-candidate inventory. Link-local IPv6 destinations are rejected because this numeric endpoint model does not carry the scope/interface ID required to disambiguate them. If the route resolves over a virtual/tunnel interface, the adapter index changes, or the route-selected interface is not in the inventory, the function fails closed. There is no name-based fallback.

The resolver validates that endpoint sets are non-empty, bounded, unique, and contain non-zero ports and unicast non-loopback destination IPs. It preserves the exact address/port/protocol tuple in each result.

## Consistency boundary

`GetBestInterfaceEx` returns the best interface at the instant of the lookup; this is not a route lock and does not make the subsequent WFP transaction atomic with Windows route changes. Re-run inventory and endpoint resolution after any route or interface notification and immediately before a future policy transaction. A route change after resolution must block or roll back Connect until the mapping is revalidated.

## Remaining security gates

- Implement and test route/interface change notifications with unregister-and-drain lifecycle; do not rely on a stale snapshot.
- Correlate DNS bootstrap results and all resolved VPN endpoint addresses before installing endpoint exceptions.
- Verify endpoint route behavior on Windows 10/11 across IPv4, IPv6, Wi-Fi/Ethernet, multiple NICs, disconnected adapters, VPN/tunnel adapters, and network compartment changes.
- Ensure policy installation, route/DNS state, and engine startup share one durable transaction and crash/reboot recovery journal.
- Keep Connect disabled. This resolver is a diagnostic/plan input only.
