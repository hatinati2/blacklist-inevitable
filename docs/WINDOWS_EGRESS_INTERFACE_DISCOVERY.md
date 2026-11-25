# Windows physical-egress interface inventory

## Status

The Rust module `windows_interfaces::discover_hardware_egress_interfaces` is a read-only inventory primitive. It is not wired into Agent Connect, does not install WFP filters, and does not change routes, DNS, adapter state, or traffic. Its output is not release acceptance for a physical-egress kill switch.

## Data source and ownership

The implementation calls `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES)` to enumerate all NDIS interfaces as a caller-owned linked list. It uses a bounded, pointer-aligned buffer and validates each linked-list node is inside that buffer, rejects cycles, and retries a bounded number of times if the interface list changes during sizing. For each adapter LUID it calls `GetIfEntry2` to obtain the full `MIB_IF_ROW2` metadata. This avoids treating `MIB_IF_TABLE2.Table` as a packed Rust slice: Microsoft explicitly warns that padding may exist before the first row and between row entries.

Microsoft API references:
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
- https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_table2

## Conservative candidate rules

An interface is selected only when:
- `HardwareInterface` is set.
- `ConnectorPresent` is set.
- `FilterInterface` is clear.
- `EndPointInterface` is clear.
- The interface type is not software loopback, proprietary virtual, tunnel, L2 VLAN, L3 IPvlan, L3 IPXvlan, or MPLS tunnel.

The inventory deliberately does not require `OperStatusUp` or a connected media state. An unplugged or temporarily down physical adapter must still be represented so a later connection cannot bypass the policy merely because that adapter was disconnected during discovery.

The candidate set is sorted by LUID, must have unique non-zero LUID/index pairs, and is rejected (never truncated) if it is empty or exceeds the policy's 32-interface bound. API errors, invalid buffer bounds, linked-list cycles, and oversized inventories fail closed.

## Remaining security gates

- This is only a hardware-candidate inventory. Driver reporting, virtual-switch stacking, VLANs, bridge/team adapters, WWAN, Wi-Fi, USB tethering, and network compartment behavior still need a supported Windows 10/11 hardware matrix.
- Reconcile the inventory with routes and the actual WFP interface condition semantics before using it to install enforcement filters.
- Detect interface add/remove/rename/metric/route changes and re-evaluate policy before permitting traffic.
- Verify physical egress with packet captures across connected/disconnected adapters, IPv4/IPv6, VPN setup/teardown, crash/reboot, sleep/resume, and network changes.
- Keep Connect disabled. No production policy installation is connected to this module.
