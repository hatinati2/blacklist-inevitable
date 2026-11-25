# Windows physical-egress interface inventory

## Status

The Rust module `windows_interfaces::discover_hardware_egress_interfaces` is a read-only inventory primitive. It is not wired into Agent Connect, does not install WFP filters, and does not change routes, DNS, adapter state, or traffic. Its output is not release acceptance for a physical-egress kill switch.

## Data source and ownership

The implementation calls Windows IP Helper `GetIfTable2`, reads the `MIB_IF_TABLE2` / `MIB_IF_ROW2` rows, and releases the allocated table with `FreeMibTable` through an RAII guard. It uses each row's stable `InterfaceLuid` and current `InterfaceIndex`; it does not infer adapter type from display names or descriptions.

Microsoft documents that GetIfTable2 enumerates logical and physical interfaces and that MIB_IF_ROW2 exposes `HardwareInterface`, `FilterInterface`, `ConnectorPresent`, and `EndPointInterface` flags:
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2
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

The candidate set is sorted by LUID, must have unique non-zero LUID/index pairs, and is rejected (never truncated) if it is empty or exceeds the policy's 32-interface bound. API errors and malformed results are fail-closed.

## Remaining security gates

- This is only a hardware-candidate inventory. Driver reporting, virtual-switch stacking, VLANs, bridge/team adapters, WWAN, Wi-Fi, USB tethering, and network compartment behavior still need a supported Windows 10/11 hardware matrix.
- Reconcile the inventory with routes and the actual WFP interface condition semantics before using it to install enforcement filters.
- Detect interface add/remove/rename/metric/route changes and re-evaluate policy before permitting traffic.
- Verify physical egress with packet captures across connected/disconnected adapters, IPv4/IPv6, VPN setup/teardown, crash/reboot, sleep/resume, and network changes.
- Keep Connect disabled. No production policy installation is connected to this module.
