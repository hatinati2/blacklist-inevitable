# Windows TUN physical-DNS acceptance probe

This is a read-only observation helper for disposable Windows 10/11 test VMs. It helps answer one narrow question:

> While the generated sing-box TUN session is active, did the DNS configuration observed on the machine's physical adapters remain unchanged?

It does **not** prove absence of DNS leaks, does not create a complete DNS recovery snapshot, and does not authorize DNS restoration.

## Why this test is now practical

The project already generates a sing-box 1.14.4 TUN inbound with:

- `dns_mode: "hijack"`
- `auto_route: true`
- `strict_route: true`
- one IPv4 and one IPv6 TUN address
- a numeric-IP HTTPS DNS endpoint with explicit TLS server name and VPN detour

The config builder has a pinned-engine validation test in `src-tauri/src/engine/sing_box.rs`. That test validates the JSON schema/configuration, not runtime behavior.

The upstream `sing-tun` Windows implementation configures DNS by obtaining the LUID of the adapter it created and calling `SetDNS` on that LUID for IPv4 and IPv6. With a TUN adapter, this is the virtual adapter—not the user's Ethernet/Wi-Fi adapter. The same implementation installs dynamic WFP filters for remote TCP/UDP port 53 when `StrictRoute` and DNS hijack are enabled. Those filters are released with the TUN session and are not the Agent-owned, durable all-protocol kill switch.

References:

- [sing-box 1.14.4 TUN documentation](https://github.com/SagerNet/sing-box/blob/v1.14.4/docs/configuration/inbound/tun.md)
- [Pinned sing-tun Windows implementation](https://github.com/SagerNet/sing-tun/blob/040db71fcd33196f1d15708b91eb61e9dc6ab8dd/tun_windows.go)
- [Microsoft netsh dnsclient](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-dnsclient)

## How to run

Use a disposable Windows 10 or Windows 11 VM with a controlled test profile and a known-good snapshot/rollback point. Do not test by changing DNS on a daily-use machine.

1. Before starting the TUN session, record the baseline:

   ```powershell
   .\scripts\windows-tun-dns-observe.ps1 -Mode Snapshot -OutputPath "$env:TEMP\dns-before.json"
   ```

2. Start the generated TUN configuration in the controlled VM. Confirm that the virtual TUN adapter exists.

3. While the TUN session is active, compare the physical-adapter DNS configuration:

   ```powershell
   .\scripts\windows-tun-dns-observe.ps1 -Mode Compare -BaselinePath "$env:TEMP\dns-before.json" -OutputPath "$env:TEMP\dns-during.json" -RequireTunAdapter
   ```

4. Disconnect/stop the TUN in the disposable VM, then compare again without `-RequireTunAdapter`:

   ```powershell
   .\scripts\windows-tun-dns-observe.ps1 -Mode Compare -BaselinePath "$env:TEMP\dns-before.json" -OutputPath "$env:TEMP\dns-after.json"
   ```

For an offline comparison of two previously captured observations (also useful for reviewing evidence after leaving the VM), pass `-CurrentSnapshotPath`. This reads both JSON files and does not query or change DNS:

```powershell
.\scripts\windows-tun-dns-observe.ps1 -Mode Compare -BaselinePath "$env:TEMP\dns-before.json" -CurrentSnapshotPath "$env:TEMP\dns-during.json" -OutputPath "$env:TEMP\dns-review.json"
```

The helper uses `InterfaceGuid` to correlate physical adapters and does not use a potentially reused interface index as its identity. The index is used only to associate same-snapshot PowerShell observations with the adapter object.

## Result interpretation

- `PASS`: only the observed physical-adapter DNS server lists, selected per-interface DNS Client settings, read-only per-interface registry DoH evidence, and selected global DNS evidence were unchanged.
- `FAIL`: one or more observed physical-adapter/global DNS values changed.
- `UNKNOWN`: a required collector failed, physical-adapter identity or physical/virtual classification is incomplete, per-interface DNS settings are missing, an IPv4/IPv6 DNS-family record is absent, or the requested virtual TUN adapter could not be identified.

The JSON also records:

- adapter identity, hardware/virtual classification, and IPv4/IPv6 DNS server lists;
- selected per-interface DNS Client settings;
- global suffix-search settings, the system DoH known-server inventory, and NRPT rules where available;
- raw `netsh dnsclient dump`, `show global`, `show state`, and `show encryption` output as review-only evidence;
- per-interface registry `Doh` (IPv4) and `Doh6` (IPv6) subkeys and each value's registry type as read-only forensic evidence.

## Important limits

1. `Get-DnsClientDohServerAddress` is a system known-server inventory. It is not the per-adapter/per-profile DoH property arrays in `DNS_INTERFACE_SETTINGS3`.
2. `Get-DnsClientServerAddress` reports server-address lists; it is not a full previous-state snapshot. The DHCP-versus-static DNS source mode appears only in the raw `netsh dnsclient dump` evidence and is not automatically compared by this probe.
3. The `Doh`/`Doh6` registry paths are included as diagnostic evidence because community tooling uses them to configure DoH. Microsoft does not document these paths as a stable complete read/restore contract; registry values are never written or deleted by this helper, and their presence alone is not accepted as proof that a server is actively using DoH.
4. `netsh dnsclient dump` is retained as text only. It is not parsed as an authoritative schema, replayed, or accepted as a canonical restore file.
5. A physical adapter DNS configuration that remains unchanged does not prove that every DNS query stayed inside the tunnel. Validate with packet capture on both physical and TUN interfaces, including UDP/TCP 53, PTR, SVCB/HTTPS record types, IPv4 and IPv6, reconnect, engine exit, and network changes.
6. This probe does not test DoH/DoT application traffic, WFP crash behavior, full egress protection, or DNS profile restoration.
7. Do not share observation JSON without reviewing it; DNS server addresses, search suffixes, NRPT namespaces, and adapter metadata can disclose local network details.

A `PASS` from this probe is one piece of TUN architecture evidence only. It does not close DNS issue #87 and does not enable Connect, Disconnect, Recover, DNS restore, or journal deletion.
