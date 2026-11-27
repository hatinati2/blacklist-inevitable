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
- [Microsoft netsh interface (IPv4/IPv6 DNS source and show/dump commands)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)

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

- `PASS`: only the observed physical-adapter DNS server lists, selected per-interface DNS Client settings, read-only per-interface registry DoH evidence, per-family netsh DNS source tokens, per-family `Get-NetIPInterface` settings, IPv6 router-discovery/RDNSS policy flags, and selected global DNS evidence were unchanged.
- `FAIL`: one or more observed physical-adapter/global DNS values changed.
- `UNKNOWN`: a required collector failed, physical-adapter identity or physical/virtual classification is incomplete, per-interface DNS settings or source-mode statements are missing/ambiguous, a `Get-NetIPInterface` family row or required IPv6 RA/DHCP policy field is missing, an IPv4/IPv6 DNS-family record is absent or duplicated, or the requested virtual TUN adapter could not be identified.

Microsoft documents `ConnectionSpecificSuffixSearchList` on the `MSFT_DNSClient` WMI class and exposes the global `UseSuffixSearchList` switch alongside `SuffixSearchList`. The comparison therefore treats either property being unavailable as UNKNOWN rather than assuming the search list is fully represented:

- [MSFT_DNSClient](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/dnsclientcimprov/msft-dnsclient)
- [Get-DnsClientGlobalSetting](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientglobalsetting)
- [Get-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface)
- [MSFT_NetIPInterface AddressFamily values](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/nettcpipprov/msft-netipinterface)
- [netsh interface IPv6 policy settings](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)

The JSON also records:

- adapter identity, hardware/virtual classification, and IPv4/IPv6 DNS server lists; the native CIM family value is retained as `addressFamilyRaw` (`2` = IPv4, `23` = IPv6) while normalized labels are used for comparison;
- separate read-only IPv4 and IPv6 DNS source-mode statements parsed from `netsh interface ipv4 dump` and `netsh interface ipv6 dump`, correlated to the contemporaneous adapter alias and retained alongside raw dump output;
- selected per-interface DNS Client settings;
- per-family `Get-NetIPInterface` DHCP/router-discovery/managed-address/other-stateful properties. The native CIM `AddressFamily` value is normalized (`2` = IPv4, `23` = IPv6) while its raw value is preserved;
- IPv6 `routerdiscovery`, `managedaddress`, `otherstateful`, `rabaseddnsconfig`, and `dhcpstaticipcoexistence` configuration policy parsed from the read-only IPv6 interface dump;
- global suffix-search settings, the system DoH known-server inventory, and NRPT rules where available;
- raw `netsh dnsclient dump`, `show global`, `show state`, and `show encryption` output as review-only evidence;
- raw `netsh interface ipv4/ipv6 dump` output as review-only evidence; the helper parses only the `set dnsservers ... source=dhcp|static` token and never executes dump output;
- per-interface registry `Doh` (IPv4) and `Doh6` (IPv6) subkeys and each value's registry type as read-only forensic evidence.

## Important limits

1. `Get-DnsClientDohServerAddress` is a system known-server inventory. It is not the per-adapter/per-profile DoH property arrays in `DNS_INTERFACE_SETTINGS3`.
2. `Get-DnsClientServerAddress` reports server-address lists; it is not a full previous-state snapshot. The observer also parses the per-family `set dnsservers source=dhcp|static` record from read-only IPv4/IPv6 interface dumps. Missing, duplicate, or unrecognized statements remain UNKNOWN. A `dhcp` token is represented as `Automatic`, not as proof of the actual upstream resolver mechanism.
3. For IPv6, the source token is not sufficient to characterize dynamic DNS policy. The observer separately records `Get-NetIPInterface` family settings and the netsh IPv6 `RouterDiscovery`, `ManagedAddress`, `OtherStateful`, `RABasedDnsConfig`, and `DHCPStaticIPCoexistence` flags. These settings describe interface policy (including whether RA-based DNS or DHCPv6 stateful configuration is enabled); they do not prove which mechanism supplied each effective resolver address. Missing or unsupported values remain UNKNOWN.
3. The `Doh`/`Doh6` registry paths are included as diagnostic evidence because community tooling uses them to configure DoH. Microsoft does not document these paths as a stable complete read/restore contract; registry values are never written or deleted by this helper, and their presence alone is not accepted as proof that a server is actively using DoH.
4. `netsh dnsclient dump` is retained as text only. It is not parsed, replayed, or accepted as a canonical restore file. The separate IPv4/IPv6 interface dumps are parsed only for documented source tokens; no generated command is executed.
5. A physical adapter DNS configuration that remains unchanged does not prove that every DNS query stayed inside the tunnel. Validate with packet capture on both physical and TUN interfaces, including UDP/TCP 53, PTR, SVCB/HTTPS record types, IPv4 and IPv6, reconnect, engine exit, and network changes.
6. This probe does not test DoH/DoT application traffic, WFP crash behavior, full egress protection, or DNS profile restoration.
7. Do not share observation JSON without reviewing it; DNS server addresses, search suffixes, NRPT namespaces, and adapter metadata can disclose local network details.

A `PASS` from this probe is one piece of TUN architecture evidence only. It does not close DNS issue #87 and does not enable Connect, Disconnect, Recover, DNS restore, or journal deletion.
