# Destination-based Global and Rule modes

## Global

Global mode sends destinations through the selected VPN outbound by default. It does not add geographic bypass rules. Any explicit application process rules already present in the generated config remain intact.

## Rule

Rule mode uses the following precedence in the generated TUN config:

1. Sniff HTTP Host, TLS SNI, and QUIC metadata where available so domain rules can match.
2. Keep private/LAN destination addresses Direct when that option is enabled.
3. Apply explicit per-application process-path rules already supplied by the application split-tunneling layer.
4. Apply user-defined exact-domain, domain-suffix, and IP/CIDR exceptions (Direct, VPN, or Block).
5. Send `.ir` domains, the `geosite-ir` destination rule-set, and the `geoip-ir` destination rule-set Direct when the Iran bypass option is enabled.
6. Send all remaining destinations through the selected VPN outbound.

The Iranian rule-sets are maintained by the community project [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules). The current application pin is the immutable upstream commit `1597f121656f3e63f2624a471401002941d888c4` (2026-11-22). The exact `geoip-ir.srs` and `geosite-ir.srs` bytes are pinned by SHA-256 and exact length in the Agent cache module and in Windows CI; the validator also asks the pinned sing-box 1.14.4 binary to parse both SRS files. The upstream commit itself is unsigned, so the application does not follow the mutable branch at runtime. Updating this snapshot requires a reviewed software change that updates both asset hashes and repeats the parser validation. These third-party data sources do not classify every CDN or newly-created Iranian service correctly.

The Agent now contains a bounded, redirect-disabled download/cache primitive. It accepts only the two hard-coded HTTPS URLs for that immutable commit, checks exact length, SRS header and SHA-256, and writes verified bytes through a same-directory temporary file followed by an atomic rename. Its cache directory is created only beneath the installer-provisioned `ProgramData\\BlacklistInevitable\\Agent` root, whose ACL is restricted to SYSTEM, Administrators and the Agent service SID. It refuses symlink/reparse-point directories and never changes ACLs itself.

This cache primitive is not called by Agent startup, status IPC, or the desktop UI. It is not yet wired to the connection transaction or to sing-box `initial_path`; it therefore does not activate Rule mode or initiate downloads on an installed machine. The future Agent connection path must require both verified assets before building a Rule-mode config and must fail closed if either is unavailable.

DNS queries continue to use the encrypted HTTPS resolver configured for the selected profile; DNS reverse mapping is enabled so destination-domain information can be retained for subsequent route matching. Rule matching uses sing-box's route sniff action and process-independent destination matchers.

## User exceptions

A user may add exact domains, suffixes (for example `*.example.com`), IPv4/IPv6 addresses or CIDRs and choose Direct, VPN, or Block. Rules are applied in the order shown. First match wins. Inputs are validated and capped to bounded counts and sizes.

## Important limitations and release gates

- The desktop now has a locally persisted Global/Rule selector and editable destination rules, but these preferences are not sent to the Agent or applied to the network.
- The Agent has a pinned, hash-verified cache primitive for the two SRS seed files, but it is not called by startup/IPC and is not yet connected to sing-box `initial_path` or the Connect transaction. Update/rollback diagnostics, cache recovery, and fail-safe connection gating remain open.
- Some apps use encrypted ClientHello/ECH or cached/shared system DNS, and some Iranian sites use foreign CDNs. Such destinations may not always be identified by domain or country IP rules. The custom domain/IP exception list is therefore required as an override mechanism.
- Rule mode's JSON must pass the pinned sing-box 1.14.4 config checker and later be verified with real packet tests on Windows. A successful config check does not prove that `.ir` traffic is actually bypassed on a live machine.
