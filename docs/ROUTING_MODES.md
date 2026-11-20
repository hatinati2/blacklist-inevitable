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

The Iranian rule-sets are maintained by the community project [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules). They are consumed in sing-box binary SRS format and refreshed every 24 hours. The project documents its `geosite-ir` and `geoip-ir` rule-set assets and their use in sing-box. These are third-party data sources, not a claim that any list can classify every CDN or newly-created Iranian service correctly.

Remote rule-set downloads use an explicitly configured HTTP client routed through the Direct outbound so the initial list download does not depend on the selected VPN node. The downloaded data and DNS reverse mappings use sing-box's cache file, whose path must be selected internally by the privileged Windows Agent under its protected ProgramData data directory. The UI must not be allowed to supply this filesystem path.

DNS queries continue to use the encrypted HTTPS resolver configured for the selected profile; DNS reverse mapping is enabled so destination-domain information can be retained for subsequent route matching. Rule matching uses sing-box's route sniff action and process-independent destination matchers.

## User exceptions

A user may add exact domains, suffixes (for example `*.example.com`), IPv4/IPv6 addresses or CIDRs and choose Direct, VPN, or Block. Rules are applied in the order shown. First match wins. Inputs are validated and capped to bounded counts and sizes.

## Important limitations and release gates

- This PR adds the Rust policy model and TUN JSON generator only. It does not yet add the Global/Rule selector or editable rule list to the desktop UI.
- It does not yet download or update rule-sets from the Windows Agent, validate their fetched bytes, or handle first-run failure when the data source cannot be reached. The Agent must implement bounded downloads, cache protection, update rollback, clear diagnostics, and fail-safe behavior before this feature is enabled in a release.
- Some apps use encrypted ClientHello/ECH or cached/shared system DNS, and some Iranian sites use foreign CDNs. Such destinations may not always be identified by domain or country IP rules. The custom domain/IP exception list is therefore required as an override mechanism.
- Rule mode's JSON must pass the pinned sing-box 1.14.4 config checker and later be verified with real packet tests on Windows. A successful config check does not prove that `.ir` traffic is actually bypassed on a live machine.
