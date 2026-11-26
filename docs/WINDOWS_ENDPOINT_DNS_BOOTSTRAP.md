# Windows VPN endpoint DNS bootstrap

## Implemented primitive

`endpoint_bootstrap::EndpointBootstrapResolver` resolves an endpoint hostname with DNS-over-HTTPS using the RFC 8484 wire format. It is deliberately separate from profile import and the not-yet-enabled Connect path.

- DoH URL and TLS name: `https://cloudflare-dns.com/dns-query` / `cloudflare-dns.com`.
- The HTTP client maps that hostname only to Cloudflare's published numeric IPv4 and IPv6 resolver addresses.
- System proxy environment variables and redirects are disabled. HTTPS and normal certificate-chain/hostname validation are mandatory.
- Requests use DNS ID zero and query both A and AAAA. A bounded CNAME chain is followed. DNS message size, answer count, connection time and overall request time are bounded.
- Malformed responses, NXDOMAIN, SERVFAIL, unexpected media types, non-unicast targets, TLS/HTTP errors and empty result sets fail closed. Literal IP endpoints cause no DNS traffic.
- There is no UDP/TCP port-53 or Windows DNS Client fallback.

References:
- Cloudflare resolver addresses: https://developers.cloudflare.com/1.1.1.1/ip-addresses/
- Cloudflare DoH endpoint: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
- DoH wire format: https://www.rfc-editor.org/rfc/rfc8484

## Route-snapshot composition

The Windows-only `WindowsEgressSnapshot::capture_for_server` composes this resolver with read-only physical-interface discovery, route lookup, and route-bound policy compilation. It accepts an explicit TCP/UDP transport tuple from the engine adapter; it never guesses transport semantics from a profile name. Every resolved A/AAAA address receives the exact supplied port and protocol, and the downstream endpoint count remains bounded to 64. DNS must complete successfully before any route snapshot is returned.

This remains a preparation primitive, not a live Connect transaction. The DoH bootstrap request happens before route-monitor capture and before tunnel startup. A successful snapshot does not install policy, mutate routes/DNS, or authorize Connected state.

## Engine-derived endpoint plan

The Windows-only `WindowsEgressSnapshot::capture_for_profile` entry point first asks the strict sing-box adapter to build its outbound configuration. The adapter then derives the remote transport tuple from that emitted configuration: Hysteria2/TUIC use UDP, Naive uses its explicit `quic` setting, Shadowsocks accounts for both TCP and UDP, and VLESS/VMess/Trojan use TCP unless the emitted transport is QUIC. Unknown outbound or transport shapes fail closed. This avoids inferring transport from a UI/profile label and keeps the endpoint allowlist aligned with the configuration that will later be launched.

The resolver performs one A/AAAA bootstrap and expands the resulting addresses across the complete protocol set. The combined address/transport count is bounded by the 64-entry WFP endpoint limit; duplicates, an empty set, or overflow are rejected before route capture.

The authenticated Windows Agent now exposes a separate PrepareConnect IPC operation. It validates the supplied profile and one-shot credentials, builds the endpoint plan from the emitted sing-box configuration, resolves the endpoint through DoH, captures the Windows-selected physical egress routes, and retains the read-only snapshot in the Agent service process. Temporary credential copies are zeroized immediately after the engine-derived endpoint plan is built, before any DoH request or route discovery. Every subsequent authenticated request checks the retained snapshot; a route/interface notification causes it to be discarded. The Desktop can invoke this preparation command without invoking Connect.

This is still preparation-only: it does not install filters, change routes/DNS, or start sing-box. The existing Connect, Disconnect, and Recover operations remain rejected. The retained snapshot is groundwork for a later serialized Agent-owned transaction, not a kill switch or proof of leak prevention.

The provider is currently fixed to Cloudflare and should become an explicit supported setting before release. The initial query is outside the tunnel and visible to the selected resolver.

Keep Connect disabled until the Agent consumes the snapshot in a serialized WFP/route/DNS/engine transaction, mixed-resource crash/reboot recovery is implemented, and physical-adapter packet-capture acceptance passes.
