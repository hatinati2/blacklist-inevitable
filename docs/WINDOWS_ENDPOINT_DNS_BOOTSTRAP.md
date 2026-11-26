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

## Not yet complete

This primitive is not yet called by the Windows Agent's Connect transaction. Until integration is implemented, actual endpoint bootstrap during a VPN connection is not yet protected by this code. The provider is currently fixed to Cloudflare and should become an explicit supported setting before release. The Agent must retain the returned address set for the current preparation attempt, resolve routes for each address, and restart preparation on network-change invalidation. The initial query is outside the tunnel and visible to the selected resolver.

Keep Connect disabled until bootstrap is integrated with route-bound WFP preparation, in-tunnel DoH, and physical-adapter packet-capture acceptance.
