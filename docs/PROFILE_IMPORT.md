# Profile import and endpoint checks

## Current share-link import support

The current importer accepts one link per line:

- VLESS URI
- VMess Base64 JSON URI
- Trojan URI
- Shadowsocks SIP002 URI
- Hysteria2 / hy2 URI
- TUIC URI

Subscription URLs, Clash YAML, sing-box JSON, plugin-based Shadowsocks links, and less common URI variants are not accepted yet. Unknown URI query fields are not silently converted into engine settings; only a small allowlist of non-secret options is retained.

The importer rejects invalid lines independently so valid links in the same paste can still be saved.

## Credential handling

Profile metadata is saved under the Tauri application data directory. Credentials (UUIDs, passwords, and similar authentication material) are stored separately using the Windows Credential Manager through the keyring crate. Raw share links are not written to the profile index or application logs.

The current profile model deliberately keeps secrets out of the UI response. A future engine adapter will retrieve credentials from the native store only when it needs to generate a temporary engine configuration.

## Basic endpoint check

The current check opens a bounded TCP connection to the configured host and port for VLESS, VMess, Trojan, and Shadowsocks. It is limited to 24 concurrent probes and a five-second timeout per endpoint. Hysteria2 and TUIC are skipped because they require UDP-aware testing.

A successful TCP connection means only that the endpoint accepted a TCP connection. It does **not** validate TLS, proxy protocol negotiation, authentication, transport settings, or the ability to carry traffic. This check never starts an engine, enables TUN, or changes the Windows system proxy.

## Next integration steps

1. Add parsers and fixtures for more import formats without discarding unsupported options.
2. Pin a sing-box version and validate generated outbound configuration against its native checker.
3. Add a supervised probe-only sing-box runtime and protocol-aware URL tests, with no TUN or system proxy.
4. Add UDP protocol tests for Hysteria2 and TUIC.
