# Profile import and endpoint checks

## Current share-link import support

The current importer accepts one link per line:

- VLESS URI
- VMess Base64 JSON URI
- Trojan URI
- Shadowsocks SIP002 URI
- Hysteria2 / hy2 URI
- TUIC URI

Subscription URLs, Clash YAML, sing-box JSON, plugin-based Shadowsocks links, and less common URI variants are not accepted yet. Only an allowlist of recognized non-secret fields is mapped into the normalized profile options. Unknown source option names are preserved separately; their values are not copied into public metadata.

The importer rejects invalid lines independently so valid links in the same paste can still be saved. Unknown URI query keys and unrecognized VMess JSON fields are retained by key name in `unsupportedOptions`. The sing-box adapter refuses to validate or test a profile while such unmapped source options remain, rather than silently dropping them.

## Credential handling

Profile metadata is saved under the Tauri application data directory. Credentials (UUIDs, passwords, and similar authentication material) are stored separately using the Windows Credential Manager through the keyring crate. Raw share links are not written to the profile index or application logs.

The current profile model deliberately keeps secrets out of the UI response. A future engine adapter will retrieve credentials from the native store only when it needs to generate a temporary engine configuration.

## Current TCP reachability diagnostic

The current diagnostic opens a bounded TCP connection to the configured host and port for TCP-capable profiles. It is limited to 24 concurrent probes and a five-second timeout per endpoint. UDP-only profiles are skipped.

A successful TCP connection means only that the endpoint accepted a TCP connection. It does **not** validate the generated engine configuration, TLS, proxy protocol negotiation, authentication, transport settings, or the ability to carry traffic. The UI labels this result as TCP reachability; it must never be shown as Real Delay.

## Required engine config validation

Before measuring a node, the app must generate that node's engine configuration and run the selected engine's native configuration checker. For the first adapter, this is the pinned sing-box `check -c` command. A successful config check proves only that the engine accepts the configuration shape; it does not prove that the remote server works or that credentials are correct.

Unsupported options must be reported explicitly. They must not be silently dropped from generated configuration.

## Required Real Delay

Real Delay must use a real HTTP(S) request sent **through the selected node** using a temporary local proxy backed by the selected engine. The measured time covers the request path through the proxy and the HTTP response from the probe endpoint. The initial default is `https://www.gstatic.com/generate_204`, with a configurable secondary URL for fallback.

Each node is tested in an isolated temporary runtime. No TUN, Windows system proxy, or normal device traffic capture is permitted. TCP handshake timing remains a distinct diagnostic, not a substitute for Real Delay.

Hiddify documents its monitoring test as a URL request through each outbound; v2rayNG exposes a dedicated native `measureOutboundDelay` API. This project follows the same principle.

See [REAL_DELAY_SPEC.md](REAL_DELAY_SPEC.md) for the complete algorithm, safety constraints, result model, and acceptance tests.
