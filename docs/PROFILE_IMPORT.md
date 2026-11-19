# Profile import and preflight checks

## Current share-link import support

The importer accepts one link per line:

- VLESS URI
- VMess Base64 JSON URI
- Trojan URI
- Shadowsocks SIP002 URI
- Hysteria2 / hy2 URI
- TUIC URI
- Naive HTTPS / QUIC (`naive+https://` and `naive+quic://`)

Subscription URLs, Clash YAML, sing-box JSON, plugin-based Shadowsocks links, Mieru, and less common URI variants are not accepted yet. The importer maps an allowlist of recognized non-secret fields into the normalized profile model. Unknown source option names are retained separately; their values are not copied into public profile metadata.

Invalid lines are rejected independently so valid links in the same paste can still be saved. Unknown query keys and unrecognized VMess JSON fields are retained by key name in `unsupportedOptions`. The sing-box adapter refuses to validate or probe a profile while unmapped options remain, rather than silently dropping them.

## Credential handling

Profile metadata is saved under the Tauri application data directory. Credentials (UUIDs, passwords, and similar authentication material) are stored separately using Windows Credential Manager through the keyring crate. Raw share links are not written to the profile index or ordinary application logs.

The profile list response does not include credentials. The engine adapter retrieves credentials only when it needs to generate a temporary engine configuration. That temporary configuration necessarily contains the credentials required by sing-box and is removed after the probe's cleanup path.

## TCP reachability diagnostic

The basic endpoint diagnostic opens a bounded TCP connection to the configured host and port for VLESS, VMess, Trojan, Shadowsocks, and Naive HTTPS profiles. Naive QUIC, Hysteria2, and TUIC are skipped by this TCP-only diagnostic because they need UDP-aware checks. It is limited to 24 concurrent probes and a five-second timeout per endpoint.

A successful TCP connection means only that the endpoint accepted a TCP connection. It does **not** validate the generated engine configuration, TLS, proxy protocol negotiation, authentication, transport settings, or the ability to carry traffic. The UI labels this result as TCP reachability; it is not Real Delay.

## sing-box config validation

The application can generate a per-profile sing-box outbound configuration and run the native `sing-box check -c` command. The standalone Validate config action reports whether sing-box accepted the generated configuration. The batch Real Delay action repeats the native check and will not start a probe when configuration generation or validation fails.

A successful config check proves only that the engine accepts the configuration shape; it does not prove that the remote server is online or that credentials are correct. Unsupported options are reported explicitly and block the probe.

## Real Delay

Real Delay is implemented using an isolated sing-box process for each tested profile. The engine exposes a temporary SOCKS inbound bound only to `127.0.0.1`; the HTTP client connects through that proxy with SOCKS5 remote DNS (`socks5h`) so the request is sent through the selected profile's outbound.

The primary endpoint is `https://www.gstatic.com/generate_204`. If it fails, the implementation tries `https://cp.cloudflare.com/generate_204`. Redirects are disabled and only HTTP 204 counts as a successful measurement. The timer covers the request through the proxy until the response headers are received. Each HTTP attempt has a nine-second timeout and at most four engine processes run concurrently.

The primary and fallback HTTPS probe URLs and timeout are configurable in the application settings and persisted locally. The timeout is bounded to 2–30 seconds, with a 9-second default. Successful measurements are returned in ascending delay order. The result includes the endpoint used, config outcome, measured milliseconds, or a failure detail.

Preflight does not enable TUN, Wintun, packet capture, Windows system proxy settings, or normal device traffic routing. This feature tests one profile at a time through its temporary local proxy; it does not connect the device to a VPN.

See [REAL_DELAY_SPEC.md](REAL_DELAY_SPEC.md) for the measurement definition, current lifecycle limitations, and remaining acceptance tests.


## Naive import and preflight

The importer accepts the v2rayN-style `naive+https://` and `naive+quic://` share-link schemes. An omitted port defaults to 443. Password-only userinfo and separate username/password userinfo are supported; percent-decoding occurs after the userinfo separator is identified so encoded colons remain part of credentials. Credentials are stored separately in Windows Credential Manager.

The adapter maps the password, optional username, SNI, QUIC mode, and bounded `insecure-concurrency` setting to the sing-box Naive outbound. The pinned official Windows sing-box archive contains `libcronet.dll`; the installer verifies the archive hash and installs that DLL beside `sing-box.exe`, as required by the upstream Naive runtime. Unknown query options remain visible by key and block preflight rather than being silently discarded.

Naive config mapping and credential separation are covered by Rust tests. A successful native config check still does not prove authentication against a remote Naive server; controlled-server testing remains a separate gate.
