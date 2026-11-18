# Config validation and Real Delay

Real Delay is a pre-connect diagnostic, not a VPN connection. It must be measured through the selected node and must never be substituted with a TCP handshake measurement.

## Current implementation

The current sing-box implementation performs two separate checks for each profile:

1. **Config validation** — generate a temporary sing-box configuration and run the native `sing-box check -c` command. Outcomes are reported as valid, invalid, unsupported, or not checked, with a sanitized diagnostic.
2. **Real Delay** — only after configuration generation and native validation succeed, start a temporary sing-box process for that profile and send an HTTPS request through its loopback-only SOCKS5 inbound. The client uses `socks5h` so the target hostname is resolved through the proxy path.

Current measurement endpoints:

- Primary: `https://www.gstatic.com/generate_204`
- Fallback: `https://cp.cloudflare.com/generate_204`

Redirects are disabled. Only HTTP 204 is accepted as success. The elapsed time covers the request through the local proxy, the selected outbound, remote connection, TLS / transport, and response headers. The endpoint used and elapsed milliseconds are returned to the UI.

The request timeout is currently nine seconds per endpoint attempt, and the batch runner limits concurrent sing-box processes to four. The endpoints and timeout are constants in the Rust code; they are not configurable in the UI yet.

## Current isolation and cleanup behavior

- Each probe creates a unique temporary directory and configuration.
- Each temporary SOCKS inbound is configured to listen on `127.0.0.1` only.
- The preflight path does not enable TUN, Wintun, packet capture, Windows system proxy, or normal device traffic routing.
- Temporary configuration-validation files and per-probe directories have synchronous Drop guards, so cancellation of a Tauri command still attempts to remove credential-bearing JSON files.
- The normal request path explicitly asks the child process to stop and waits up to four seconds for process exit.
- A child-process kill-on-drop setting and temporary-directory Drop guard provide fallback cleanup if the command future is dropped.

This is not yet a complete application-wide process supervisor. Cancellation and application-shutdown paths do not yet share a runtime-health gate that verifies child termination before permitting a future normal Connect. There is no normal Connect / Disconnect feature yet. These guarantees must be completed and tested before device-wide routing is added.

## User-visible result model

For each profile, show separate fields:

| Field | Values |
| --- | --- |
| Config | Valid / Invalid / Unsupported / Not checked |
| Real Delay | milliseconds / Failed / Not run |
| TCP reachability | optional diagnostic only; never labelled Real Delay |

A profile with invalid or unsupported configuration must not be sent to the Real Delay stage. A profile with valid configuration but failed Real Delay should remain visible with its reason.

## Protocol coverage

The importer can accept a link before the sing-box adapter supports every source option. The adapter must explicitly report unsupported options and refuse to claim a valid configuration. Never silently discard Reality, transport, TLS, flow, obfuscation, plugin, or other protocol settings.

The current adapter maps a tested subset of VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and TUIC options into sing-box outbounds. It still requires broader fixture coverage and controlled-server testing for the full supported matrix. Native config acceptance alone does not prove that the remote server can authenticate or carry the probe request.

## Acceptance tests still required

- Exercise controlled test servers for every claimed protocol and transport on Windows.
- Confirm bad credentials fail the proxied HTTP request and cannot be reported as a successful Real Delay.
- Confirm HTTP 204 through the selected node produces a measured delay.
- Confirm a direct-network response cannot be mistaken for a proxied response.
- Verify DNS, TLS, transport, and authentication failures are diagnosed where the engine exposes enough detail.
- Verify that success, failure, timeout, user cancellation, and app shutdown leave no child process, listener, or temporary file behind.
- Cancel config validation while sing-box is reading the temporary JSON and verify that no credential-bearing file remains in the preflight cache.
- Verify that TUN and system proxy settings remain unchanged before, during, and after the test batch.
- Add configurable test endpoints and timeout controls.

