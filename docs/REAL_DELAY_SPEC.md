# Config validation and Real Delay specification

This is a release requirement for the Windows version, not an optional enhancement.

## Two independent outcomes per profile

Every pre-connect test result has two separate stages:

1. **Config validation** — generate a temporary configuration for the selected engine and ask that exact engine to validate it. With the first adapter, run the pinned sing-box binary with `check -c <temporary-config>`. Report `Valid`, `Invalid`, or `Unsupported`, plus a sanitized diagnostic.
2. **Real Delay** — only after config validation succeeds, start that node's temporary engine runtime and issue an HTTP(S) request through that node. Measure elapsed time until a valid HTTP response is received. Report milliseconds or a specific failure reason.

A config that parses is not necessarily a reachable server. A reachable TCP port is not necessarily a valid proxy. These outcomes must never be conflated.

## Real Delay measurement

- Default URL: `https://www.gstatic.com/generate_204`.
- Provide a configurable fallback URL, initially `https://cp.cloudflare.com/`.
- Send a real HTTP(S) request through the selected profile's temporary local proxy, backed by the selected engine outbound.
- Measure the request round trip, including proxy negotiation, remote connection, TLS/transport, and response headers.
- Do not measure only a TCP connect to the proxy server.
- Do not measure a direct request that bypasses the selected profile.
- Require an expected response from the configured probe (the default endpoint should return HTTP 204); treat captive-portal redirects and unexpected bodies/statuses as failures, not successful delays.
- Use a bounded timeout and concurrency. Start conservatively (four parallel engine processes) and tune only after resource tests.
- Sort successful results by measured Real Delay, with failures and unsupported profiles after them.
- Show the URL and test time so results can be interpreted and reproduced.

This follows the approach documented by Hiddify (URL request through each outbound) and the dedicated `measureOutboundDelay` interface exposed by v2rayNG.

## Isolation and cleanup

- Each test runtime uses a loopback-only SOCKS/HTTP inbound bound to an ephemeral port.
- Never enable TUN, Wintun, packet capture, Windows system proxy, or normal traffic routing during preflight.
- Each child process is owned by the Rust supervisor; it must never be detached.
- Use a unique temporary directory and temporary configuration per node.
- Do not write credentials to the persistent profile index, logs, CI output, or UI metadata.
- Kill and wait for the process on success, failure, timeout, cancellation, app shutdown, and unexpected UI closure.
- Remove temporary config and runtime files after process exit.
- If shutdown or cleanup cannot be confirmed, mark the test subsystem as unhealthy and block normal Connect until it is reconciled.

## User-visible status

For each profile, show independent fields:

| Field | Values |
| --- | --- |
| Config | Valid / Invalid / Unsupported / Not checked |
| Real Delay | milliseconds / Timed out / Failed / Not supported / Not checked |
| TCP reachability | optional diagnostic only; never labelled as Real Delay |

A profile with an invalid config must not be sent to the Real Delay stage. A profile with valid config but failed Real Delay should display the reason without being silently removed.

## Protocol coverage

The importer may accept a link before every engine adapter supports every field. The adapter must explicitly report unsupported options and refuse to claim full validation. Never silently discard Reality, transport, TLS, flow, obfuscation, plugin, or other protocol settings.

The first sing-box adapter must have fixture-backed config generation and native config-check coverage for every protocol/transport it claims to support. UDP protocols (including Hysteria2 and TUIC) must be tested through the protocol-aware engine request path, not skipped merely because a TCP-only probe cannot test them.

## Acceptance tests

- Invalid generated configuration is reported as Invalid and never starts a probe process.
- Valid configuration with bad credentials produces a Real Delay failure, not a TCP-success result.
- An HTTP 204 through the selected node produces a Real Delay value in milliseconds.
- A direct-network response cannot be mistaken for a proxied result.
- DNS/TLS/transport/handshake errors are distinguished where the engine exposes enough detail.
- A timeout, cancellation, or crashed engine leaves no child process, listener, or temporary config behind.
- Tests run with TUN and system proxy unchanged before, during, and after the full batch.
