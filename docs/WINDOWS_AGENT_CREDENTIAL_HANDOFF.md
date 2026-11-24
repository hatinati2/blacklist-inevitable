# Windows Agent one-shot credential handoff

## Implemented transport slice

The unelevated desktop now exposes the Tauri command `submit_agent_connect_request`. It looks up profile metadata by profile ID, retrieves the corresponding secret map from the current user's Windows Credential Manager, and sends one typed `Connect` request over the local authenticated Agent named pipe.

The handoff is constrained as follows:

- The desktop verifies the named-pipe server process/session and LocalSystem identity before writing a request.
- The service independently authenticates the active physical-console user's SID and session before reading the request. Remote named-pipe clients are rejected.
- The request uses the versioned, bounded 128 KiB frame and a random request ID. The pipe connection handles one request and closes; the service replay guard validates the ID.
- The protocol carries a validated `AgentProfile` and a protocol-specific credential map. It does not accept arbitrary engine JSON, executable paths, command lines, or working directories.
- The desktop does not persist or log the handed-off credentials. The Agent does not persist, log, or echo them.
- The keyring JSON buffer, loaded credential map, imported credential values, serialized IPC frame, received IPC payload, and each deserialized credential value use zeroizing/drop-based cleanup. Debug formatting for secret-bearing profile and credential values is redacted.

## Deliberate limitation

The named-pipe service still rejects `Connect`, `Disconnect`, and `Recover`. This slice proves the typed, authenticated, one-shot transport foundation only; the current service response is a deliberate rejection and **does not establish a VPN connection**.

Do not wire the command to a production Connect button or describe the product as connected until the Agent has a tested connection runtime, durable recovery, route/DNS handling, and an Agent-owned all-protocol physical-egress kill switch. The handoff also does not prove that every transient copy made by the operating system, allocator, or serialization implementation can be eliminated from process memory.
