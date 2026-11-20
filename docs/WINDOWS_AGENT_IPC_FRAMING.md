# Windows Agent IPC framing contract

## Scope

The Rust Agent protocol now has a transport-independent framing layer for an ordered byte stream. It is ready for a future Windows named-pipe listener/client adapter, but it is not itself a named-pipe implementation and does not authenticate a caller.

## Wire format

Each request is exactly one frame:

| Offset | Size | Meaning |
|---|---:|---|
| 0 | 4 bytes | Unsigned payload length, little-endian |
| 4 | N bytes | One UTF-8 JSON `AgentRequest` |

The payload length must be between 1 byte and 128 KiB inclusive. The receiver reads exactly four header bytes, validates the length before allocating, then reads exactly that number of payload bytes. It must not interpret a truncated payload, accept extra trailing bytes as part of the same frame, or allocate based on an unchecked length.

`encode_agent_frame` / `decode_agent_frame` support complete in-memory frames. `read_agent_message` / `write_agent_message` provide bounded asynchronous stream I/O and preserve subsequent frames on the stream. Write completion includes a flush.

The JSON layer continues to reject unknown fields, unsupported protocol versions, invalid request IDs, invalid profile metadata, oversized options, and protocol-incompatible credential fields. Connect payloads must never be logged or formatted with Debug.

## Duplicate request protection

Create one `AgentRequestReplayGuard` after the named-pipe peer has been authenticated, and keep it for the full lifetime of that authenticated connection. Call `accept` before dispatching every decoded request. A request ID may be accepted only once on that connection.

The guard retains at most 4,096 IDs. Once its budget is exhausted, the listener must close the connection; it must not evict old IDs and silently make a replay acceptable. A poisoned or unavailable guard also fails closed.

The guard detects duplicate request IDs within one authenticated connection. It does not replace the pipe DACL, rejection of remote clients, or per-connection Windows token/session verification, and it is not a persistent anti-replay database across service restarts or independent connections. The listener must enforce those separate authentication and connection-lifecycle requirements.

## Required listener behavior

- Use a local-only Windows named pipe with restrictive DACL; allow only the active interactive user SID, SYSTEM, and Administrators as specified in the Agent design.
- Reject remote clients and verify the connected client token/session before constructing the replay guard.
- Apply a finite connection/read/write timeout and close on malformed frames, invalid requests, duplicate request IDs, exhausted request budget, or transport errors.
- Never process more than one request concurrently on the same connection unless ordering and replay semantics are explicitly preserved.
- Never pass arbitrary command lines, filesystem paths, or engine JSON through this protocol.
- Do not transition connection state to Connected until the Agent independently verifies engine containment, TUN state, routes, DNS, and configured policy.

## Explicit non-goals

This change does not create/register a Windows service, create the named pipe, apply pipe ACLs, authenticate a Windows token, transfer credentials from Tauri, start sing-box in TUN mode, or mutate routes/DNS/firewall state. Those remain separate implementation and Windows integration-test tasks.
