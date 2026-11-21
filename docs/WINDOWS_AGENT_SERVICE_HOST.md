# Windows Agent service host and authenticated status pipe

## Implemented foundation

- A separate Cargo binary target builds as `blacklist-inevitable-agent.exe`.
- The binary enters the Windows Service Control Manager through `StartServiceCtrlDispatcherW`.
- The service reports start-pending, running, stop-pending, and stopped states.
- Stop and shutdown signal a manual-reset event. Every blocking pipe operation uses an OVERLAPPED record and waits on both its I/O event and the service-stop event; on Stop, the operation is cancelled and drained before its buffer/OVERLAPPED storage is released.
- The service creates one first-instance named pipe at `\\.\pipe\BlacklistInevitable.Agent.v1`.
- The pipe DACL grants SYSTEM and Administrators full access, and Interactive Users read/write access only. No Everyone or broad Users ACE is added.
- `PIPE_REJECT_REMOTE_CLIENTS` rejects remote pipe clients. The server accepts one local client at a time.
- Before reading a request, the server compares the pipe client session ID with the active physical-console session, obtains that session's user token, impersonates the pipe client only long enough to read the token SID/session ID, calls `RevertToSelf`, and requires both identities to match.
- If `RevertToSelf` fails, the service process terminates rather than reusing a thread that might still carry a client impersonation token.
- IPC frames use the shared four-byte little-endian length prefix, are bounded to 128 KiB, and have a finite 30-second read deadline.
- The listener validates the active-console session, reads only the fixed four-byte frame header, then impersonates and verifies the client SID/session before allocating/reading the JSON payload or dispatching any operation. This ordering is required because Win32 binds `ImpersonateNamedPipeClient` to the last client message read from the pipe. The implementation drains the pipe buffer incrementally so a payload larger than the kernel buffer cannot deadlock.
- A replay guard is created after peer authentication. One request is handled per connection; malformed or unauthorized clients are dropped.
- Only `GetStatus` and `GetDiagnostics` return a status-only response. `Connect`, `Disconnect`, and `Recover` are explicitly rejected.
- The Windows CI builds this executable independently, stages it as a Tauri sidecar, and exercises its service installation/start/removal lifecycle in the NSIS smoke test.

## Important identity and deployment constraints

The current listener targets the active physical-console session. It deliberately rejects other sessions, including RDP sessions, until a tested multi-session policy is implemented.

The active user's reference token is queried with `WTSQueryUserToken`. Microsoft documents that this API requires the caller to run as LocalSystem with `SE_TCB_NAME`; it is intended for highly trusted services and token handles must be closed. The eventual service installer must therefore define and verify this service account/privilege model instead of assuming any service identity will work.

The named-pipe DACL is only the first access gate. Authorization also compares the actual impersonated client SID and session ID; it does not trust the DACL alone. The thread is reverted before response dispatch. No privileged filesystem or networking operation is performed while impersonating the client.

## Deliberate non-goals

This is now an installable Windows service/IPC foundation, but not an operational VPN Agent. The per-machine NSIS installer bundles the Agent sidecar and, when the desktop and Agent executables have valid matching Authenticode signatures, registers the service as LocalSystem with a service SID and protected ProgramData ACLs. An unsigned pair skips service registration; invalid or mismatched signatures fail closed. See [WINDOWS_AGENT_INSTALLATION.md](WINDOWS_AGENT_INSTALLATION.md).

The installer lifecycle does not yet connect the desktop UI to the pipe. The Agent continues to answer only `GetStatus` and `GetDiagnostics`; `Connect`, `Disconnect`, and `Recover` remain rejected. It does not open WFP, start sing-box, create TUN, change routes/DNS, mutate firewall policy, or load the recovery journal.

## Required next slices

1. [x] Add the unelevated desktop status-only named-pipe client with finite timeouts, protocol-version checks, request correlation, and a hosted-Windows install/start/query/uninstall smoke test. No credentials or network-mutating requests are sent.
2. Verify the server process image and signer from the desktop side before adding authenticated profile/credential handoff with one-shot memory handling and no secret logging/persistence.
3. Integrate the recovery journal and WFP transaction backend. Persist exact state before OS mutations and verify it during startup recovery.
4. Add the Agent-owned connection runtime only after authorization and crash recovery are tested.
5. Add Windows 10/11 integration tests for user logon/logoff, session switching, remote-client rejection, unauthorized SID rejection, malformed/oversized/replayed frames, stop during blocked pipe connect/read, service crash/reboot, and packet-capture leak acceptance.

A green CI service lifecycle test proves that the signed test package can install, start, query, and remove the service on the hosted Windows runner. It does not prove that the desktop client connects, that VPN operations work, or that an active kill switch or leak prevention exists.

## Microsoft API references

- [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew) and [named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Impersonating a named-pipe client](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client)
- [WTSGetActiveConsoleSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid)
- [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
- [CancelSynchronousIo](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio)
