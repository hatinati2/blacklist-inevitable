# Windows Agent service host foundation

## Implemented in this slice

- A separate Cargo binary target builds as `blacklist-inevitable-agent.exe`.
- The binary enters the Windows Service Control Manager through `StartServiceCtrlDispatcherW`.
- The service registers an extended control handler and reports the start-pending, running, stop-pending, and stopped states.
- Stop and shutdown requests are delivered through a manual-reset event. Handle publication and closure are synchronized so the handler cannot signal a closed/reused event handle.
- The Windows CI builds this executable independently from the Tauri desktop installer.

## Deliberate non-goals

This is only the SCM process/lifecycle shell. It currently waits for Stop/Shutdown and does not:

- register or install itself as a Windows service;
- choose or configure a service account;
- create a named pipe or set a pipe DACL;
- authenticate a user/session or accept IPC messages;
- open WFP, start sing-box, create TUN, change routes/DNS, or mutate firewall policy;
- load the recovery journal or report an active VPN connection.

The desktop app does not launch or install this binary. The NSIS installer does not bundle it yet. Do not manually register this executable as a production VPN service.

## Required next slices

1. Implement a local-only named-pipe listener with a restrictive DACL, reject remote clients, impersonate the pipe client, and verify both the client's user SID and session ID against the expected interactive session. Close the connection on any identity or framing error.
2. Add bounded request/response framing, per-connection replay protection, finite I/O deadlines, and status-only dispatch. Network-mutating operations remain rejected.
3. Add service installation/upgrade/removal with explicit UAC consent, signed-binary verification, service-account policy, protected journal directory provisioning, and tested rollback.
4. Integrate the recovery journal, WFP transaction backend, and process supervisor only after the IPC and service lifecycle tests pass.
5. Add Windows 10/11 integration tests for user logon/logoff, session switching, stop/shutdown, crash, reboot, and packet-capture leak acceptance.

A green service-host build proves only that the service entry point compiles and its lifecycle code is linked. It is not evidence of a running Agent, active kill switch, or leak prevention.
