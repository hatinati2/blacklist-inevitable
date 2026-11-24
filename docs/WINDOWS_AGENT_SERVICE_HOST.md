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
- IPC frames use the shared four-byte little-endian length prefix, are bounded to 128 KiB, and have a finite 30-second read deadline. The implementation drains the pipe buffer incrementally so a payload larger than the kernel buffer cannot deadlock.
- A replay guard is created after peer authentication. One request is handled per connection; malformed or unauthorized clients are dropped.
- Only `GetStatus` and `GetDiagnostics` return a status-only response. `Connect`, `Disconnect`, and `Recover` are explicitly rejected.
- Before reporting the service as running, the Agent opens the existing `%ProgramData%\\blacklist-inevitable\\Agent` recovery-journal directory provisioned by the signed installer and loads every committed checkpoint. Missing, unsafe, oversized, filename-mismatched, or corrupt journal state blocks service startup; malformed committed state is never skipped.
- Startup status/diagnostics include the number of unresolved sessions found. An unresolved journal does not trigger guessed cleanup: all VPN network operations remain disabled and the service explicitly reports that automatic network recovery is not implemented.
- The unelevated desktop now has a status-only named-pipe client with a five-second timeout, bounded response framing, and request/response correlation. It verifies the server PID and session 0 from the pipe handle, then verifies the process token SID (LocalSystem) when token inspection is available; for a standard user that cannot open the SYSTEM token, it fails over to reading the pipe object's owner SID and accepts only LocalSystem. It sends no credentials and no network-mutating operations.
- A separate `submit_agent_connect_request` command retrieves credentials only from the current user's Windows Credential Manager and sends one typed `Connect` frame over the same authenticated local pipe. The profile/credential schema is bounded and protocol-specific; imported and loaded secret values, IPC frames, and individually deserialized credential strings use zeroizing cleanup, and debug output redacts them. The service currently rejects `Connect` and drops the payload without persistence or logging; this is a handoff foundation, not a working connection. See `WINDOWS_AGENT_CREDENTIAL_HANDOFF.md`.
- The Windows CI builds this executable independently from the Tauri desktop installer.

## Installer and signed service deployment

- The per-machine NSIS installer bundles `blacklist-inevitable-agent.exe`, the PowerShell service helper, and a publisher-thumbprint pin file under the installed resources directory.
- The installer requires the normal Windows per-machine elevation/UAC consent. The desktop application itself remains unelevated.
- Before upgrade, the hook stops an existing Agent service before NSIS replaces the installed Agent executable. Before uninstall, it removes the Agent service before the executable is deleted. If the service cannot be stopped/removed, the hook aborts that installer operation instead of deleting a live service binary.
- During install, the helper verifies that both the Agent binary and the NSIS installer have valid Authenticode signatures from the exact same 40-hex publisher thumbprint pinned in the bundled file. A missing or unconfigured pin returns a no-install status; unsigned development and CI builds therefore leave the privileged service unregistered.
- The signed deployment explicitly registers the service as LocalSystem because the current authentication path uses `WTSQueryUserToken` and needs `SE_TCB_NAME`. It applies a restricted service SID, a SYSTEM/Administrators-only service-control DACL, SCM restart-on-failure actions, and a protected `%ProgramData%\\blacklist-inevitable\\Agent` journal directory whose write access includes only SYSTEM, Administrators, and the service SID.
- The current Windows CI deliberately writes the `UNCONFIGURED` publisher pin and does not sign either binary. Its smoke test verifies the fail-closed unsigned path and confirms that a fresh unsigned install does not register the LocalSystem Agent service. A trusted release signing pipeline and publisher thumbprint must be configured before the signed positive install path can be used; the current workflow does not yet automate PFX import or signing.
- Uninstallation preserves the ProgramData recovery-journal directory for later reconciliation; it does not silently delete potentially important network-recovery state.
- The unsigned Windows installer smoke test launches the installed desktop app, requests normal window shutdown, force-stops only remaining processes whose executable path matches the installed binary, and verifies that NSIS removes the installed executable before passing.
- SCM restart-on-failure actions only restart the status-only service process. They do not reconcile tunnel, route, DNS, WFP, or recovery-journal state and must not be presented as VPN crash recovery.

The signed positive deployment path still requires a trusted release certificate and clean Windows 10/11 validation. The ordinary CI workflow without signing secrets validates resource packaging and the fail-closed unsigned path only; it does not prove a signed service was installed or exercised.

## Important identity and deployment constraints

The current listener targets the active physical-console session. It deliberately rejects other sessions, including RDP sessions, until a tested multi-session policy is implemented.

The active user's reference token is queried with `WTSQueryUserToken`. Microsoft documents that this API requires the caller to run as LocalSystem with `SE_TCB_NAME`; it is intended for highly trusted services and token handles must be closed. The signed deployment therefore uses LocalSystem and adds a restricted service SID. Because a restricted token is subject to its restricted-SID access check, the installer grants that exact service SID read/execute access to the Program Files path and Agent executable, and modify access only to the protected ProgramData journal directory. The restricted-token filesystem access still needs clean-machine Windows 10/11 validation.

The named-pipe DACL is only the first access gate. Authorization also compares the actual impersonated client SID and session ID; it does not trust the DACL alone. The thread is reverted before response dispatch. No privileged filesystem or networking operation is performed while impersonating the client.

### Restricted service SID and WFP access

The installer configures the Agent service with `SERVICE_SID_TYPE_RESTRICTED`. This causes Windows to evaluate both the normal token SIDs and the token's restricted SID list on protected-object access checks. WFP's default engine ACL does not by itself prove that this restricted token can run the Agent's future filter lifecycle.

Before WFP operations are enabled, the provisioned ACLs must cover the complete operation set: `FWPM_ACTRL_OPEN` and `FWPM_ACTRL_BEGIN_WRITE_TXN` on the BFE engine; `FWPM_ACTRL_ADD` on the filter container; `FWPM_ACTRL_ADD_LINK` on the Agent provider, target ALE layers, and sublayer; and `FWPM_ACTRL_READ` plus standard `DELETE` on every Agent-owned filter. These are distinct access checks; granting only filter deletion is insufficient. ACL provisioning must preserve existing BFE permissions and be verified under the actual restricted service token before the service calls WFP.

The rollback-only WFP smoke test in Windows CI runs as the hosted runner's administrative account. It verifies the live BFE add/read-back/exact-delete/abort sequence, but does not validate the restricted service SID's effective permissions.

The Windows workflow now creates a disposable service using the exact production service name, runs the Agent executable as LocalSystem with `SERVICE_SID_TYPE_RESTRICTED`, and invokes a probe-only entry point. The probe calls the same WFP namespace and rollback-only filter validation path from that real SCM-created service token. Its JSON artifact reports either `access_granted` or `access_blocked` and includes the first failing WFP operation. The test service is deleted after the probe. No traffic filter is committed; the live probe only commits provider/sublayer metadata on the disposable hosted runner.

This is an access-discovery test, not an authorization pass gate: CI remains green when the probe reports `access_blocked`, because that result is the evidence needed to design and provision the missing ACLs safely. A green workflow proves that the restricted-token probe ran and produced a report; only `access_granted` proves that the current WFP lifecycle path completed under the restricted service token. The WFP backend remains disconnected from production service startup until required rights are provisioned, verified, and covered by a hard-failing acceptance test.

## Deliberate non-goals

The installer/deployment foundation does not turn the status-only service into an operational VPN Agent. The service performs a fail-closed recovery-journal bootstrap only; it does not yet run recovery actions. The service still:

- rejects `Connect`, `Disconnect`, and `Recover`;
- does not use profile credentials to start an engine session; it receives only a bounded one-shot handoff and rejects `Connect` until the runtime exists;
- does not start sing-box, create TUN, change routes/DNS, or activate firewall policy;
- loads and validates recovery journal checkpoints at startup, but does not yet reconcile or restore the recorded operating-system resources and does not report a real VPN connection state;
- has an exact-key, transactional WFP filter-removal primitive in the WFP backend, but it is not wired into startup recovery or an active policy lifecycle;
- does not provide an Agent-owned all-protocol physical-egress kill switch or prove packet-level leak prevention.

A successful unsigned CI smoke test proves resource packaging and the fail-closed no-service path only. It is not evidence that a trusted signed service was installed. The positive signed path still needs a release certificate and clean Windows 10/11 integration testing for service SID restrictions, LocalSystem token access, failed-upgrade rollback, service crash/reboot, and packet-capture leak acceptance.

The desktop process does not launch the Agent directly. The per-machine NSIS installer bundles it and uses the signature-gated service lifecycle hooks above. Do not manually register an unsigned or unpinned executable as a production VPN service.

## Required next slices

1. Implement exact startup reconciliation and rollback for recorded engine, TUN, route, DNS, and WFP resources; add durable WFP filter transactions with stable filter identities. The bootstrap now loads and validates the journal but deliberately performs no network cleanup or mutation.
2. Add the Agent-owned connection runtime only after authorization and crash recovery are tested.
3. Add Windows 10/11 integration tests for user logon/logoff, session switching, remote-client rejection, unauthorized SID rejection, malformed/oversized/replayed frames, stop during blocked pipe connect/read, service crash/reboot, and packet-capture leak acceptance.

A green service-host build proves only that the Windows binary compiles and its automated checks pass. It is not evidence of a registered service, a connected desktop client, an active kill switch, or leak prevention.

## Microsoft API references

- [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew) and [named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Impersonating a named-pipe client](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client)
- [WTSGetActiveConsoleSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid)
- [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
- [CancelSynchronousIo](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio)
