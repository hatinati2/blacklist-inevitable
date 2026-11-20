# Windows Agent service installation lifecycle

## What this slice installs

The Windows NSIS package now includes the dedicated
`blacklist-inevitable-agent.exe` sidecar beside the desktop executable. The
installer uses Tauri's per-machine mode, so Windows elevation is required before
it can register the privileged service.

The NSIS lifecycle hooks invoke `windows/agent-service.ps1`:

- Before file replacement, an existing service is checked for the expected
  executable path and LocalSystem account, stopped, and disabled. This prevents
  Windows from automatically restarting an old or partially replaced binary
  during an interrupted upgrade.
- After files are installed, both the desktop executable and Agent executable
  must have valid Authenticode signatures whose signer certificate thumbprints
  match exactly. Only then is the service registered or upgraded.
- Before uninstall removes files, the expected service is stopped and deleted.
  The ProgramData directory is retained so future recovery metadata is not
  silently discarded by application removal.

A package in which both binaries are unsigned installs the desktop application
but deliberately skips the privileged Agent service. The NSIS UI explains that
a signed package is required. A partially signed package, an invalid signature,
or a signer mismatch fails closed instead of installing the service.

## Service policy

The installer provisions the service as:

- Service name: `BlacklistInevitableAgent`
- Account: `LocalSystem`
- Start mode: automatic
- Service SID type: `UNRESTRICTED` (the service SID is enabled in the token;
  this is not a restricted-token sandbox)
- Service object DACL: SYSTEM and Administrators receive full access;
  Interactive Users receive query-status access only
- Service executable: the packaged sidecar in the per-machine install folder

LocalSystem is intentional: the current peer-authentication implementation
uses `WTSQueryUserToken`, which Microsoft documents as requiring LocalSystem
and `SE_TCB_NAME`. The service identity is verified after configuration.

The installer obtains the service SID from the Service Control Manager and
protects `%ProgramData%\BlacklistInevitable` and its `Agent` child. Their
protected DACLs contain only SYSTEM and Administrators; the Agent child also
grants full control to the Agent service SID. The directories are checked not
to be reparse points, inherited access is removed, the owner is set to
Administrators, and the resulting principals are verified after applying ACLs.

The installer refuses to modify or delete a service with the same name if its
registered executable path or service account does not match the expected
installation. It also leaves the ProgramData directory in place during
uninstallation.

## Signing boundary

The installer currently checks that both executable signatures are valid in
the local Windows Authenticode trust context and that both files have the same
signer certificate thumbprint. This prevents the installer from pairing an
unsigned Agent with a signed desktop binary or with a different signer.

This is not yet a pinned publisher allow-list. Before public distribution,
release signing must use a stable publisher certificate, the expected
thumbprint must be pinned in the release policy, and the outer NSIS installer
must also be signed. The CI workflow creates an ephemeral code-signing
certificate, trusts it only on the disposable runner, signs both inner
executables, and exercises the real service lifecycle. That CI certificate is
not a production signing identity.

## Validation performed by Windows CI

The installer smoke test verifies:

- the Agent sidecar is present next to the desktop executable;
- the signed CI package installs and starts the service;
- the service runs as LocalSystem and is configured for automatic startup;
- the service SID is enabled;
- the service DACL grants only the expected service-management rights;
- the ProgramData directory ACL contains only SYSTEM, Administrators, and the
  service SID, with inheritance disabled;
- the desktop application launches;
- uninstall stops and removes the service and both executables.

The unsigned-package branch is also checked: no privileged service may be
registered when both binaries lack Authenticode signatures.

A successful CI smoke test demonstrates installer/service lifecycle behavior
on the hosted Windows runner. It does not replace integration testing on
Windows 10/11 physical machines, and does not prove that VPN traffic is
protected. The Agent still exposes status-only IPC; Connect, Disconnect, and
Recover remain rejected, and no WFP/TUN/route/DNS operation is enabled.

## References

- [Tauri Windows installer hooks and per-machine install mode](https://v2.tauri.app/distribute/windows-installer/)
- [Tauri external binaries configuration](https://v2.tauri.app/reference/config/)
- [Microsoft: WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
- [Microsoft: configuring services with SC.exe](https://learn.microsoft.com/en-us/windows/win32/services/configuring-a-service-using-sc)
