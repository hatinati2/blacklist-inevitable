# Windows Agent recovery journal

## Implemented foundation

`src-tauri/src/recovery_journal.rs` defines a versioned, bounded, non-secret checkpoint format and a file store for the future privileged Windows Agent. It is a persistence primitive only: it does not start sing-box, create a TUN adapter, change routes or DNS, install WFP filters, or run a Windows service.

A journal records only the resource identities and exact previous settings needed for recovery:

- Engine PID plus its Windows process-creation timestamp, so recovery can distinguish PID reuse.
- TUN adapter GUID, interface index, alias, MTU, and assigned addresses.
- Each route state applied by the session and the previous route state, if one existed.
- DNS mode and server list applied to each interface, plus the previous DHCP/static configuration.
- WFP provider/layer GUIDs, stable filter GUIDs when available, and BFE runtime filter IDs owned by the session. The stable filter GUID is the deletion/read-back key; the runtime ID is diagnostic only.

The schema does not contain profile credentials, share links, engine JSON, command lines, executable paths, or arbitrary filesystem paths. All collections and the serialized file size have explicit upper bounds. Unknown fields and unsupported schema versions are rejected.

`FirewallFilterRecord.filterKey` is optional only for compatibility with older version-1 records that predate stable filter-key recording. Newly created WFP filter records must always include a canonical filter GUID. Recovery must never attempt to delete a legacy filter using only its runtime ID; it must enumerate and reconcile exact provider-owned filters or leave policy cleanup unconfirmed.

## Storage and recovery semantics

The privileged service installer must create the journal directory before the service starts. The directory must be owned by the service identity and have a restrictive DACL that prevents modification by ordinary users. The module deliberately does not create the root directory or set its ACL.

For each checkpoint, the store validates the full record, creates a unique pending file with create-new semantics, writes and flushes its contents, then commits it under a unique session/revision filename. On Windows the commit uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`. Incomplete pending files are ignored; a committed but corrupt, oversized, reparse-point, or filename-mismatched record makes recovery fail closed.

`load_unresolved` returns the newest committed revision for each session. A new revision must be greater than the prior committed revision. The service must reconcile every returned session against actual process, adapter, route, DNS, and WFP state before accepting a new Connect request.

`remove_session` is idempotent, but it must only be called after the service has independently verified engine exit, TUN teardown, route/DNS restoration, and WFP filter cleanup. A journal is not a substitute for checking the real operating-system state.

## Security boundary and remaining work

The journal is not an authentication or integrity mechanism. Its trust depends on the service-owned directory ACL and the service's validation of every record. The service must not open a user-writable directory as its journal root. Reparse-point entries are rejected, and files are never selected using a caller-supplied path.

The current code is not yet connected to `ConnectionCoordinator` or a Windows service. The following are still release-blocking work:

- Provision and verify the service-owned directory DACL during agent installation.
- Wire a checkpoint before each OS mutation and after each successful mutation.
- Implement startup reconciliation against actual process, TUN, route, DNS, and WFP state.
- Implement rollback in reverse order and only remove journal files after verified cleanup.
- Exercise process/agent crash, forced termination, restart, tampered journal, ACL, and reparse-point cases on real Windows 10/11 machines.

A green installer build or unit test does not prove live network recovery or leak-free VPN operation.
