# Windows Agent recovery journal

## Implemented foundation

`src-tauri/src/recovery_journal.rs` defines a versioned, bounded, non-secret checkpoint format and a file store used by the privileged Windows Agent at service startup. The service now opens the pre-provisioned protected directory and loads every committed checkpoint before it exposes clean status. This is a fail-closed startup gate, not yet an OS reconciler: it does not start sing-box, create a TUN adapter, change routes or DNS, or install WFP filters.

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

## Read-only reconciliation assessment

`src-tauri/src/recovery_assessment.rs` now compares a journal against an explicitly supplied OS observation snapshot. It is a pure planner and does not query Windows or perform cleanup. Each resource is classified as:

- `VerifiedClean`: positively absent or the exact prior route/DNS state is restored.
- `NeedsCleanup`: the exact journaled engine, tunnel, route, or WFP filter is still present.
- `NeedsRestore`: the exact session-applied route/DNS state still needs its recorded previous value restored.
- `Conflict`: the observation does not match the journal's ownership and expected state.
- `Unknown`: the OS observation is incomplete or cannot safely identify the resource.

The planner uses process creation time with PID, stable tunnel GUID, exact route and DNS values, and provider/layer/filter GUIDs for WFP. It deliberately ignores the WFP runtime filter ID when identifying a filter. Missing route/DNS observations, incomplete WFP enumeration, legacy WFP records that cannot be matched by stable key, unexpected provider-owned filters, PID reuse, and conflicting resource state all keep recovery blocked.

The `can_remove_journal` result is true only when every recorded resource is positively clean and the complete provider-scoped WFP inventory confirms no product-owned filters remain. A future Windows reconciler must gather authoritative snapshots, perform cleanup/restoration using exact ownership checks, take a fresh snapshot, and only then act on this result. This planner does not itself authorize or execute destructive operations.

## Windows read-only resource observers

`src-tauri/src/recovery_observer.rs` now contains read-only Windows observation calls:

- The engine-process probe opens the journaled PID with only query and synchronize rights, checks its wait state, reads the kernel FILETIME creation value, and checks liveness again. A PID that no longer exists is reported absent; access denied, API failures, and inconclusive states are errors and must become `Unknown`. The creation timestamp is compared by the assessment planner, so PID reuse is a conflict rather than permission to terminate another process.
- The tunnel-interface probe reads `GetIfTable2` and matches the stable interface GUID, then checks the journaled interface index, alias, and MTU. It does not yet enumerate unicast IP addresses, so it is not proof that every assigned TUN address matches the journal.
- The route probe reads the full IPv4/IPv6 table with `GetIpForwardTable2(AF_UNSPEC)`, frees the IP Helper snapshot with `FreeMibTable`, and compares canonical destination prefixes, interface indexes, next hops, and metrics. If a destination prefix has multiple rows, it reports `Unknown`: the current journal schema keys routes only by destination prefix and cannot safely disambiguate multiple interfaces.
- The WFP probe calls `WfpEngine::enumerate_owned_filters`. It begins an explicit read-only BFE transaction, creates a provider-key-scoped enumeration handle, reads every bounded page, verifies each returned provider and stable filter GUID, destroys the enumeration handle, and commits the read-only transaction. It returns `Present(empty)` only after a complete successful enumeration. A missing provider, any API error, or an inventory above the 256-filter journal bound remains `Unknown`.

These probes do not stop processes, create/delete filters, alter WFP policy, change routes or DNS, or remove journal files. They are not wired into the Agent startup gate; that gate remains fail-closed. DNS settings are still not represented by a complete read-only observer for every supported Windows DNS configuration, and TUN address enumeration is still incomplete. A route with duplicate destination prefixes also remains unverified until the journal identity is extended to include the interface.

## Security boundary and remaining work

The journal is not an authentication or integrity mechanism. Its trust depends on the service-owned directory ACL and the service's validation of every record. The service must not open a user-writable directory as its journal root. Reparse-point entries are rejected, and files are never selected using a caller-supplied path.

The service now loads the journal at startup and fails closed when the directory is missing/unsafe, a committed record is corrupt, or any prior session remains unresolved. It deliberately does not guess that recorded resources are gone, delete journals, or mutate networking during this gate. The following are still release-blocking work:

- Independently verify the service-owned directory DACL when opening it; installation currently provisions and smoke-tests the protected ACL.
- Wire a checkpoint before each OS mutation and after each successful mutation.
- Implement startup reconciliation against actual process, TUN, route, DNS, and WFP state, then remove a journal only after each recorded resource is confirmed absent/restored.
- Implement rollback in reverse order and only remove journal files after verified cleanup.
- Exercise process/agent crash, forced termination, restart, tampered journal, ACL, and reparse-point cases on real Windows 10/11 machines.

A green installer build or unit test does not prove live network recovery or leak-free VPN operation.
