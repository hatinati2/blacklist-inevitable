# Windows Agent recovery journal

## Implemented foundation

`src-tauri/src/recovery_journal.rs` defines a versioned, bounded, non-secret checkpoint format and a file store used by the privileged Windows Agent. The service now performs a deliberately narrow startup recovery for WFP-only sessions; it does not start sing-box, create a TUN adapter, change routes or DNS, or activate a traffic policy.

A journal records only the resource identities and exact previous settings needed for recovery:

- Engine PID plus its Windows process-creation timestamp, so recovery can distinguish PID reuse.
- TUN adapter GUID, interface index, alias, MTU, and assigned addresses.
- Each route state applied by the session and the previous route state, if one existed.
- DNS mode and server list applied to each interface, plus the previous DHCP/static configuration.
- WFP provider/layer GUIDs, stable filter GUIDs, and optional BFE runtime filter IDs owned by the session. The stable filter GUID is the only supported deletion/read-back key. The runtime ID is diagnostic only and may be absent in a pre-mutation intent checkpoint.

The schema does not contain profile credentials, share links, engine JSON, command lines, executable paths, or arbitrary filesystem paths. All collections and the serialized file size have explicit upper bounds. Unknown fields and unsupported schema versions are rejected.

`FirewallFilterRecord.filterKey` is optional only for compatibility with older version-1 records that predate stable filter-key recording. Newly created WFP filter records must always include a canonical filter GUID. `filterId` is optional so a complete stable-key intent can be persisted before adding a filter; after a successful BFE read-back, a later journal revision may attach the runtime ID for diagnostics. Recovery must never attempt to delete a legacy filter using only its runtime ID; it must enumerate and reconcile exact provider-owned filters or leave policy cleanup unconfirmed.

## Storage and recovery semantics

The privileged service installer must create the journal directory before the service starts. The directory must be owned by the service identity and have a restrictive DACL that prevents modification by ordinary users. The module deliberately does not create the root directory or set its ACL.

For each checkpoint, the store validates the full record, creates a unique pending file with create-new semantics, writes and flushes its contents, then commits it under a unique session/revision filename. On Windows the commit uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`. Incomplete pending files are ignored; a committed but corrupt, oversized, reparse-point, or filename-mismatched record makes recovery fail closed.

`load_unresolved` returns the newest committed revision for each session. A new revision must be greater than the prior committed revision. The service must reconcile every returned session against actual process, adapter, route, DNS, and WFP state before accepting a new Connect request.

`remove_session` is idempotent, but it must only be called after the service has independently verified engine exit, TUN teardown, route/DNS restoration, and WFP filter cleanup. A journal is not a substitute for checking the real operating-system state.

## WFP exact-removal backend foundation

The Windows-only `WfpEngine::remove_owned_filters` primitive accepts only journalled stable filter GUIDs. It refuses legacy runtime-ID-only entries, non-Agent provider GUIDs, unsupported layers, duplicate keys, and any read-back whose provider, sublayer, layer, persistence flag, or recorded runtime ID differs from the journal. It performs all exact deletions in one WFP transaction, commits once, then queries every key again and requires each to be absent.

The optional runtime ID supports the crash window between writing a stable-key intent checkpoint and obtaining the BFE ID. A filter that is already absent is treated as idempotently cleaned, but journal removal is still the caller's responsibility after all other resource types are restored and independently verified. Microsoft documents that `FwpmFilterDeleteByKey0` requires DELETE access and `FwpmFilterGetByKey0` requires WFP READ access on the filter.

The Windows CI now has an opt-in live-BFE smoke test that adds test filters, reads each one back, deletes each by stable key, and aborts the encompassing write transaction. This exercises the real add/read-back/delete API sequence without committing any traffic filter. The test also provisions only the Agent's persistent provider/sublayer metadata on the disposable hosted runner; it does not install a network policy. The test runs in an administrative CI context and does **not** prove access under the restricted LocalSystem Agent service token.

The scoped WFP access model places rights at the object where each operation checks access: Engine `BEGIN_WRITE_TXN`; Agent provider and sublayer `READ | ADD_LINK`; target ALE layer objects `ADD_LINK`; Filter-container `ADD`; and per-filter `READ | DELETE` through an explicit descriptor passed to `FwpmFilterAdd0`. The Filter-container ACE is non-inheriting. The restricted service receives no generic write/all, no global provider/sublayer ADD, and no container-wide READ/DELETE permissions.

The Windows acceptance workflow seeds the persistent Agent provider/sublayer on a disposable hosted runner, snapshots the DACLs for the Engine, provider, sublayer, both target ALE layers, and Filter container, then applies the scoped ACEs for a LocalSystem SCM service with `SERVICE_SID_TYPE_RESTRICTED`. The service persists a pre-mutation `FirewallFilterRecord` set containing stable GUIDs but no runtime IDs, commits four synthetic persistent filters with per-filter `READ | DELETE` descriptors, reloads the on-disk journal, and invokes `remove_owned_filters` in a separate committed WFP transaction. It then invokes the same recovery again to require idempotent already-absent results. Only after all filter keys are verified absent does it remove the journal session. It also persists and reloads the post-add runtime-ID revision.

The probe uses TEST-NET endpoint addresses and a deliberately non-existent interface LUID/index. Four real persistent test filters are briefly committed on the disposable CI machine and are removed before success; this is not a production traffic policy and the runner is discarded after the workflow. The test requires the journal to be absent after verified cleanup. On exit, the harness restores all captured WFP DACLs in reverse order and verifies exact byte-for-byte equality; any failed restoration fails CI.

This proves the current scoped ACL and journaled exact-filter-removal path under the restricted service token on the hosted runner. It does not prove that all crash windows have been reconciled, that a filter will be safely removed after sudden power loss, or that Windows 10/11 production installation ACLs have been provisioned. The production service remains status-only and does not install or activate WFP traffic policy. Its startup path now uses this exact-removal backend only for isolated WFP-only recovery journals.

Agent startup now performs a narrowly scoped WFP-only reconciliation before exposing its status pipe. A journal is eligible only when it contains one or more firewall filter records and has no engine process, TUN interface, route, or DNS records. For each eligible session, the service opens BFE and calls `WfpEngine::remove_owned_filters`, which validates provider ownership, sublayer, layer, persistence, stable filter GUID, and any recorded runtime ID; it clears the journal only after the exact keys are independently confirmed absent. If access is denied, identity validation fails, or journal cleanup fails, the session remains unresolved and startup diagnostics report the failure. Journals containing any engine, TUN, route, or DNS state are deliberately deferred without partial cleanup. The Agent remains status-only: this recovery path does not install filters, start sing-box, change routes/DNS, or activate a kill switch.

## Production installer WFP ACL provisioning

The per-machine Agent installer now bundles `scripts/windows-agent-wfp-acl.ps1`. After creating the LocalSystem service and enabling its restricted service SID, the installer invokes the helper to verify or create the persistent Agent provider/sublayer namespace and provision six non-inheriting object-scoped grants:

- Engine: `BEGIN_WRITE_TXN` only.
- Agent provider and sublayer: `READ | ADD_LINK`.
- ALE_AUTH_CONNECT_V4 and ALE_AUTH_CONNECT_V6 layer objects: `ADD_LINK` only.
- Filter container: `ADD` only; no inheritance.

The helper preserves the existing DACL by adding only the Agent service SID ACE. It refuses NULL DACLs and verifies the provider/sublayer identity and persistence flags before granting access. If provisioning fails part-way, it attempts to remove the grants it just applied and the installer does not start the service. Uninstall/upgrade stops the service, removes only that service SID's six ACEs, then deletes the SCM service. Persistent provider/sublayer metadata is intentionally left in place; no traffic filters are installed or removed by the installer helper.

The Windows restricted-SID acceptance probe now calls this same provision/remove helper, then exercises the service's journaled WFP filter add/read/delete path. The harness snapshots all six DACLs and restores them byte-for-byte after the test. This validates the helper's WFP ACL operations on a disposable hosted runner. It does not exercise the signed production installer because the repository's publisher thumbprint remains `UNCONFIGURED`; a trusted signed install and clean Windows 10/11 verification remain release gates.

## Agent-owned persistent ALE policy transaction

The Windows WFP backend now exposes
`WfpEngine::install_egress_policy_for_service_sid`. It requires the restricted
Agent service SID and a valid session journal, flushes every stable filter GUID
before the first filter mutation, adds the complete bounded plan in one WFP
transaction, commits once, reads every committed filter back, and persists a
second journal revision with the BFE runtime IDs. If the transaction or the
post-commit checkpoint/read-back fails, the durable stable-key intent is retained
and the caller must keep the session blocked; startup reconciliation can remove
only those exact Agent-owned keys.

The install plan is capped at 256 filters so the policy cannot exceed the journal
schema's 256-filter capacity. The restricted-SID live CI acceptance path now
calls this same install API with TEST-NET endpoints and a deliberately nonexistent
interface identity, then reloads the journal and verifies exact-key deletion and
idempotent absence on the disposable Windows runner.

**This is an ALE connection-authorization milestone, not the complete physical
egress kill switch.** The current plan uses only
`ALE_AUTH_CONNECT_V4/V6`; it does not yet install packet-layer filters for every
protocol or multicast/broadcast path, classify physical versus virtual adapters,
wire policy installation into production Connect, or implement route/DNS/engine
lifecycle rollback. The installer/CI smoke test does not establish leak-free
traffic behavior. Keep Connect disabled until the broader WFP policy and
Windows 10/11 physical-adapter packet-capture gates pass.

## Security boundary and remaining work

The journal is not an authentication or integrity mechanism. Its trust depends on the service-owned directory ACL and the service's validation of every record. The service must not open a user-writable directory as its journal root. Reparse-point entries are rejected, and files are never selected using a caller-supplied path.

The Windows Agent now opens this journal during service startup, before making its authenticated pipe available, and fails closed if committed state is missing, unsafe, or corrupt. It reports unresolved-session counts but does not yet reconcile those records with `ConnectionCoordinator` or restore operating-system resources. This is a startup inventory check, not periodic reconciliation or proof that the network was restored. The following are still release-blocking work:

- [x] Provision the service-owned journal directory and the six limited WFP ACL grants through the signed per-machine Agent installer; remove only the service SID ACEs on upgrade/uninstall.
- Wire a checkpoint before each OS mutation and after each successful mutation.
- [x] Reconcile isolated WFP-only startup journals by exact stable filter key; retain the journal on any WFP or journal-cleanup failure.
- Implement full startup reconciliation against actual process, TUN, route, DNS, and mixed WFP state; mixed-resource sessions remain deferred until reverse-order cleanup is implemented.
- Implement rollback in reverse order and only remove journal files after verified cleanup.
- Exercise process/agent crash, forced termination, restart, tampered journal, ACL, and reparse-point cases on real Windows 10/11 machines.

A green installer build or unit test does not prove live network recovery or leak-free VPN operation.
