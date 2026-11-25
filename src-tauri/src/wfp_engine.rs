//! Minimal Windows Filtering Platform engine and persistent namespace ownership.
//!
//! The provider/sublayer setup is durable metadata only. Filter validation uses an
//! explicit WFP write transaction and always aborts it after read-back, leaving no
//! traffic filters installed. This module does not enable a kill switch. It must only
//! be called by a future authenticated privileged service, never by the unelevated UI.

#[cfg(windows)]
use windows_sys::core::GUID;

#[cfg(windows)]
const PROVIDER_KEY: GUID = GUID::from_u128(0x9d45d56a_6b31_48aa_9c45_72c8b25e2f10);
#[cfg(windows)]
const SUBLAYER_KEY: GUID = GUID::from_u128(0x4aabbc48_c0a2_4f76_9f2a_0a90da1caa37);

#[cfg(windows)]
fn guid_to_u128(value: &GUID) -> u128 {
    ((value.data1 as u128) << 96)
        | ((value.data2 as u128) << 80)
        | ((value.data3 as u128) << 64)
        | (u64::from_be_bytes(value.data4) as u128)
}

#[cfg(windows)]
fn guid_eq(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

#[cfg(windows)]
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
#[cfg(windows)]
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
#[cfg(windows)]
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterValidationReport {
    /// Number of complete IPv4/IPv6 filter objects added and read back inside
    /// the transaction before it was rolled back.
    pub validated_filter_count: usize,
    /// Number of generated filter keys confirmed absent after rollback.
    pub rolled_back_filter_count: usize,
}

#[cfg(windows)]
struct FilterSecurityDescriptor(*mut core::ffi::c_void);

#[cfg(windows)]
impl FilterSecurityDescriptor {
    fn for_service_sid(service_sid: &str) -> Result<Self, String> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;

        let service_sid_suffix = service_sid.strip_prefix("S-1-5-80-");
        if service_sid.len() > 128
            || service_sid_suffix.is_none_or(|suffix| {
                let parts: Vec<_> = suffix.split('-').collect();
                parts.len() != 5
                    || parts.iter().any(|part| {
                        part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
                    })
            })
        {
            return Err("The restricted Agent service SID has an invalid service-SID representation.".into());
        }

        // Keep filter-object permissions local to Agent-created filters. The
        // filter container receives ADD only; READ/DELETE are attached to each
        // owned filter through this explicit security descriptor.
        let sddl = format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00010080;;;{service_sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        let mut descriptor_size = 0u32;
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                &mut descriptor_size,
            )
        };
        if converted == 0 || descriptor.is_null() || descriptor_size == 0 {
            return Err(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed with Windows error {}.",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            ));
        }
        Ok(Self(descriptor))
    }

    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for FilterSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterRemovalReport {
    /// Filters deleted inside the committed WFP transaction and confirmed absent.
    pub removed_filter_count: usize,
    /// Journalled filter keys that were already absent before the transaction.
    pub already_absent_filter_count: usize,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum ExpectedCondition {
    InterfaceLuid(u64),
    RemoteIpv4 { address: u32, mask: u32 },
    RemoteIpv6 { address: [u8; 16], prefix_length: u8 },
    RemotePort(u16),
    IpProtocol(u8),
}

#[cfg(windows)]
fn ipv4_addr_host_order(address: std::net::Ipv4Addr) -> u32 {
    // FWP_V4_ADDR_AND_MASK explicitly uses host byte order.
    u32::from_ne_bytes(address.octets())
}

#[cfg(all(test, windows))]
mod ipv4_wfp_order_tests {
    use super::ipv4_addr_host_order;

    #[test]
    fn address_is_encoded_in_host_order_without_reversing_network_octets() {
        let address = std::net::Ipv4Addr::new(203, 0, 113, 8);
        assert_eq!(ipv4_addr_host_order(address).to_ne_bytes(), [203, 0, 113, 8]);
    }
}

#[cfg(windows)]
fn expected_condition_key(value: ExpectedCondition) -> GUID {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
        FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    };
    match value {
        ExpectedCondition::InterfaceLuid(_) => FWPM_CONDITION_IP_LOCAL_INTERFACE,
        ExpectedCondition::RemoteIpv4 { .. } | ExpectedCondition::RemoteIpv6 { .. } => {
            FWPM_CONDITION_IP_REMOTE_ADDRESS
        }
        ExpectedCondition::RemotePort(_) => FWPM_CONDITION_IP_REMOTE_PORT,
        ExpectedCondition::IpProtocol(_) => FWPM_CONDITION_IP_PROTOCOL,
    }
}

#[cfg(windows)]
fn wfp_layer_guid(layer: crate::wfp_policy::WfpLayer) -> GUID {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };
    match layer {
        crate::wfp_policy::WfpLayer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        crate::wfp_policy::WfpLayer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}

#[cfg(windows)]
pub struct WfpEngine {
    handle: windows_sys::Win32::Foundation::HANDLE,
    poisoned: bool,
}

#[cfg(windows)]
unsafe impl Send for WfpEngine {}

#[cfg(windows)]
impl WfpEngine {
    /// Open the local Base Filtering Engine. Callers must run in an authorized
    /// service context. A successful open does not imply any filter is installed.
    pub fn open_local() -> Result<Self, String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0;
        use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                std::ptr::null(),
                &mut handle,
            )
        };
        if status != 0 {
            return Err(format!("FwpmEngineOpen0 failed with Windows status 0x{status:08X}."));
        }
        if handle.is_null() {
            return Err("FwpmEngineOpen0 succeeded without returning an engine handle.".into());
        }
        Ok(Self { handle, poisoned: false })
    }

    fn ensure_open(&self) -> Result<(), String> {
        if self.handle.is_null() || self.poisoned {
            return Err("The WFP engine session is closed or poisoned after an unconfirmed transaction; open a new session.".into());
        }
        Ok(())
    }

    /// Abort the current WFP transaction. If BFE cannot confirm the abort,
    /// poison and close this session: Microsoft documents that destroying the
    /// session makes BFE abort any remaining transaction automatically.
    fn abort_transaction_or_poison(&mut self) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineClose0, FwpmTransactionAbort0,
        };

        let abort = unsafe { FwpmTransactionAbort0(self.handle) };
        if abort == 0 {
            return Ok(());
        }

        self.poisoned = true;
        let close = unsafe { FwpmEngineClose0(self.handle) };
        if close == 0 {
            self.handle = std::ptr::null_mut();
            return Err(format!(
                "FwpmTransactionAbort0 failed (0x{abort:08X}); the WFP engine session was closed to force BFE rollback."
            ));
        }

        Err(format!(
            "FwpmTransactionAbort0 failed (0x{abort:08X}) and FwpmEngineClose0 also failed (0x{close:08X}); this session is poisoned and must not be reused. Drop will retry closing it."
        ))
    }

    /// Ensure this product's persistent WFP provider and sublayer exist.
    ///
    /// Existing objects are accepted only when their stable keys, persistence
    /// flags, and provider ownership match this binary's namespace. This is a
    /// metadata operation only: no filters are created and no traffic is changed.
    pub fn ensure_persistent_namespace(&mut self) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmProviderAdd0, FwpmProviderGetByKey0, FwpmSubLayerAdd0,
            FwpmSubLayerGetByKey0, FwpmTransactionBegin0, FwpmTransactionCommit0,
            FwpmFreeMemory0, FWPM_DISPLAY_DATA0, FWPM_PROVIDER0,
            FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
        };

        self.ensure_open()?;
        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }

        let operation = (|| -> Result<(), String> {
            let mut provider_ptr = std::ptr::null_mut();
            let provider_status = unsafe {
                FwpmProviderGetByKey0(self.handle, &PROVIDER_KEY, &mut provider_ptr)
            };
            if provider_status == 0 {
                if provider_ptr.is_null() {
                    return Err("WFP provider lookup returned a null object.".into());
                }
                let provider = unsafe { &*provider_ptr };
                let valid = guid_eq(&provider.providerKey, &PROVIDER_KEY)
                    && provider.flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0;
                let mut allocation = provider_ptr.cast();
                unsafe { FwpmFreeMemory0(&mut allocation) };
                if !valid {
                    return Err("The existing WFP provider key is not owned by the expected persistent policy.".into());
                }
            } else if provider_status == FWP_E_PROVIDER_NOT_FOUND {
                let mut name: Vec<u16> = "Blacklist Inevitable VPN Agent".encode_utf16().chain(Some(0)).collect();
                let provider = FWPM_PROVIDER0 {
                    providerKey: PROVIDER_KEY,
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: name.as_mut_ptr(),
                        description: std::ptr::null_mut(),
                    },
                    flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                    providerData: unsafe { std::mem::zeroed() },
                    serviceName: std::ptr::null_mut(),
                };
                let add = unsafe { FwpmProviderAdd0(self.handle, &provider, std::ptr::null_mut()) };
                if add != 0 && add != FWP_E_ALREADY_EXISTS {
                    return Err(format!("FwpmProviderAdd0 failed with Windows status 0x{add:08X}."));
                }
            } else {
                return Err(format!("FwpmProviderGetByKey0 failed with Windows status 0x{provider_status:08X}."));
            }

            let mut sublayer_ptr = std::ptr::null_mut();
            let sublayer_status = unsafe {
                FwpmSubLayerGetByKey0(self.handle, &SUBLAYER_KEY, &mut sublayer_ptr)
            };
            if sublayer_status == 0 {
                if sublayer_ptr.is_null() {
                    return Err("WFP sublayer lookup returned a null object.".into());
                }
                let sublayer = unsafe { &*sublayer_ptr };
                let provider_matches = !sublayer.providerKey.is_null()
                    && guid_eq(unsafe { &*sublayer.providerKey }, &PROVIDER_KEY);
                let valid = guid_eq(&sublayer.subLayerKey, &SUBLAYER_KEY)
                    && sublayer.flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
                    && provider_matches;
                let mut allocation = sublayer_ptr.cast();
                unsafe { FwpmFreeMemory0(&mut allocation) };
                if !valid {
                    return Err("The existing WFP sublayer is not owned by the expected persistent provider.".into());
                }
            } else if sublayer_status == FWP_E_SUBLAYER_NOT_FOUND {
                let mut name: Vec<u16> = "Blacklist Inevitable VPN egress policy".encode_utf16().chain(Some(0)).collect();
                let sublayer = FWPM_SUBLAYER0 {
                    subLayerKey: SUBLAYER_KEY,
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: name.as_mut_ptr(),
                        description: std::ptr::null_mut(),
                    },
                    flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
                    providerData: unsafe { std::mem::zeroed() },
                    weight: 0x7FFF,
                };
                let add = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, std::ptr::null_mut()) };
                if add != 0 && add != FWP_E_ALREADY_EXISTS {
                    return Err(format!("FwpmSubLayerAdd0 failed with Windows status 0x{add:08X}."));
                }
            } else {
                return Err(format!("FwpmSubLayerGetByKey0 failed with Windows status 0x{sublayer_status:08X}."));
            }
            Ok(())
        })();

        if let Err(error) = operation {
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }

        let commit = unsafe { FwpmTransactionCommit0(self.handle) };
        if commit != 0 {
            let error = format!("FwpmTransactionCommit0 failed with Windows status 0x{commit:08X}.");
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }
        Ok(())
    }

    /// Ask BFE to validate a complete dual-stack policy plan inside one explicit
    /// write transaction: add each filter, read it back, delete it by its stable
    /// key, then ABORT the transaction.
    ///
    /// No traffic policy is committed or left installed. The former design tried
    /// to add FWPM_FILTER_FLAG_DISABLED, but Microsoft documents that this flag
    /// cannot be supplied when adding a new filter. A rollback-only transaction
    /// exercises both the add/read-back and exact-key delete APIs without changing
    /// packet handling.
    pub fn validate_egress_policy_transaction(
        &mut self,
        spec: &crate::wfp_policy::EgressPolicySpec,
    ) -> Result<FilterValidationReport, String> {
        self.validate_egress_policy_transaction_with_filter_sd(spec, std::ptr::null_mut())
    }

    /// Rollback-only validation with a per-filter security descriptor. The
    /// descriptor is supplied to FwpmFilterAdd0 so READ/DELETE rights can be
    /// granted only on these exact Agent-owned filter objects.
    pub fn validate_egress_policy_transaction_for_service_sid(
        &mut self,
        spec: &crate::wfp_policy::EgressPolicySpec,
        service_sid: &str,
    ) -> Result<FilterValidationReport, String> {
        let descriptor = FilterSecurityDescriptor::for_service_sid(service_sid)?;
        self.validate_egress_policy_transaction_with_filter_sd(spec, descriptor.as_ptr())
    }

    fn validate_egress_policy_transaction_with_filter_sd(
        &mut self,
        spec: &crate::wfp_policy::EgressPolicySpec,
        filter_security_descriptor: *mut core::ffi::c_void,
    ) -> Result<FilterValidationReport, String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionBegin0;

        self.ensure_open()?;
        let plan = spec.compile_plan()?;
        self.ensure_persistent_namespace()?;

        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }

        let mut generated_keys = Vec::with_capacity(plan.filters.len());
        let operation = (|| -> Result<(), String> {
            for planned in &plan.filters {
                let key = GUID::from_u128(uuid::Uuid::new_v4().as_u128());
                generated_keys.push(key);
                self.add_and_verify_planned_filter(key, planned, filter_security_descriptor)?;

                let deletion = unsafe {
                    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteByKey0(
                        self.handle,
                        &key,
                    )
                };
                if deletion != 0 {
                    return Err(format!(
                        "FwpmFilterDeleteByKey0 failed during rollback-only WFP validation with Windows status 0x{deletion:08X}."
                    ));
                }
            }
            Ok(())
        })();

        if let Err(abort_error) = self.abort_transaction_or_poison() {
            return match operation {
                Ok(()) => Err(format!("{abort_error} Do not continue with network policy.")),
                Err(operation_error) => Err(format!("{operation_error} {abort_error} Do not continue with network policy.")),
            };
        }

        for key in &generated_keys {
            verify_filter_absent(self.handle, key)?;
        }

        operation?;
        Ok(FilterValidationReport {
            validated_filter_count: generated_keys.len(),
            rolled_back_filter_count: generated_keys.len(),
        })
    }

    /// Remove only exact, persistent filters owned by this Agent provider.
    ///
    /// The caller must load these records from the protected recovery journal.
    /// A stable filter GUID is mandatory; legacy records containing only a BFE
    /// runtime ID are deliberately not actionable. The provider, sublayer, layer,
    /// persistence flag, and optional runtime ID are read back before deletion.
    /// All deletions are committed as one WFP transaction and every key is then
    /// queried again. The caller must retain the journal unless this verification
    /// succeeds.
    pub fn remove_owned_filters(
        &mut self,
        records: &[crate::recovery_journal::FirewallFilterRecord],
    ) -> Result<FilterRemovalReport, String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterDeleteByKey0, FwpmFilterGetByKey0, FwpmFreeMemory0,
            FwpmTransactionBegin0, FwpmTransactionCommit0,
            FWPM_FILTER_FLAG_PERSISTENT,
        };

        const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;

        self.ensure_open()?;
        let exact_keys = validate_owned_filter_records(records)?;
        if exact_keys.is_empty() {
            return Ok(FilterRemovalReport {
                removed_filter_count: 0,
                already_absent_filter_count: 0,
            });
        }

        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }

        let mut removed_filter_count = 0usize;
        let mut already_absent_filter_count = 0usize;
        let operation = (|| -> Result<(), String> {
            for identity in &exact_keys {
                let key = &identity.filter_key;
                let mut filter_ptr = std::ptr::null_mut();
                let lookup = unsafe { FwpmFilterGetByKey0(self.handle, key, &mut filter_ptr) };
                if lookup == FWP_E_FILTER_NOT_FOUND {
                    already_absent_filter_count += 1;
                    continue;
                }
                if lookup != 0 {
                    return Err(format!(
                        "FwpmFilterGetByKey0 failed during recovery with Windows status 0x{lookup:08X}."
                    ));
                }
                if filter_ptr.is_null() {
                    return Err("WFP recovery lookup returned a null filter object.".into());
                }

                let verified = (|| -> Result<(), String> {
                    let filter = unsafe { &*filter_ptr };
                    let provider_matches = !filter.providerKey.is_null()
                        && guid_eq(unsafe { &*filter.providerKey }, &PROVIDER_KEY);
                    if !guid_eq(&filter.filterKey, key)
                        || filter.filterId == 0
                        || !provider_matches
                        || !guid_eq(&filter.subLayerKey, &SUBLAYER_KEY)
                        || !guid_eq(&filter.layerKey, &identity.layer_key)
                        || filter.flags & FWPM_FILTER_FLAG_PERSISTENT == 0
                        || identity.expected_runtime_id.is_some_and(|id| id != filter.filterId)
                    {
                        return Err("A journalled WFP filter key resolved to an object whose provider, sublayer, layer, persistence, or runtime identity did not match; deletion was refused.".into());
                    }
                    Ok(())
                })();
                let mut allocation = filter_ptr.cast();
                unsafe { FwpmFreeMemory0(&mut allocation) };
                verified?;

                let deletion = unsafe { FwpmFilterDeleteByKey0(self.handle, key) };
                if deletion != 0 {
                    return Err(format!(
                        "FwpmFilterDeleteByKey0 failed during recovery with Windows status 0x{deletion:08X}."
                    ));
                }
                removed_filter_count += 1;
            }
            Ok(())
        })();

        if let Err(error) = operation {
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }

        let commit = unsafe { FwpmTransactionCommit0(self.handle) };
        if commit != 0 {
            let error = format!("FwpmTransactionCommit0 failed during WFP recovery with Windows status 0x{commit:08X}.");
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }

        for identity in &exact_keys {
            verify_filter_absent(self.handle, &identity.filter_key)?;
        }

        Ok(FilterRemovalReport {
            removed_filter_count,
            already_absent_filter_count,
        })
    }

    fn add_and_verify_planned_filter(
        &self,
        filter_key: GUID,
        planned: &crate::wfp_policy::PlannedFilter,
        filter_security_descriptor: *mut core::ffi::c_void,
    ) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterAdd0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_DISPLAY_DATA0,
            FWPM_FILTER0, FWPM_FILTER0_0, FWPM_FILTER_FLAG_PERSISTENT,
            FWPM_FILTER_CONDITION0, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
            FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
            FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
            FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
        };

        let mut interface_luid = planned.interface_luid;
        let mut remote_port = 0u16;
        let mut ip_protocol = 0u8;
        let mut remote_v4 = FWP_V4_ADDR_AND_MASK { addr: 0, mask: u32::MAX };
        let mut remote_v6 = FWP_V6_ADDR_AND_MASK { addr: [0; 16], prefixLength: 128 };
        let mut expected = vec![ExpectedCondition::InterfaceLuid(interface_luid)];
        let mut conditions = Vec::<FWPM_FILTER_CONDITION0>::with_capacity(4);

        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: expected_condition_key(expected[0]),
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: &mut interface_luid,
                },
            },
        });

        let (action, weight, label) = match planned.intent {
            crate::wfp_policy::FilterIntent::BlockOtherPhysicalEgress => {
                (FWP_ACTION_BLOCK, 0x0E, "physical egress block")
            }
            crate::wfp_policy::FilterIntent::PermitVpnEndpoint(endpoint) => {
                remote_port = endpoint.port;
                ip_protocol = match endpoint.protocol {
                    crate::wfp_policy::TransportProtocol::Tcp => 6,
                    crate::wfp_policy::TransportProtocol::Udp => 17,
                };
                let remote_condition = match endpoint.address {
                    std::net::IpAddr::V4(address) => {
                        // FWPM_CONDITION_IP_REMOTE_ADDRESS expects FWP_V4_ADDR_AND_MASK in host order.
                        remote_v4.addr = ipv4_addr_host_order(address);
                        let value = ExpectedCondition::RemoteIpv4 {
                            address: remote_v4.addr,
                            mask: remote_v4.mask,
                        };
                        conditions.push(FWPM_FILTER_CONDITION0 {
                            fieldKey: expected_condition_key(value),
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_V4_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v4AddrMask: &mut remote_v4,
                                },
                            },
                        });
                        value
                    }
                    std::net::IpAddr::V6(address) => {
                        remote_v6.addr = address.octets();
                        let value = ExpectedCondition::RemoteIpv6 {
                            address: remote_v6.addr,
                            prefix_length: remote_v6.prefixLength,
                        };
                        conditions.push(FWPM_FILTER_CONDITION0 {
                            fieldKey: expected_condition_key(value),
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_V6_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v6AddrMask: &mut remote_v6,
                                },
                            },
                        });
                        value
                    }
                };
                expected.push(remote_condition);
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: expected_condition_key(ExpectedCondition::RemotePort(remote_port)),
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: remote_port },
                    },
                });
                expected.push(ExpectedCondition::RemotePort(remote_port));
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: expected_condition_key(ExpectedCondition::IpProtocol(ip_protocol)),
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: ip_protocol },
                    },
                });
                expected.push(ExpectedCondition::IpProtocol(ip_protocol));
                (FWP_ACTION_PERMIT, 0x0F, "VPN endpoint permit")
            }
        };

        let mut name: Vec<u16> = format!("Blacklist Inevitable staged {label}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut filter_id = 0u64;
        let filter = FWPM_FILTER0 {
            filterKey: filter_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            providerData: unsafe { std::mem::zeroed() },
            layerKey: wfp_layer_guid(planned.layer),
            subLayerKey: SUBLAYER_KEY,
            weight: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                    uint8: weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::from_u128(0),
                },
            },
            Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
            reserved: std::ptr::null_mut(),
            filterId: 0,
            effectiveWeight: unsafe { std::mem::zeroed() },
        };

        let add = unsafe {
            FwpmFilterAdd0(self.handle, &filter, filter_security_descriptor, &mut filter_id)
        };
        if add != 0 {
            return Err(format!("FwpmFilterAdd0({label}) failed with Windows status 0x{add:08X}."));
        }
        if filter_id == 0 {
            return Err(format!("FwpmFilterAdd0({label}) returned an invalid zero filter ID."));
        }

        verify_staged_filter(
            self.handle,
            &filter_key,
            filter_id,
            planned,
            action,
            weight,
            &expected,
        )
    }

    /// Remove only this product's WFP provider and sublayer after a separate
    /// reconciliation step has proved no owned filters remain. Never call this
    /// during ordinary disconnect before filters have been enumerated and removed.
    pub fn remove_empty_persistent_namespace(&mut self) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmProviderDeleteByKey0, FwpmSubLayerDeleteByKey0,
            FwpmTransactionBegin0, FwpmTransactionCommit0,
        };

        self.ensure_open()?;
        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }
        let sublayer = unsafe { FwpmSubLayerDeleteByKey0(self.handle, &SUBLAYER_KEY) };
        if sublayer != 0 {
            let error = format!("FwpmSubLayerDeleteByKey0 failed with Windows status 0x{sublayer:08X}.");
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }
        let provider = unsafe { FwpmProviderDeleteByKey0(self.handle, &PROVIDER_KEY) };
        if provider != 0 {
            let error = format!("FwpmProviderDeleteByKey0 failed with Windows status 0x{provider:08X}.");
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }
        let commit = unsafe { FwpmTransactionCommit0(self.handle) };
        if commit != 0 {
            let error = format!("FwpmTransactionCommit0 failed with Windows status 0x{commit:08X}.");
            return match self.abort_transaction_or_poison() {
                Ok(()) => Err(error),
                Err(abort_error) => Err(format!("{error} {abort_error}")),
            };
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct OwnedFilterIdentity {
    filter_key: GUID,
    layer_key: GUID,
    expected_runtime_id: Option<u64>,
}

/// Validate and canonicalize recovery identities without opening or mutating BFE.
/// This keeps malformed, legacy, foreign-provider, and duplicate records out of
/// the transactional deletion path and makes those boundaries unit-testable.
#[cfg(windows)]
fn validate_owned_filter_records(
    records: &[crate::recovery_journal::FirewallFilterRecord],
) -> Result<Vec<OwnedFilterIdentity>, String> {
    const MAX_OWNED_FILTERS: usize = 256;

    if records.len() > MAX_OWNED_FILTERS {
        return Err("The recovery journal contains too many WFP filter identities.".into());
    }

    let v4_layer = wfp_layer_guid(crate::wfp_policy::WfpLayer::AleAuthConnectV4);
    let v6_layer = wfp_layer_guid(crate::wfp_policy::WfpLayer::AleAuthConnectV6);
    let mut seen_keys = std::collections::BTreeSet::new();
    let mut validated = Vec::with_capacity(records.len());

    for record in records {
        let provider = parse_canonical_wfp_guid(&record.provider_key)?;
        if !guid_eq(&provider, &PROVIDER_KEY) {
            return Err("A recovery record names a WFP provider not owned by this Agent.".into());
        }

        let filter_key_text = record.filter_key.as_deref().ok_or_else(|| {
            "A legacy WFP recovery record has no stable filter GUID; runtime IDs are not safe deletion keys.".to_string()
        })?;
        let filter_key = parse_canonical_wfp_guid(filter_key_text)?;
        let layer_key = parse_canonical_wfp_guid(&record.layer_key)?;
        if !guid_eq(&layer_key, &v4_layer) && !guid_eq(&layer_key, &v6_layer) {
            return Err("A recovery record names a WFP layer outside the Agent's supported egress policy.".into());
        }
        if record.filter_id == Some(0) {
            return Err("A recovery record contains an invalid zero WFP runtime filter ID.".into());
        }
        if !seen_keys.insert(guid_to_u128(&filter_key)) {
            return Err("The recovery journal contains a duplicate stable WFP filter GUID.".into());
        }

        validated.push(OwnedFilterIdentity {
            filter_key,
            layer_key,
            expected_runtime_id: record.filter_id,
        });
    }

    Ok(validated)
}

#[cfg(windows)]
fn parse_canonical_wfp_guid(value: &str) -> Result<GUID, String> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| "A recovery record contains an invalid WFP GUID.".to_string())?;
    if !parsed.to_string().eq_ignore_ascii_case(value) {
        return Err("A recovery record contains a non-canonical WFP GUID.".into());
    }
    Ok(GUID::from_u128(parsed.as_u128()))
}

#[cfg(all(test, windows))]
mod owned_filter_validation_tests {
    use super::{
        guid_to_u128, validate_owned_filter_records, wfp_layer_guid, PROVIDER_KEY,
    };
    use crate::recovery_journal::FirewallFilterRecord;
    use crate::wfp_policy::WfpLayer;

    fn guid_string(value: &windows_sys::core::GUID) -> String {
        uuid::Uuid::from_u128(guid_to_u128(value)).to_string()
    }

    fn record(key: u128, layer: WfpLayer) -> FirewallFilterRecord {
        FirewallFilterRecord {
            provider_key: guid_string(&PROVIDER_KEY),
            filter_key: Some(uuid::Uuid::from_u128(key).to_string()),
            layer_key: guid_string(&wfp_layer_guid(layer)),
            filter_id: Some(42),
        }
    }

    #[test]
    fn accepts_stable_intent_without_runtime_id() {
        let mut value = record(
            0xac9a_f5e4_5e27_4dce_8b6a_19c175e233d1,
            WfpLayer::AleAuthConnectV4,
        );
        value.filter_id = None;
        let validated = validate_owned_filter_records(&[value]).unwrap();
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].expected_runtime_id, None);
    }

    #[test]
    fn rejects_legacy_runtime_id_only_record() {
        let mut value = record(
            0xac9a_f5e4_5e27_4dce_8b6a_19c175e233d1,
            WfpLayer::AleAuthConnectV4,
        );
        value.filter_key = None;
        assert!(validate_owned_filter_records(&[value]).is_err());
    }

    #[test]
    fn rejects_foreign_provider_and_unsupported_layer() {
        let mut foreign = record(
            0xac9a_f5e4_5e27_4dce_8b6a_19c175e233d1,
            WfpLayer::AleAuthConnectV4,
        );
        foreign.provider_key = "4d36e972-e325-11ce-bfc1-08002be10318".to_string();
        assert!(validate_owned_filter_records(&[foreign]).is_err());

        let mut unsupported = record(
            0xac9a_f5e4_5e27_4dce_8b6a_19c175e233d1,
            WfpLayer::AleAuthConnectV4,
        );
        unsupported.layer_key =
            "4d36e972-e325-11ce-bfc1-08002be10318".to_string();
        assert!(validate_owned_filter_records(&[unsupported]).is_err());
    }

    #[test]
    fn rejects_duplicate_filter_keys_and_zero_runtime_ids() {
        let value = record(
            0xac9a_f5e4_5e27_4dce_8b6a_19c175e233d1,
            WfpLayer::AleAuthConnectV4,
        );
        assert!(validate_owned_filter_records(&[value.clone(), value]).is_err());

        let mut zero_id = record(
            0xac9a_f5e4_5e27_4dce_8b6a_19c175e233d1,
            WfpLayer::AleAuthConnectV4,
        );
        zero_id.filter_id = Some(0);
        assert!(validate_owned_filter_records(&[zero_id]).is_err());
    }
}

#[cfg(all(test, windows))]
mod recovery_guid_tests {
    use super::{guid_eq, parse_canonical_wfp_guid};

    #[test]
    fn parses_canonical_filter_guids_case_insensitively() {
        let lower = parse_canonical_wfp_guid("ac9af5e4-5e27-4dce-8b6a-19c175e233d1").unwrap();
        let upper = parse_canonical_wfp_guid("AC9AF5E4-5E27-4DCE-8B6A-19C175E233D1").unwrap();
        assert!(guid_eq(&lower, &upper));
    }

    #[test]
    fn rejects_non_guid_and_non_canonical_representations() {
        assert!(parse_canonical_wfp_guid("not-a-guid").is_err());
        assert!(parse_canonical_wfp_guid("{ac9af5e4-5e27-4dce-8b6a-19c175e233d1}").is_err());
    }
}

#[cfg(all(test, windows))]
mod live_bfe_transaction_tests {
    use super::WfpEngine;
    use crate::wfp_policy::{
        EgressPolicySpec, PhysicalInterface, TransportProtocol, VpnEndpoint,
    };

    /// This test deliberately runs only on a disposable, elevated Windows runner.
    /// It creates the Agent's persistent provider/sublayer metadata, but every
    /// traffic filter is added, read back, deleted, and then rolled back in one
    /// uncommitted BFE transaction. No packet policy is committed.
    #[test]
    #[ignore = "requires an elevated disposable Windows runner with BFE running"]
    fn live_bfe_adds_reads_deletes_and_aborts_a_dual_stack_filter_plan() {
        let spec = EgressPolicySpec {
            physical_interfaces: vec![PhysicalInterface {
                interface_luid: 1,
                interface_index: 1,
            }],
            vpn_endpoints: vec![
                VpnEndpoint {
                    address: "198.51.100.7".parse().expect("valid TEST-NET-2 IPv4 address"),
                    port: 443,
                    protocol: TransportProtocol::Tcp,
                },
                VpnEndpoint {
                    address: "2001:db8::7".parse().expect("valid documentation IPv6 address"),
                    port: 443,
                    protocol: TransportProtocol::Tcp,
                },
            ],
        };

        let mut engine = WfpEngine::open_local().expect("open local BFE as the test runner");
        let report = engine
            .validate_egress_policy_transaction(&spec)
            .expect("BFE should add, read back, delete, and roll back the test filters");

        assert_eq!(report.validated_filter_count, report.rolled_back_filter_count);
        assert_eq!(report.validated_filter_count, 4);
    }
}

#[cfg(windows)]
fn verify_staged_filter(
    engine: windows_sys::Win32::Foundation::HANDLE,
    key: &GUID,
    expected_id: u64,
    planned: &crate::wfp_policy::PlannedFilter,
    expected_action: u32,
    expected_weight: u8,
    expected_conditions: &[ExpectedCondition],
) -> Result<(), String> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFilterGetByKey0, FwpmFreeMemory0, FWPM_FILTER_FLAG_PERSISTENT,
        FWPM_FILTER_FLAG_DISABLED, FWP_MATCH_EQUAL, FWP_UINT8,
    };

    let mut filter_ptr = std::ptr::null_mut();
    let status = unsafe { FwpmFilterGetByKey0(engine, key, &mut filter_ptr) };
    if status != 0 {
        return Err(format!("FwpmFilterGetByKey0 failed with Windows status 0x{status:08X}."));
    }
    if filter_ptr.is_null() {
        return Err("WFP filter lookup returned a null object.".into());
    }

    let verification = (|| -> Result<(), String> {
        let filter = unsafe { &*filter_ptr };
        let provider_matches = !filter.providerKey.is_null()
            && guid_eq(unsafe { &*filter.providerKey }, &PROVIDER_KEY);
        let flags_valid = filter.flags & FWPM_FILTER_FLAG_PERSISTENT != 0
            && filter.flags & FWPM_FILTER_FLAG_DISABLED == 0;
        if !guid_eq(&filter.filterKey, key)
            || filter.filterId != expected_id
            || !guid_eq(&filter.layerKey, &wfp_layer_guid(planned.layer))
            || !guid_eq(&filter.subLayerKey, &SUBLAYER_KEY)
            || !provider_matches
            || !flags_valid
            || filter.action.r#type != expected_action
            || filter.numFilterConditions as usize != expected_conditions.len()
            || (filter.numFilterConditions != 0 && filter.filterCondition.is_null())
            || filter.weight.r#type != FWP_UINT8
            || unsafe { filter.weight.Anonymous.uint8 } != expected_weight
        {
            return Err("The staged WFP filter did not read back with the expected provider, layer, action, weight, flags, or condition count.".into());
        }

        let actual = if filter.numFilterConditions == 0 {
            &[][..]
        } else {
            unsafe {
                std::slice::from_raw_parts(
                    filter.filterCondition,
                    filter.numFilterConditions as usize,
                )
            }
        };
        for (index, expected) in expected_conditions.iter().enumerate() {
            let condition = &actual[index];
            if !guid_eq(&condition.fieldKey, &expected_condition_key(*expected))
                || condition.matchType != FWP_MATCH_EQUAL
            {
                return Err(format!("WFP condition {index} did not read back with the expected field key and match type."));
            }
            match *expected {
                ExpectedCondition::InterfaceLuid(value) => {
                    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64;
                    if condition.conditionValue.r#type != FWP_UINT64 {
                        return Err("WFP interface condition has the wrong value type.".into());
                    }
                    let pointer = unsafe { condition.conditionValue.Anonymous.uint64 };
                    if pointer.is_null() || unsafe { *pointer } != value {
                        return Err("WFP interface LUID condition failed read-back verification.".into());
                    }
                }
                ExpectedCondition::RemoteIpv4 { address, mask } => {
                    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V4_ADDR_MASK;
                    if condition.conditionValue.r#type != FWP_V4_ADDR_MASK {
                        return Err("WFP IPv4 endpoint condition has the wrong value type.".into());
                    }
                    let pointer = unsafe { condition.conditionValue.Anonymous.v4AddrMask };
                    if pointer.is_null()
                        || unsafe { (*pointer).addr } != address
                        || unsafe { (*pointer).mask } != mask
                    {
                        return Err("WFP IPv4 remote address condition failed read-back verification.".into());
                    }
                }
                ExpectedCondition::RemoteIpv6 { address, prefix_length } => {
                    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V6_ADDR_MASK;
                    if condition.conditionValue.r#type != FWP_V6_ADDR_MASK {
                        return Err("WFP IPv6 endpoint condition has the wrong value type.".into());
                    }
                    let pointer = unsafe { condition.conditionValue.Anonymous.v6AddrMask };
                    if pointer.is_null()
                        || unsafe { (*pointer).addr } != address
                        || unsafe { (*pointer).prefixLength } != prefix_length
                    {
                        return Err("WFP IPv6 remote address condition failed read-back verification.".into());
                    }
                }
                ExpectedCondition::RemotePort(value) => {
                    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16;
                    if condition.conditionValue.r#type != FWP_UINT16
                        || unsafe { condition.conditionValue.Anonymous.uint16 } != value
                    {
                        return Err("WFP remote port condition failed read-back verification.".into());
                    }
                }
                ExpectedCondition::IpProtocol(value) => {
                    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8;
                    if condition.conditionValue.r#type != FWP_UINT8
                        || unsafe { condition.conditionValue.Anonymous.uint8 } != value
                    {
                        return Err("WFP IP protocol condition failed read-back verification.".into());
                    }
                }
            }
        }
        Ok(())
    })();

    let mut allocation = filter_ptr.cast();
    unsafe { FwpmFreeMemory0(&mut allocation) };
    verification
}

#[cfg(windows)]
fn verify_filter_absent(
    engine: windows_sys::Win32::Foundation::HANDLE,
    key: &GUID,
) -> Result<(), String> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFilterGetByKey0, FwpmFreeMemory0,
    };
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;

    let mut filter_ptr = std::ptr::null_mut();
    let status = unsafe { FwpmFilterGetByKey0(engine, key, &mut filter_ptr) };
    if status == FWP_E_FILTER_NOT_FOUND {
        return Ok(());
    }
    if status == 0 {
        if !filter_ptr.is_null() {
            let mut allocation = filter_ptr.cast();
            unsafe { FwpmFreeMemory0(&mut allocation) };
        }
        return Err("A WFP filter remained visible after transaction completion; policy state is unconfirmed.".into());
    }
    Err(format!(
        "Could not confirm that a WFP filter was removed (0x{status:08X})."
    ))
}

/// Resolve a Windows interface index to its stable NET_LUID and verify the
/// reverse mapping still returns the same index. This does not classify an
/// adapter as physical; callers must exclude loopback, tunnel, and virtual NICs.
#[cfg(windows)]
pub fn resolve_interface_luid(
    interface_index: u32,
) -> Result<crate::wfp_policy::PhysicalInterface, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    if interface_index == 0 {
        return Err("Cannot resolve a zero Windows interface index.".into());
    }

    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let to_luid = unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut luid) };
    if to_luid != 0 {
        return Err(format!("ConvertInterfaceIndexToLuid({interface_index}) failed with Windows error {to_luid}."));
    }
    let interface_luid = unsafe { luid.Value };
    if interface_luid == 0 {
        return Err("Windows returned a zero NET_LUID for the selected interface.".into());
    }

    let mut round_trip_index = 0u32;
    let to_index = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut round_trip_index) };
    if to_index != 0 || round_trip_index != interface_index {
        return Err(format!("Windows interface LUID round-trip verification failed for interface index {interface_index}."));
    }

    Ok(crate::wfp_policy::PhysicalInterface {
        interface_luid,
        interface_index,
    })
}

#[cfg(windows)]
impl Drop for WfpEngine {
    fn drop(&mut self) {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
        if !self.handle.is_null() {
            let status = unsafe { FwpmEngineClose0(self.handle) };
            if status != 0 {
                eprintln!("FwpmEngineClose0 failed with Windows status 0x{status:08X}.");
            }
            self.handle = std::ptr::null_mut();
        }
    }
}
