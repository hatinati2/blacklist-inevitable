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
        Ok(Self { handle })
    }

    /// Ensure this product's persistent WFP provider and sublayer exist.
    ///
    /// Existing objects are accepted only when their stable keys, persistence
    /// flags, and provider ownership match this binary's namespace. This is a
    /// metadata operation only: no filters are created and no traffic is changed.
    pub fn ensure_persistent_namespace(&self) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmProviderAdd0, FwpmProviderGetByKey0, FwpmSubLayerAdd0,
            FwpmSubLayerGetByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
            FwpmTransactionCommit0, FwpmFreeMemory0, FWPM_DISPLAY_DATA0, FWPM_PROVIDER0,
            FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
        };

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
            unsafe { FwpmTransactionAbort0(self.handle) };
            return Err(error);
        }

        let commit = unsafe { FwpmTransactionCommit0(self.handle) };
        if commit != 0 {
            let _ = unsafe { FwpmTransactionAbort0(self.handle) };
            return Err(format!("FwpmTransactionCommit0 failed with Windows status 0x{commit:08X}."));
        }
        Ok(())
    }

    /// Ask BFE to validate a complete dual-stack policy plan inside one explicit
    /// write transaction, read every filter back, then ABORT the transaction.
    ///
    /// No traffic policy is committed or left installed. The former design tried
    /// to add FWPM_FILTER_FLAG_DISABLED, but Microsoft documents that this flag
    /// cannot be supplied when adding a new filter. A rollback-only transaction is
    /// used instead to validate filter structures without changing packet handling.
    pub fn validate_egress_policy_transaction(
        &self,
        spec: &crate::wfp_policy::EgressPolicySpec,
    ) -> Result<FilterValidationReport, String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmTransactionAbort0, FwpmTransactionBegin0,
        };

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
                self.add_and_verify_planned_filter(key, planned)?;
            }
            Ok(())
        })();

        let abort = unsafe { FwpmTransactionAbort0(self.handle) };
        if abort != 0 {
            return Err(format!(
                "FwpmTransactionAbort0 failed with Windows status 0x{abort:08X}; staged WFP state is unconfirmed. Do not continue with network policy."
            ));
        }

        for key in &generated_keys {
            verify_filter_absent_after_abort(self.handle, key)?;
        }

        operation?;
        Ok(FilterValidationReport {
            validated_filter_count: generated_keys.len(),
            rolled_back_filter_count: generated_keys.len(),
        })
    }

    fn add_and_verify_planned_filter(
        &self,
        filter_key: GUID,
        planned: &crate::wfp_policy::PlannedFilter,
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
            FwpmFilterAdd0(self.handle, &filter, std::ptr::null_mut(), &mut filter_id)
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
    pub fn remove_empty_persistent_namespace(&self) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmProviderDeleteByKey0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
            FwpmTransactionBegin0, FwpmTransactionCommit0,
        };

        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }
        let sublayer = unsafe { FwpmSubLayerDeleteByKey0(self.handle, &SUBLAYER_KEY) };
        if sublayer != 0 {
            unsafe { FwpmTransactionAbort0(self.handle) };
            return Err(format!("FwpmSubLayerDeleteByKey0 failed with Windows status 0x{sublayer:08X}."));
        }
        let provider = unsafe { FwpmProviderDeleteByKey0(self.handle, &PROVIDER_KEY) };
        if provider != 0 {
            unsafe { FwpmTransactionAbort0(self.handle) };
            return Err(format!("FwpmProviderDeleteByKey0 failed with Windows status 0x{provider:08X}."));
        }
        let commit = unsafe { FwpmTransactionCommit0(self.handle) };
        if commit != 0 {
            let _ = unsafe { FwpmTransactionAbort0(self.handle) };
            return Err(format!("FwpmTransactionCommit0 failed with Windows status 0x{commit:08X}."));
        }
        Ok(())
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
fn verify_filter_absent_after_abort(
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
        return Err("A staged WFP filter remained visible after transaction rollback; policy state is unconfirmed.".into());
    }
    Err(format!(
        "Could not confirm that a staged WFP filter was removed by transaction rollback (0x{status:08X})."
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
