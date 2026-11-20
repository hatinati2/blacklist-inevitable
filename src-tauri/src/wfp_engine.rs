//! Minimal Windows Filtering Platform engine and persistent namespace ownership.
//!
//! The provider/sublayer setup is durable metadata only. This module intentionally
//! does not install traffic filters or enable a kill switch. It must only be called
//! by a future authenticated privileged service, never by the unelevated UI.

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
pub struct DisabledFilterReceipt {
    /// GUID encoded as a u128 so it can be journaled without platform-specific layout.
    pub filter_key: u128,
    pub filter_id: u64,
    pub layer: crate::wfp_policy::WfpLayer,
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

    /// Add a persistent, explicitly disabled BLOCK filter as an inert WFP lifecycle probe.
    ///
    /// This validates provider/sublayer ownership, filter persistence, and read-back
    /// without changing packet treatment. The disabled flag is mandatory and is
    /// verified after installation. This is not a kill switch or traffic policy.
    pub fn create_disabled_block_filter(
        &self,
        layer: crate::wfp_policy::WfpLayer,
    ) -> Result<DisabledFilterReceipt, String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
            FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_DISPLAY_DATA0,
            FWPM_FILTER0, FWPM_FILTER0_0, FWPM_FILTER_FLAG_DISABLED,
            FWPM_FILTER_FLAG_PERSISTENT, FWP_VALUE0, FWP_VALUE0_0, FWP_ACTION_BLOCK,
            FWP_UINT8,
        };

        self.ensure_persistent_namespace()?;
        let filter_key = GUID::from_u128(uuid::Uuid::new_v4().as_u128());
        let layer_key = wfp_layer_guid(layer);
        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }

        let operation = (|| -> Result<u64, String> {
            let mut name: Vec<u16> = "Blacklist Inevitable disabled WFP lifecycle probe"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let filter = FWPM_FILTER0 {
                filterKey: filter_key,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: std::ptr::null_mut(),
                },
                flags: FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_PERSISTENT,
                providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
                providerData: unsafe { std::mem::zeroed() },
                layerKey: layer_key,
                subLayerKey: SUBLAYER_KEY,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: 0x0F },
                },
                numFilterConditions: 0,
                filterCondition: std::ptr::null_mut(),
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    Anonymous: FWPM_ACTION0_0 {
                        filterType: GUID::from_u128(0),
                    },
                },
                Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
                reserved: std::ptr::null_mut(),
                filterId: 0,
                effectiveWeight: unsafe { std::mem::zeroed() },
            };

            let mut filter_id = 0u64;
            let add = unsafe {
                FwpmFilterAdd0(self.handle, &filter, std::ptr::null_mut(), &mut filter_id)
            };
            if add != 0 {
                return Err(format!("FwpmFilterAdd0 failed with Windows status 0x{add:08X}."));
            }
            if filter_id == 0 {
                return Err("FwpmFilterAdd0 returned an invalid zero filter ID.".into());
            }
            self.verify_disabled_filter(filter_key, filter_id, layer_key)?;
            Ok(filter_id)
        })();

        let filter_id = match operation {
            Ok(id) => id,
            Err(error) => {
                unsafe { FwpmTransactionAbort0(self.handle) };
                return Err(error);
            }
        };

        let commit = unsafe { FwpmTransactionCommit0(self.handle) };
        if commit != 0 {
            let _ = unsafe { FwpmTransactionAbort0(self.handle) };
            return Err(format!("FwpmTransactionCommit0 failed with Windows status 0x{commit:08X}."));
        }

        Ok(DisabledFilterReceipt {
            filter_key: guid_to_u128(&filter_key),
            filter_id,
            layer,
        })
    }

    /// Verify a previously returned disabled-filter receipt against the live BFE.
    pub fn verify_disabled_block_filter(
        &self,
        receipt: &DisabledFilterReceipt,
    ) -> Result<(), String> {
        self.verify_disabled_filter(
            GUID::from_u128(receipt.filter_key),
            receipt.filter_id,
            wfp_layer_guid(receipt.layer),
        )
    }

    /// Delete only a filter that still matches the exact disabled, persistent
    /// BLOCK probe recorded in the receipt. Active or modified filters are refused.
    pub fn delete_disabled_block_filter(
        &self,
        receipt: &DisabledFilterReceipt,
    ) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
            FwpmTransactionCommit0,
        };

        let begin = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if begin != 0 {
            return Err(format!("FwpmTransactionBegin0 failed with Windows status 0x{begin:08X}."));
        }

        let key = GUID::from_u128(receipt.filter_key);
        let operation = (|| -> Result<(), String> {
            self.verify_disabled_filter(key, receipt.filter_id, wfp_layer_guid(receipt.layer))?;
            let status = unsafe { FwpmFilterDeleteByKey0(self.handle, &key) };
            if status != 0 {
                return Err(format!("FwpmFilterDeleteByKey0 failed with Windows status 0x{status:08X}."));
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

    fn verify_disabled_filter(
        &self,
        key: GUID,
        expected_id: u64,
        expected_layer: GUID,
    ) -> Result<(), String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterGetByKey0, FwpmFreeMemory0, FWPM_FILTER_FLAG_DISABLED,
            FWPM_FILTER_FLAG_PERSISTENT, FWP_ACTION_BLOCK,
        };

        let mut filter_ptr = std::ptr::null_mut();
        let status = unsafe { FwpmFilterGetByKey0(self.handle, &key, &mut filter_ptr) };
        if status != 0 {
            return Err(format!("FwpmFilterGetByKey0 failed with Windows status 0x{status:08X}."));
        }
        if filter_ptr.is_null() {
            return Err("WFP filter lookup returned a null object.".into());
        }

        let filter = unsafe { &*filter_ptr };
        let provider_matches = !filter.providerKey.is_null()
            && guid_eq(unsafe { &*filter.providerKey }, &PROVIDER_KEY);
        let valid = guid_eq(&filter.filterKey, &key)
            && filter.filterId == expected_id
            && guid_eq(&filter.layerKey, &expected_layer)
            && guid_eq(&filter.subLayerKey, &SUBLAYER_KEY)
            && provider_matches
            && filter.flags & (FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_PERSISTENT)
                == (FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_PERSISTENT)
            && filter.numFilterConditions == 0
            && filter.filterCondition.is_null()
            && filter.action.r#type == FWP_ACTION_BLOCK;
        let mut allocation = filter_ptr.cast();
        unsafe { FwpmFreeMemory0(&mut allocation) };

        if !valid {
            return Err("The WFP filter no longer matches the expected disabled persistent probe; refusing the operation.".into());
        }
        Ok(())
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
