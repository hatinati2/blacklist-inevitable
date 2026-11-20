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
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
#[cfg(windows)]
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
#[cfg(windows)]
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

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

        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                0,
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
                let valid = provider.providerKey == PROVIDER_KEY
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
                    && unsafe { *sublayer.providerKey } == PROVIDER_KEY;
                let valid = sublayer.subLayerKey == SUBLAYER_KEY
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
