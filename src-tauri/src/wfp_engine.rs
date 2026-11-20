//! Minimal Windows Filtering Platform engine handle ownership.
//!
//! This is only the native API boundary foundation. It does not install filters,
//! create providers/sublayers, change traffic policy, or claim leak protection.

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
        // A null session requests a non-dynamic engine session. No WFP objects
        // are created here; persistent policy installation is a separate step.
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
}

#[cfg(windows)]
impl Drop for WfpEngine {
    fn drop(&mut self) {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
        if !self.handle.is_null() {
            let status = unsafe { FwpmEngineClose0(self.handle) };
            if status != 0 {
                // Drop cannot return an error. Production callers must close
                // explicitly and surface failures before releasing policy state.
                eprintln!("FwpmEngineClose0 failed with Windows status 0x{status:08X}.");
            }
            self.handle = std::ptr::null_mut();
        }
    }
}
