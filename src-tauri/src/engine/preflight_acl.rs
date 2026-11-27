//! Atomic, verified access control for credential-bearing preflight files.
//!
//! Every preflight directory and config file is created with a protected DACL.
//! Existing directories are never silently "fixed": their owner and complete
//! DACL must already match the expected descriptor or the engine operation fails
//! before any profile credentials are written.

use std::fs;
use std::io::Write;
use std::path::Path;

#[cfg(windows)]
mod platform {
    use super::*;
        use std::iter::once;
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FlushFileBuffers, GetFileInformationByHandle,
        WriteFile, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const SDDL_REVISION_1: u32 = 1;

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct LocalAllocation(*mut core::ffi::c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    struct PrivateDescriptor {
        raw: *mut core::ffi::c_void,
        canonical: String,
    }

    impl Drop for PrivateDescriptor {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                unsafe {
                    LocalFree(self.raw);
                }
            }
        }
    }

    impl PrivateDescriptor {
        fn new(is_directory: bool) -> Result<Self, String> {
            let user_sid = current_user_sid_string()?;
            let sddl = if is_directory {
                format!(
                    "O:{user_sid}D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                )
            } else {
                format!(
                    "O:{user_sid}D:P(A;;FA;;;{user_sid})(A;;FA;;;SY)(A;;FA;;;BA)"
                )
            };
            Self::from_sddl(&sddl)
        }

        fn from_sddl(sddl: &str) -> Result<Self, String> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(once(0)).collect();
            let mut raw = null_mut();
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut raw,
                    null_mut(),
                )
            };
            if converted == 0 || raw.is_null() {
                return Err("A restrictive Windows security descriptor could not be created.".into());
            }

            let canonical = match canonical_sddl(raw) {
                Ok(value) => value,
                Err(error) => {
                    unsafe {
                        LocalFree(raw);
                    }
                    return Err(error);
                }
            };
            Ok(Self { raw, canonical })
        }

        fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.raw,
                bInheritHandle: 0,
            }
        }
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect()
    }

    fn current_user_sid_string() -> Result<String, String> {
        unsafe {
            let mut token = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err("The current Windows user SID could not be read.".into());
            }
            let token = Handle(token);

            let mut required = 0u32;
            GetTokenInformation(
                token.0,
                TokenUser,
                null_mut(),
                0,
                &mut required,
            );
            if required == 0 {
                return Err("The current Windows user SID could not be read.".into());
            }

            // TOKEN_USER contains pointer-aligned fields; a byte Vec is not guaranteed
            // to meet the alignment requirement on every allocator/platform.
            let mut buffer = vec![0u64; (required as usize + 7) / 8];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            ) == 0
            {
                return Err("The current Windows user SID could not be read.".into());
            }

            let token_user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut sid_text = null_mut();
            if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) == 0
                || sid_text.is_null()
            {
                return Err("The current Windows user SID could not be formatted.".into());
            }
            let allocation = LocalAllocation(sid_text.cast());
            let mut length = 0usize;
            while *sid_text.add(length) != 0 {
                length += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, length));
            drop(allocation);
            Ok(value)
        }
    }

    fn canonical_sddl(descriptor: *mut core::ffi::c_void) -> Result<String, String> {
        unsafe {
            let mut text: *mut u16 = null_mut();
            let mut length = 0u32;
            if ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut text,
                &mut length,
            ) == 0
                || text.is_null()
            {
                return Err("The Windows security descriptor could not be verified.".into());
            }
            let allocation = LocalAllocation(text.cast());
            let mut actual_length = 0usize;
            while *text.add(actual_length) != 0 {
                actual_length += 1;
            }
            let value =
                String::from_utf16_lossy(std::slice::from_raw_parts(text, actual_length));
            drop(allocation);
            Ok(value)
        }
    }

    fn verify_handle_acl(handle: HANDLE, expected: &PrivateDescriptor) -> Result<(), String> {
        unsafe {
            let mut actual: *mut core::ffi::c_void = null_mut();
            let status = GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut actual,
            );
            if status != 0 || actual.is_null() {
                return Err("The preflight object's Windows owner and ACL could not be inspected.".into());
            }
            let allocation = LocalAllocation(actual);
            let actual_canonical = canonical_sddl(actual)?;
            drop(allocation);
            if actual_canonical != expected.canonical {
                return Err(
                    "The preflight directory or config file has an unexpected Windows owner or ACL; engine startup is blocked."
                        .into(),
                );
            }
            Ok(())
        }
    }

    fn open_directory(path: &Path, allow_missing: bool) -> Result<Option<Handle>, String> {
        let path_wide = wide_path(path);
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            if allow_missing && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                return Ok(None);
            }
            return Err("The preflight directory could not be opened safely.".into());
        }

        let handle = Handle(handle);
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(handle.0, &mut information) } == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(
                "The preflight path is not a plain directory; engine startup is blocked.".into(),
            );
        }
        Ok(Some(handle))
    }

    pub fn verify_private_directory_if_exists(path: &Path) -> Result<(), String> {
        let expected = PrivateDescriptor::new(true)?;
        if let Some(handle) = open_directory(path, true)? {
            verify_handle_acl(handle.0, &expected)?;
        }
        Ok(())
    }

    pub fn ensure_private_directory(path: &Path) -> Result<(), String> {
        let descriptor = PrivateDescriptor::new(true)?;
        let attributes = descriptor.security_attributes();
        let path_wide = wide_path(path);
        let created = unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) };
        if created == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err("A private preflight directory could not be created.".into());
        }

        let handle = open_directory(path, false)?
            .ok_or_else(|| "A private preflight directory could not be created.".to_string())?;
        verify_handle_acl(handle.0, &descriptor)
    }

    pub fn create_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
        if contents.len() > u32::MAX as usize {
            return Err("The temporary engine configuration is too large.".into());
        }

        let descriptor = PrivateDescriptor::new(false)?;
        let attributes = descriptor.security_attributes();
        let path_wide = wide_path(path);
        let raw_handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                GENERIC_WRITE | READ_CONTROL,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if raw_handle == INVALID_HANDLE_VALUE {
            return Err(
                "A new private preflight configuration file could not be created.".into(),
            );
        }
        let handle = Handle(raw_handle);

        let result = (|| {
            // Verify owner and DACL before the first credential byte is written.
            verify_handle_acl(handle.0, &descriptor)?;

            let mut offset = 0usize;
            while offset < contents.len() {
                let mut written = 0u32;
                let remaining = (contents.len() - offset) as u32;
                let ok = unsafe {
                    WriteFile(
                        handle.0,
                        contents[offset..].as_ptr(),
                        remaining,
                        &mut written,
                        null_mut(),
                    )
                };
                if ok == 0 || written == 0 || written > remaining {
                    return Err("The private preflight configuration could not be written.".into());
                }
                offset += written as usize;
            }
            if unsafe { FlushFileBuffers(handle.0) } == 0 {
                return Err("The private preflight configuration could not be flushed.".into());
            }
            Ok(())
        })();

        drop(handle);
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use uuid::Uuid;

        fn test_path(label: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "blacklist-inevitable-acl-{label}-{}",
                Uuid::new_v4()
            ))
        }

        #[test]
        fn creates_protected_root_nested_directory_and_config() {
            let root = test_path("private");
            let run = root.join("run");
            let config = run.join("config.json");
            ensure_private_directory(&root).expect("private root");
            ensure_private_directory(&run).expect("private run directory");
            create_private_file(&config, br#"{"password":"test-secret"}"#)
                .expect("private config");

            assert_eq!(
                fs::read(&config).expect("read own config"),
                br#"{"password":"test-secret"}"#
            );
            verify_private_directory_if_exists(&root).expect("verify root");
            verify_private_directory_if_exists(&run).expect("verify run directory");
            fs::remove_dir_all(root).expect("remove test tree");
        }

        #[test]
        fn rejects_existing_directory_with_broad_acl() {
            let path = test_path("broad");
            let sid = current_user_sid_string().expect("user SID");
            let broad = PrivateDescriptor::from_sddl(&format!(
                "O:{sid}D:P(A;OICI;FA;;;WD)"
            ))
            .expect("broad test descriptor");
            let attributes = broad.security_attributes();
            let path_wide = wide_path(&path);
            assert_ne!(
                unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) },
                0,
                "create broad test directory"
            );

            assert!(
                ensure_private_directory(&path).is_err(),
                "an existing broad DACL must fail closed"
            );
            fs::remove_dir(path).expect("remove test directory");
        }

        #[test]
        fn config_creation_never_overwrites_an_existing_file() {
            let root = test_path("no-overwrite");
            ensure_private_directory(&root).expect("private root");
            let config = root.join("config.json");
            fs::write(&config, b"sentinel").expect("create collision");
            assert!(create_private_file(&config, b"secret").is_err());
            assert_eq!(fs::read(&config).expect("read sentinel"), b"sentinel");
            fs::remove_dir_all(root).expect("remove test tree");
        }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    fn verify_private_directory(path: &Path) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "The preflight directory could not be inspected.".to_string())?;
        if !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
            return Err("The preflight directory has unsafe permissions.".into());
        }
        Ok(())
    }

    pub fn verify_private_directory_if_exists(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(_) => verify_private_directory(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("The preflight directory could not be inspected.".into()),
        }
    }

    pub fn ensure_private_directory(path: &Path) -> Result<(), String> {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("A private preflight directory could not be created.".into()),
        }
        verify_private_directory(path)
    }

    pub fn create_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| "A private preflight configuration file could not be created.".to_string())?;
            file.write_all(contents)
                .and_then(|_| file.sync_all())
                .map_err(|_| "The private preflight configuration could not be written.".to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use super::*;

    pub fn verify_private_directory_if_exists(_path: &Path) -> Result<(), String> {
        Err("Secure temporary preflight storage is unavailable on this platform.".into())
    }

    pub fn ensure_private_directory(_path: &Path) -> Result<(), String> {
        Err("Secure temporary preflight storage is unavailable on this platform.".into())
    }

    pub fn create_private_file(_path: &Path, _contents: &[u8]) -> Result<(), String> {
        Err("Secure temporary preflight storage is unavailable on this platform.".into())
    }
}

pub use platform::{
    create_private_file, ensure_private_directory, verify_private_directory_if_exists,
};
