//! Bounded Windows backup-stream transfer and thread-scoped backup privileges.
use crate::CopyOptions;
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
type Handle = *mut c_void;
#[repr(C)]
#[derive(Default)]
struct Luid {
    low: u32,
    high: i32,
}

#[repr(C)]
struct TokenPrivileges {
    count: u32,
    luid: Luid,
    attributes: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenThreadToken(thread: Handle, access: u32, open_as_self: i32, token: *mut Handle) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn DuplicateTokenEx(
        token: Handle,
        access: u32,
        attributes: *const c_void,
        level: u32,
        token_type: u32,
        duplicate: *mut Handle,
    ) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable: i32,
        state: *const TokenPrivileges,
        length: u32,
        previous: *mut c_void,
        returned: *mut u32,
    ) -> i32;
    fn SetThreadToken(thread: *const Handle, token: Handle) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn SetLastError(error: u32);
    fn BackupSeek(
        file: Handle,
        low: u32,
        high: u32,
        low_seeked: *mut u32,
        high_seeked: *mut u32,
        context: *mut Handle,
    ) -> i32;
    fn BackupRead(
        file: Handle,
        buffer: *mut u8,
        count: u32,
        read: *mut u32,
        abort: i32,
        security: i32,
        context: *mut Handle,
    ) -> i32;
    fn BackupWrite(
        file: Handle,
        buffer: *const u8,
        count: u32,
        written: *mut u32,
        abort: i32,
        security: i32,
        context: *mut Handle,
    ) -> i32;
}

struct OwnedToken(Handle);

impl Drop for OwnedToken {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one successfully opened token handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Enables backup, restore, and SACL privileges on a duplicated impersonation
/// token, restoring the previous thread token on drop. The guard is not Send.
pub(crate) struct BackupPrivileges {
    previous: Option<OwnedToken>,
    _active: OwnedToken,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl BackupPrivileges {
    pub(crate) fn acquire(security: bool) -> io::Result<Self> {
        let mut original = ptr::null_mut();
        // SAFETY: outputs point to initialized local storage; pseudo-handles are
        // valid only for this call and are never closed.
        let previous = unsafe {
            if OpenThreadToken(
                GetCurrentThread(),
                0x0002 | 0x0004 | 0x0008,
                1,
                &mut original,
            ) != 0
            {
                Some(OwnedToken(original))
            } else if GetLastError() == 1008 {
                // ERROR_NO_TOKEN
                None
            } else {
                return Err(io::Error::last_os_error());
            }
        };
        let process;
        let source = if let Some(token) = &previous {
            token.0
        } else {
            let mut raw = ptr::null_mut();
            // SAFETY: valid pseudo-handle and writable output pointer.
            if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0002 | 0x0008, &mut raw) } == 0 {
                return Err(io::Error::last_os_error());
            }
            process = OwnedToken(raw);
            process.0
        };
        let mut duplicate = ptr::null_mut();
        // SAFETY: source token stays alive and output points to local storage.
        if unsafe {
            DuplicateTokenEx(
                source,
                0x0004 | 0x0008 | 0x0020,
                ptr::null(),
                2,
                2,
                &mut duplicate,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let active = OwnedToken(duplicate);
        for name in ["SeBackupPrivilege", "SeRestorePrivilege"]
            .into_iter()
            .chain(security.then_some("SeSecurityPrivilege"))
        {
            let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let mut luid = Luid::default();
            // SAFETY: name is NUL terminated, luid is writable, token is owned.
            unsafe {
                if LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let state = TokenPrivileges {
                    count: 1,
                    luid,
                    attributes: 2,
                };
                SetLastError(0);
                if AdjustTokenPrivileges(active.0, 0, &state, 0, ptr::null_mut(), ptr::null_mut())
                    == 0
                {
                    return Err(io::Error::last_os_error());
                }
                // AdjustTokenPrivileges succeeds even when a privilege is absent.
                let error = GetLastError();
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
            }
        }
        // SAFETY: the impersonation token remains owned until the guard drops.
        if unsafe { SetThreadToken(ptr::null(), active.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            previous,
            _active: active,
            _thread_bound: std::marker::PhantomData,
        })
    }
}

impl Drop for BackupPrivileges {
    fn drop(&mut self) {
        let prior = self
            .previous
            .as_ref()
            .map_or(ptr::null_mut(), |token| token.0);
        // SAFETY: prior remains alive through this call; NULL reverts impersonation.
        // Failure is security-critical: continuing would leave elevated thread state.
        if unsafe { SetThreadToken(ptr::null(), prior) } == 0 {
            std::process::abort();
        }
    }
}

struct BackupContext<'a> {
    file: &'a File,
    context: Handle,
    writing: bool,
}

impl Drop for BackupContext<'_> {
    fn drop(&mut self) {
        let mut amount = 0;
        // SAFETY: context belongs to this file and API; abort releases its state.
        unsafe {
            if self.writing {
                BackupWrite(
                    self.file.as_raw_handle(),
                    ptr::null(),
                    0,
                    &mut amount,
                    1,
                    0,
                    &mut self.context,
                );
            } else {
                BackupRead(
                    self.file.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    &mut amount,
                    1,
                    0,
                    &mut self.context,
                );
            }
        }
    }
}

impl BackupContext<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        // SAFETY: Owned synchronous file/context and writable bounded byte slice.
        if unsafe {
            BackupRead(
                self.file.as_raw_handle(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut count,
                0,
                0,
                &mut self.context,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if count as usize > bytes.len() {
            return Err(io::Error::other("invalid backup read count"));
        }
        Ok(count as usize)
    }
    fn exact(&mut self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let count = self.read(bytes)?;
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut count = 0;
            // SAFETY: Owned file/context and readable bounded slice; partial writes are retried.
            if unsafe {
                BackupWrite(
                    self.file.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut count,
                    0,
                    0,
                    &mut self.context,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if count == 0 || count as usize > bytes.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[count as usize..];
        }
        Ok(())
    }
    fn skip(&mut self, size: u64) -> io::Result<()> {
        if size == 0 {
            return Ok(());
        }
        let (mut low, mut high) = (0, 0);
        // SAFETY: Read context is positioned at one stream's payload and outputs are writable.
        if unsafe {
            BackupSeek(
                self.file.as_raw_handle(),
                size as u32,
                (size >> 32) as u32,
                &mut low,
                &mut high,
                &mut self.context,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if (u64::from(high) << 32) | u64::from(low) != size {
            return Err(io::Error::other("short backup stream seek"));
        }
        Ok(())
    }
}
/// Transfer only requested EA and alternate-data records; normal data and
/// security are handled separately. Streaming retains at most one name and buffer.
pub(super) fn copy(
    source: &Path,
    destination: &Path,
    follow: bool,
    options: &CopyOptions,
) -> io::Result<()> {
    let flags = 0x02000000 | if follow { 0 } else { 0x00200000 };
    let input = OpenOptions::new()
        .access_mode(0x0012_0089)
        .custom_flags(flags)
        .open(source)?;
    let output = OpenOptions::new()
        .access_mode(0x0012_019f)
        .custom_flags(flags)
        .open(destination)?;
    let mut reader = BackupContext {
        file: &input,
        context: ptr::null_mut(),
        writing: false,
    };
    let mut writer = BackupContext {
        file: &output,
        context: ptr::null_mut(),
        writing: true,
    };
    let mut buffer = vec![0; options.buffer_size as usize];
    loop {
        options.cancellation.check()?;
        // WIN32_STREAM_ID has a 20-byte wire header, despite C struct tail padding.
        let mut header = [0; 20];
        let count = reader.read(&mut header)?;
        if count == 0 {
            break;
        }
        reader.exact(&mut header[count..])?;
        let id = u32::from_le_bytes(header[..4].try_into().unwrap());
        let size = i64::from_le_bytes(header[8..16].try_into().unwrap());
        let name_size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if size < 0 || name_size > 65534 || !name_size.is_multiple_of(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Windows backup stream header",
            ));
        }
        let mut name = vec![0; name_size];
        reader.exact(&mut name)?;
        if options.preserve_windows_attributes && matches!(id, 7 | 8 | 10) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported native backup metadata record",
            ));
        }
        let selected =
            (id == 2 && options.preserve_xattrs) || (id == 4 && options.preserve_streams);
        if !selected {
            reader.skip(size as u64)?;
            continue;
        }
        writer.write(&header)?;
        writer.write(&name)?;
        let mut remaining = size as u64;
        while remaining != 0 {
            options.cancellation.check()?;
            let limit = remaining.min(buffer.len() as u64) as usize;
            reader.exact(&mut buffer[..limit])?;
            writer.write(&buffer[..limit])?;
            remaining -= limit as u64;
        }
    }
    drop(writer);
    drop(reader);
    super::close(output)?;
    super::close(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn CreateRestrictedToken(
            existing: Handle,
            flags: u32,
            disable_count: u32,
            disable: *const c_void,
            delete_count: u32,
            delete: *const c_void,
            restrict_count: u32,
            restrict: *const c_void,
            new_token: *mut Handle,
        ) -> i32;
    }
    #[test]
    fn missing_backup_privileges_fail_instead_of_downgrading() {
        let mut process = ptr::null_mut();
        // SAFETY: process pseudo-handle and writable token result are valid.
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), 0x2 | 0x8, &mut process) },
            0
        );
        let process = OwnedToken(process);
        let mut restricted = ptr::null_mut();
        // SAFETY: NULL lists have zero counts; DISABLE_MAX_PRIVILEGE strips all
        // privileges except traverse, leaving no backup/restore/security grant.
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    process.0,
                    1,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut restricted,
                )
            },
            0
        );
        let restricted = OwnedToken(restricted);
        let mut impersonation = ptr::null_mut();
        // SAFETY: owned token, no security attributes, impersonation token output.
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    restricted.0,
                    0x4 | 0x8 | 0x2,
                    ptr::null(),
                    2,
                    2,
                    &mut impersonation,
                )
            },
            0
        );
        let impersonation = OwnedToken(impersonation);
        // SAFETY: token has TOKEN_IMPERSONATE and is retained during the test.
        assert_ne!(unsafe { SetThreadToken(ptr::null(), impersonation.0) }, 0);
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // SAFETY: NULL removes this test's thread impersonation token.
                assert_ne!(unsafe { SetThreadToken(ptr::null(), ptr::null_mut()) }, 0);
            }
        }
        let _revert = Revert;
        let error = match BackupPrivileges::acquire(true) {
            Ok(_) => panic!("stripped privileges unexpectedly enabled"),
            Err(error) => error,
        };
        assert_eq!(error.raw_os_error(), Some(1300)); // ERROR_NOT_ALL_ASSIGNED
        // The failed acquisition must leave the restricted thread token active.
        let mut current = ptr::null_mut();
        // SAFETY: Current-thread pseudo-handle and writable owned handle output.
        assert_ne!(
            unsafe { OpenThreadToken(GetCurrentThread(), 0x8, 1, &mut current) },
            0
        );
        let _current = OwnedToken(current);
    }
}
