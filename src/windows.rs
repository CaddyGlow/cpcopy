//! Native Windows copy engine. File identities are checked on open handles before
//! truncation; paths and link contents retain their original UTF-16 representation.
use crate::{
    BackupMode, CopyDiagnostics, CopyEvent, CopyOptions, Dereference, EventKind, ReflinkMode,
    SparseMode,
};
use anyhow::{Result, bail};
use std::{
    collections::HashMap,
    ffi::{OsStr, c_void},
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, IntoRawHandle},
    },
    path::{Path, PathBuf},
};
mod native_metadata;
type Handle = *mut c_void;
#[repr(C)]
#[derive(Default)]
struct FileTime {
    low: u32,
    high: u32,
}
#[repr(C)]
#[derive(Default)]
struct FileInformation {
    attributes: u32,
    creation: FileTime,
    access: FileTime,
    write: FileTime,
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[repr(C)]
struct DuplicateExtents {
    source: Handle,
    source_offset: i64,
    target_offset: i64,
    length: i64,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(handle: Handle, info: *mut FileInformation) -> i32;
    fn GetFileInformationByHandleEx(
        handle: Handle,
        class: u32,
        info: *mut c_void,
        length: u32,
    ) -> i32;
    fn DeviceIoControl(
        handle: Handle,
        code: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetCurrentThread() -> Handle;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn SetFileInformationByHandle(
        handle: Handle,
        class: u32,
        info: *const c_void,
        length: u32,
    ) -> i32;
    fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenThreadToken(thread: Handle, access: u32, open_as_self: i32, token: *mut Handle) -> i32;
    fn GetSecurityInfo(
        handle: Handle,
        object_type: u32,
        information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn SetSecurityInfo(
        handle: Handle,
        object_type: u32,
        information: u32,
        owner: *const c_void,
        group: *const c_void,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;
    fn EqualSid(first: *const c_void, second: *const c_void) -> i32;
    fn GetSecurityDescriptorControl(
        descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
}
struct SecurityDescriptor {
    memory: *mut c_void,
    owner: *mut c_void,
    group: *mut c_void,
    dacl: *mut c_void,
    sacl: *mut c_void,
}
impl SecurityDescriptor {
    fn sacl_protection(&self) -> io::Result<u32> {
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: Retained descriptor and correctly sized initialized control outputs.
        checked(unsafe { GetSecurityDescriptorControl(self.memory, &mut control, &mut revision) })?;
        Ok(if control & 0x2000 != 0 {
            0x40000000
        } else {
            0x10000000
        })
    }
    fn dacl_protection(&self) -> io::Result<u32> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: Descriptor remains owned and live; outputs match native WORD/DWORD sizes.
        checked(unsafe { GetSecurityDescriptorControl(self.memory, &mut control, &mut revision) })?;
        // Preserve protection explicitly: otherwise SetSecurityInfo can merge the
        // destination parent's inherited ACEs into a protected source DACL.
        Ok(if control & 0x1000 != 0 {
            0x80000000
        } else {
            0x20000000
        })
    }
}
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocates the descriptor through LocalAlloc.
        unsafe {
            LocalFree(self.memory);
        }
    }
}
fn security(file: &File, information: u32) -> io::Result<SecurityDescriptor> {
    let mut descriptor = SecurityDescriptor {
        memory: std::ptr::null_mut(),
        owner: std::ptr::null_mut(),
        group: std::ptr::null_mut(),
        dacl: std::ptr::null_mut(),
        sacl: std::ptr::null_mut(),
    };
    // SAFETY: Live handle and valid output pointers, descriptor owns resulting allocation.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            information,
            &mut descriptor.owner,
            &mut descriptor.group,
            &mut descriptor.dacl,
            &mut descriptor.sacl,
            &mut descriptor.memory,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(descriptor)
}
fn preserve_security(
    source: &Path,
    destination: &Path,
    follow: bool,
    ownership: bool,
    mode: bool,
    sacl: bool,
) -> io::Result<()> {
    let flags = 0x02000000 | if follow { 0 } else { 0x00200000 };
    let source = OpenOptions::new()
        .access_mode(0x20000 | if sacl { 0x01000000 } else { 0 })
        .custom_flags(flags)
        .open(source)
        .map_err(|error| {
            io::Error::new(error.kind(), format!("opening source security: {error}"))
        })?;
    let information =
        (if ownership { 3 } else { 0 }) | (if mode { 4 } else { 0 }) | if sacl { 8 } else { 0 };
    let source_security = security(&source, information).map_err(|error| {
        io::Error::new(error.kind(), format!("reading source security: {error}"))
    })?;
    let destination_read = OpenOptions::new()
        .access_mode(0x20000 | if sacl { 0x01000000 } else { 0 })
        .custom_flags(flags)
        .open(destination)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("opening destination security: {error}"),
            )
        })?;
    let destination_security = security(&destination_read, information).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("reading destination security: {error}"),
        )
    })?;
    let owner_differs =
        ownership && unsafe { EqualSid(source_security.owner, destination_security.owner) } == 0;
    let group_differs =
        ownership && unsafe { EqualSid(source_security.group, destination_security.group) } == 0;
    let apply = (if owner_differs { 1 } else { 0 })
        | (if group_differs { 2 } else { 0 })
        | (if mode {
            4 | source_security.dacl_protection()?
        } else {
            0
        })
        | if sacl {
            8 | source_security.sacl_protection()?
        } else {
            0
        };
    if apply != 0 {
        let destination = OpenOptions::new()
            .access_mode(
                0x20000
                    | (if owner_differs || group_differs {
                        0x80000
                    } else {
                        0
                    })
                    | (if mode { 0x40000 } else { 0 })
                    | if sacl { 0x01000000 } else { 0 },
            )
            .custom_flags(flags)
            .open(destination)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("opening destination to write security: {error}"),
                )
            })?;
        // SAFETY: SID and ACL pointers live within retained descriptors; handle has required rights.
        let error = unsafe {
            SetSecurityInfo(
                destination.as_raw_handle(),
                1,
                apply,
                source_security.owner,
                source_security.group,
                source_security.dacl,
                source_security.sacl,
            )
        };
        if error != 0 {
            return Err(io::Error::other(format!(
                "writing destination security: {}",
                io::Error::from_raw_os_error(error as i32)
            )));
        }
    }
    Ok(())
}
fn rename_new(source: &Path, destination: &Path) -> io::Result<()> {
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: Terminated UTF-16 paths; flags zero prevents replacement of existing names.
    checked(unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Identity(u32, u64);
#[derive(Default)]
pub(crate) struct CopyState {
    links: HashMap<Identity, (PathBuf, Identity)>,
    symlinks: HashMap<PathBuf, Identity>,
}
fn checked(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn identity(file: &File) -> io::Result<Identity> {
    let mut info = FileInformation::default();
    // SAFETY: Live file handle and correctly sized writable output structure.
    checked(unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) })?;
    Ok(Identity(
        info.volume,
        (u64::from(info.index_high) << 32) | u64::from(info.index_low),
    ))
}
fn metadata_handle(path: &Path, follow: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .access_mode(0)
        .custom_flags(0x02000000 | if follow { 0 } else { 0x00200000 })
        .open(path)
}
pub(crate) fn source_identity(path: &Path) -> io::Result<String> {
    let Identity(volume, index) = path_identity(path, false)?;
    Ok(format!("{volume}:{index}"))
}
fn path_identity(path: &Path, follow: bool) -> io::Result<Identity> {
    identity(&metadata_handle(path, follow)?)
}
fn close(file: File) -> io::Result<()> {
    // SAFETY: Ownership is transferred out of File exactly once.
    checked(unsafe { CloseHandle(file.into_raw_handle()) })
}
fn operation(operation: &'static str, path: &Path, error: io::Error) -> anyhow::Error {
    crate::FileOperationError {
        operation,
        path: path.to_owned(),
        error,
    }
    .into()
}
fn remove(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(0x10000)
        .custom_flags(0x02000000 | 0x00200000)
        .open(path)?;
    let flags = 1_u32 | 2 | 0x10;
    // SAFETY: DELETE handle, DWORD disposition flags; ignores readonly without changing alias attributes.
    checked(unsafe {
        SetFileInformationByHandle(file.as_raw_handle(), 21, (&flags as *const u32).cast(), 4)
    })?;
    close(file)
}

fn glob(pattern: &[u16], name: &[u16]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((&42, rest)) => (0..=name.len()).any(|index| glob(rest, &name[index..])),
        Some((&63, rest)) => !name.is_empty() && glob(rest, &name[1..]),
        Some((&91, rest)) => {
            let Some(end) = rest.iter().position(|unit| *unit == 93) else {
                return name.first() == Some(&91) && glob(rest, &name[1..]);
            };
            let Some(&unit) = name.first() else {
                return false;
            };
            let mut class = &rest[..end];
            let negate = matches!(class.first(), Some(33 | 94));
            if negate {
                class = &class[1..];
            }
            let mut found = false;
            let mut offset = 0;
            while offset < class.len() {
                if offset + 2 < class.len() && class[offset + 1] == 45 {
                    found |= (class[offset]..=class[offset + 2]).contains(&unit);
                    offset += 3;
                } else {
                    found |= class[offset] == unit;
                    offset += 1;
                }
            }
            found != negate && glob(&rest[end + 1..], &name[1..])
        }
        Some((&unit, rest)) => name.first() == Some(&unit) && glob(rest, &name[1..]),
    }
}
fn set_sparse(file: &File) -> io::Result<()> {
    let mut returned = 0;
    // SAFETY: Owned writable handle; FSCTL_SET_SPARSE needs no input or output buffer.
    checked(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x000900c4,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    })
}
fn clone_failure_is_terminal(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            8 | 14
                | 23
                | 29
                | 30
                | 31
                | 39
                | 112
                | 1117
                | 1392
                | 1393
                | 1450
                | 1453
                | 1454
                | 1455
                | 1816
        )
    )
}
fn clone_data(source: &File, destination: &File, length: u64) -> io::Result<()> {
    destination.set_len(length)?;
    let input = DuplicateExtents {
        source: source.as_raw_handle(),
        source_offset: 0,
        target_offset: 0,
        length: i64::try_from(length)
            .map_err(|_| io::Error::other("file exceeds supported clone size"))?,
    };
    let mut returned = 0;
    // SAFETY: Both handles are live, input is the native DUPLICATE_EXTENTS_DATA layout.
    checked(unsafe {
        DeviceIoControl(
            destination.as_raw_handle(),
            0x00098344,
            (&input as *const DuplicateExtents).cast(),
            std::mem::size_of::<DuplicateExtents>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    })
}
#[repr(C)]
#[derive(Default)]
struct AllocatedRange {
    offset: i64,
    length: i64,
}
fn unsupported(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(1 | 50 | 87))
}
fn allocated_ranges(source: &File, length: u64) -> io::Result<Option<Vec<(u64, u64)>>> {
    let mut ranges = Vec::new();
    let mut position = 0;
    while position < length {
        let input = AllocatedRange {
            offset: position as i64,
            length: (length - position) as i64,
        };
        let mut output = AllocatedRange::default();
        let mut returned = 0;
        // SAFETY: Valid regular source handle and bounded native range input/output structures.
        let result = unsafe {
            DeviceIoControl(
                source.as_raw_handle(),
                0x000940cf,
                (&input as *const AllocatedRange).cast(),
                16,
                (&mut output as *mut AllocatedRange).cast(),
                16,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            if unsupported(&error) {
                return Ok(None);
            }
            if error.raw_os_error() != Some(234) {
                return Err(error);
            }
        }
        if returned == 0 {
            break;
        }
        if returned != 16 || output.offset < position as i64 || output.length <= 0 {
            return Err(io::Error::other(
                "invalid allocated range returned by filesystem",
            ));
        }
        let offset = output.offset as u64;
        let end = offset.saturating_add(output.length as u64).min(length);
        if end <= offset {
            return Err(io::Error::other("allocated range exceeds file length"));
        }
        ranges.push((offset, end - offset));
        position = end;
    }
    Ok(Some(ranges))
}
fn buffered_data(
    source_path: &Path,
    destination_path: &Path,
    input: &mut File,
    output: &mut File,
    info: &Metadata,
    options: &CopyOptions,
    diagnostics: &mut CopyDiagnostics,
) -> Result<u64> {
    #[cfg(feature = "live-progress")]
    let mut tracker = crate::ProgressTracker::new(options.live_progress.as_ref());
    let requested_holes = options.sparse == SparseMode::Always
        || (options.sparse == SparseMode::Auto && info.file_attributes() & 0x200 != 0);
    let make_holes = if requested_holes {
        match set_sparse(output) {
            Ok(()) => true,
            Err(error) if unsupported(&error) => false,
            Err(error) => return Err(operation("cannot make sparse", destination_path, error)),
        }
    } else {
        false
    };
    let ranges = if make_holes && info.file_attributes() & 0x200 != 0 {
        allocated_ranges(input, info.len())?
    } else {
        None
    };
    if !make_holes && info.file_attributes() & 0x200 == 0 && info.len() >= 8 * 1024 * 1024 {
        struct CancellableReader<'a> {
            input: &'a mut File,
            cancellation: &'a crate::Cancellation,
        }
        impl Read for CancellableReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                // The pipeline retries Interrupted, so use Other to terminate
                // its reader; the coordinator restores the cancellation type.
                self.cancellation.check().map_err(io::Error::other)?;
                self.input.read(buffer)
            }
        }
        let mut reader = CancellableReader {
            input,
            cancellation: &options.cancellation,
        };
        #[cfg(feature = "live-progress")]
        let mut output = crate::ProgressWriter {
            output,
            tracker: &mut tracker,
        };
        #[cfg(not(feature = "live-progress"))]
        let mut output = output;
        return crate::pipeline::copy(&mut reader, &mut output, options.buffer_size as usize)
            .map_err(|failure| {
                if let Err(error) = options.cancellation.check() {
                    return CallbackError(error.into()).into();
                }
                match failure {
                    crate::pipeline::Failure::Read(error) => {
                        operation("error reading", source_path, error)
                    }
                    crate::pipeline::Failure::Write(error) => {
                        operation("error writing", destination_path, error)
                    }
                    crate::pipeline::Failure::Worker(error) => {
                        operation("copy reader failed", source_path, error)
                    }
                }
            });
    }
    diagnostics.seek_hole = ranges.is_some();
    let extent_copy = ranges.is_some();
    let ranges = ranges.unwrap_or_else(|| vec![(0, u64::MAX)]);
    // Small files should not pay for the large-file transfer buffer. A minimum
    // 4 KiB request still handles empty or concurrently growing source files.
    let buffer_size = info.len().clamp(4096, u64::from(options.buffer_size)) as usize;
    let mut buffer = vec![0_u8; buffer_size];
    let mut bytes = 0;
    for (offset, length) in ranges {
        if extent_copy {
            input
                .seek(SeekFrom::Start(offset))
                .map_err(|error| operation("cannot lseek", source_path, error))?;
            output
                .seek(SeekFrom::Start(offset))
                .map_err(|error| operation("cannot lseek", destination_path, error))?;
            #[cfg(feature = "live-progress")]
            tracker.add(offset.saturating_sub(bytes));
            bytes = offset;
        }
        let mut remaining = length;
        while remaining > 0 {
            options
                .cancellation
                .check()
                .map_err(|e| CallbackError(e.into()))?;
            let limit = remaining.min(buffer.len() as u64) as usize;
            let count = match input.read(&mut buffer[..limit]) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(operation("error reading", source_path, error)),
            };
            if count == 0 {
                break;
            }
            diagnostics.scanned_zeros |= make_holes;
            for chunk in buffer[..count].chunks(if make_holes { 4096 } else { count }) {
                if make_holes && chunk.iter().all(|byte| *byte == 0) {
                    output.seek(SeekFrom::Current(chunk.len() as i64))?;
                    #[cfg(feature = "live-progress")]
                    tracker.add(chunk.len() as u64);
                } else {
                    // Track each successful short write, including prefixes retained
                    // when a later write fails.
                    #[cfg(feature = "live-progress")]
                    let mut writer = crate::ProgressWriter {
                        output,
                        tracker: &mut tracker,
                    };
                    #[cfg(not(feature = "live-progress"))]
                    let writer = &mut *output;
                    writer
                        .write_all(chunk)
                        .map_err(|error| operation("error writing", destination_path, error))?;
                }
                bytes += chunk.len() as u64;
            }
            remaining -= count as u64;
        }
    }
    if extent_copy {
        #[cfg(feature = "live-progress")]
        tracker.add(info.len().saturating_sub(bytes));
        bytes = info.len();
    }
    if make_holes {
        output
            .set_len(bytes)
            .map_err(|error| operation("failed to extend", destination_path, error))?;
    }
    Ok(bytes)
}
#[derive(Debug)]
struct CallbackError(anyhow::Error);
impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for CallbackError {}
struct Copier<'a> {
    options: &'a CopyOptions,
    events: &'a mut dyn FnMut(&CopyEvent) -> Result<()>,
    overwrite: &'a mut dyn FnMut(&Path, &Path) -> Result<bool>,
    state: &'a mut CopyState,
    completed: u64,
    bytes: u64,
    ancestors: Vec<Identity>,
    root_volume: Option<u32>,
    declined: bool,
}
impl Copier<'_> {
    fn event(
        &mut self,
        kind: EventKind,
        source: &Path,
        destination: &Path,
        bytes: u64,
        diagnostics: Option<CopyDiagnostics>,
    ) -> Result<()> {
        if kind == EventKind::Completed {
            self.completed += 1;
            self.bytes += bytes;
            #[cfg(feature = "live-progress")]
            if let Some(progress) = &self.options.live_progress {
                progress.complete();
            }
        }
        (self.events)(&CopyEvent {
            kind,
            source: source.to_owned(),
            destination: destination.to_owned(),
            bytes,
            completed: self.completed,
            copied_bytes: self.bytes,
            diagnostics,
            warning: None,
        })
        .map_err(|error| CallbackError(error).into())
    }
    fn attrs(
        &mut self,
        source: &Path,
        destination: &Path,
        info: &Metadata,
        follow: bool,
    ) -> Result<()> {
        self.attrs_after_times(source, destination, info, follow, false)
    }
    fn attrs_after_times(
        &mut self,
        source: &Path,
        destination: &Path,
        info: &Metadata,
        follow: bool,
        times_applied: bool,
    ) -> Result<()> {
        if (self.options.preserve_xattrs || self.options.preserve_streams)
            && let Err(error) = native_metadata::copy(source, destination, follow, self.options)
        {
            if self.options.preserve_streams || self.options.require_preserve_xattrs {
                return Err(crate::MetadataPreservationError {
                    destination: destination.to_owned(),
                    error,
                }
                .into());
            }
            if !self.options.reduce_xattr_diagnostics {
                (self.events)(&CopyEvent {
                    kind: EventKind::Warning,
                    source: source.to_owned(),
                    destination: destination.to_owned(),
                    bytes: 0,
                    completed: self.completed,
                    copied_bytes: self.bytes,
                    diagnostics: None,
                    warning: Some(crate::MetadataWarning {
                        destination: destination.to_owned(),
                        error: error.raw_os_error().unwrap_or(50),
                    }),
                })
                .map_err(CallbackError)?;
            }
        }
        if self.options.preserve_windows_attributes {
            let file = OpenOptions::new()
                .access_mode(0x100)
                .custom_flags(0x02000000 | if follow { 0 } else { 0x00200000 })
                .open(destination)?;
            #[repr(C)]
            struct BasicInfo {
                creation: i64,
                access: i64,
                write: i64,
                change: i64,
                attributes: u32,
            }
            let basic = BasicInfo {
                creation: info.creation_time() as i64,
                access: info.last_access_time() as i64,
                write: info.last_write_time() as i64,
                change: 0,
                attributes: info.file_attributes() & !(0x10 | 0x400 | 0x4000 | 0x200 | 0x800),
            };
            // SAFETY: Live attribute-write handle and correctly aligned FILE_BASIC_INFO.
            checked(unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    0,
                    (&basic as *const BasicInfo).cast(),
                    std::mem::size_of::<BasicInfo>() as u32,
                )
            })?;
            close(file)?;
        }
        if self.options.preserve_timestamps
            && !self.options.preserve_windows_attributes
            && !times_applied
        {
            let file = OpenOptions::new()
                .access_mode(0x100)
                .custom_flags(0x02000000 | if follow { 0 } else { 0x00200000 })
                .open(destination)
                .map_err(|error| operation("cannot open for setting times", destination, error))?;
            file.set_times(
                std::fs::FileTimes::new()
                    .set_accessed(info.accessed()?)
                    .set_modified(info.modified()?),
            )
            .map_err(|error| operation("preserving times for", destination, error))?;
            close(file).map_err(|error| operation("failed to close", destination, error))?;
        }
        if self.options.preserve_mode && follow {
            fs::set_permissions(destination, info.permissions())
                .map_err(|error| operation("preserving permissions for", destination, error))?;
        }
        if self.options.preserve_ownership
            || self.options.preserve_mode
            || self.options.preserve_sacl
        {
            preserve_security(
                source,
                destination,
                follow,
                self.options.preserve_ownership,
                self.options.preserve_mode,
                self.options.preserve_sacl,
            )
            .map_err(|error| crate::MetadataPreservationError {
                destination: destination.to_owned(),
                error,
            })?;
        }
        Ok(())
    }
    fn backup(&self, source: &Path, destination: &Path) -> Result<()> {
        let suffix = self
            .options
            .backup_suffix
            .as_deref()
            .unwrap_or(OsStr::new("~"));
        let mut simple = destination.as_os_str().to_owned();
        simple.push(suffix);
        let mut prefix: Vec<u16> = destination
            .file_name()
            .ok_or_else(|| io::Error::other("backup destination has no filename"))?
            .encode_wide()
            .collect();
        prefix.extend(".~".encode_utf16());
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut maximum = 0_u64;
        for entry in fs::read_dir(parent)? {
            let name: Vec<u16> = entry?.file_name().encode_wide().collect();
            if let Some(tail) = name.strip_prefix(prefix.as_slice())
                && tail.last() == Some(&126)
                && tail.len() > 1
            {
                let number = tail[..tail.len() - 1]
                    .iter()
                    .try_fold(0_u64, |value, unit| {
                        if (48..=57).contains(unit) {
                            value.checked_mul(10)?.checked_add(u64::from(*unit - 48))
                        } else {
                            None
                        }
                    });
                if let Some(number) = number {
                    maximum = maximum.max(number);
                }
            }
        }
        let numbered = self.options.backup_mode == BackupMode::Numbered
            || (self.options.backup_mode == BackupMode::Existing && maximum > 0);
        if numbered {
            for number in maximum
                .checked_add(1)
                .ok_or_else(|| io::Error::other("backup version overflow"))?..
            {
                let mut name = destination.as_os_str().to_owned();
                name.push(format!(".~{number}~"));
                let target = Path::new(&name);
                if target == source {
                    return Err(crate::BackupWouldDestroySource.into());
                }
                match rename_new(destination, target) {
                    Ok(()) => return Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            unreachable!();
        }
        let target = Path::new(&simple);
        if target == source {
            return Err(crate::BackupWouldDestroySource.into());
        }
        if fs::symlink_metadata(target).is_ok() {
            remove(target)?;
        }
        fs::rename(destination, target)?;
        Ok(())
    }
    fn entry(&mut self, source: &Path, destination: &Path, depth: usize) -> Result<()> {
        self.options
            .cancellation
            .check()
            .map_err(|e| CallbackError(e.into()))?;
        let basename: Vec<u16> = source
            .file_name()
            .unwrap_or(source.as_os_str())
            .encode_wide()
            .collect();
        if self
            .options
            .exclusions
            .iter()
            .any(|pattern| glob(&pattern.encode_wide().collect::<Vec<_>>(), &basename))
        {
            return self.event(EventKind::Excluded, source, destination, 0, None);
        }
        let follow = self.options.dereference == Dereference::Always
            || (depth == 0 && self.options.dereference == Dereference::CommandLine);
        if self.options.reject_symlinks
            && fs::symlink_metadata(source)?.file_attributes() & 0x400 != 0
        {
            bail!("source contains a reparse point: {}", source.display());
        }
        let info = (if follow {
            fs::metadata(source)
        } else {
            fs::symlink_metadata(source)
        })
        .map_err(|error| crate::SourceStatError {
            path: source.to_owned(),
            error,
        })?;
        let source_id = path_identity(source, follow).map_err(|error| crate::SourceStatError {
            path: source.to_owned(),
            error,
        })?;
        let destination_info = match fs::symlink_metadata(destination) {
            Ok(info) => Some(info),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(existing) = &destination_info {
            if !info.is_dir() {
                if self.options.no_clobber
                    || (self.options.update && existing.modified()? >= info.modified()?)
                {
                    if self.options.update
                        && self.options.preserve_links
                        && info.is_file()
                        && let Ok(id) = path_identity(destination, true)
                    {
                        self.state
                            .links
                            .insert(source_id, (destination.to_owned(), id));
                    }
                    self.event(EventKind::Skipped, source, destination, 0, None)?;
                    if self.options.fail_on_skip {
                        bail!("not replacing destination");
                    }
                    return Ok(());
                }
                if !(self.overwrite)(source, destination).map_err(CallbackError)? {
                    self.declined = true;
                    return self.event(EventKind::Skipped, source, destination, 0, None);
                }
            }
            if path_identity(destination, follow).is_ok_and(|id| id == source_id)
                && !(self.options.backup_suffix.is_some() && self.options.force)
            {
                if self.options.hard_link {
                    return self.event(EventKind::Completed, source, destination, 0, None);
                }
                return Err(crate::SameFileError {
                    source_path: source.to_owned(),
                    destination_path: destination.to_owned(),
                }
                .into());
            }
            if !info.is_dir() {
                if depth == 0
                    && existing.file_type().is_symlink()
                    && self.options.backup_suffix.is_none()
                    && !self.options.remove_destination
                    && !(info.file_type().is_symlink()
                        && !self.options.hard_link
                        && !self.options.symbolic_link)
                    && self.state.symlinks.get(destination).is_some_and(|id| {
                        path_identity(destination, false).ok().as_ref() == Some(id)
                    })
                {
                    return Err(crate::CreatedSymlinkError {
                        source_path: source.to_owned(),
                        destination_path: destination.to_owned(),
                    }
                    .into());
                }
                if self.options.backup_suffix.is_some() {
                    self.backup(source, destination)?;
                } else if self.options.remove_destination {
                    remove(destination)?;
                }
            }
        }
        if info.is_dir() {
            return self.directory(source, destination, &info, source_id, depth);
        }
        if self.options.hard_link || self.options.symbolic_link || info.file_type().is_symlink() {
            if fs::symlink_metadata(destination).is_ok() {
                if self.options.attributes_only
                    && !self.options.hard_link
                    && !self.options.symbolic_link
                {
                    bail!("cannot overwrite destination symlink in attributes-only mode");
                }
                if self.options.force || self.options.overwrite || info.file_type().is_symlink() {
                    remove(destination)?;
                }
            }
            if self.options.hard_link {
                fs::hard_link(source, destination).map_err(|error| crate::LinkCreationError {
                    source_path: source.to_owned(),
                    destination_path: destination.to_owned(),
                    symbolic: false,
                    error,
                })?;
            } else {
                let target = if self.options.symbolic_link {
                    source.to_owned()
                } else {
                    fs::read_link(source)?
                };
                let directory_link = info.file_attributes() & 0x10 != 0;
                let result = if directory_link {
                    std::os::windows::fs::symlink_dir(target, destination)
                } else {
                    std::os::windows::fs::symlink_file(target, destination)
                };
                result.map_err(|error| crate::LinkCreationError {
                    source_path: source.to_owned(),
                    destination_path: destination.to_owned(),
                    symbolic: true,
                    error,
                })?;
                self.attrs(source, destination, &info, false)?;
                if depth == 0 {
                    self.state
                        .symlinks
                        .insert(destination.to_owned(), path_identity(destination, false)?);
                }
            }
            return self.event(EventKind::Completed, source, destination, 0, None);
        }
        if !info.is_file() {
            bail!("unsupported Windows source file type");
        }
        if self.options.preserve_links
            && let Some((path, id)) = self.state.links.get(&source_id).cloned()
            && path != destination
            && path_identity(&path, true).ok() == Some(id)
        {
            if fs::symlink_metadata(destination).is_ok() {
                remove(destination)?;
            }
            fs::hard_link(path, destination)?;
            return self.event(EventKind::Completed, source, destination, 0, None);
        }
        self.regular(source, destination, &info, source_id)?;
        Ok(())
    }
    fn directory(
        &mut self,
        source: &Path,
        destination: &Path,
        info: &Metadata,
        id: Identity,
        depth: usize,
    ) -> Result<()> {
        if !self.options.recursive {
            bail!("omitting directory (recursive copy was not requested)");
        }
        if self.ancestors.contains(&id) {
            bail!("cannot copy cyclic symbolic link");
        }
        let exists = fs::symlink_metadata(destination).ok();
        if let Some(existing) = exists {
            if existing.file_type().is_symlink()
                && !(self.options.keep_directory_symlink && self.options.copy_contents)
            {
                bail!("cannot overwrite destination directory symlink");
            }
            if !fs::metadata(destination)?.is_dir() || !self.options.merge_directories {
                bail!("destination already exists or is not a directory");
            }
        } else {
            fs::create_dir(destination)?;
            self.event(EventKind::DirectoryCreated, source, destination, 0, None)?;
        }
        if self.root_volume.is_none() {
            self.root_volume = Some(id.0);
        }
        self.ancestors.push(id);
        let mut failures = Vec::new();
        if !self.options.one_file_system || depth == 0 || self.root_volume == Some(id.0) {
            match fs::read_dir(source) {
                Ok(entries) => {
                    let parallel = self.parallel_allowed() && case_insensitive_directory(source);
                    let mut entries = entries.peekable();
                    while entries.peek().is_some() {
                        let result = if parallel
                            && entries.peek().is_some_and(|entry| {
                                entry
                                    .as_ref()
                                    .is_ok_and(|entry| fresh_regular(entry, destination))
                            }) {
                            self.parallel_files(&mut entries, destination, &mut failures)
                        } else {
                            let Some(entry) = entries.next() else {
                                break;
                            };
                            entry.map_err(anyhow::Error::from).and_then(|entry| {
                                self.entry(
                                    &entry.path(),
                                    &destination.join(entry.file_name()),
                                    depth + 1,
                                )
                            })
                        };
                        if let Err(error) = result {
                            if self.options.stop_on_error || error.is::<CallbackError>() {
                                self.ancestors.pop();
                                return Err(error);
                            }
                            failures.push(error);
                        }
                    }
                }
                Err(error) => failures.push(operation("cannot access directory", source, error)),
            }
        }
        self.ancestors.pop();
        if let Err(error) = self.attrs(source, destination, info, true) {
            failures.push(error);
        }
        if failures.is_empty() {
            self.event(EventKind::Completed, source, destination, 0, None)
        } else {
            Err(crate::MultipleCopyErrors(failures).into())
        }
    }
    fn parallel_allowed(&self) -> bool {
        let options = self.options;
        if options.jobs <= 1
            || options.preserve_links
            || options.hard_link
            || options.symbolic_link
            || options.backup_suffix.is_some()
            || options.update
            || options.no_clobber
            || options.attributes_only
            || options.copy_contents
            || options.force
            || options.remove_destination
            || options.preserve_sacl
        {
            return false;
        }
        let mut token = std::ptr::null_mut();
        // SAFETY: Current-thread pseudo handle and valid token output. Workers
        // inherit process credentials, so an impersonating caller stays serial.
        if unsafe { OpenThreadToken(GetCurrentThread(), 0x8, 1, &mut token) } != 0 {
            // SAFETY: OpenThreadToken returned an owned token handle.
            unsafe {
                CloseHandle(token);
            }
            return false;
        }
        io::Error::last_os_error().raw_os_error() == Some(1008)
    }
    fn parallel_files(
        &mut self,
        entries: &mut std::iter::Peekable<fs::ReadDir>,
        destination: &Path,
        failures: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
        let mut options = self.options.clone();
        // Classification cannot reserve the namespace. Never truncate a target
        // created between classification and a worker's create_new operation.
        options.overwrite = false;
        options.recursive = false;
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let jobs = std::iter::from_fn(|| {
            if !entries.peek().is_some_and(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| fresh_regular(entry, destination))
            }) {
                return None;
            }
            let entry = entries.next()?.ok()?;
            Some((entry.path(), destination.join(entry.file_name())))
        });
        let result = crate::pool::run(
            jobs,
            options.jobs,
            &cancellation,
            |(source, destination)| {
                let mut recorded = Vec::new();
                let mut record = |event: &CopyEvent| {
                    recorded.push(event.clone());
                    Ok(())
                };
                let mut approve = |_: &Path, _: &Path| Ok(true);
                let mut state = CopyState::default();
                let mut copier = Copier {
                    options: &options,
                    events: &mut record,
                    overwrite: &mut approve,
                    state: &mut state,
                    completed: 0,
                    bytes: 0,
                    ancestors: Vec::new(),
                    root_volume: None,
                    declined: false,
                };
                let result = copier.fresh_regular_file(&source, &destination);
                (result, recorded)
            },
            |(result, recorded)| {
                self.options
                    .cancellation
                    .check()
                    .map_err(|error| CallbackError(error.into()))?;
                for mut event in recorded {
                    if event.kind == EventKind::Completed {
                        self.completed += 1;
                        self.bytes += event.bytes;
                        self.state.symlinks.remove(&event.destination);
                    }
                    event.completed = self.completed;
                    event.copied_bytes = self.bytes;
                    (self.events)(&event).map_err(CallbackError)?;
                }
                if let Err(error) = result {
                    if self.options.stop_on_error || error.is::<CallbackError>() {
                        return Err(error);
                    }
                    failures.push(error);
                }
                Ok::<(), anyhow::Error>(())
            },
        );
        match result {
            Ok(()) => Ok(()),
            Err(crate::pool::PoolError::Consumer(error)) => Err(error),
            Err(error) => Err(CallbackError(anyhow::Error::new(error)).into()),
        }
    }
    fn fresh_regular_file(&mut self, source: &Path, destination: &Path) -> Result<()> {
        self.options
            .cancellation
            .check()
            .map_err(|error| CallbackError(error.into()))?;
        let basename: Vec<u16> = source
            .file_name()
            .unwrap_or(source.as_os_str())
            .encode_wide()
            .collect();
        if self
            .options
            .exclusions
            .iter()
            .any(|pattern| glob(&pattern.encode_wide().collect::<Vec<_>>(), &basename))
        {
            return self.event(EventKind::Excluded, source, destination, 0, None);
        }
        let info = fs::symlink_metadata(source).map_err(|error| crate::SourceStatError {
            path: source.to_owned(),
            error,
        })?;
        if !info.is_file() || info.file_attributes() & 0x400 != 0 {
            return Err(crate::ReplacedSourceError(source.to_owned()).into());
        }
        let discovered = path_identity(source, false).map_err(|error| crate::SourceStatError {
            path: source.to_owned(),
            error,
        })?;
        self.regular(source, destination, &info, discovered)
    }
    fn regular(
        &mut self,
        source: &Path,
        destination: &Path,
        info: &Metadata,
        discovered: Identity,
    ) -> Result<()> {
        if self.options.preserve_windows_attributes && info.file_attributes() & 0x4000 != 0 {
            bail!(
                "native EFS preservation is unsupported: {}",
                source.display()
            );
        }
        let mut input = File::open(source)
            .map_err(|error| operation("cannot open for reading", source, error))?;
        let observed = identity(&input).map_err(|error| crate::SourceStatError {
            path: source.to_owned(),
            error,
        })?;
        if observed != discovered {
            return Err(crate::ReplacedSourceError(source.to_owned()).into());
        }
        let mut fresh = false;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination);
        let mut output = match output {
            Ok(file) => {
                fresh = true;
                file
            }
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists && self.options.overwrite =>
            {
                if fs::symlink_metadata(destination)?.file_type().is_symlink()
                    && fs::metadata(destination).is_err()
                    && !self.options.allow_dangling_destination
                {
                    return Err(crate::DanglingDestination.into());
                }
                let existing = OpenOptions::new()
                    .read(self.options.attributes_only)
                    .write(!self.options.attributes_only)
                    .open(destination);
                match existing {
                    Ok(file) => file,
                    Err(_) if self.options.force => {
                        remove(destination)?;
                        fresh = true;
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(destination)?
                    }
                    Err(error) => {
                        return Err(operation("cannot create regular file", destination, error));
                    }
                }
            }
            Err(error) => return Err(operation("cannot create regular file", destination, error)),
        };
        let output_id =
            identity(&output).map_err(|error| operation("cannot stat", destination, error))?;
        if observed == output_id {
            return Err(crate::SameFileError {
                source_path: source.to_owned(),
                destination_path: destination.to_owned(),
            }
            .into());
        }
        if self.options.preserve_windows_attributes && info.file_attributes() & 0x800 != 0 {
            let mut returned = 0;
            let format = 1u16;
            // SAFETY: Writable output and a native compression-format word.
            checked(unsafe {
                DeviceIoControl(
                    output.as_raw_handle(),
                    0x9c040,
                    (&format as *const u16).cast(),
                    2,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            })?;
        }
        let mut bytes = 0;
        let mut diagnostics = CopyDiagnostics::default();
        if !self.options.attributes_only {
            output
                .set_len(0)
                .map_err(|error| operation("cannot truncate", destination, error))?;
            if self.options.reflink != ReflinkMode::Never
                && self.options.sparse != SparseMode::Never
            {
                diagnostics.reflink_attempted = true;
                match clone_data(&input, &output, info.len()) {
                    Ok(()) => {
                        diagnostics.cloned = true;
                        bytes = info.len();
                        #[cfg(feature = "live-progress")]
                        if let Some(progress) = &self.options.live_progress {
                            progress.add_bytes(bytes);
                        }
                    }
                    Err(error) if self.options.reflink == ReflinkMode::Always => {
                        drop(output);
                        if fresh {
                            remove(destination)?;
                        }
                        return Err(crate::FilePairOperationError {
                            operation: "failed to clone",
                            source: source.to_owned(),
                            destination: destination.to_owned(),
                            error,
                        }
                        .into());
                    }
                    Err(error) if clone_failure_is_terminal(&error) => {
                        return Err(error.into());
                    }
                    Err(_) => {
                        output.set_len(0)?;
                    }
                }
            }
            if !diagnostics.cloned {
                bytes = buffered_data(
                    source,
                    destination,
                    &mut input,
                    &mut output,
                    info,
                    self.options,
                    &mut diagnostics,
                )?;
            }
        }
        self.options
            .cancellation
            .check()
            .map_err(|error| CallbackError(error.into()))?;
        let times_applied = self.options.preserve_timestamps
            && !self.options.preserve_windows_attributes
            && !self.options.preserve_streams
            && !self.options.preserve_xattrs
            && !self.options.attributes_only;
        if times_applied {
            output
                .set_times(
                    std::fs::FileTimes::new()
                        .set_accessed(info.accessed()?)
                        .set_modified(info.modified()?),
                )
                .map_err(|error| operation("preserving times for", destination, error))?;
        }
        close(output).map_err(|error| operation("failed to close", destination, error))?;
        close(input).map_err(|error| operation("failed to close", source, error))?;
        self.attrs_after_times(source, destination, info, true, times_applied)?;
        if fresh && !self.options.preserve_mode && !self.options.default_permissions {
            fs::set_permissions(destination, info.permissions())?;
        }
        if self.options.preserve_links {
            self.state.links.insert(
                discovered,
                (destination.to_owned(), path_identity(destination, true)?),
            );
        }
        self.state.symlinks.remove(destination);
        self.event(
            EventKind::Completed,
            source,
            destination,
            bytes,
            if self.options.attributes_only {
                None
            } else {
                Some(diagnostics)
            },
        )
    }
}
fn case_insensitive_directory(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new()
        .access_mode(0x80)
        .custom_flags(0x02000000)
        .open(path)
    else {
        return false;
    };
    let mut flags = 0_u32;
    // SAFETY: A live directory handle and native FILE_CASE_SENSITIVE_INFO output.
    let result = unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 23, (&mut flags as *mut u32).cast(), 4)
    };
    result != 0 && flags & 1 == 0
}
fn fresh_regular(entry: &fs::DirEntry, destination: &Path) -> bool {
    entry.file_type().is_ok_and(|kind| kind.is_file())
        && entry
            .metadata()
            .is_ok_and(|info| info.file_attributes() & 0x400 == 0)
        && fs::symlink_metadata(destination.join(entry.file_name()))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}
fn destination_absolute(destination: &Path) -> io::Result<PathBuf> {
    if let Ok(path) = fs::canonicalize(destination) {
        return Ok(path);
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = if parent == destination {
        return Err(io::Error::other("cannot resolve destination"));
    } else {
        destination_absolute(parent)?
    };
    Ok(parent.join(
        destination
            .file_name()
            .ok_or_else(|| io::Error::other("destination has no filename"))?,
    ))
}

pub(crate) fn copy_tree(
    source: &Path,
    destination: &Path,
    options: &CopyOptions,
    events: &mut dyn FnMut(&CopyEvent) -> Result<()>,
    overwrite: &mut dyn FnMut(&Path, &Path) -> Result<bool>,
    state: &mut CopyState,
) -> Result<()> {
    if !(4096..=16 * 1024 * 1024).contains(&options.buffer_size) {
        bail!("buffer size must be between 4096 and 16777216");
    }
    if options.hard_link && options.symbolic_link {
        bail!("cannot make both hard and symbolic links");
    }
    if options.reflink == ReflinkMode::Always && options.sparse != SparseMode::Auto {
        bail!("--reflink=always requires --sparse=auto");
    }
    for pattern in &options.exclusions {
        if pattern.encode_wide().any(|unit| unit == 0) {
            bail!("exclusion pattern contains NUL");
        }
    }
    let _privileges = if options.preserve_sacl {
        Some(native_metadata::BackupPrivileges::acquire(true)?)
    } else {
        None
    };
    let info = (if options.dereference == Dereference::Never {
        fs::symlink_metadata(source)
    } else {
        fs::metadata(source)
    })
    .map_err(|error| crate::SourceStatError {
        path: source.to_owned(),
        error,
    })?;
    let source_resolved = fs::canonicalize(source).ok();
    if info.is_dir()
        && source_resolved.as_ref().is_some_and(|root| {
            destination_absolute(destination)
                .is_ok_and(|target| target.starts_with(root) && target != *root)
        })
    {
        return Err(crate::IntoSelfError {
            source_path: source.to_owned(),
            destination_path: destination.to_owned(),
        }
        .into());
    }
    let mut copier = Copier {
        options,
        events,
        overwrite,
        state,
        completed: 0,
        bytes: 0,
        ancestors: Vec::new(),
        root_volume: None,
        declined: false,
    };
    let mut parents = Vec::new();
    if options.parents {
        let mut source_parent = source.parent();
        let mut destination_parent = destination.parent();
        while let Some(source_path) = source_parent {
            if source_path.as_os_str().is_empty() || source_path.file_name().is_none() {
                break;
            }
            let destination_path = destination_parent
                .ok_or_else(|| io::Error::other("missing mapped destination parent"))?;
            let metadata = fs::metadata(source_path)?;
            if !metadata.is_dir() {
                bail!("source parent is not a directory");
            }
            parents.push((
                source_path.to_owned(),
                destination_path.to_owned(),
                metadata,
            ));
            source_parent = source_path.parent();
            destination_parent = destination_path.parent();
        }
        for (source_path, destination_path, _) in parents.iter().rev() {
            match fs::metadata(destination_path) {
                Ok(info) if info.is_dir() => (),
                Ok(_) => bail!("destination parent is not a directory"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(destination_path)?;
                    copier.event(
                        EventKind::DirectoryCreated,
                        source_path,
                        destination_path,
                        0,
                        None,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    let mut result = copier.entry(source, destination, 0);
    for (source, destination, info) in parents {
        if let Err(error) = copier.attrs(&source, &destination, &info, true)
            && result.is_ok()
        {
            result = Err(error);
        }
    }
    if result.is_ok() && copier.declined {
        result = Err(crate::OverwriteDeclined.into());
    }
    copier.event(
        if result.is_ok() {
            EventKind::Done
        } else {
            EventKind::Failed
        },
        source,
        destination,
        0,
        None,
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::clone_failure_is_terminal;
    use std::io;

    #[test]
    fn clone_io_resource_and_quota_failures_are_terminal() {
        for code in [
            8, 14, 23, 29, 30, 31, 39, 112, 1117, 1392, 1393, 1450, 1453, 1454, 1455, 1816,
        ] {
            assert!(
                clone_failure_is_terminal(&io::Error::from_raw_os_error(code)),
                "code {code}"
            );
        }
        for code in [1, 5, 17, 50, 87] {
            assert!(
                !clone_failure_is_terminal(&io::Error::from_raw_os_error(code)),
                "code {code}"
            );
        }
    }
}

#[cfg(test)]
mod native_metadata_tests {
    use super::*;
    use std::ptr;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetEaFile(file: Handle, status: *mut [usize; 2], data: *const u8, length: u32) -> i32;
        fn NtQueryEaFile(
            file: Handle,
            status: *mut [usize; 2],
            data: *mut u8,
            length: u32,
            single: u8,
            list: *const c_void,
            list_length: u32,
            index: *const u32,
            restart: u8,
        ) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorSacl(
            descriptor: *const c_void,
            present: *mut i32,
            sacl: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *const c_void,
            revision: u32,
            information: u32,
            text: *mut *mut u16,
            size: *mut u32,
        ) -> i32;
    }
    fn ea(path: &Path, set: bool) -> Vec<u8> {
        let file = OpenOptions::new()
            .access_mode(0x18)
            .custom_flags(0x02000000)
            .open(path)
            .unwrap();
        let mut status = [0usize; 2];
        if set {
            let mut data = vec![0, 0, 0, 0, 0, 7, 4, 0];
            data.extend_from_slice(b"Test.EA\0\x00\xff\x12\x00");
            // SAFETY: One complete FILE_FULL_EA_INFORMATION record with name terminator and binary value.
            assert_eq!(
                unsafe {
                    NtSetEaFile(
                        file.as_raw_handle(),
                        &mut status,
                        data.as_ptr(),
                        data.len() as u32,
                    )
                },
                0
            );
        }
        let mut data = vec![0u8; 4096];
        // SAFETY: EA-read handle and initialized bounded native output/IO status storage.
        assert_eq!(
            unsafe {
                NtQueryEaFile(
                    file.as_raw_handle(),
                    &mut status,
                    data.as_mut_ptr(),
                    data.len() as u32,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    1,
                )
            },
            0
        );
        data.truncate(status[1]);
        data
    }
    fn audit(path: &Path, set: bool) -> String {
        let file = OpenOptions::new()
            .access_mode(0x01060000)
            .custom_flags(0x02000000)
            .open(path)
            .unwrap();
        if set {
            let text: Vec<_> = "S:P(AU;SAFA;0x120089;;;WD)"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut raw = ptr::null_mut();
            // SAFETY: Terminated SDDL and writable descriptor output; returned LocalAlloc memory is freed below.
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        text.as_ptr(),
                        1,
                        &mut raw,
                        ptr::null_mut(),
                    )
                },
                0
            );
            let mut sacl = ptr::null_mut();
            let (mut present, mut defaulted) = (0, 0);
            // SAFETY: Converted valid descriptor and correctly typed outputs.
            assert_ne!(
                unsafe { GetSecurityDescriptorSacl(raw, &mut present, &mut sacl, &mut defaulted) },
                0
            );
            // SAFETY: Live audit-write handle and retained converted SACL; protection requested explicitly.
            assert_eq!(
                unsafe {
                    SetSecurityInfo(
                        file.as_raw_handle(),
                        1,
                        8 | 0x40000000,
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        sacl,
                    )
                },
                0
            );
            // SAFETY: Descriptor was allocated by the conversion API.
            unsafe { LocalFree(raw) };
        }
        let descriptor = security(&file, 8).unwrap();
        let mut text = ptr::null_mut();
        // SAFETY: Retained security descriptor and valid writable string output.
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor.memory,
                    1,
                    8,
                    &mut text,
                    ptr::null_mut(),
                )
            },
            0
        );
        let mut length = 0;
        // SAFETY: API returned terminated UTF-16 text.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: All units preceding the terminator belong to the returned allocation.
        let value =
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap();
        // SAFETY: String memory is allocated by the security API.
        unsafe { LocalFree(text.cast()) };
        value
    }
    #[test]
    #[ignore = "requires elevated Windows on NTFS with backup, restore and security privileges"]
    fn native_copy_restores_file_directory_empty_ads_binary_eas_and_protected_sacl() {
        let _privileges = native_metadata::BackupPrivileges::acquire(true).unwrap();
        let tree = tempfile::tempdir().unwrap();
        let source = tree.path().join("source");
        fs::create_dir(&source).unwrap();
        let file = source.join("file");
        fs::write(&file, b"main data").unwrap();
        fs::write(source.join("file:ads"), b"alternate data").unwrap();
        fs::write(source.join("file:empty"), b"").unwrap();
        let root_ads = PathBuf::from(format!("{}:directory-ads", source.display()));
        fs::write(root_ads, b"directory stream").unwrap();
        fs::hard_link(&file, source.join("alias")).unwrap();
        let file_ea = ea(&file, true);
        let dir_ea = ea(&source, true);
        let file_audit = audit(&file, true);
        let dir_audit = audit(&source, true);
        let destination = tree.path().join("destination");
        let options = CopyOptions {
            preserve_streams: true,
            preserve_sacl: true,
            preserve_windows_attributes: true,
            preserve_xattrs: true,
            preserve_links: true,
            ..CopyOptions::default()
        };
        crate::copy(&source, &destination, &options).unwrap();
        assert_eq!(
            fs::read(destination.join("file:ads")).unwrap(),
            b"alternate data"
        );
        assert_eq!(fs::read(destination.join("alias:empty")).unwrap(), b"");
        assert_eq!(
            fs::read(PathBuf::from(format!(
                "{}:directory-ads",
                destination.display()
            )))
            .unwrap(),
            b"directory stream"
        );
        assert_eq!(ea(&destination.join("file"), false), file_ea);
        assert_eq!(ea(&destination, false), dir_ea);
        assert_eq!(audit(&destination.join("file"), false), file_audit);
        assert_eq!(audit(&destination, false), dir_audit);
        assert_eq!(
            path_identity(&destination.join("file"), true).unwrap(),
            path_identity(&destination.join("alias"), true).unwrap()
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().creation_time(),
            fs::metadata(&source).unwrap().creation_time()
        );
        fs::write(destination.join("file:ads"), b"alias edit").unwrap();
        assert_eq!(
            fs::read(destination.join("alias:ads")).unwrap(),
            b"alias edit"
        );
    }
}
