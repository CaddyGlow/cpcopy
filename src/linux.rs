use crate::{CopyDiagnostics, CopyEvent, CopyOptions, EventKind};
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::Path,
};

#[derive(Default)]
pub(crate) struct CopyState {
    created_symlinks: std::collections::HashMap<std::path::PathBuf, (libc::dev_t, libc::ino_t)>,
    links: std::collections::HashMap<(libc::dev_t, libc::ino_t), LinkRecord>,
}
struct LinkRecord {
    path: std::path::PathBuf,
    identity: (libc::dev_t, libc::ino_t),
    follow: bool,
}

#[derive(Debug)]
struct CallbackError(anyhow::Error);
impl std::fmt::Display for CallbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for CallbackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

struct Copier<'a> {
    options: &'a CopyOptions,
    events: &'a mut dyn FnMut(&CopyEvent) -> Result<()>,
    overwrite: &'a mut dyn FnMut(&Path, &Path) -> Result<bool>,
    declined: bool,
    warnings: Vec<crate::MetadataWarning>,
    root_device: libc::dev_t,
    created_symlinks:
        &'a mut std::collections::HashMap<std::path::PathBuf, (libc::dev_t, libc::ino_t)>,
    patterns: Vec<CString>,
    completed: u64,
    bytes: u64,
    ancestors: std::collections::HashSet<(libc::dev_t, libc::ino_t)>,
    links: &'a mut std::collections::HashMap<(libc::dev_t, libc::ino_t), LinkRecord>,
}
impl Copier<'_> {
    fn event(
        &mut self,
        kind: EventKind,
        source: &Path,
        destination: &Path,
        bytes: u64,
    ) -> Result<()> {
        self.event_detailed(kind, source, destination, bytes, None)
    }
    fn event_detailed(
        &mut self,
        kind: EventKind,
        source: &Path,
        destination: &Path,
        bytes: u64,
        diagnostics: Option<CopyDiagnostics>,
    ) -> Result<()> {
        #[cfg(feature = "live-progress")]
        if kind == EventKind::Completed
            && let Some(progress) = &self.options.live_progress
        {
            progress.complete();
        }
        (self.events)(&CopyEvent {
            warning: None,
            kind,
            source: source.to_owned(),
            destination: destination.to_owned(),
            bytes,
            completed: self.completed,
            copied_bytes: self.bytes,
            diagnostics,
        })
        .map_err(CallbackError)?;
        Ok(())
    }
    fn flush_warnings(&mut self, source: &Path, destination: &Path) -> Result<()> {
        for warning in std::mem::take(&mut self.warnings) {
            (self.events)(&CopyEvent {
                kind: EventKind::Warning,
                source: source.to_owned(),
                destination: destination.to_owned(),
                bytes: 0,
                completed: self.completed,
                copied_bytes: self.bytes,
                diagnostics: None,
                warning: Some(warning),
            })
            .map_err(CallbackError)?;
        }
        Ok(())
    }
    fn remember_symlink(&mut self, destination: &Path, depth: usize) -> Result<()> {
        if depth == 0 {
            let info = stat(&name(destination)?)?;
            if info.st_mode & libc::S_IFMT == libc::S_IFLNK {
                self.created_symlinks
                    .insert(destination.to_owned(), (info.st_dev, info.st_ino));
            } else {
                self.created_symlinks.remove(destination);
            }
        }
        Ok(())
    }
    fn excluded(&self, source: &Path) -> Result<bool> {
        let basename = CString::new(source.file_name().unwrap_or(source.as_os_str()).as_bytes())?;
        Ok(self.patterns.iter().any(|pattern| {
            // SAFETY: Both inputs are terminated native-byte strings.
            unsafe { libc::fnmatch(pattern.as_ptr(), basename.as_ptr(), 0) == 0 }
        }))
    }
}

fn name(path: &Path) -> Result<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}

fn backup_path(
    destination: &Path,
    suffix: &std::ffi::OsStr,
    mode: crate::BackupMode,
) -> Result<std::path::PathBuf> {
    let mut path = destination.as_os_str().to_owned();
    if mode != crate::BackupMode::Simple {
        let parent = destination.parent().unwrap_or(Path::new("."));
        let mut prefix = destination
            .file_name()
            .context("missing destination basename")?
            .as_bytes()
            .to_vec();
        prefix.extend_from_slice(b".~");
        let mut maximum = 0_u64;
        for entry in std::fs::read_dir(parent)? {
            let basename = entry?.file_name();
            if let Some(number) = basename
                .as_bytes()
                .strip_prefix(prefix.as_slice())
                .and_then(|rest| rest.strip_suffix(b"~"))
                && let Ok(number) = std::str::from_utf8(number).unwrap_or("").parse::<u64>()
            {
                maximum = maximum.max(number);
            }
        }
        if mode == crate::BackupMode::Numbered || maximum > 0 {
            let next = maximum.checked_add(1).context("backup number overflow")?;
            path.push(format!(".~{next}~"));
            return Ok(path.into());
        }
    }
    path.push(suffix);
    Ok(path.into())
}
fn checked(value: libc::c_int) -> io::Result<()> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn stat_policy(path: &CStr, follow: bool) -> io::Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: Terminated path and writable output; lstat never follows the leaf.
    checked(unsafe {
        if follow {
            libc::stat(path.as_ptr(), value.as_mut_ptr())
        } else {
            libc::lstat(path.as_ptr(), value.as_mut_ptr())
        }
    })?;
    // SAFETY: Successful lstat initialized output.
    Ok(unsafe { value.assume_init() })
}
fn stat(path: &CStr) -> io::Result<libc::stat> {
    stat_policy(path, false)
}
fn fd_stat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: Borrowed descriptor and writable stat output.
    checked(unsafe { libc::fstat(fd.as_raw_fd(), value.as_mut_ptr()) })?;
    // SAFETY: Successful fstat initialized output.
    Ok(unsafe { value.assume_init() })
}
fn open(path: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<OwnedFd> {
    // SAFETY: Terminated path; a successful descriptor becomes owned.
    let fd = unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful open returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn close(fd: OwnedFd) -> io::Result<()> {
    // SAFETY: Transfer ownership to close, checking delayed write errors.
    // Linux releases the descriptor even when close returns EINTR.
    checked(unsafe { libc::close(fd.into_raw_fd()) })
}
fn times(info: &libc::stat) -> [libc::timespec; 2] {
    [
        libc::timespec {
            tv_sec: info.st_atime,
            tv_nsec: info.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: info.st_mtime,
            tv_nsec: info.st_mtime_nsec,
        },
    ]
}
struct AlignedBuffer {
    pointer: *mut libc::c_void,
    size: usize,
}
impl AlignedBuffer {
    fn new(size: usize) -> io::Result<Self> {
        // SAFETY: sysconf takes a valid constant and has no pointer inputs.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::other("cannot determine page size"));
        }
        let mut pointer = std::ptr::null_mut();
        // SAFETY: Valid output pointer, page alignment and bounded allocation.
        let error = unsafe { libc::posix_memalign(&mut pointer, page as usize, size) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(Self { pointer, size })
    }
}
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: Allocation belongs to this object and was created by posix_memalign.
        unsafe { libc::free(self.pointer) };
    }
}
#[derive(Default)]
struct ContentCopy {
    bytes: u64,
    diagnostics: CopyDiagnostics,
}

fn offload(mut copy_range: impl FnMut(usize) -> io::Result<usize>) -> io::Result<ContentCopy> {
    let mut copied = ContentCopy::default();
    copied.diagnostics.offload_attempted = true;
    loop {
        // Linux limits individual transfers; keep requests comfortably within ssize_t.
        match copy_range(1 << 30) {
            Ok(0) => return Ok(copied),
            Ok(count) => {
                copied.bytes += count as u64;
                copied.diagnostics.offloaded = true;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if copied.bytes == 0
                    && matches!(
                        error.raw_os_error(),
                        Some(
                            libc::ENOSYS
                                | libc::ENOTTY
                                | libc::ENOTSUP
                                | libc::EINVAL
                                | libc::EBADF
                                | libc::EXDEV
                                | libc::ETXTBSY
                                | libc::EPERM
                                | libc::EACCES
                                | libc::ENOENT
                        )
                    ) =>
            {
                return Ok(copied);
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug)]
struct TransferFailure {
    operation: &'static str,
    error: io::Error,
}
impl std::fmt::Display for TransferFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}
impl std::error::Error for TransferFailure {}
fn transfer_failure(operation: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), TransferFailure { operation, error })
}

fn transfer(
    source: &OwnedFd,
    destination: &OwnedFd,
    size: usize,
    make_holes: bool,
    mut navigate_holes: bool,
    allow_offload: bool,
    options: &CopyOptions,
) -> io::Result<ContentCopy> {
    let cancellation = &options.cancellation;
    #[cfg(feature = "live-progress")]
    let progress = options.live_progress.as_ref();
    #[cfg(feature = "live-progress")]
    let mut tracker = crate::ProgressTracker::new(progress);
    // Advisory only, like cp; an unsupported hint does not fail copying.
    // SAFETY: Borrowed descriptor and valid advisory parameters.
    unsafe { libc::posix_fadvise(source.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
    let mut diagnostics = CopyDiagnostics::default();
    if allow_offload && !make_holes {
        let copied = offload(|length| {
            // EINTR means retry the syscall, while cancellation must end it.
            cancellation.check().map_err(io::Error::other)?;
            #[cfg(feature = "live-progress")]
            let length = if progress.is_some() {
                length.min(8 * 1024 * 1024)
            } else {
                length
            };
            // SAFETY: Live distinct regular descriptors, null offsets use their current
            // positions, and length is bounded. No userspace buffer is accessed.
            let count = unsafe {
                libc::copy_file_range(
                    source.as_raw_fd(),
                    std::ptr::null_mut(),
                    destination.as_raw_fd(),
                    std::ptr::null_mut(),
                    length,
                    0,
                )
            };
            if count < 0 {
                Err(io::Error::last_os_error())
            } else {
                #[cfg(feature = "live-progress")]
                tracker.add(count as u64);
                Ok(count as usize)
            }
        })
        .map_err(|error| transfer_failure("error copying", error))?;
        if copied.bytes > 0 {
            return Ok(copied);
        }
        // Zero can mean unsupported procfs semantics, rather than EOF. Reading
        // verifies empty input and handles kernels that silently copy no bytes.
        diagnostics = copied.diagnostics;
    }
    let buffer = AlignedBuffer::new(size)?;
    let mut total = 0_u64;
    loop {
        let mut read_size = buffer.size;
        if navigate_holes {
            let position = libc::off_t::try_from(total)
                .map_err(|_| io::Error::other("copied file exceeds supported size"))?;
            // SAFETY: Regular source descriptor and nonnegative offset.
            let hole = unsafe { libc::lseek(source.as_raw_fd(), position, libc::SEEK_HOLE) };
            if hole < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENXIO) {
                    let length = fd_stat(source)?.st_size.max(position);
                    checked(unsafe { libc::ftruncate(destination.as_raw_fd(), length) })
                        .map_err(|error| transfer_failure("failed to extend", error))?;
                    #[cfg(feature = "live-progress")]
                    tracker.add(length as u64 - total);
                    return Ok(ContentCopy {
                        bytes: length as u64,
                        diagnostics,
                    });
                }
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS)
                ) {
                    navigate_holes = false;
                } else {
                    return Err(transfer_failure("cannot lseek source", error));
                }
            } else {
                diagnostics.seek_hole = true;
            }
            // SEEK_HOLE moves the offset; restore it before fallback or querying data.
            // SAFETY: Live regular source and a previously valid position.
            if unsafe { libc::lseek(source.as_raw_fd(), position, libc::SEEK_SET) } < 0 {
                return Err(transfer_failure(
                    "cannot lseek source",
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: Regular source descriptor and nonnegative offset.
            let data = unsafe { libc::lseek(source.as_raw_fd(), position, libc::SEEK_DATA) };
            if data < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENXIO) {
                    let length = fd_stat(source)?.st_size.max(position);
                    // SAFETY: Regular destination descriptor; preserve the trailing hole.
                    checked(unsafe { libc::ftruncate(destination.as_raw_fd(), length) })
                        .map_err(|error| transfer_failure("failed to extend", error))?;
                    #[cfg(feature = "live-progress")]
                    tracker.add(length as u64 - total);
                    return Ok(ContentCopy {
                        bytes: length as u64,
                        diagnostics,
                    });
                }
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS)
                ) {
                    navigate_holes = false;
                } else {
                    return Err(transfer_failure("cannot lseek source", error));
                }
            } else if data > position {
                // SAFETY: Regular destination and absolute nonnegative data offset.
                if unsafe { libc::lseek(destination.as_raw_fd(), data, libc::SEEK_SET) } < 0 {
                    return Err(transfer_failure("cannot lseek", io::Error::last_os_error()));
                }
                #[cfg(feature = "live-progress")]
                tracker.add(data as u64 - total);
                total = data as u64;
            } else if hole > position {
                read_size = read_size.min((hole - position) as usize);
            }
        }
        cancellation.check()?;
        // SAFETY: Writable allocation of buffer.size bytes and a borrowed FD.
        let count = unsafe { libc::read(source.as_raw_fd(), buffer.pointer, read_size) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(transfer_failure("error reading", error));
        }
        if count == 0 {
            if make_holes {
                let length = libc::off_t::try_from(total)
                    .map_err(|_| io::Error::other("copied file exceeds supported size"))?;
                // SAFETY: Regular destination descriptor; establish a trailing hole's length.
                checked(unsafe { libc::ftruncate(destination.as_raw_fd(), length) })
                    .map_err(|error| transfer_failure("failed to extend", error))?;
            }
            return Ok(ContentCopy {
                bytes: total,
                diagnostics,
            });
        }
        diagnostics.scanned_zeros |= make_holes;
        let mut offset = 0;
        while offset < count as usize {
            let length = if make_holes {
                (count as usize - offset).min(4096)
            } else {
                count as usize - offset
            };
            // SAFETY: This read initialized count bytes within the live allocation.
            let data = unsafe {
                std::slice::from_raw_parts(buffer.pointer.cast::<u8>().add(offset), length)
            };
            if make_holes && data.iter().all(|byte| *byte == 0) {
                // SAFETY: Regular destination descriptor and bounded positive seek increment.
                if unsafe {
                    libc::lseek(
                        destination.as_raw_fd(),
                        length as libc::off_t,
                        libc::SEEK_CUR,
                    )
                } < 0
                {
                    return Err(transfer_failure("cannot lseek", io::Error::last_os_error()));
                }
                offset += length;
                total += length as u64;
                #[cfg(feature = "live-progress")]
                tracker.add(length as u64);
                continue;
            }
            // SAFETY: The initialized read prefix bounds this slice of the allocation.
            let written = unsafe {
                libc::write(
                    destination.as_raw_fd(),
                    buffer.pointer.cast::<u8>().add(offset).cast(),
                    length,
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(transfer_failure("error writing", error));
            }
            if written == 0 {
                // GNU full_write treats a zero-byte write as a full device,
                // including buggy drivers that leave errno unchanged.
                return Err(transfer_failure(
                    "error writing",
                    io::Error::from_raw_os_error(libc::ENOSPC),
                ));
            }
            offset += written as usize;
            total += written as u64;
            #[cfg(feature = "live-progress")]
            tracker.add(written as u64);
        }
    }
}
fn file_operation(
    operation: &'static str,
    path: &CStr,
    error: io::Error,
) -> crate::FileOperationError {
    crate::FileOperationError {
        operation,
        path: Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())).to_owned(),
        error,
    }
}
fn pair_operation(
    operation: &'static str,
    source: &CStr,
    destination: &CStr,
    error: io::Error,
) -> crate::FilePairOperationError {
    crate::FilePairOperationError {
        operation,
        source: Path::new(std::ffi::OsStr::from_bytes(source.to_bytes())).to_owned(),
        destination: Path::new(std::ffi::OsStr::from_bytes(destination.to_bytes())).to_owned(),
        error,
    }
}
fn checked_seek_end(fd: &OwnedFd) -> io::Result<libc::off_t> {
    // SAFETY: Owned regular destination descriptor; SEEK_END takes no pointer.
    let result = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_END) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
fn regular(
    source: &CStr,
    destination: &CStr,
    discovered: &libc::stat,
    size: usize,
    follow: bool,
    options: &CopyOptions,
    warnings: &mut Vec<crate::MetadataWarning>,
) -> Result<ContentCopy> {
    let source_path = source;
    let source = open(
        source,
        libc::O_RDONLY | if follow { 0 } else { libc::O_NOFOLLOW },
        0,
    )
    .map_err(|error| file_operation("cannot open for reading", source_path, error))?;
    let observed =
        fd_stat(&source).map_err(|error| file_operation("cannot fstat", source_path, error))?;
    if observed.st_mode & libc::S_IFMT != discovered.st_mode & libc::S_IFMT
        || (observed.st_dev, observed.st_ino) != (discovered.st_dev, discovered.st_ino)
    {
        return Err(crate::ReplacedSourceError(
            Path::new(std::ffi::OsStr::from_bytes(source_path.to_bytes())).to_owned(),
        )
        .into());
    }
    // Use the metadata observed from the opened source, as GNU cp does.
    let discovered = &observed;
    let destination_path = destination;
    let mut creation_mode = (if options.default_permissions && !options.preserve_mode {
        0o666
    } else {
        discovered.st_mode & 0o777
    }) & !options.creation_mask;
    // Ownership preservation withholds group/other access until final metadata.
    if options.preserve_ownership {
        creation_mode &= 0o700;
    }
    // Publish directly to the final name, as cp does for a new destination.
    let fresh = open(
        destination,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        creation_mode,
    );
    let (destination, existing) = match fresh {
        Ok(fd) => (fd, false),
        Err(error) if options.overwrite && error.kind() == io::ErrorKind::AlreadyExists => {
            // Do not create through a dangling symlink or truncate before checking
            // the opened inode: the destination can alias the source.
            match open(
                destination,
                if options.attributes_only {
                    libc::O_RDONLY
                } else {
                    libc::O_WRONLY
                },
                0,
            ) {
                Ok(fd) => (fd, true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !options.allow_dangling_destination {
                        return Err(crate::DanglingDestination.into());
                    }
                    (
                        open(destination, libc::O_WRONLY | libc::O_CREAT, creation_mode).map_err(
                            |error| {
                                file_operation(
                                    "cannot create regular file",
                                    destination_path,
                                    error,
                                )
                            },
                        )?,
                        false,
                    )
                }
                Err(_) if options.force => {
                    // SAFETY: Terminated path; unlink never removes a directory.
                    if let Err(error) = checked(unsafe { libc::unlink(destination.as_ptr()) })
                        && error.kind() != io::ErrorKind::NotFound
                    {
                        return Err(file_operation("cannot remove", destination_path, error).into());
                    }
                    (
                        open(
                            destination,
                            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                            creation_mode,
                        )
                        .map_err(|error| {
                            file_operation("cannot create regular file", destination_path, error)
                        })?,
                        false,
                    )
                }
                Err(error) => {
                    return Err(file_operation(
                        "cannot create regular file",
                        destination_path,
                        error,
                    )
                    .into());
                }
            }
        }
        Err(error) => {
            return Err(
                file_operation("cannot create regular file", destination_path, error).into(),
            );
        }
    };
    let destination_info = fd_stat(&destination)
        .map_err(|error| file_operation("cannot fstat", destination_path, error))?;
    if (destination_info.st_dev, destination_info.st_ino) == (observed.st_dev, observed.st_ino) {
        return Err(crate::SameFileError {
            source_path: Path::new(std::ffi::OsStr::from_bytes(source_path.to_bytes())).to_owned(),
            destination_path: Path::new(std::ffi::OsStr::from_bytes(destination_path.to_bytes()))
                .to_owned(),
        }
        .into());
    }
    if destination_info.st_mode & libc::S_IFMT == libc::S_IFDIR {
        bail!("destination is a directory");
    }
    if existing
        && !options.attributes_only
        && destination_info.st_mode & libc::S_IFMT == libc::S_IFREG
    {
        // SAFETY: Checked regular descriptor distinct from the source inode.
        checked(unsafe { libc::ftruncate(destination.as_raw_fd(), 0) }).map_err(|error| {
            file_operation("cannot create regular file", destination_path, error)
        })?;
    }
    let mut cloned = false;
    let mut reflink_attempted = false;
    if !options.attributes_only
        && options.reflink != crate::ReflinkMode::Never
        && options.sparse != crate::SparseMode::Never
    {
        reflink_attempted = true;
        // SAFETY: Live descriptors; FICLONE takes the source descriptor as an integer.
        match checked(unsafe {
            libc::ioctl(destination.as_raw_fd(), libc::FICLONE, source.as_raw_fd())
        }) {
            Ok(()) => cloned = true,
            Err(error) => {
                let terminal = matches!(
                    error.raw_os_error(),
                    Some(libc::EIO | libc::ENOMEM | libc::ENOSPC | libc::EDQUOT)
                );
                if options.reflink == crate::ReflinkMode::Always || terminal {
                    let clone_error = anyhow::Error::from(pair_operation(
                        "failed to clone",
                        source_path,
                        destination_path,
                        error,
                    ));
                    if !existing
                        && options.reflink == crate::ReflinkMode::Always
                        && (!terminal
                            || checked_seek_end(&destination).is_ok_and(|length| length == 0))
                        && stat(destination_path).is_ok_and(|info| {
                            (info.st_dev, info.st_ino)
                                == (destination_info.st_dev, destination_info.st_ino)
                        })
                    {
                        // SAFETY: Remove only the newly created destination matching our descriptor.
                        if let Err(error) =
                            checked(unsafe { libc::unlink(destination_path.as_ptr()) })
                            && error.kind() != io::ErrorKind::NotFound
                        {
                            return Err(crate::MultipleCopyErrors(vec![
                                clone_error,
                                anyhow::Error::from(file_operation(
                                    "cannot remove",
                                    destination_path,
                                    error,
                                )),
                            ])
                            .into());
                        }
                    }
                    return Err(clone_error);
                }
            }
        }
    }
    let mut copied = if options.attributes_only {
        ContentCopy::default()
    } else if cloned {
        let bytes = fd_stat(&destination)?.st_size as u64;
        #[cfg(feature = "live-progress")]
        if let Some(progress) = &options.live_progress {
            progress.add_bytes(bytes);
        }
        ContentCopy {
            bytes,
            diagnostics: CopyDiagnostics::default(),
        }
    } else {
        let make_holes = destination_info.st_mode & libc::S_IFMT == libc::S_IFREG
            && (options.sparse == crate::SparseMode::Always
                || (options.sparse == crate::SparseMode::Auto
                    && observed.st_mode & libc::S_IFMT == libc::S_IFREG
                    && observed.st_blocks.saturating_mul(512) < observed.st_size));
        let navigate_holes = make_holes
            && observed.st_mode & libc::S_IFMT == libc::S_IFREG
            && observed.st_blocks.saturating_mul(512) < observed.st_size;
        let allow_offload = options.reflink != crate::ReflinkMode::Never
            && options.sparse != crate::SparseMode::Never
            && observed.st_mode & libc::S_IFMT == libc::S_IFREG
            && destination_info.st_mode & libc::S_IFMT == libc::S_IFREG;
        transfer(
            &source,
            &destination,
            size,
            make_holes,
            navigate_holes,
            allow_offload,
            options,
        )
        .map_err(|error| {
            if let Err(cancelled) = options.cancellation.check() {
                return anyhow::Error::from(CallbackError(cancelled.into()));
            }
            if let Some(failure) = error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<TransferFailure>())
            {
                let path = if matches!(failure.operation, "error reading" | "cannot lseek source") {
                    source_path
                } else {
                    destination_path
                };
                let cause = failure.error.raw_os_error().map_or_else(
                    || io::Error::new(failure.error.kind(), failure.error.to_string()),
                    io::Error::from_raw_os_error,
                );
                if failure.operation == "error copying" {
                    anyhow::Error::from(pair_operation(
                        failure.operation,
                        source_path,
                        destination_path,
                        cause,
                    ))
                } else {
                    anyhow::Error::from(file_operation(
                        if failure.operation == "cannot lseek source" {
                            "cannot lseek"
                        } else {
                            failure.operation
                        },
                        path,
                        cause,
                    ))
                }
            } else {
                error.into()
            }
        })?
    };
    copied.diagnostics.reflink_attempted = reflink_attempted;
    copied.diagnostics.cloned = cloned;
    let mut preserved_mode = discovered.st_mode & 0o7777;
    if options.preserve_ownership
        && (destination_info.st_uid, destination_info.st_gid)
            != (discovered.st_uid, discovered.st_gid)
    {
        // SAFETY: Owned destination descriptor and discovered ownership IDs.
        let ownership_result = checked(unsafe {
            libc::fchown(
                destination.as_raw_fd(),
                discovered.st_uid,
                discovered.st_gid,
            )
        });
        if let Err(error) = ownership_result {
            // GNU cp tolerates these ownership failures for unprivileged users,
            // tries the group separately, and drops all special mode bits.
            // SAFETY: geteuid has no arguments or preconditions.
            if unsafe { libc::geteuid() } != 0
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EPERM | libc::EINVAL | libc::EACCES)
                )
            {
                // SAFETY: Owned descriptor; uid -1 leaves its owner unchanged.
                let _ = unsafe { libc::fchown(destination.as_raw_fd(), !0, discovered.st_gid) };
                preserved_mode &= !(libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX);
            } else {
                return Err(file_operation(
                    "failed to preserve ownership for",
                    destination_path,
                    error,
                )
                .into());
            }
        }
    }
    // SAFETY: Borrowed destination and two initialized timestamps.
    if options.preserve_timestamps {
        checked(unsafe { libc::futimens(destination.as_raw_fd(), times(discovered).as_ptr()) })
            .map_err(|error| file_operation("preserving times for", destination_path, error))?;
    }
    // SAFETY: Borrowed destination descriptor and source permission bits.
    if !existing || options.preserve_mode {
        let mode = if options.preserve_mode {
            preserved_mode
        } else {
            (if options.default_permissions {
                0o666
            } else {
                discovered.st_mode & 0o777
            }) & !options.creation_mask
        };
        checked(unsafe { libc::fchmod(destination.as_raw_fd(), mode) }).map_err(|error| {
            file_operation("preserving permissions for", destination_path, error)
        })?;
    }
    if options.preserve_xattrs {
        preserve_xattrs(
            copy_fd_xattrs(&source, &destination, destination_path, options, warnings),
            options,
        )?;
    }
    if options.preserve_mode {
        copy_fd_acl(&source, &destination).map_err(|error| {
            match error.downcast::<io::Error>() {
                Ok(error) => anyhow::Error::from(file_operation(
                    "preserving permissions for",
                    destination_path,
                    error,
                )),
                Err(error) => error,
            }
        })?;
    }
    let mut close_errors = Vec::new();
    if let Err(error) = close(destination) {
        close_errors.push(anyhow::Error::from(file_operation(
            "failed to close",
            destination_path,
            error,
        )));
    }
    if let Err(error) = close(source) {
        close_errors.push(anyhow::Error::from(file_operation(
            "failed to close",
            source_path,
            error,
        )));
    }
    if close_errors.len() == 1 {
        return Err(close_errors.remove(0));
    }
    if !close_errors.is_empty() {
        return Err(crate::MultipleCopyErrors(close_errors).into());
    }
    Ok(copied)
}

fn read_attribute(mut read: impl FnMut(*mut libc::c_void, usize) -> isize) -> io::Result<Vec<u8>> {
    loop {
        let size = read(std::ptr::null_mut(), 0);
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut value = vec![0; size as usize];
        let count = read(value.as_mut_ptr().cast(), value.len());
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(error);
        }
        if count as usize > value.len() {
            continue;
        }
        value.truncate(count as usize);
        return Ok(value);
    }
}

// GNU archive/all preservation is best effort for xattrs. Attributes-only
// requests report unsupported metadata separately from the data-copy status.
fn xattr_warning(
    error: &io::Error,
    destination: &CStr,
    options: &CopyOptions,
    warnings: &mut Vec<crate::MetadataWarning>,
) {
    if options.attributes_only
        || (!options.reduce_xattr_diagnostics
            && !matches!(
                error.raw_os_error(),
                Some(libc::ENOTSUP | libc::ENODATA | libc::ENOSYS)
            ))
    {
        warnings.push(crate::MetadataWarning {
            destination: Path::new(std::ffi::OsStr::from_bytes(destination.to_bytes())).to_owned(),
            error: error.raw_os_error().unwrap_or(libc::EIO),
        });
    }
}

fn preserve_xattrs(result: Result<()>, options: &CopyOptions) -> Result<()> {
    if options.require_preserve_xattrs {
        result
    } else {
        Ok(())
    }
}

fn copy_directory_acls(source: &CStr, destination: &CStr) -> Result<()> {
    for attribute in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        let value = read_attribute(|output, size| {
            // SAFETY: Terminated directory/name and bounded output or size query.
            unsafe { libc::getxattr(source.as_ptr(), attribute.as_ptr(), output, size) }
        });
        match value {
            Ok(value) => {
                // SAFETY: Terminated directory/name and initialized ACL bytes.
                checked(unsafe {
                    libc::setxattr(
                        destination.as_ptr(),
                        attribute.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                })?;
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENODATA | libc::ENOTSUP | libc::ENOSYS | libc::EINVAL | libc::EBUSY)
                ) =>
            {
                // SAFETY: Terminated directory/name; remove a stale destination ACL.
                if let Err(error) =
                    checked(unsafe { libc::removexattr(destination.as_ptr(), attribute.as_ptr()) })
                    && !matches!(
                        error.raw_os_error(),
                        Some(
                            libc::ENODATA
                                | libc::ENOTSUP
                                | libc::ENOSYS
                                | libc::EINVAL
                                | libc::EBUSY
                        )
                    )
                {
                    return Err(error.into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn copy_fd_acl(source: &OwnedFd, destination: &OwnedFd) -> Result<()> {
    let attribute = c"system.posix_acl_access";
    let value = read_attribute(|output, size| {
        // SAFETY: Owned descriptor, terminated ACL name and bounded output.
        unsafe { libc::fgetxattr(source.as_raw_fd(), attribute.as_ptr(), output, size) }
    });
    match value {
        Ok(value) => {
            // SAFETY: Owned destination and initialized kernel ACL encoding.
            checked(unsafe {
                libc::fsetxattr(
                    destination.as_raw_fd(),
                    attribute.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            })?;
        }
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENODATA | libc::ENOTSUP | libc::ENOSYS | libc::EINVAL | libc::EBUSY)
            ) =>
        {
            // SAFETY: Owned descriptor; remove a stale ACL when the source lacks one.
            if let Err(error) =
                checked(unsafe { libc::fremovexattr(destination.as_raw_fd(), attribute.as_ptr()) })
                && !matches!(
                    error.raw_os_error(),
                    Some(libc::ENODATA | libc::ENOTSUP | libc::ENOSYS | libc::EINVAL | libc::EBUSY)
                )
            {
                return Err(error.into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn copy_path_xattrs(
    source: &CStr,
    destination: &CStr,
    follow: bool,
    options: &CopyOptions,
    warnings: &mut Vec<crate::MetadataWarning>,
) -> Result<()> {
    let names = read_attribute(|output, size| {
        // SAFETY: Terminated source and bounded output, or a null size query.
        unsafe {
            if follow {
                libc::listxattr(source.as_ptr(), output.cast(), size)
            } else {
                libc::llistxattr(source.as_ptr(), output.cast(), size)
            }
        }
    });
    let names = match names {
        Ok(names) => names,
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::ENOSYS)) => {
            return Ok(());
        }
        Err(error) => {
            if options.require_preserve_xattrs {
                return Err(crate::MetadataPreservationError {
                    destination: Path::new(std::ffi::OsStr::from_bytes(destination.to_bytes()))
                        .to_owned(),
                    error,
                }
                .into());
            }
            xattr_warning(&error, destination, options, warnings);
            return Ok(());
        }
    };
    for attribute in names
        .split(|byte| *byte == 0)
        .filter(|attribute| !attribute.is_empty())
    {
        if attribute.starts_with(b"system.posix_acl_") {
            continue;
        }
        let attribute = CString::new(attribute)?;
        let value = read_attribute(|output, size| {
            // SAFETY: Terminated path/name and bounded output.
            unsafe {
                if follow {
                    libc::getxattr(source.as_ptr(), attribute.as_ptr(), output, size)
                } else {
                    libc::lgetxattr(source.as_ptr(), attribute.as_ptr(), output, size)
                }
            }
        });
        let value = match value {
            Ok(value) => value,
            Err(error) if !options.require_preserve_xattrs => {
                xattr_warning(&error, destination, options, warnings);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        // SAFETY: Terminated destination/name and initialized binary attribute value.
        let result = checked(unsafe {
            if follow {
                libc::setxattr(
                    destination.as_ptr(),
                    attribute.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            } else {
                libc::lsetxattr(
                    destination.as_ptr(),
                    attribute.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            }
        });
        if let Err(error) = result {
            if options.require_preserve_xattrs {
                return Err(crate::MetadataPreservationError {
                    destination: Path::new(std::ffi::OsStr::from_bytes(destination.to_bytes()))
                        .to_owned(),
                    error,
                }
                .into());
            }
            xattr_warning(&error, destination, options, warnings);
        }
    }
    Ok(())
}

fn copy_fd_xattrs(
    source: &OwnedFd,
    destination: &OwnedFd,
    path: &CStr,
    options: &CopyOptions,
    warnings: &mut Vec<crate::MetadataWarning>,
) -> Result<()> {
    let names = read_attribute(|output, size| {
        // SAFETY: Owned descriptor; output is null for a size query or writable
        // for exactly size bytes, as provided by read_attribute.
        unsafe { libc::flistxattr(source.as_raw_fd(), output.cast(), size) }
    });
    let names = match names {
        Ok(names) => names,
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::ENOSYS)) => {
            return Ok(());
        }
        Err(error) => {
            if options.require_preserve_xattrs {
                return Err(crate::MetadataPreservationError {
                    destination: Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())).to_owned(),
                    error,
                }
                .into());
            }
            xattr_warning(&error, path, options, warnings);
            return Ok(());
        }
    };
    for attribute in names
        .split(|byte| *byte == 0)
        .filter(|attribute| !attribute.is_empty())
    {
        if attribute.starts_with(b"system.posix_acl_") {
            continue;
        }
        let attribute = CString::new(attribute)?;
        let value = read_attribute(|output, size| {
            // SAFETY: Owned descriptor, terminated name and bounded output.
            unsafe { libc::fgetxattr(source.as_raw_fd(), attribute.as_ptr(), output, size) }
        });
        let value = match value {
            Ok(value) => value,
            Err(error) if !options.require_preserve_xattrs => {
                xattr_warning(&error, path, options, warnings);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        // SAFETY: Owned destination, terminated attribute name and initialized value.
        let result = checked(unsafe {
            libc::fsetxattr(
                destination.as_raw_fd(),
                attribute.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        });
        if let Err(error) = result {
            if options.require_preserve_xattrs {
                return Err(crate::MetadataPreservationError {
                    destination: Path::new(std::ffi::OsStr::from_bytes(path.to_bytes())).to_owned(),
                    error,
                }
                .into());
            }
            xattr_warning(&error, path, options, warnings);
        }
    }
    Ok(())
}
struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: This object owns the successful opendir stream.
        unsafe { libc::closedir(self.0) };
    }
}
fn entries(path: &CStr) -> io::Result<Vec<(libc::ino_t, CString)>> {
    // SAFETY: Terminated directory path; successful stream is owned below.
    let stream = unsafe { libc::opendir(path.as_ptr()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let stream = Directory(stream);
    let mut entries = Vec::new();
    loop {
        // SAFETY: Thread-local errno pointer and owned live directory stream.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error);
            }
            break;
        }
        // SAFETY: readdir's record remains valid until the next call; copy its name.
        let (inode, name) = unsafe { ((*entry).d_ino, CStr::from_ptr((*entry).d_name.as_ptr())) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            entries.push((inode, name.to_owned()));
        }
    }
    // Matches savedir's FASTREAD ordering on Linux with d_ino available.
    entries.sort_unstable_by_key(|(inode, _)| *inode);
    Ok(entries)
}
// Returns false when GNU cp's unprivileged ownership fallback was needed.
fn preserve_path_owner(destination: &CStr, info: &libc::stat) -> io::Result<bool> {
    let set_owner = |uid, gid| {
        // SAFETY: Terminated path and discovered IDs. Only source symlinks
        // require non-following ownership; kept directory symlinks are followed.
        checked(unsafe {
            if info.st_mode & libc::S_IFMT == libc::S_IFLNK {
                libc::lchown(destination.as_ptr(), uid, gid)
            } else {
                libc::chown(destination.as_ptr(), uid, gid)
            }
        })
    };
    match set_owner(info.st_uid, info.st_gid) {
        Ok(()) => Ok(true),
        Err(error) => {
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EPERM | libc::EINVAL | libc::EACCES)
                )
            {
                let _ = set_owner(!0, info.st_gid);
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

fn symbolic_link(
    source: &CStr,
    destination: &CStr,
    info: &libc::stat,
    overwrite: bool,
    options: &CopyOptions,
    warnings: &mut Vec<crate::MetadataWarning>,
) -> Result<()> {
    let mut target = vec![0; 256];
    loop {
        // SAFETY: Terminated source and bounded writable target buffer.
        let count =
            unsafe { libc::readlink(source.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
        if count < 0 {
            return Err(file_operation(
                "cannot read symbolic link",
                source,
                io::Error::last_os_error(),
            )
            .into());
        }
        if (count as usize) < target.len() {
            target.truncate(count as usize);
            break;
        }
        if target.len() >= 65536 {
            bail!("symlink target exceeds experiment limit");
        }
        target.resize(target.len() * 2, 0);
    }
    let target = CString::new(target)?;
    // SAFETY: Two terminated strings; create the link without following its target.
    if let Err(error) = checked(unsafe { libc::symlink(target.as_ptr(), destination.as_ptr()) }) {
        if !overwrite || options.attributes_only || error.kind() != io::ErrorKind::AlreadyExists {
            return Err(file_operation("cannot create symbolic link", destination, error).into());
        }
        let destination_info = stat(destination)?;
        if (destination_info.st_dev, destination_info.st_ino) == (info.st_dev, info.st_ino) {
            bail!("source and destination are the same file");
        }
        // SAFETY: Terminated path; unlink refuses directories and preserves
        // the referent when replacing a destination symbolic link.
        checked(unsafe { libc::unlink(destination.as_ptr()) })
            .map_err(|error| file_operation("cannot remove", destination, error))?;
        // SAFETY: Target and destination strings remain valid after unlink.
        checked(unsafe { libc::symlink(target.as_ptr(), destination.as_ptr()) })
            .map_err(|error| file_operation("cannot create symbolic link", destination, error))?;
    }
    // SAFETY: Valid destination and times; do not follow the new link.
    if options.preserve_ownership {
        // SAFETY: Terminated symlink path; lchown changes the link, not its referent.
        preserve_path_owner(destination, info)?;
    }
    if options.preserve_xattrs {
        preserve_xattrs(
            copy_path_xattrs(source, destination, false, options, warnings),
            options,
        )?;
    }
    if options.preserve_timestamps {
        checked(unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                destination.as_ptr(),
                times(info).as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
        .map_err(|error| file_operation("preserving times for", destination, error))?;
    }
    Ok(())
}
fn fresh_regular_entry(source: &Path, destination: &Path, entry: &CStr) -> bool {
    let entry = std::ffi::OsStr::from_bytes(entry.to_bytes());
    let Ok(source) = name(&source.join(entry)) else {
        return false;
    };
    let Ok(destination) = name(&destination.join(entry)) else {
        return false;
    };
    // Source hard-link aliases share access times; preserve their serial
    // metadata observation order even when destination links aren't preserved.
    stat(&source)
        .is_ok_and(|info| info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_nlink == 1)
        && stat(&destination).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}
fn fresh_regular_copy(
    source: &Path,
    destination: &Path,
    options: &CopyOptions,
    patterns: &[CString],
    warnings: &mut Vec<crate::MetadataWarning>,
) -> Result<Option<ContentCopy>> {
    options
        .cancellation
        .check()
        .map_err(|error| CallbackError(error.into()))?;
    let basename = CString::new(source.file_name().unwrap_or(source.as_os_str()).as_bytes())?;
    if patterns.iter().any(|pattern| {
        // SAFETY: Both native basename and glob are terminated strings.
        unsafe { libc::fnmatch(pattern.as_ptr(), basename.as_ptr(), 0) == 0 }
    }) {
        return Ok(None);
    }
    let source_name = name(source)?;
    let destination_name = name(destination)?;
    let info = stat(&source_name).map_err(|error| crate::SourceStatError {
        path: source.to_owned(),
        error,
    })?;
    if info.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(crate::ReplacedSourceError(source.to_owned()).into());
    }
    let copied = regular(
        &source_name,
        &destination_name,
        &info,
        options.buffer_size as usize,
        false,
        options,
        warnings,
    );
    options
        .cancellation
        .check()
        .map_err(|error| CallbackError(error.into()))?;
    copied.map(Some)
}
impl Copier<'_> {
    fn parallel_allowed(&self) -> bool {
        let options = self.options;
        options.jobs > 1
            && !options.preserve_links
            && !options.hard_link
            && !options.symbolic_link
            && options.backup_suffix.is_none()
            && !options.update
            && !options.no_clobber
            && !options.attributes_only
            && !options.force
            && !options.remove_destination
            && !options.copy_contents
            && !options.parents
    }
    fn parallel_files(
        &mut self,
        entries: &mut std::iter::Peekable<std::vec::IntoIter<(libc::ino_t, CString)>>,
        source: &Path,
        destination: &Path,
        failures: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
        let mut options = self.options.clone();
        // Reserve new destinations exclusively; a raced entry must never be
        // truncated without the coordinator's overwrite policy.
        options.overwrite = false;
        let patterns = self.patterns.clone();
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let jobs = std::iter::from_fn(|| {
            if !entries
                .peek()
                .is_some_and(|(_, entry)| fresh_regular_entry(source, destination, entry))
            {
                return None;
            }
            let (_, entry) = entries.next()?;
            let entry = std::ffi::OsStr::from_bytes(entry.to_bytes());
            Some((source.join(entry), destination.join(entry)))
        });
        let result = crate::pool::run(
            jobs,
            options.jobs,
            &cancellation,
            |(source, destination)| {
                let mut warnings = Vec::new();
                let result =
                    fresh_regular_copy(&source, &destination, &options, &patterns, &mut warnings);
                (source, destination, result, warnings)
            },
            |(source, destination, result, warnings)| {
                self.options
                    .cancellation
                    .check()
                    .map_err(|error| CallbackError(error.into()))?;
                self.warnings.extend(warnings);
                self.flush_warnings(&source, &destination)?;
                match result {
                    Ok(Some(copied)) => {
                        self.completed += 1;
                        self.bytes += copied.bytes;
                        self.created_symlinks.remove(&destination);
                        self.links.retain(|_, record| record.path != destination);
                        self.event_detailed(
                            EventKind::Completed,
                            &source,
                            &destination,
                            copied.bytes,
                            Some(copied.diagnostics),
                        )?;
                    }
                    Ok(None) => self.event(EventKind::Excluded, &source, &destination, 0)?,
                    Err(error) => {
                        if self.options.stop_on_error || error.is::<CallbackError>() {
                            return Err(error);
                        }
                        failures.push(error.context(format!("copy {}", source.display())));
                    }
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
    fn copy_entry(&mut self, source: &Path, destination: &Path, depth: usize) -> Result<()> {
        self.options
            .cancellation
            .check()
            .map_err(|e| CallbackError(e.into()))?;
        if self.options.reject_symlinks
            && std::fs::symlink_metadata(source)?.file_type().is_symlink()
        {
            bail!("source contains a symbolic link: {}", source.display());
        }
        if self.excluded(source)? {
            return self.event(EventKind::Excluded, source, destination, 0);
        }
        let size = self.options.buffer_size as usize;
        if depth > 128 {
            bail!("experiment directory depth exceeds 128");
        }
        let source_name = name(source)?;
        let destination_name = name(destination)?;
        let follow = self.options.dereference == crate::Dereference::Always
            || (depth == 0 && self.options.dereference == crate::Dereference::CommandLine);
        let info = stat_policy(&source_name, follow).map_err(|error| crate::SourceStatError {
            path: source.to_owned(),
            error,
        })?;
        if info.st_mode & libc::S_IFMT == libc::S_IFDIR && !self.options.recursive {
            bail!(
                "-r not specified; omitting directory '{}'",
                source.display()
            );
        }
        let identity = (info.st_dev, info.st_ino);
        if let Some(previous) = self.links.get(&identity) {
            let observed = stat_policy(&name(&previous.path)?, previous.follow);
            if !observed.is_ok_and(|info| (info.st_dev, info.st_ino) == previous.identity) {
                self.links.remove(&identity);
            }
        }
        if info.st_mode & libc::S_IFMT != libc::S_IFDIR {
            if self.options.no_clobber && stat(&destination_name).is_ok() {
                if self.options.fail_on_skip {
                    bail!("not replacing '{}'", destination.display());
                }
                return self.event(EventKind::Skipped, source, destination, 0);
            }
            if self.options.update {
                match stat_policy(
                    &destination_name,
                    info.st_mode & libc::S_IFMT == libc::S_IFREG,
                ) {
                    Ok(destination_info)
                        if (destination_info.st_mtime, destination_info.st_mtime_nsec)
                            >= (info.st_mtime, info.st_mtime_nsec) =>
                    {
                        // A retained destination is the anchor for subsequent
                        // source hard links, even when those destinations are newer.
                        if !self.options.preserve_links {
                            return self.event(EventKind::Skipped, source, destination, 0);
                        }
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            self.links.entry(identity)
                        {
                            entry.insert(LinkRecord {
                                path: destination.to_owned(),
                                identity: (destination_info.st_dev, destination_info.st_ino),
                                follow: info.st_mode & libc::S_IFMT == libc::S_IFREG,
                            });
                            return self.event(EventKind::Skipped, source, destination, 0);
                        }
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if info.st_mode & libc::S_IFMT == libc::S_IFLNK
            && stat(&destination_name)
                .is_ok_and(|info| info.st_mode & libc::S_IFMT == libc::S_IFREG)
            && source
                .canonicalize()
                .is_ok_and(|referent| referent == destination)
        {
            if self.options.hard_link {
                self.completed += 1;
                return self.event(EventKind::Completed, source, destination, 0);
            }
            if self.options.backup_suffix.is_none() {
                return Err(crate::SameFileError {
                    source_path: source.to_owned(),
                    destination_path: destination.to_owned(),
                }
                .into());
            }
        }
        if info.st_mode & libc::S_IFMT != libc::S_IFDIR
            && stat(&destination_name).is_ok()
            && !(self.overwrite)(source, destination).map_err(CallbackError)?
        {
            self.declined = true;
            return self.event(EventKind::Skipped, source, destination, 0);
        }
        if depth == 0
            && self.options.backup_suffix.is_none()
            && !self.options.remove_destination
            && !(info.st_mode & libc::S_IFMT == libc::S_IFLNK
                && !self.options.hard_link
                && !self.options.symbolic_link)
            && let Some(identity) = self.created_symlinks.get(destination)
            && stat(&destination_name).is_ok_and(|info| {
                info.st_mode & libc::S_IFMT == libc::S_IFLNK
                    && (info.st_dev, info.st_ino) == *identity
            })
        {
            return Err(crate::CreatedSymlinkError {
                source_path: source.to_owned(),
                destination_path: destination.to_owned(),
            }
            .into());
        }
        if info.st_mode & libc::S_IFMT != libc::S_IFDIR
            && let Some(suffix) = &self.options.backup_suffix
            && let Ok(existing) = stat(&destination_name)
        {
            if existing.st_mode & libc::S_IFMT == libc::S_IFDIR {
                bail!("cannot back up directory with a non-directory source");
            }
            let backup = name(&backup_path(destination, suffix, self.options.backup_mode)?)?;
            if backup == source_name
                || stat(&backup)
                    .is_ok_and(|backup_info| (backup_info.st_dev, backup_info.st_ino) == identity)
            {
                return Err(crate::BackupWouldDestroySource.into());
            }
            if backup == destination_name {
                bail!("backup suffix must not be empty");
            }
            let simple = backup_path(destination, suffix, crate::BackupMode::Simple)?;
            let numbered = backup != name(&simple)?;
            // SAFETY: Terminated paths. Numbered names must never replace an
            // existing backup if another writer claims the name after scanning.
            checked(unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    destination_name.as_ptr(),
                    libc::AT_FDCWD,
                    backup.as_ptr(),
                    if numbered { libc::RENAME_NOREPLACE } else { 0 },
                )
            })
            .map_err(|error| file_operation("cannot backup", &destination_name, error))?;
        }
        if self.options.remove_destination && info.st_mode & libc::S_IFMT != libc::S_IFDIR {
            match stat(&destination_name) {
                Ok(existing) => {
                    if (existing.st_dev, existing.st_ino) == identity
                        && source.canonicalize()? == destination
                    {
                        bail!("source and destination are the same file");
                    }
                    // SAFETY: Terminated destination path; unlink refuses directories.
                    checked(unsafe { libc::unlink(destination_name.as_ptr()) }).map_err(
                        |error| file_operation("cannot remove", &destination_name, error),
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if self.options.preserve_links
            && info.st_mode & libc::S_IFMT != libc::S_IFDIR
            && let Some(previous) = self.links.get(&identity)
        {
            let follow_previous = previous.follow;
            let previous = name(&previous.path)?;
            if let Ok(existing) = stat_policy(&destination_name, follow_previous) {
                let linked = stat_policy(&previous, follow_previous)?;
                if (existing.st_dev, existing.st_ino) == (linked.st_dev, linked.st_ino) {
                    self.completed += 1;
                    return self.event(EventKind::Completed, source, destination, 0);
                }
                if !self.options.overwrite {
                    bail!("destination already exists");
                }
                // SAFETY: Terminated destination; unlink refuses directories.
                checked(unsafe { libc::unlink(destination_name.as_ptr()) })
                    .map_err(|error| file_operation("cannot remove", &destination_name, error))?;
            }
            // SAFETY: Both names are terminated; link does not follow symbolic links.
            checked(unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    previous.as_ptr(),
                    libc::AT_FDCWD,
                    destination_name.as_ptr(),
                    if follow_previous {
                        libc::AT_SYMLINK_FOLLOW
                    } else {
                        0
                    },
                )
            })?;
            self.remember_symlink(destination, depth)?;
            self.completed += 1;
            return self.event(EventKind::Completed, source, destination, 0);
        }
        if (self.options.hard_link || self.options.symbolic_link)
            && info.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            let create = || {
                // SAFETY: Terminated paths; link creation never replaces a name.
                checked(unsafe {
                    if self.options.hard_link {
                        libc::linkat(
                            libc::AT_FDCWD,
                            source_name.as_ptr(),
                            libc::AT_FDCWD,
                            destination_name.as_ptr(),
                            if follow { libc::AT_SYMLINK_FOLLOW } else { 0 },
                        )
                    } else {
                        libc::symlink(source_name.as_ptr(), destination_name.as_ptr())
                    }
                })
            };
            if let Err(error) = create() {
                if !self.options.force || error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(crate::LinkCreationError {
                        source_path: source.to_owned(),
                        destination_path: destination.to_owned(),
                        symbolic: self.options.symbolic_link,
                        error,
                    }
                    .into());
                }
                // SAFETY: Terminated path; unlink refuses directories.
                checked(unsafe { libc::unlink(destination_name.as_ptr()) })
                    .map_err(|error| file_operation("cannot remove", &destination_name, error))?;
                create().map_err(|error| crate::LinkCreationError {
                    source_path: source.to_owned(),
                    destination_path: destination.to_owned(),
                    symbolic: self.options.symbolic_link,
                    error,
                })?;
            }
            self.remember_symlink(destination, depth)?;
            self.completed += 1;
            return self.event(EventKind::Completed, source, destination, 0);
        }
        // A later operand can overwrite an earlier output path. Its cached
        // source relationship no longer describes the resulting contents.
        self.links.retain(|_, record| record.path != destination);
        let mut copied = ContentCopy::default();
        let result: Result<()> = (|| {
            match info.st_mode & libc::S_IFMT {
                libc::S_IFREG => {
                    copied = regular(
                        &source_name,
                        &destination_name,
                        &info,
                        size,
                        follow,
                        self.options,
                        &mut self.warnings,
                    )?;
                    Ok(())
                }
                libc::S_IFLNK => symbolic_link(
                    &source_name,
                    &destination_name,
                    &info,
                    self.options.overwrite,
                    self.options,
                    &mut self.warnings,
                ),
                libc::S_IFDIR => {
                    let identity = (info.st_dev, info.st_ino);
                    if !self.ancestors.insert(identity) {
                        bail!("cannot copy cyclic symbolic link '{}'", source.display());
                    }
                    // SAFETY: New terminated path and private initial permissions.
                    let created = match checked(unsafe {
                        libc::mkdir(destination_name.as_ptr(), 0o700)
                    }) {
                        Ok(()) => true,
                        Err(error)
                            if self.options.merge_directories
                                && error.kind() == io::ErrorKind::AlreadyExists =>
                        {
                            if stat_policy(
                                &destination_name,
                                self.options.keep_directory_symlink && self.options.copy_contents,
                            )?
                            .st_mode
                                & libc::S_IFMT
                                != libc::S_IFDIR
                            {
                                bail!("destination is not a directory");
                            }
                            false
                        }
                        Err(error) => {
                            return Err(file_operation(
                                "cannot create directory",
                                &destination_name,
                                error,
                            )
                            .into());
                        }
                    };
                    if created {
                        self.event(EventKind::DirectoryCreated, source, destination, 0)?;
                    }
                    let mut child_errors = Vec::new();
                    let entries = if self.options.one_file_system
                        && depth > 0
                        && info.st_dev != self.root_device
                    {
                        Ok(Vec::new())
                    } else {
                        entries(&source_name)
                    };
                    match entries {
                        Ok(entries) => {
                            let parallel = self.parallel_allowed() && depth < 128;
                            let mut entries = entries.into_iter().peekable();
                            while entries.peek().is_some() {
                                let result = if parallel
                                    && entries.peek().is_some_and(|(_, entry)| {
                                        fresh_regular_entry(source, destination, entry)
                                    }) {
                                    self.parallel_files(
                                        &mut entries,
                                        source,
                                        destination,
                                        &mut child_errors,
                                    )
                                } else {
                                    let Some((_, entry)) = entries.next() else {
                                        break;
                                    };
                                    let entry = std::ffi::OsString::from_vec(entry.into_bytes());
                                    self.copy_entry(
                                        &source.join(&entry),
                                        &destination.join(&entry),
                                        depth + 1,
                                    )
                                    .with_context(|| {
                                        format!("copy {}", source.join(&entry).display())
                                    })
                                };
                                if let Err(error) = result {
                                    if self.options.stop_on_error
                                        || error.downcast_ref::<CallbackError>().is_some()
                                    {
                                        return Err(error);
                                    }
                                    child_errors.push(error);
                                }
                            }
                        }
                        Err(error) => child_errors
                            .push(file_operation("cannot access", &source_name, error).into()),
                    }
                    if let Err(error) = finalize_directory(
                        &source_name,
                        &destination_name,
                        &info,
                        created,
                        self.options,
                        &mut self.warnings,
                    ) {
                        child_errors.push(error);
                    }
                    self.ancestors.remove(&identity);
                    if child_errors.len() == 1 {
                        return Err(child_errors.remove(0));
                    }
                    if !child_errors.is_empty() {
                        return Err(crate::MultipleCopyErrors(child_errors).into());
                    }
                    Ok(())
                }
                libc::S_IFIFO | libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK
                    if self.options.recursive && !self.options.copy_contents =>
                {
                    let create = || {
                        // SAFETY: Terminated path and stat-derived object type/device.
                        checked(unsafe {
                            libc::mknod(
                                destination_name.as_ptr(),
                                (info.st_mode & libc::S_IFMT) | 0o600,
                                info.st_rdev,
                            )
                        })
                    };
                    if let Err(error) = create() {
                        if !self.options.overwrite || error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(file_operation(
                                if info.st_mode & libc::S_IFMT == libc::S_IFIFO {
                                    "cannot create fifo"
                                } else {
                                    "cannot create special file"
                                },
                                &destination_name,
                                error,
                            )
                            .into());
                        }
                        let existing = stat(&destination_name)?;
                        if (existing.st_dev, existing.st_ino) == identity {
                            bail!("source and destination are the same file");
                        }
                        // SAFETY: Terminated path; unlink cannot remove a directory.
                        checked(unsafe { libc::unlink(destination_name.as_ptr()) }).map_err(
                            |error| file_operation("cannot remove", &destination_name, error),
                        )?;
                        create().map_err(|error| {
                            file_operation(
                                if info.st_mode & libc::S_IFMT == libc::S_IFIFO {
                                    "cannot create fifo"
                                } else {
                                    "cannot create special file"
                                },
                                &destination_name,
                                error,
                            )
                        })?;
                    }
                    let ownership_preserved = !self.options.preserve_ownership
                        || preserve_path_owner(&destination_name, &info)?;
                    if self.options.preserve_xattrs {
                        preserve_xattrs(
                            copy_path_xattrs(
                                &source_name,
                                &destination_name,
                                false,
                                self.options,
                                &mut self.warnings,
                            ),
                            self.options,
                        )?;
                    }
                    let mut mode = if self.options.preserve_mode {
                        info.st_mode & 0o7777
                    } else {
                        (if self.options.default_permissions {
                            0o666
                        } else {
                            info.st_mode & 0o777
                        }) & !self.options.creation_mask
                    };
                    if !ownership_preserved {
                        mode &= !(libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX);
                    }
                    // SAFETY: New special file with terminated path.
                    checked(unsafe { libc::chmod(destination_name.as_ptr(), mode) }).map_err(
                        |error| {
                            file_operation("preserving permissions for", &destination_name, error)
                        },
                    )?;
                    if self.options.preserve_timestamps {
                        // SAFETY: Initialized timestamps and new special file path.
                        checked(unsafe {
                            libc::utimensat(
                                libc::AT_FDCWD,
                                destination_name.as_ptr(),
                                times(&info).as_ptr(),
                                0,
                            )
                        })
                        .map_err(|error| {
                            file_operation("preserving times for", &destination_name, error)
                        })?;
                    }
                    Ok(())
                }
                _ => {
                    copied = regular(
                        &source_name,
                        &destination_name,
                        &info,
                        size,
                        follow,
                        self.options,
                        &mut self.warnings,
                    )?;
                    Ok(())
                }
            }
        })();
        self.flush_warnings(source, destination)?;
        result?;
        self.remember_symlink(destination, depth)?;
        let bytes = copied.bytes;
        self.completed += 1;
        self.bytes += bytes;
        if self.options.preserve_links && info.st_mode & libc::S_IFMT != libc::S_IFDIR {
            let follow = info.st_mode & libc::S_IFMT == libc::S_IFREG;
            let copied = stat_policy(&destination_name, follow)?;
            self.links.insert(
                identity,
                LinkRecord {
                    path: destination.to_owned(),
                    identity: (copied.st_dev, copied.st_ino),
                    follow,
                },
            );
        }
        let diagnostics = (!self.options.attributes_only
            && !matches!(info.st_mode & libc::S_IFMT, libc::S_IFDIR | libc::S_IFLNK)
            && (info.st_mode & libc::S_IFMT == libc::S_IFREG
                || self.options.copy_contents
                || !self.options.recursive))
            .then_some(copied.diagnostics);
        self.flush_warnings(source, destination)?;
        self.event_detailed(
            EventKind::Completed,
            source,
            destination,
            bytes,
            diagnostics,
        )
    }
}

fn finalize_directory(
    source: &CStr,
    destination: &CStr,
    info: &libc::stat,
    created: bool,
    options: &CopyOptions,
    warnings: &mut Vec<crate::MetadataWarning>,
) -> Result<()> {
    // Directories are finalized after descendants, like cp.
    // SAFETY: Terminated path, initialized timestamps and source mode.
    let ownership_preserved =
        !options.preserve_ownership || preserve_path_owner(destination, info)?;
    let mut errors = Vec::new();
    if options.preserve_xattrs
        && let Err(error) = preserve_xattrs(
            copy_path_xattrs(source, destination, true, options, warnings),
            options,
        )
    {
        errors.push(error);
    }
    if created || options.preserve_mode || options.preserve_timestamps {
        if options.preserve_timestamps
            && let Err(error) = checked(unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    destination.as_ptr(),
                    times(info).as_ptr(),
                    0,
                )
            })
            .map_err(|error| file_operation("preserving times for", destination, error))
        {
            errors.push(error.into());
        }
        if created || options.preserve_mode {
            let mut mode = if options.preserve_mode {
                info.st_mode & 0o7777
            } else {
                (if options.default_permissions {
                    0o777
                } else {
                    info.st_mode & 0o777
                }) & !options.creation_mask
            };
            if !ownership_preserved {
                mode &= !(libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX);
            }
            if let Err(error) = checked(unsafe { libc::chmod(destination.as_ptr(), mode) })
                .map_err(|error| file_operation("preserving permissions for", destination, error))
            {
                errors.push(error.into());
            }
        }
    }
    if options.preserve_mode
        && let Err(error) = copy_directory_acls(source, destination)
    {
        let error = error.downcast::<io::Error>()?;
        errors.push(file_operation("preserving permissions for", destination, error).into());
    }
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(crate::MultipleCopyErrors(errors).into()),
    }
}

fn validate_options(options: &CopyOptions) -> Result<()> {
    if options.reflink == crate::ReflinkMode::Always && options.sparse != crate::SparseMode::Auto {
        bail!("--reflink=always requires --sparse=auto");
    }
    if !(4096..=16777216).contains(&options.buffer_size) {
        bail!("invalid buffer size");
    }
    if options.hard_link && options.symbolic_link {
        bail!("cannot combine hard and symbolic link modes");
    }
    for pattern in &options.exclusions {
        CString::new(pattern.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn copy_with_parents(
    source: &Path,
    destination: &Path,
    options: &CopyOptions,
    events: &mut dyn FnMut(&CopyEvent) -> Result<()>,
    overwrite: &mut dyn FnMut(&Path, &Path) -> Result<bool>,
    state: &mut CopyState,
) -> Result<()> {
    validate_options(options)?;
    // Validate the complete source before creating any parent. This rejects
    // paths through regular files without leaving spurious destination dirs.
    stat_policy(
        &name(source)?,
        options.dereference != crate::Dereference::Never,
    )
    .map_err(|error| crate::SourceStatError {
        path: source.to_owned(),
        error,
    })?;
    let mut parents = Vec::new();
    let mut source_parent = source.parent();
    let mut destination_parent = destination.parent();
    while let Some(source_path) = source_parent {
        if source_path.as_os_str().is_empty() || source_path == Path::new("/") {
            break;
        }
        let destination_path = destination_parent.context("missing mapped destination parent")?;
        let info = stat_policy(&name(source_path)?, true)?;
        if info.st_mode & libc::S_IFMT != libc::S_IFDIR {
            bail!("source parent is not a directory");
        }
        parents.push((
            source_path.to_owned(),
            destination_path.to_owned(),
            info,
            false,
        ));
        source_parent = source_path.parent();
        destination_parent = destination_path.parent();
    }
    for (source_path, destination_path, _, created) in parents.iter_mut().rev() {
        let destination_name = name(destination_path)?;
        // SAFETY: Terminated path; start new parent directories privately.
        match checked(unsafe { libc::mkdir(destination_name.as_ptr(), 0o700) }) {
            Ok(()) => {
                *created = true;
                events(&CopyEvent {
                    warning: None,
                    kind: EventKind::DirectoryCreated,
                    source: source_path.clone(),
                    destination: destination_path.clone(),
                    bytes: 0,
                    completed: 0,
                    copied_bytes: 0,
                    diagnostics: None,
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if stat_policy(&destination_name, true)?.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    bail!("destination parent is not a directory");
                }
            }
            Err(error) => {
                return Err(
                    file_operation("cannot make directory", &destination_name, error).into(),
                );
            }
        }
    }
    let mut summary = None;
    let mut result = copy_tree(
        source,
        destination,
        options,
        &mut |event| {
            if matches!(event.kind, EventKind::Done | EventKind::Failed) {
                summary = Some(event.clone());
                Ok(())
            } else {
                events(event)
            }
        },
        overwrite,
        state,
    );
    if result
        .as_ref()
        .is_err_and(|error| error.downcast_ref::<CallbackError>().is_some())
    {
        return result;
    }
    let mut warnings = Vec::new();
    for (source_path, destination_path, info, created) in parents {
        if let Err(error) = finalize_directory(
            &name(&source_path)?,
            &name(&destination_path)?,
            &info,
            created,
            options,
            &mut warnings,
        ) && result.is_ok()
        {
            result = Err(error);
        }
    }
    for warning in warnings {
        events(&CopyEvent {
            kind: EventKind::Warning,
            source: source.to_owned(),
            destination: destination.to_owned(),
            bytes: 0,
            completed: 0,
            copied_bytes: 0,
            diagnostics: None,
            warning: Some(warning),
        })
        .map_err(CallbackError)?;
    }
    if let Some(mut event) = summary {
        if result.is_err() {
            event.kind = EventKind::Failed;
        }
        events(&event)?;
    }
    result
}

pub(crate) fn copy_tree(
    source: &Path,
    destination: &Path,
    options: &CopyOptions,
    events: &mut dyn FnMut(&CopyEvent) -> Result<()>,
    overwrite: &mut dyn FnMut(&Path, &Path) -> Result<bool>,
    state: &mut CopyState,
) -> Result<()> {
    validate_options(options)?;
    let size = options.buffer_size;
    let mut copier = Copier {
        options,
        events,
        overwrite,
        declined: false,
        warnings: Vec::new(),
        root_device: 0,
        created_symlinks: &mut state.created_symlinks,
        patterns: options
            .exclusions
            .iter()
            .map(|p| CString::new(p.as_bytes()))
            .collect::<std::result::Result<_, _>>()?,
        completed: 0,
        bytes: 0,
        ancestors: std::collections::HashSet::new(),
        links: &mut state.links,
    };
    let source_info = stat_policy(
        &name(source)?,
        options.dereference != crate::Dereference::Never,
    )
    .map_err(|error| crate::SourceStatError {
        path: source.to_owned(),
        error,
    })?;
    copier.root_device = source_info.st_dev;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize()?;
    if source_info.st_mode & libc::S_IFMT == libc::S_IFDIR
        && parent.starts_with(source.canonicalize()?)
    {
        return Err(crate::IntoSelfError {
            source_path: source.to_owned(),
            destination_path: destination.to_owned(),
        }
        .into());
    }
    let follow_directory = options.keep_directory_symlink
        && options.copy_contents
        && source_info.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let destination = if stat_policy(&name(destination)?, follow_directory)
        .is_ok_and(|info| info.st_mode & libc::S_IFMT == libc::S_IFDIR)
    {
        destination.canonicalize()?
    } else {
        parent.join(
            destination
                .file_name()
                .context("missing destination name")?,
        )
    };
    if source_info.st_mode & libc::S_IFMT == libc::S_IFDIR
        && destination.starts_with(source.canonicalize()?)
        && destination != source.canonicalize()?
    {
        return Err(crate::IntoSelfError {
            source_path: source.to_owned(),
            destination_path: destination.to_owned(),
        }
        .into());
    }
    match stat_policy(&name(&destination)?, follow_directory) {
        Ok(info) => {
            if options.no_clobber && source_info.st_mode & libc::S_IFMT != libc::S_IFDIR {
                if options.fail_on_skip {
                    bail!("not replacing '{}'", destination.display());
                }
                copier.event(EventKind::Skipped, source, &destination, 0)?;
                return copier.event(EventKind::Done, source, &destination, 0);
            }
            let symlink_alias = source_info.st_mode & libc::S_IFMT == libc::S_IFLNK
                && info.st_mode & libc::S_IFMT == libc::S_IFLNK
                && !options.symbolic_link
                && source
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or(Path::new("."))
                    .canonicalize()?
                    .join(source.file_name().context("missing source basename")?)
                    != destination;
            if (info.st_dev, info.st_ino) == (source_info.st_dev, source_info.st_ino)
                && symlink_alias
                && (options.backup_suffix.is_none() || options.hard_link)
            {
                return copier.event(EventKind::Done, source, &destination, 0);
            }
            if (info.st_dev, info.st_ino) == (source_info.st_dev, source_info.st_ino)
                && !(symlink_alias && options.backup_suffix.is_some())
                && !((options.remove_destination
                    || (options.backup_suffix.is_some()
                        && !options.hard_link
                        && !options.symbolic_link))
                    && stat(&name(source)?)?.st_mode & libc::S_IFMT == libc::S_IFREG
                    && source.canonicalize()? != destination)
            {
                if options.hard_link
                    && !(options.force
                        && options.backup_suffix.is_some()
                        && source_info.st_mode & libc::S_IFMT == libc::S_IFREG
                        && stat(&name(source)?)?.st_mode & libc::S_IFMT == libc::S_IFREG
                        && source.canonicalize()? == destination)
                {
                    return copier.event(EventKind::Done, source, &destination, 0);
                }
                if options.force
                    && source_info.st_mode & libc::S_IFMT == libc::S_IFREG
                    && stat(&name(source)?)?.st_mode & libc::S_IFMT == libc::S_IFREG
                    && source.canonicalize()? == destination
                    && let Some(suffix) = &options.backup_suffix
                {
                    let backup = backup_path(&destination, suffix, options.backup_mode)?;
                    if backup == destination {
                        bail!("backup suffix must not be empty");
                    }
                    if copier.excluded(source)? {
                        copier.event(EventKind::Excluded, source, &backup, 0)?;
                    } else {
                        let copied = if options.hard_link {
                            let backup_name = name(&backup)?;
                            let linked = match stat(&backup_name) {
                                Ok(info) => {
                                    if (info.st_dev, info.st_ino)
                                        == (source_info.st_dev, source_info.st_ino)
                                    {
                                        true
                                    } else {
                                        // SAFETY: Terminated backup path; unlink refuses directories.
                                        checked(unsafe { libc::unlink(backup_name.as_ptr()) })?;
                                        false
                                    }
                                }
                                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                                Err(error) => return Err(error.into()),
                            };
                            if !linked {
                                // SAFETY: Terminated regular-file source and backup path.
                                checked(unsafe {
                                    libc::link(name(source)?.as_ptr(), backup_name.as_ptr())
                                })?;
                            }
                            ContentCopy::default()
                        } else {
                            regular(
                                &name(source)?,
                                &name(&backup)?,
                                &source_info,
                                size as usize,
                                options.dereference != crate::Dereference::Never,
                                options,
                                &mut copier.warnings,
                            )?
                        };
                        copier.completed += 1;
                        copier.bytes += copied.bytes;
                        copier.event_detailed(
                            EventKind::Completed,
                            source,
                            &backup,
                            copied.bytes,
                            (!options.attributes_only && !options.hard_link)
                                .then_some(copied.diagnostics),
                        )?;
                    }
                    return copier.event(EventKind::Done, source, &backup, 0);
                }
                return Err(crate::SameFileError {
                    source_path: source.to_owned(),
                    destination_path: destination.to_owned(),
                }
                .into());
            }
            if !(options.hard_link
                || options.symbolic_link
                || (options.merge_directories
                    && source_info.st_mode & libc::S_IFMT == libc::S_IFDIR
                    && info.st_mode & libc::S_IFMT == libc::S_IFDIR)
                || (options.overwrite
                    && matches!(
                        source_info.st_mode & libc::S_IFMT,
                        libc::S_IFREG | libc::S_IFLNK
                    ))
                || (options.overwrite
                    && matches!(
                        source_info.st_mode & libc::S_IFMT,
                        libc::S_IFIFO | libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK
                    )))
            {
                bail!("destination already exists; this experiment requires a fresh tree");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let result = copier.copy_entry(source, &destination, 0).and_then(|()| {
        if copier.declined {
            Err(crate::OverwriteDeclined.into())
        } else {
            Ok(())
        }
    });
    copier.event(
        if result.is_ok() {
            EventKind::Done
        } else {
            EventKind::Failed
        },
        source,
        &destination,
        0,
    )?;
    result
}

#[cfg(test)]
mod offload_tests {
    use super::offload;
    use std::io;

    #[test]
    #[cfg(feature = "live-progress")]
    fn live_progress_is_visible_while_a_transfer_waits_for_more_source_data() {
        use std::io::Write;
        use std::os::{fd::OwnedFd, unix::net::UnixStream};
        use std::time::{Duration, Instant};
        let (mut producer, source) = UnixStream::pair().unwrap();
        let destination = tempfile::tempfile().unwrap();
        let progress = crate::LiveProgress::default();
        let observer = progress.clone();
        let worker = std::thread::spawn(move || {
            let source: OwnedFd = source.into();
            let destination: OwnedFd = destination.into();
            super::transfer(
                &source,
                &destination,
                4096,
                false,
                false,
                false,
                &crate::CopyOptions {
                    live_progress: Some(progress.clone()),
                    ..Default::default()
                },
            )
            .unwrap()
            .bytes
        });
        producer.write_all(&vec![42; 256 * 1024]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while observer.snapshot().bytes < 256 * 1024 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let before_eof = observer.snapshot();
        // Always release the worker before asserting, even if publication fails.
        drop(producer);
        assert_eq!(worker.join().unwrap(), 256 * 1024);
        assert_eq!(before_eof.bytes, 256 * 1024);
        assert_eq!(before_eof.completed, 0);
    }

    #[test]
    #[cfg(feature = "live-progress")]
    fn live_progress_counts_sparse_holes_once_and_flushes_the_tail() {
        use std::io::{Seek, SeekFrom, Write};
        let mut source = tempfile::tempfile().unwrap();
        source.set_len(1024 * 1024 + 17).unwrap();
        source.seek(SeekFrom::Start(512 * 1024)).unwrap();
        source.write_all(&[42; 17]).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        let destination = tempfile::tempfile().unwrap();
        let progress = crate::LiveProgress::default();
        let copied = super::transfer(
            &source.into(),
            &destination.into(),
            4096,
            true,
            true,
            false,
            &crate::CopyOptions {
                live_progress: Some(progress.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(copied.bytes, 1024 * 1024 + 17);
        assert_eq!(progress.snapshot().bytes, copied.bytes);
    }

    #[test]
    fn cancelled_offload_terminates_instead_of_retrying_interrupted() {
        let source: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let destination: std::os::fd::OwnedFd = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into();
        let cancellation = crate::Cancellation::default();
        cancellation.cancel();
        let result = super::transfer(
            &source,
            &destination,
            4096,
            false,
            false,
            true,
            &crate::CopyOptions {
                cancellation,
                ..Default::default()
            },
        );
        let error = match result {
            Ok(_) => panic!("cancelled transfer succeeded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("copy cancelled"), "{error}");
    }
    #[test]
    fn cancellation_after_partial_offload_is_terminal() {
        let cancellation = crate::Cancellation::default();
        let mut calls = 0;
        let result = offload(|_| {
            calls += 1;
            cancellation.check().map_err(io::Error::other)?;
            cancellation.cancel();
            Ok(17)
        });
        let error = match result {
            Ok(_) => panic!("partial cancelled offload succeeded"),
            Err(error) => error,
        };
        assert_eq!(calls, 2);
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("copy cancelled"));
    }
    #[test]
    fn interrupted_and_short_offloads_continue_until_eof() {
        let mut calls = [
            Err(io::Error::from_raw_os_error(libc::EINTR)),
            Ok(17),
            Ok(3),
            Ok(0),
        ]
        .into_iter();
        let copied = offload(|_| calls.next().unwrap()).unwrap();
        assert_eq!(copied.bytes, 20);
        assert!(copied.diagnostics.offloaded);
        assert!(calls.next().is_none());
    }

    #[test]
    fn unsupported_offload_before_data_requests_fallback() {
        let copied = offload(|_| Err(io::Error::from_raw_os_error(libc::EXDEV))).unwrap();
        assert_eq!(copied.bytes, 0);
        assert!(copied.diagnostics.offload_attempted);
        assert!(!copied.diagnostics.offloaded);
    }

    #[test]
    fn zero_initial_offload_requests_read_fallback() {
        let copied = offload(|_| Ok(0)).unwrap();
        assert_eq!(copied.bytes, 0);
        assert!(!copied.diagnostics.offloaded);
    }

    #[test]
    fn fatal_offload_errors_are_not_hidden_by_fallback() {
        for code in [libc::EIO, libc::ENOMEM, libc::ENOSPC, libc::EDQUOT] {
            let error = offload(|_| Err(io::Error::from_raw_os_error(code)))
                .err()
                .unwrap();
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn unsupported_offload_after_data_is_reported() {
        for code in [libc::EPERM, libc::EOPNOTSUPP, libc::EIO] {
            let mut calls = [Ok(17), Err(io::Error::from_raw_os_error(code))].into_iter();
            let error = offload(|_| calls.next().unwrap()).err().unwrap();
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }
}
