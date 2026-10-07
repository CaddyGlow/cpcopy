//! Independent copying engine, with native paths and synchronous progress events.
//!
//! Native Linux and Windows engines implement file, link, and tree copying.
//! GNU cp compatibility is developed against upstream test cases; this is not yet
//! a complete replacement.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(windows, test))]
mod pipeline;
#[cfg(any(target_os = "linux", windows, test))]
mod pool;
#[cfg(windows)]
mod windows;

const DEFAULT_BUFFER_SIZE: u32 = if cfg!(windows) { 1048576 } else { 262144 };

/// Copy policies independent of command-line parsing and output formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dereference {
    /// Preserve symbolic links at every level.
    Never,
    /// Follow symbolic links at every level.
    Always,
    /// Follow only top-level source operands.
    CommandLine,
}

/// Copy policies independent of command-line parsing and output formatting.
#[derive(Debug, Clone)]
pub struct CopyOptions {
    /// Maximum buffered transfer request size, from 4 KiB to 16 MiB.
    pub buffer_size: u32,
    /// Maximum concurrent independent regular-file copies, from 1 to 64.
    /// One preserves serial traversal; dependent entries remain serial.
    pub jobs: usize,
    /// Optional counters observable from another thread without transfer callbacks.
    #[cfg(feature = "live-progress")]
    pub live_progress: Option<LiveProgress>,
    /// Whether to clone file data through the filesystem.
    pub reflink: ReflinkMode,
    /// When zero-filled data may be represented as holes.
    pub sparse: SparseMode,
    /// Case-sensitive glob patterns applied to basenames at every depth.
    /// Matching directories are pruned. Patterns use native bytes on Linux and
    /// UTF-16 code units on Windows.
    pub exclusions: Vec<OsString>,
    /// Create hard links instead of copying data.
    pub hard_link: bool,
    /// Create symbolic links containing the source operand.
    pub symbolic_link: bool,
    /// Remove an existing non-directory destination when creating a link.
    pub force: bool,
    /// Allow regular-file copies to overwrite an existing regular file.
    pub overwrite: bool,
    /// Unlink non-directory destination entries before copying.
    pub remove_destination: bool,
    /// Save overwritten non-directory destinations under this suffix.
    pub backup_suffix: Option<OsString>,
    /// Select simple, numbered, or existing numbered backups when enabled.
    pub backup_mode: BackupMode,
    /// Skip existing non-directory destination entries.
    pub no_clobber: bool,
    /// Report a failure when no-clobber skips an existing destination.
    pub fail_on_skip: bool,
    /// Skip non-directory copies when the destination timestamp is at least as new.
    pub update: bool,
    /// Merge source directories into existing destination directories.
    pub merge_directories: bool,
    /// Restore source access and modification times after copying.
    pub preserve_timestamps: bool,
    /// Restore source permission bits (Linux), or read-only status and DACL (Windows),
    /// including on existing destinations.
    pub preserve_mode: bool,
    /// Restore source user/group IDs on Linux or owner/group SIDs on Windows;
    /// failures are reported to the caller.
    pub preserve_ownership: bool,
    /// Preserve hard-link relationships within one copied tree.
    pub preserve_links: bool,
    /// Preserve regular-file extended attributes other than POSIX ACLs.
    pub preserve_xattrs: bool,
    /// Fail the copy when extended attributes cannot be preserved.
    pub require_preserve_xattrs: bool,
    /// Suppress optional extended-attribute diagnostics, as archive mode does.
    pub reduce_xattr_diagnostics: bool,
    /// Preserve named NTFS data streams on Windows, including directory streams.
    /// Unsupported platforms report an error when requested.
    pub preserve_streams: bool,
    /// Preserve Windows audit ACLs and their inheritance protection. Requires
    /// backup, restore and security privileges; unavailable privileges fail.
    pub preserve_sacl: bool,
    /// Preserve native Windows creation times, file attributes and compression.
    /// Encrypted files and unsupported native backup records fail explicitly.
    pub preserve_windows_attributes: bool,
    /// Reject source symbolic links/reparse points instead of recreating them.
    pub reject_symlinks: bool,
    /// Stop traversal on the first error instead of accumulating entry errors.
    pub stop_on_error: bool,
    /// Cooperative cancellation, checked between entries and transfer chunks.
    pub cancellation: Cancellation,
    /// Apply metadata without copying regular-file contents.
    pub attributes_only: bool,
    /// Permission mask applied to newly created objects when mode is not preserved.
    pub creation_mask: u32,
    /// Use default creation permissions rather than source permissions.
    pub default_permissions: bool,
    /// Permit creating a referent through an existing dangling destination link.
    pub allow_dangling_destination: bool,
    /// Allow copying directories and their descendants.
    pub recursive: bool,
    /// Read special-file contents during recursive copies instead of recreating objects.
    pub copy_contents: bool,
    /// Follow existing destination directory symlinks when copying contents.
    pub keep_directory_symlink: bool,
    /// Create and preserve source parent directories at the mapped destination.
    pub parents: bool,
    /// Create cross-filesystem directories without descending into them.
    pub one_file_system: bool,
    /// Which source symbolic links to follow.
    pub dereference: Dereference,
}
impl Default for CopyOptions {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            jobs: 1,
            #[cfg(feature = "live-progress")]
            live_progress: None,
            reflink: ReflinkMode::Never,
            sparse: SparseMode::Auto,
            exclusions: Vec::new(),
            hard_link: false,
            symbolic_link: false,
            force: false,
            overwrite: false,
            remove_destination: false,
            backup_suffix: None,
            backup_mode: BackupMode::Simple,
            no_clobber: false,
            fail_on_skip: false,
            update: false,
            merge_directories: false,
            preserve_timestamps: true,
            preserve_mode: true,
            preserve_ownership: false,
            preserve_links: false,
            preserve_xattrs: false,
            require_preserve_xattrs: true,
            reduce_xattr_diagnostics: false,
            preserve_streams: false,
            preserve_sacl: false,
            preserve_windows_attributes: false,
            reject_symlinks: false,
            stop_on_error: false,
            cancellation: Cancellation::default(),
            attributes_only: false,
            creation_mask: 0,
            default_permissions: false,
            allow_dangling_destination: false,
            recursive: true,
            copy_contents: false,
            keep_directory_symlink: false,
            parents: false,
            one_file_system: false,
            dereference: Dereference::Never,
        }
    }
}

/// Optional shared, nonblocking transfer counters. Clone the handle to observe
/// copying from another thread. Counters accumulate across copy calls using it.
#[cfg(feature = "live-progress")]
#[derive(Debug, Clone, Default)]
pub struct LiveProgress {
    counters: std::sync::Arc<ProgressCounters>,
}
#[cfg(feature = "live-progress")]
#[derive(Debug, Default)]
struct ProgressCounters {
    bytes: std::sync::atomic::AtomicU64,
    completed: std::sync::atomic::AtomicU64,
}
/// Independently sampled counters; a snapshot is not a transaction across fields.
#[cfg(feature = "live-progress")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveProgressSnapshot {
    /// Logical content bytes processed, including holes and clones. Partially
    /// copied failed files remain counted; this is not a durability guarantee.
    pub bytes: u64,
    /// Successfully completed entries, including directories and links.
    pub completed: u64,
}
#[cfg(feature = "live-progress")]
impl LiveProgress {
    /// Read counters without locking or invoking the copy callback.
    pub fn snapshot(&self) -> LiveProgressSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        LiveProgressSnapshot {
            bytes: self.counters.bytes.load(Relaxed),
            completed: self.counters.completed.load(Relaxed),
        }
    }
    pub(crate) fn add_bytes(&self, bytes: u64) {
        self.counters
            .bytes
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }
    pub(crate) fn complete(&self) {
        self.counters
            .completed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
/// Batch counter writes to avoid contending between workers for every small
/// sparse block. Flush on success and failure, retaining partial-copy progress.
#[cfg(feature = "live-progress")]
struct ProgressTracker<'a> {
    progress: Option<&'a LiveProgress>,
    pending: u64,
}
#[cfg(feature = "live-progress")]
impl<'a> ProgressTracker<'a> {
    fn new(progress: Option<&'a LiveProgress>) -> Self {
        Self {
            progress,
            pending: 0,
        }
    }
    fn add(&mut self, bytes: u64) {
        if self.progress.is_some() {
            self.pending += bytes;
            if self.pending >= 256 * 1024 {
                self.flush();
            }
        }
    }
    fn flush(&mut self) {
        if self.pending != 0 {
            if let Some(progress) = self.progress {
                progress.add_bytes(self.pending);
            }
            self.pending = 0;
        }
    }
}
#[cfg(feature = "live-progress")]
impl Drop for ProgressTracker<'_> {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(all(feature = "live-progress", any(windows, test)))]
struct ProgressWriter<'a, 'b, W> {
    output: &'a mut W,
    tracker: &'a mut ProgressTracker<'b>,
}
#[cfg(all(feature = "live-progress", any(windows, test)))]
impl<W: std::io::Write> std::io::Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let count = self.output.write(buffer)?;
        self.tracker.add(count as u64);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

/// Shared cooperative cancellation plus optional job cancellation markers.
#[derive(Debug, Clone, Default)]
pub struct Cancellation {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub marker_paths: Vec<PathBuf>,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn check(&self) -> std::io::Result<()> {
        if self.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "copy cancelled",
            ));
        }
        for path in &self.marker_paths {
            match std::fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "copy cancelled",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

/// Sparse destination allocation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseMode {
    /// Detect holes when the source allocation indicates sparseness.
    Auto,
    /// Convert zero-filled blocks to holes whenever possible.
    Always,
    /// Write zero-filled data instead of creating holes.
    Never,
}

/// Filesystem cloning policy for file contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflinkMode {
    /// Attempt cloning and fall back when the operation is unsupported.
    Auto,
    /// Require cloning; a failure fails the copy.
    Always,
    /// Transfer contents without attempting cloning.
    Never,
}

/// Naming policy for destination backups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupMode {
    Simple,
    Numbered,
    Existing,
}

#[derive(Debug)]
pub(crate) struct DanglingDestination;
impl std::fmt::Display for DanglingDestination {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("not writing through dangling symlink")
    }
}
impl std::error::Error for DanglingDestination {}

#[derive(Debug)]
pub(crate) struct BackupWouldDestroySource;
impl std::fmt::Display for BackupWouldDestroySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("backing up destination might destroy source")
    }
}
impl std::error::Error for BackupWouldDestroySource {}

/// Event outcomes distinguish completed entries from terminal summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A directory name was created, before its descendants are copied.
    DirectoryCreated,
    /// Recoverable metadata failure; does not make the copy fail.
    Warning,
    Completed,
    Excluded,
    Skipped,
    Done,
    Failed,
}
impl EventKind {
    /// Stable spelling used by the CLI JSON Lines protocol.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryCreated => "directory_created",
            Self::Warning => "warning",
            Self::Completed => "completed",
            Self::Excluded => "excluded",
            Self::Skipped => "skipped",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

/// Transfer paths actually used for a completed content copy.
#[derive(Debug, Clone, Copy, Default)]
pub struct CopyDiagnostics {
    pub offload_attempted: bool,
    pub offloaded: bool,
    pub reflink_attempted: bool,
    pub cloned: bool,
    pub seek_hole: bool,
    pub scanned_zeros: bool,
}

/// A synchronous event. Completion occurs after metadata and checked file closes.
/// Directory completion occurs after its descendants have completed.
#[derive(Debug, Clone)]
pub struct CopyEvent {
    /// Optional recoverable metadata failure.
    pub warning: Option<MetadataWarning>,
    pub kind: EventKind,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub bytes: u64,
    pub completed: u64,
    pub copied_bytes: u64,
    /// Content-copy diagnostics; absent for metadata-only and link operations.
    pub diagnostics: Option<CopyDiagnostics>,
}

/// Read a source object's native identity and metadata version for recovery logs.
/// A snapshot is evidence only; it does not authorize skipping revalidation.
pub fn source_snapshot(path: &Path) -> std::io::Result<(String, String)> {
    let metadata = std::fs::symlink_metadata(path)?;
    #[cfg(target_os = "linux")]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}", metadata.dev(), metadata.ino())
    };
    #[cfg(windows)]
    let identity = windows::source_identity(path)?;
    #[cfg(not(any(target_os = "linux", windows)))]
    let identity = return Err(std::io::ErrorKind::Unsupported.into());
    let version = format!(
        "{}:{:?}:{:?}",
        metadata.len(),
        metadata.modified()?,
        metadata.permissions()
    );
    Ok((identity, version))
}

/// Copy a fresh file, symbolic link or tree without emitting progress output.
pub fn copy(source: &Path, destination: &Path, options: &CopyOptions) -> anyhow::Result<()> {
    copy_with_events(source, destination, options, &mut |_| Ok(()))
}

/// Copy with synchronous events. A callback error stops the copy; completed files
/// remain in the destination. Copies are direct and errors can leave partial files.
/// Paths in events preserve native bytes. No filesystem durability is promised.
pub fn copy_with_events(
    source: &Path,
    destination: &Path,
    options: &CopyOptions,
    events: &mut dyn FnMut(&CopyEvent) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    CopySession::default().copy_with_events(source, destination, options, events)
}

/// Copy session retaining hard-link relationships across source operands.
/// Use a fresh session for each invocation; completion totals remain per operand.
#[derive(Default)]
pub struct CopySession {
    #[cfg(target_os = "linux")]
    state: linux::CopyState,
    #[cfg(windows)]
    state: windows::CopyState,
}
impl CopySession {
    /// Copy one operand with shared link state and synchronous events.
    pub fn copy_with_events(
        &mut self,
        source: &Path,
        destination: &Path,
        options: &CopyOptions,
        events: &mut dyn FnMut(&CopyEvent) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.copy_with_overwrite_policy(source, destination, options, events, &mut |_, _| Ok(true))
    }

    /// Copy with a decision callback before replacing an existing non-directory.
    /// Returning false retains that entry, continues traversal, and fails the operand.
    pub fn copy_with_overwrite_policy(
        &mut self,
        source: &Path,
        destination: &Path,
        options: &CopyOptions,
        events: &mut dyn FnMut(&CopyEvent) -> anyhow::Result<()>,
        overwrite: &mut dyn FnMut(&Path, &Path) -> anyhow::Result<bool>,
    ) -> anyhow::Result<()> {
        if !(1..=64).contains(&options.jobs) {
            anyhow::bail!("jobs must be between 1 and 64");
        }
        options.cancellation.check()?;
        #[cfg(target_os = "linux")]
        {
            if options.preserve_streams
                || options.preserve_sacl
                || options.preserve_windows_attributes
            {
                anyhow::bail!("Windows stream/SACL preservation requires Windows");
            }
            let copy = if options.parents {
                linux::copy_with_parents
            } else {
                linux::copy_tree
            };
            copy(
                source,
                destination,
                options,
                events,
                overwrite,
                &mut self.state,
            )
        }
        #[cfg(windows)]
        {
            windows::copy_tree(
                source,
                destination,
                options,
                events,
                overwrite,
                &mut self.state,
            )
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (source, destination, options, events, overwrite);
            anyhow::bail!("cpcopy requires Linux or Windows")
        }
    }
}

#[derive(Debug)]
pub(crate) struct OverwriteDeclined;
impl std::fmt::Display for OverwriteDeclined {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("overwrite declined")
    }
}
impl std::error::Error for OverwriteDeclined {}

#[derive(Debug)]
pub(crate) struct SourceStatError {
    pub path: PathBuf,
    pub error: std::io::Error,
}
impl std::fmt::Display for SourceStatError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = self.error.to_string();
        let message = message
            .rsplit_once(" (os error ")
            .map_or(message.as_str(), |(text, _)| text);
        write!(
            formatter,
            "cannot stat '{}': {message}",
            self.path.display()
        )
    }
}
impl std::error::Error for SourceStatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub(crate) struct SameFileError {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
}
impl std::fmt::Display for SameFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "'{}' and '{}' are the same file",
            self.source_path.display(),
            self.destination_path.display()
        )
    }
}
impl std::error::Error for SameFileError {}

#[derive(Debug)]
pub(crate) struct LinkCreationError {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub symbolic: bool,
    pub error: std::io::Error,
}
impl std::fmt::Display for LinkCreationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "cannot create {} '{}' to '{}': {}",
            if self.symbolic {
                "symlink"
            } else {
                "hard link"
            },
            self.destination_path.display(),
            self.source_path.display(),
            self.error
        )
    }
}
impl std::error::Error for LinkCreationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub(crate) struct CreatedSymlinkError {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
}
impl std::fmt::Display for CreatedSymlinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "will not copy '{}' through just-created symlink '{}'",
            self.source_path.display(),
            self.destination_path.display()
        )
    }
}
impl std::error::Error for CreatedSymlinkError {}

#[derive(Debug)]
pub(crate) struct IntoSelfError {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
}
impl std::fmt::Display for IntoSelfError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "cannot copy a directory, '{}', into itself, '{}'",
            self.source_path.display(),
            self.destination_path.display()
        )
    }
}
impl std::error::Error for IntoSelfError {}

// Retain every recoverable failure while directory traversal continues. Expose
// the first cause through Error::source for existing library callers.
#[derive(Debug)]
pub(crate) struct MultipleCopyErrors(pub Vec<anyhow::Error>);
impl std::fmt::Display for MultipleCopyErrors {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index > 0 {
                writeln!(formatter)?;
            }
            write!(formatter, "{error:#}")?;
        }
        Ok(())
    }
}
impl std::error::Error for MultipleCopyErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.first().map(|error| error.as_ref())
    }
}

/// A recoverable failure to preserve destination metadata.
#[derive(Debug, Clone)]
pub struct MetadataWarning {
    pub destination: PathBuf,
    pub error: i32,
}

#[derive(Debug)]
pub(crate) struct FileOperationError {
    pub operation: &'static str,
    pub path: PathBuf,
    pub error: std::io::Error,
}
impl std::fmt::Display for FileOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} '{}': {}",
            self.operation,
            self.path.display(),
            self.error
        )
    }
}
impl std::error::Error for FileOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub(crate) struct MetadataPreservationError {
    pub destination: PathBuf,
    pub error: std::io::Error,
}
impl std::fmt::Display for MetadataPreservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "setting attributes for {}: {}",
            self.destination.display(),
            self.error
        )
    }
}
impl std::error::Error for MetadataPreservationError {}

#[derive(Debug)]
pub(crate) struct FilePairOperationError {
    pub operation: &'static str,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub error: std::io::Error,
}
impl std::fmt::Display for FilePairOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} '{}' to '{}': {}",
            self.operation,
            self.source.display(),
            self.destination.display(),
            self.error
        )
    }
}
impl std::error::Error for FilePairOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub(crate) struct ReplacedSourceError(pub PathBuf);
impl std::fmt::Display for ReplacedSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "skipping file '{}', as it was replaced while being copied",
            self.0.display()
        )
    }
}
impl std::error::Error for ReplacedSourceError {}

#[cfg(all(test, feature = "live-progress"))]
mod live_progress_tests {
    use super::{LiveProgress, ProgressTracker};
    #[test]
    fn trackers_flush_partial_progress_on_error_without_double_counting() {
        let progress = LiveProgress::default();
        let result: std::io::Result<()> = {
            let mut tracker = ProgressTracker::new(Some(&progress));
            tracker.add(256 * 1024);
            tracker.add(17);
            assert_eq!(progress.snapshot().bytes, 256 * 1024);
            Err(std::io::Error::other("injected failure"))
        };
        assert!(result.is_err());
        assert_eq!(progress.snapshot().bytes, 256 * 1024 + 17);
    }
    #[test]
    fn pipelined_short_write_then_failure_counts_only_the_written_prefix() {
        use std::io::{self, Cursor, Write};
        struct PrefixWriter {
            bytes: Vec<u8>,
        }
        impl Write for PrefixWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                if self.bytes.is_empty() {
                    self.bytes.extend_from_slice(&buffer[..7]);
                    Ok(7)
                } else {
                    Err(io::Error::other("injected write failure"))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let progress = LiveProgress::default();
        let mut output = PrefixWriter { bytes: Vec::new() };
        {
            let mut tracker = ProgressTracker::new(Some(&progress));
            let mut writer = super::ProgressWriter {
                output: &mut output,
                tracker: &mut tracker,
            };
            let error = crate::pipeline::copy(&mut Cursor::new(vec![42; 32768]), &mut writer, 4096);
            assert!(matches!(error, Err(crate::pipeline::Failure::Write(_))));
        }
        assert_eq!(output.bytes, [42; 7]);
        assert_eq!(progress.snapshot().bytes, 7);
        assert_eq!(progress.snapshot().completed, 0);
    }
    #[test]
    fn cloned_handles_aggregate_multiple_workers_without_lost_updates() {
        let progress = LiveProgress::default();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let progress = &progress;
                scope.spawn(move || {
                    let mut tracker = ProgressTracker::new(Some(progress));
                    for _ in 0..1000 {
                        tracker.add(4099);
                    }
                    tracker.flush();
                    progress.complete();
                });
            }
        });
        assert_eq!(progress.snapshot().bytes, 8 * 1000 * 4099);
        assert_eq!(progress.clone().snapshot().completed, 8);
    }
}
