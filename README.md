# cpcopy

Independent Rust copy engine and command-line interface with native Linux and
Windows backends. The engines copy regular files, symbolic links and directory
trees, preserving timestamps, empty directories and native filenames. Linux
preserves permission bits; Windows preserves read-only attributes and DACLs.
It does not invoke GNU cp, rbcp, Robocopy or PowerShell to copy files.
The test runner reuses unchanged GNU cp shell tests. Full GNU cp compatibility
remains unproven; the current crate must not be presented as cp-compatible.

```sh
cargo build -p cpcopy --release --locked
cargo run -p cpcopy -- -R SOURCE NEW_DESTINATION --exclude '*.tmp' --progress
cargo test -p cpcopy --locked
cargo test -p cpcopy --no-default-features --locked
```

The root `cargo build --bin cpcopy` remains supported through workspace default
members. There is one CLI target, owned by this crate.

## Windows

Build on Windows with `cargo build -p cpcopy --release --locked`, or cross-compile
and export a Windows x64 executable with a static CRT:

```sh
task build:windows:cpcopy
# Output: dist/cpcopy.exe
```

The Windows backend uses native UTF-16 paths, including filenames containing
unpaired surrogates. JSON progress exposes `source_utf16` and `destination_utf16`
arrays. It supports recursive copies, hard links across session operands,
symlink policies, backups, overwrite/update/no-clobber policies, exclusions,
metadata-only copies, parent-directory mapping and synchronous progress callbacks.
Metadata preservation uses native access/modification times, read-only attributes,
DACLs (including protection against parent inheritance), and owner/group SIDs.
Creating symlinks and assigning ownership can require
Windows privileges; failures are reported with their operation and destination.

Sparse copies use allocated-range queries and sparse-file controls to avoid
reading large holes. Reflinks use filesystem extent cloning; `--reflink=auto`
falls back for unsupported cloning, while `--reflink=always` reports failure.
Terminal storage/resource errors are propagated. ReFS cloning is implemented but
has not been validated on a ReFS volume. NTFS validation covers clone fallback.

Dense Windows files of at least 8 MiB overlap reads and writes through two reusable
buffers. The default request size is 1 MiB on Windows and 256 KiB on Linux;
`--buffer-size` overrides it. Small Windows files allocate smaller buffers, and
sparse copies retain the sparse-aware transfer path. The
[same-run optimization benchmark](../../docs/fixtures/copy-engine/cpcopy-windows-optimization-20261004/README.md)
reduced the 256 MiB copy median from 115.5 ms to 77.2 ms with all payloads verified.

`-j N` / `--jobs=N` opts into bounded Windows concurrency (1..64; default 1). Only
independent regular files with fresh destinations in case-insensitive source
directories run concurrently. Other entries form serial barriers; links,
backups, update/no-clobber, attributes-only, special-file contents, forced
replacement, SACL preservation and caller impersonation retain serial execution.
At most `2 * jobs` copies are outstanding, and callbacks replay on the caller
thread in traversal order.

The [concurrency and metadata benchmark](../../docs/fixtures/copy-engine/cpcopy-windows-concurrency-20261004/README.md)
reduced the 1,000-file median from 425.2 ms to 367.1 ms with timestamp-handle
reuse and one worker. Two workers reached 360.0 ms; four and eight were slower
than the new serial path on that VM. The default remains one worker.

`--preserve=streams` preserves NTFS alternate data streams, including empty and
directory streams. `--preserve=xattr` preserves binary NTFS extended attributes.
`--preserve=sacl` preserves audit ACLs and their inheritance protection using
thread-scoped backup, restore and security privileges. Missing privileges fail;
process-wide token privileges are not changed. Archive mode includes Windows
streams and optional EAs; audit ACL preservation is an explicit opt-in.

The library's `preserve_windows_attributes` option also restores creation times,
hidden/system/archive attributes and compression. EFS, object IDs and arbitrary
reparse-point types are not supported by the native media profile and fail
explicitly. This is not a complete Windows backup tool or full GNU cp compatibility
claim. Same-path force-with-backup copies are not supported.

[Windows validation and benchmark evidence](../../docs/fixtures/copy-engine/cpcopy-windows-20261004/README.md)
records 26 passing integration tests in a Windows 11 NTFS VM, including the
privilege-dependent cases, plus the library-only tests and comparisons with
Robocopy and PowerShell `cp`.

## Linux concurrency

`-j N` / `--jobs=N` also enables bounded Linux multi-file copying (1..64;
default 1). Consecutive independent regular files with fresh destinations run
concurrently. Directory finalization, existing destinations, links, backups,
update/no-clobber, attributes-only, forced replacement, special-file contents
and parent-directory mapping retain serial processing. Source files with
multiple hard links remain serial even when link preservation is disabled.
Enabling hardlink preservation keeps the tree serial.

At most `2 * jobs` copies are outstanding. Callbacks and metadata warnings
remain on the calling thread in the original inode traversal order; a directory
completes after its descendants. Callback aborts and cancellation join workers,
and failed copies can retain partial destination files. Worker creation uses
exclusive destination opens and refuses substituted source symlinks. Permissions,
ACLs, timestamps, xattrs, sparse files and reflinks use the existing file-copy path.
The library does not change the process umask when starting workers.

```sh
cpcopy -R -j 4 --preserve=timestamps SOURCE NEW_DESTINATION
```

The [Linux concurrency benchmark](../../docs/fixtures/copy-engine/cpcopy-linux-concurrency-20261004/README.md)
verified 288 copies on warm ext4. Two workers reduced the 10,000 × 4 KiB median
from 151.4 ms to 120.2 ms; eight reduced sixteen 16 MiB files from 61.4 ms to
27.4 ms. A single 256 MiB file did not improve. The default remains one worker.

## Library

Use a path dependency with `default-features = false` to omit Clap and JSON output:

```toml
cpcopy = { path = "crates/cpcopy", default-features = false }
```

```rust,no_run
use cpcopy::{CopyOptions, copy_with_events};
use std::path::Path;

let options = CopyOptions {
    exclusions: vec!["*.tmp".into()],
    ..CopyOptions::default()
};
copy_with_events(Path::new("source"), Path::new("destination"), &options,
    &mut |event| {
        println!("{}: {}", event.kind.as_str(), event.destination.display());
        Ok(())
    })?;
# Ok::<(), anyhow::Error>(())
```

Windows metadata records are transferred through bounded BackupRead/BackupWrite
buffers; unnamed data remains on the existing sparse/reflink copy path. ADS and
EAs are applied before timestamps and security. Existing directory metadata is
merged; this is not an exact deletion of destination-only metadata. `Cancellation`
checks shared flags and job marker paths between entries and buffered transfer
chunks. `stop_on_error` aborts traversal on the first error, and `reject_symlinks`
rejects links/reparse points for source media.

Callbacks run synchronously. `Completed` is emitted after file metadata and checked
closes, or after descendants and directory metadata. Callback errors stop copying.
The library has no terminal output. `copy` disables event handling.

## CLI extensions

`--attributes-only` applies selected metadata without copying regular-file
contents. Existing data is retained; fresh regular-file destinations are empty.
These entries emit completion with zero copied bytes. Combinations with backup,
link and symlink modes still require a full upstream audit.

`--preserve=xattr` copies regular-file extended attributes through open file
descriptors and directory attributes through their paths, preserving binary
values. Symlinks and special objects use non-following attribute calls; actual
symlink attribute writes remain unverified on the development host.
`--no-preserve=xattr` disables this policy. Regular-file access ACLs are copied
with mode preservation, independently of xattr selection; stale destination
access ACLs are removed when the source lacks one. Directory access/default
ACLs are also restored under mode preservation, after final permissions are
applied. Unavailable ACL interfaces fall back to permission bits; failure to
install a source ACL still fails preservation. Explicit `--preserve=xattr`
requires successful xattr preservation. Archive and `--preserve=all` tolerate
xattr failures and continue later attributes; attributes-only copies report
recoverable metadata warnings without changing a successful status. The library
enables xattr copying through `CopyOptions::preserve_xattrs` and defaults to
strict errors through `require_preserve_xattrs`.

`--no-preserve=mode,timestamps,ownership,links` disables selected preservation
policies. For each attribute, the last explicit preservation or disabling option
wins, including `-p` and `-d`. Disabling mode preservation uses default creation
permissions (0666 for files, 0777 for directories), masked by umask.

`--backup=simple` (or `never`) renames overwritten non-directory entries to
their old name plus `--suffix`, `SIMPLE_BACKUP_SUFFIX`, or `~`. Backup paths
aliasing the source are rejected. `--backup=none`/`off` disables backups.
With force and simple backups, copying a regular file to the same path creates
the backup copy while preserving the original. GNU `backup-1.sh` and
`backup-is-src.sh` pass unchanged. `numbered`/`t` selects successive `.~N~`
names; `existing`/`nil` numbers backups only when numbered backups already
exist. `-b` and `--backup` without a value use `VERSION_CONTROL`, defaulting
to existing mode when unset or empty. Explicit backup modes override the
environment. Invalid environment modes fail before copying. Numbered
renames refuse to replace backups claimed concurrently; collision retry remains
unfinished. The library exposes
`CopyOptions::backup_suffix` and `BackupMode`.

`--remove-destination` unlinks existing non-directory destination entries before
copying, breaking their old hard-link relationships and replacing destination
symlinks directly. Existing directories continue to merge. An identical source
and destination path is rejected before removal. The library exposes this as
`CopyOptions::remove_destination` alongside overwrite permission.

`-n`/`--no-clobber` skips existing non-directory destination entries.
`-u`/`--update` skips a non-directory copy when the destination modification
timestamp is equal or newer. Directory traversal continues under both options.
Skipped entries emit `skipped` progress events and do not increase completion or
byte totals. `--update=older` selects the timestamp policy, `--update=all`
selects ordinary overwrite, `--update=none` skips existing entries successfully,
and `--update=none-fail` reports a failure when an entry is not replaced.

Recursive copies recreate FIFOs, device nodes and sockets without opening their
contents. Creating device nodes requires the host's usual privileges. Existing
non-directory destinations are replaced. Nonrecursive copies read special-file
contents; recursive content copying requires `--copy-contents`.
GNU `special-f.sh` is used to verify FIFO
replacement without blocking.

Ordinary CLI copies use new timestamps. `--preserve=timestamps` restores source
access and modification times for files, symlinks, and newly created directories.
`--preserve=mode` restores source permission bits, including on existing
destinations. Both may be combined as `--preserve=mode,timestamps`. Ordinary
CLI copies apply the process umask to newly created objects and retain modes
of existing objects. Library callers can set `preserve_mode` and `creation_mask`.
`--preserve=ownership` restores user and group IDs, and `-p` requests mode,
ownership and timestamps together. Ownership changes precede mode restoration.
The library exposes `preserve_ownership`. Unprivileged ownership failures with
`EPERM`, `EINVAL`, or `EACCES` retry the group alone and clear special mode bits;
other ownership failures fail the copy. Security-context selection remains
unimplemented. Library defaults preserve
timestamps; set `CopyOptions::preserve_timestamps` to false to disable restoration.

`--preserve=links` retains hard-link relationships within copied trees and
across source operands in one CLI invocation. The library enables this with
`CopyOptions::preserve_links`; use one `CopySession` for multiple operands.
Single-copy functions start fresh sessions. Event completion totals remain
per operand.

`-d` combines source symlink preservation with hard-link preservation. A later
`-L`, `-P`, or `-H` changes dereferencing without disabling hard-link preservation.
The unchanged GNU `no-deref-link1.sh`, `no-deref-link2.sh`, `no-deref-link3.sh`
and `symlink-slash.sh` tests pass after adding this shorthand.

Directories require `-R`/`-r`/`--recursive`. Ordinary copies follow source
symlinks; recursive copies preserve them by default. `-L`/`--dereference`
follows all source links, `-P`/`--no-dereference` preserves all links, and `-H`
follows only command-line source links. The last policy flag takes precedence.
Ancestor directory cycles are rejected before creating the cyclic destination.
Library defaults remain recursive with symlinks preserved; callers can select
`CopyOptions::dereference` explicitly.

The CLI accepts `SOURCE... DIRECTORY`, `-t DIRECTORY SOURCE...`, and
`-T SOURCE DESTINATION`. An existing destination directory receives each source
under its basename unless `-T` is used. A failed source does not prevent attempts
to copy later sources; any failure produces a failing exit status. Individual
Symlink copies replace existing non-directory destination entries without
modifying their old referents. Directory copies merge
into existing directories, retaining their modes and unrelated entries.
`SOURCE/.` copies source contents directly into the destination directory.
The library enables merging with `CopyOptions::merge_directories`.
Regular-file
copies overwrite existing regular files, including through destination symlinks,
while retaining the destination inode and mode. Source aliases are rejected
before truncation. The library defaults to rejecting existing entries and can
enable regular-file overwrite with `CopyOptions::overwrite`. Dangling destination
links are rejected with a specific diagnostic, including with `-f`. Setting
`POSIXLY_CORRECT` allows creating their referents; the library exposes this
policy as `CopyOptions::allow_dangling_destination` without reading the environment.
For regular-file copies, `-f` removes a destination that cannot be opened and
retries with a fresh file, including looping destination symlinks.
The library takes an exact destination
path and does not append basenames.

`--exclude PATTERN` is repeatable and matches basenames at every depth using
case-sensitive libc glob rules (`*`, `?`, brackets and escaping). Patterns match
native bytes, including non-UTF-8 filenames. Matching directories are pruned.

`--progress` emits JSON Lines on stderr, with `completed`, `excluded`, `done`
and `failed` events, per-entry bytes and cumulative completion/byte totals.
`source_bytes` and `destination_bytes` are byte arrays to preserve exact Linux
paths. Diagnostics also use stderr; consumers should distinguish JSON event
lines from error lines. Events do not provide a pre-scanned total or ETA.

Copies write final filenames directly. Errors may leave partial files, and
completion does not imply fsync or durable storage. There is no interrupted-file
resume or persistent journal support yet.

## GNU cp parity work

Run unchanged upstream shell tests using the GNU coreutils 9.7 release sources:

```sh
cargo build -p cpcopy --locked
python3 crates/cpcopy/tests/run-upstream.py /path/to/coreutils-9.7 /path/to/cpcopy proc-zero-len.sh proc-short-read.sh link.sh
```

The runner installs the supplied binary as `cp` in an isolated temporary test
directory. Other utilities come from PATH. Omitting test names runs all cp shell
tests; unsupported features still produce failures. The three tests above pass
on the development Linux host. `link.sh` was observed failing before adding
`-l`/`--link`, `-s`/`--symbolic-link`, and `-f`/`--force` for link replacement.

Tests requiring `CONFIG_HEADER` report an infrastructure failure when the
configured header is unavailable. Supply its path in that environment variable
or use a source tree with `lib/config.h`. This avoids mistaking missing build
configuration for a platform capability skip.
`link-no-deref.sh` and `cp-deref.sh` also pass after adding source link policies
and recursive flags. Recursive link modes create directories and link their
non-directory descendants. `thru-dangling.sh` also passes after implementing
dangling-link diagnostics, the POSIX environment policy, and forced replacement
of looping destination links. Complete GNU
link/dereferencing semantics remain unfinished.

The regression tests adapt the unoptioned same-path and hard-link cases from
[GNU coreutils v9.7 `tests/cp/same-file.sh`](https://github.com/coreutils/coreutils/blob/v9.7/tests/cp/same-file.sh):
both operations fail before writing and leave the source contents intact. Fresh
regular-file and top-level dangling-symlink copies are also tested. The full upstream `same-file.sh` now also passes after implementing the
alias and backup policies described below; the full cp suite is still incomplete.

Remaining parity work includes edge cases in cp operand/destination resolution,
trailing-slash symlink semantics, overwrite policies,
backup and link modes, metadata selection, ownership/ACL/xattr preservation,
sparse files, reflinks, special files, diagnostics and complete upstream-suite
execution. The supported overwrite behavior does not establish full parity.

Archive selection (`-a`/`--archive`) enables recursive copying, preserves source
symlinks, and selects mode, ownership, timestamps, hard links and extended
attributes. `--preserve=all` and `--no-preserve=all` select these attributes;
later selectors override earlier ones. GNU coreutils 9.7's unchanged
`preserve-mode.sh`, `backup-dir.sh` and `link-symlink.sh` pass with the configured
coreutils header. Archive xattr handling follows the reduced-diagnostic policy;
security-context handling remains a parity gap. Unprivileged ownership
fallbacks are implemented below.

GNU coreutils 9.7's unchanged `attr-existing.sh` and `preserve-link.sh` pass.
Attributes-only symbolic-link copying refuses to replace an existing destination
unless it is explicitly removed first. Archive updates retain a skipped newer
destination as the hard-link anchor for later names from that source inode,
including when those later destinations are newer separate files. Regression
coverage verifies both behaviors before and after the fixes.

Interactive copying (`-i`/`--interactive`) prompts before replacing existing
non-directories; refusal retains the entry, continues other entries, and returns
failure. The later of `-i` and `-n` wins, while `--update=none` disables prompts.
Backups conflict with no-clobber policies. `-v`/`--verbose` prints completed
source/destination pairs. The unchanged coreutils 9.7 `cp-i.sh` passes, including
force, no-clobber, update and backup combinations. A library overwrite-decision
callback provides the same traversal behavior without reading process stdin.
GNU filename quoting and locale-aware affirmative responses still require
compatibility work.

Verbose directory copies announce newly created directories before descendants,
and do not announce an existing directory merely because it is merged. GNU's
unchanged `src-base-dot.sh` passes. The event stream includes `directory_created`
with unchanged completion totals; directory `completed` events still follow
metadata finalization and descendant completion.

Nonrecursive special-file sources are opened for content copying into regular
files. Existing FIFO and device destinations accept content without truncation;
regular destinations retain the checked-inode-before-truncate protection.
GNU coreutils 9.7's unchanged `sparse-to-pipe.sh`, `special-f.sh`,
`proc-zero-len.sh` and `proc-short-read.sh` pass. Ordinary stream-copy events
count actual transferred bytes rather than source stat size. Recursive special
files are still recreated as filesystem objects; sparse extent handling still requires further validation.

`--copy-contents` selects stream reading for recursive special-file sources;
without it, recursive special files remain filesystem objects. GNU's unchanged
`file-perm-race.sh` passes and verifies private permissions during FIFO transfer.
`existing-perm-race.sh` cannot establish ownership behavior on this host: its
group change fails and a misspelled upstream framework helper lets it return
zero. The runner reports that setup failure as INFRA rather than PASS.

`--reflink[=always|auto|never]` selects Linux FICLONE cloning. A bare option
requires a clone; the CLI default is auto, while the library default remains
never. Auto falls back for unsupported cloning, but reports I/O, memory, space
and quota errors. Required-clone failure removes the matching newly created
empty destination. Attributes-only skips cloning. Bare `--preserve` selects
mode, ownership and timestamps.
GNU's unchanged `reflink-perm.sh` passes. `reflink-auto.sh` passes after adding sparse policy selection, including
cross-filesystem failure and fallback. The development filesystem rejects FICLONE, so successful
clone execution still requires validation on a supporting filesystem. The
runner now sets `abs_srcdir` for upstream helper scripts.

`--sparse=auto|always|never` controls hole creation, defaulting to auto.
Always converts zero-filled blocks to holes; auto does so when the source
allocation indicates sparseness. Never writes zeros and disables automatic
reflinking. Required reflinking conflicts with non-auto sparse policies.
Sparse regular sources use SEEK_DATA to skip holes, falling back to sequential
copying when unsupported; trailing holes retain the final logical size.
GNU's unchanged `sparse.sh`, `reflink-auto.sh` and `sparse-to-pipe.sh` pass.
A regression copies a 1 TiB hole within two seconds without allocating blocks.
Upstream `sparse-perf.sh` passes after adding actual transfer diagnostics to
`--debug` output.
Preallocated unwritten extents and remaining extent/performance tests still
require validation.

`--debug` implies verbose output and reports actual reflink attempts, successful
clones, zero scanning and SEEK_HOLE navigation, plus skipped destinations.
Completed content-copy library events include these diagnostics; metadata-only
operations omit them. Linux regular-file copies can use `copy_file_range` when
reflinks are allowed and hole detection is unnecessary. Unsupported initial
offload attempts fall back to buffered copying; errors after partial offload
remain failures. `--reflink=never` and `--sparse=never` disable this path.
Debug output reports whether offload ran, was unsupported, or was avoided.
GNU's unchanged `debug.sh`, `sparse-perf.sh`
and `sparse-2.sh` pass. Host tools requested by an upstream test's `print_ver_`
line are advertised by the runner when available; the supplied copier always
provides cp. `sparse-extents-2.sh` returns zero but encounters broken filesystem
setup and shell comparison errors on this host, so the runner treats that as
INFRA rather than proof of complete extent validation.

`--keep-directory-symlink` with `--copy-contents` follows existing destination
directory symlinks when merging directories. Without it those entries are
rejected, matching GNU. Regression coverage checks both outcomes, retained
symlink text and GNU's permitted merge into a sibling source directory.
The unchanged coreutils 9.7 `keep-directory-symlink.sh` omits its final failure
exit and records the expected initial refusal as a failure. The runner now
honors a remaining shell `fail` variable at script completion. That script
therefore fails with both this copier and the host GNU 9.11 reference; its
former zero exit was not valid parity evidence. Original scripts remain
unmodified.

Recursive hard-link mode follows source symlinks by default, matching GNU;
explicit `-P`, `-d`, archive, `-L` and `-H` policies retain their precedence.
Source stat failures retain the failing native path and produce GNU-style
`cannot stat` diagnostics for ordinary filenames. The unchanged coreutils 9.7
`link-deref.sh`, `link-symlink.sh`, `link-no-deref.sh` and `cp-HL.sh` pass.
Filename diagnostics use native bytes and GNU-style shell quoting in C and
UTF-8 locales. Translation of diagnostic text remains unimplemented.

Directory traversal continues through filesystem errors in individual children
and attempts to finalize parent permissions and metadata before returning
failure. Callback errors still stop copying immediately. Destination permission
lookup failures preserve GNU's `cannot stat` or explicit `target directory`
diagnostic context. The unchanged coreutils 9.7 `fail-perm.sh`,
`existing-perm-dir.sh` and `cp-i.sh` pass. A regression checks readable siblings,
parent mode finalization and inaccessible destination symlinks after a failed
child. Traversal retains and reports every recoverable child and finalization
failure; callback failures still abort immediately. Some metadata-finalization
diagnostics still need further GNU compatibility coverage.

`--parents` (including the GNU `--parent` spelling) maps the full source path
under an existing target directory, stripping an absolute leading root.
Source parents are checked before creation; parent directories are finalized
from inner to outer after copying using shared directory metadata handling.
Existing parents receive explicitly preserved attributes, while new parents
honor source modes or explicit default permissions. Terminal completion events
follow parent finalization. GNU's unchanged `cp-parents.sh`, `parent-perm.sh`
and `parent-perm-race.sh` pass. Invalid copy-policy combinations fail before
creating parents. Setup-failure cleanup, native path edge cases and complete
parent diagnostics still require further parity work.

`-x`/`--one-file-system` restricts recursive descent to each source operand's
filesystem. Crossing directory entries are created and finalized without their
children; explicitly named source operands establish their own filesystem.
A regression uses a followed proc-filesystem directory to verify both outcomes,
which were also checked against GNU. Exclusions remain available through the
repeatable `--exclude` extension; `-x` now has GNU's filesystem-policy meaning.
The unchanged upstream `cp-deref.sh`, `cp-HL.sh` and `cp-parents.sh` still pass.

GNU coreutils 9.7's unchanged `same-file.sh` passes in full. Same-file checks
preserve source data when a copied symlink names the destination referent.
Backups can safely replace distinct regular hard-link aliases; hard-linked
symlink aliases are no-ops in link mode and retain GNU backup behavior in copy
mode. Forced hard-link backup of a same-path regular file creates a backup
hard link. Same-file and explicit link-creation diagnostics retain operand
names, and unambiguous long-option abbreviations such as `--rem` are accepted.
Regression coverage verifies contents, symlink targets and backup inode
relationships. `backup-is-src.sh` and `backup-1.sh` also pass. Full GNU quoting,
concurrent backup allocation and complete upstream-suite validation remain
outstanding.

The copy session tracks symlinks created for top-level operands by destination
path and inode identity. Later operands cannot copy through those links unless
a removal or backup policy first replaces the destination entry. The cache is
validated against the current entry, avoiding dependence on stale path names.
GNU's unchanged `abuse.sh` passes for both dangling and writable referents;
regressions verify that no referent is created or modified. Directory containment
errors retain operand names and match the diagnostic in unchanged
`into-self.sh`, which also passes. `same-file.sh` remains passing. These checks
do not establish protection against arbitrary concurrent filesystem mutations.

## Error and metadata fallback validation

Differential regressions compare cpcopy with host GNU cp for native filename
quoting in C/UTF-8 locales, multiple directory failures, source open/read/access,
destination create/write, and terminal seek/extension/close/clone/offload errors.
Fault injection verifies strict and optional xattr status, nonfatal warnings,
continued preservation of later attributes, and unavailable ACL interface
fallbacks for files and directories. The library exposes recoverable metadata
warnings through `EventKind::Warning` and `CopyEvent::warning`.

Additional fault-injection matrices cover uncommon stat, source replacement,
initial truncation, forced-removal races, metadata writes, ACL errors, clone
cleanup, symlink operations, directory reads/creation, special-file creation,
backup renaming, parent creation, and zero-byte writes. The regular-file matrix
compares retained destination contents and permissions as well as status and
diagnostics. Directory timestamp failures still finalize permissions; terminal
clone failures retain partial data and report cleanup errors separately.

The combined implementation passes 92 crate tests, 27 tests without CLI
features, formatting, and Clippy with warnings denied. Thirty-one unchanged
GNU scripts covering diagnostics, metadata, permissions, sparse files, reflinks,
backups, special files, and procfs pass. `cp-mv-enotsup-xattr.sh` skips because
it requires root and filesystem mounts; fault-injection tests establish the tested fallback branches,
not full mounted-filesystem correctness. Diagnostic translation, legacy locale
quoting, security contexts, and allocation/auxiliary lookup error paths still need
work. Full GNU cp parity is not established.

## Copy performance evidence

The optional `live-progress` Cargo feature enables library counters and the
`--live-progress` CLI flag. It is disabled by default and does not require `cli`
for library use. Build the CLI with `cargo build -p cpcopy --release --features
live-progress`, or enable `features = ["live-progress"]` in a library dependency.
Without the feature, counter storage, transfer tracking, and terminal rendering
are compiled out.

`--live-progress` uses `indicatif` for a terminal bar when the total is known
and a spinner for trees or unknown totals. The renderer dependencies are optional
and enabled only by the `live-progress` Cargo feature.

`--live-progress` shows bytes, average throughput, elapsed time, and completed
entries while copying, including within a large file. A single regular source
file also gets a progress bar and estimated remaining time based on its initial
size. Tree and multiple-source copies show `ETA unknown`: the copier does not
scan directories twice just to calculate a total. Source growth beyond the
initial size also discards that estimate. The byte counter includes logical
sparse holes and reflinked data; throughput is logical bytes per second, not
physical device bandwidth, and may include partial data from failed copies.

```sh
cpcopy --live-progress -R -j 4 SOURCE DESTINATION
```

Progress is opt-in. Transfer workers update counters without formatting or
terminal writes; a separate reporter renders at most five times per second and
wakes immediately when copying finishes. A terminal gets an updating line;
redirected stderr gets plain lines. Output failures disable the reporter without
failing the copy. `--progress` retains JSON Lines events and cannot be combined
with `--live-progress`. The reporter owns a duplicated stderr handle, leaving
Rust's shared stderr lock available for diagnostics. Shutdown waits at most
100 ms for the final render, then detaches a stalled reporter so output
backpressure cannot hold up CLI exit. The final line is best-effort; a detached
reporter can remain blocked until its output drains or the process exits.
Progress and diagnostic output can interleave. Enabled tracking batches counter updates every
256 KiB and caps Linux offload requests at 8 MiB; small transfers flush their
remaining counts when the transfer ends. These choices reduce overhead but do
not make enabled progress free.

The [live progress measurements](../../docs/fixtures/copy-engine/cpcopy-live-progress-20261004/README.md)
verified 464 warm-cache Linux benchmark copies, including real terminal output.
Most terminal median deltas were around 0–2%; the largest increase was 4.6%.
Single-file bar/ETA runs showed no median regression. These measurements do not
guarantee zero overhead on other hosts; Windows overhead remains unmeasured.

A release benchmark on `/data/cache` copied a warm-cache 256 MiB dense file
three times per configuration, checking SHA-256 after each copy. Median times
were 48.0 ms for cpcopy auto offload, 50.3 ms for cpcopy buffered copying, and
48.5 ms for GNU cp auto. This run shows comparable performance, not a material
speedup. Both tools copied a 1 TiB empty sparse file in approximately 1.1 ms,
retaining its logical size with zero allocated blocks. These measurements
exclude fsync and do not establish cold-cache, network, or other-filesystem
performance. Sparse extent data still uses buffered copying.

## Backup option validation

Backup controls accept unambiguous prefixes (including `VERSION_CONTROL`),
reject ambiguous prefixes before copying, and support `-S` as the suffix option.
Repeated suffix and long backup options use the last value. A suffix alone
enables backups using the environment's backup mode or the default `existing`.
Regressions for prefixes and suffix-only backups failed before implementation;
GNU cp was checked on the same prefix cases. Unchanged GNU `backup-1.sh`,
`backup-is-src.sh`, `backup-dir.sh`, and `cp-mv-backup.sh` pass.

## Trailing slash option validation

`--strip-trailing-slashes` now strips source slashes when copying into a target
directory, preserving native filename bytes and a root slash. Exact-destination
copies retain their original source slashes, matching GNU cp's current behavior.
A regression first failed because the option was missing, then passed; both
target-directory and exact-destination cases were checked against host GNU cp.
Unchanged GNU `symlink-slash.sh`, `sparse-to-pipe.sh`, and `sparse-extents.sh`
also pass. `cross-dev-symlink.sh` skips because it requires root.

## Additional ownership validation

Regular-file ownership preservation now follows GNU cp's unprivileged
fallback for `EPERM`, `EINVAL`, and `EACCES`: retry the group alone, continue
copying, and clear setuid, setgid, and sticky bits when ownership could not be
preserved. A regression copying `/proc/version` with `-p` failed before this
change and passes afterward; host GNU cp succeeds on the same fixture.
The same fallback now applies to directories, symlinks, and special files.
A second regression exercises foreign-owned `/proc/self` symlink copying and
parent-directory preservation for `/proc/version`; both operations also succeed
with host GNU cp. Special-file ownership failures still lack direct coverage.
Root-only ownership/capability tests and SELinux tests skipped in this environment
and provide no validation evidence.
All 68 crate tests, Clippy with warnings denied, and unchanged GNU
`preserve-2.sh`, `preserve-mode.sh`, `preserve-slink-time.sh`, and
`attr-existing.sh` pass after this change.
