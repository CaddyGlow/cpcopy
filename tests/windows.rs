#![cfg(target_os = "windows")]

use cpcopy::{BackupMode, CopyOptions, CopySession, Dereference, EventKind, ReflinkMode};
use std::{
    ffi::OsString,
    fs::{self, File, FileTimes, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::windows::{
        ffi::OsStringExt,
        fs::{symlink_dir, symlink_file},
        io::AsRawHandle,
    },
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

#[repr(C)]
#[derive(Default)]
struct FileInformation {
    attributes: u32,
    creation: [u32; 2],
    accessed: [u32; 2],
    modified: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        handle: *mut std::ffi::c_void,
        information: *mut FileInformation,
    ) -> i32;
}
fn identity(path: &Path) -> (u32, u32, u32) {
    let file = File::open(path).unwrap();
    let mut information = FileInformation::default();
    // SAFETY: Live file handle and initialized writable structure of the Win32 layout.
    assert_ne!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) },
        0
    );
    (
        information.volume,
        information.index_high,
        information.index_low,
    )
}
#[expect(
    clippy::permissions_set_readonly_false,
    reason = "Windows clears the readonly attribute without changing POSIX permission bits"
)]
fn writable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}
fn set_modified(path: &Path, seconds: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)))
        .unwrap();
}

#[test]
fn native_utf16_tree_payloads_and_postorder_progress_are_preserved() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let nested = source.join("資料-é-🦀");
    fs::create_dir_all(&nested).unwrap();
    let name = OsString::from_wide(&[0x0066, 0xD800, 0x0069, 0x006C, 0x0065]);
    let payload = (0..130_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(nested.join(&name), &payload).unwrap();
    fs::write(source.join("empty"), []).unwrap();
    let destination = tree.path().join("destination");
    let mut events = Vec::new();
    cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions::default(),
        &mut |event| {
            events.push(event.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(destination.join("資料-é-🦀").join(&name)).unwrap(),
        payload
    );
    assert_eq!(fs::metadata(destination.join("empty")).unwrap().len(), 0);
    let file = events
        .iter()
        .position(|event| event.kind == EventKind::Completed && event.source == nested.join(&name))
        .unwrap();
    let directory = events
        .iter()
        .position(|event| event.kind == EventKind::Completed && event.source == nested)
        .unwrap();
    assert!(file < directory);
    assert_eq!(events.last().unwrap().kind, EventKind::Done);
    assert_eq!(events.last().unwrap().copied_bytes, payload.len() as u64);
}

#[test]
fn readonly_and_source_timestamps_are_restored_after_data_copy() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::write(&source, b"metadata").unwrap();
    let file = OpenOptions::new().write(true).open(&source).unwrap();
    let accessed = UNIX_EPOCH + Duration::from_secs(1_650_000_000);
    let modified = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    file.set_times(
        FileTimes::new()
            .set_accessed(accessed)
            .set_modified(modified),
    )
    .unwrap();
    drop(file);
    let mut permissions = fs::metadata(&source).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&source, permissions).unwrap();
    cpcopy::copy(&source, &destination, &CopyOptions::default()).unwrap();
    let metadata = fs::metadata(&destination).unwrap();
    assert!(metadata.permissions().readonly());
    assert_eq!(metadata.modified().unwrap(), modified);
    assert_eq!(metadata.accessed().unwrap(), accessed);
    writable(&source);
    writable(&destination);
}

#[test]
fn overwrite_retains_destination_identity_and_same_file_rejection_retains_bytes() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::write(&source, b"new").unwrap();
    fs::write(&destination, b"long old contents").unwrap();
    let original = identity(&destination);
    let options = CopyOptions {
        overwrite: true,
        ..CopyOptions::default()
    };
    cpcopy::copy(&source, &destination, &options).unwrap();
    assert_eq!(identity(&destination), original);
    assert_eq!(fs::read(&destination).unwrap(), b"new");
    let alias = tree.path().join("alias");
    fs::hard_link(&source, &alias).unwrap();
    assert!(cpcopy::copy(&source, &alias, &options).is_err());
    assert_eq!(fs::read(&source).unwrap(), b"new");
    assert_eq!(identity(&source), identity(&alias));
}

#[test]
fn hard_links_are_created_and_preserved_across_session_operands() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::write(&source, b"hard linked").unwrap();
    let linked = tree.path().join("linked");
    cpcopy::copy(
        &source,
        &linked,
        &CopyOptions {
            hard_link: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(identity(&source), identity(&linked));
    let first = tree.path().join("first");
    let second = tree.path().join("second");
    let options = CopyOptions {
        preserve_links: true,
        ..CopyOptions::default()
    };
    let mut session = CopySession::default();
    session
        .copy_with_events(&source, &first, &options, &mut |_| Ok(()))
        .unwrap();
    session
        .copy_with_events(&linked, &second, &options, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(identity(&first), identity(&second));
    assert_ne!(identity(&first), identity(&source));
}

#[test]
fn backup_modes_keep_original_contents_and_never_replace_numbered_backups() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::write(&source, b"new").unwrap();
    for mode in [
        BackupMode::Simple,
        BackupMode::Numbered,
        BackupMode::Existing,
    ] {
        let destination = tree.path().join(format!("destination_{mode:?}"));
        fs::write(&destination, b"old").unwrap();
        let options = CopyOptions {
            overwrite: true,
            backup_suffix: Some(".saved".into()),
            backup_mode: mode,
            ..CopyOptions::default()
        };
        cpcopy::copy(&source, &destination, &options).unwrap();
        let suffix = if mode == BackupMode::Numbered {
            ".~1~"
        } else {
            ".saved"
        };
        assert_eq!(
            fs::read(tree.path().join(format!("destination_{mode:?}{suffix}"))).unwrap(),
            b"old"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        if mode == BackupMode::Numbered {
            fs::write(&destination, b"second old").unwrap();
            cpcopy::copy(&source, &destination, &options).unwrap();
            assert_eq!(
                fs::read(tree.path().join("destination_Numbered.~1~")).unwrap(),
                b"old"
            );
            assert_eq!(
                fs::read(tree.path().join("destination_Numbered.~2~")).unwrap(),
                b"second old"
            );
        }
    }
}

#[test]
fn update_and_no_clobber_skip_and_report_selected_status() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::write(&source, b"new").unwrap();
    fs::write(&destination, b"retain").unwrap();
    set_modified(&source, 1_600_000_000);
    set_modified(&destination, 1_700_000_000);
    for options in [
        CopyOptions {
            overwrite: true,
            update: true,
            ..CopyOptions::default()
        },
        CopyOptions {
            overwrite: true,
            no_clobber: true,
            ..CopyOptions::default()
        },
    ] {
        let mut events = Vec::new();
        cpcopy::copy_with_events(&source, &destination, &options, &mut |event| {
            events.push(event.kind);
            Ok(())
        })
        .unwrap();
        assert!(events.contains(&EventKind::Skipped));
        assert_eq!(fs::read(&destination).unwrap(), b"retain");
    }
    assert!(
        cpcopy::copy(
            &source,
            &destination,
            &CopyOptions {
                no_clobber: true,
                fail_on_skip: true,
                ..CopyOptions::default()
            }
        )
        .is_err()
    );
    set_modified(&destination, 1_500_000_000);
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            overwrite: true,
            update: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"new");
}

#[test]
fn attributes_only_retains_contents_and_updates_modification_time() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::write(&source, b"source").unwrap();
    fs::write(&destination, b"keep destination").unwrap();
    set_modified(&source, 1_600_000_000);
    let options = CopyOptions {
        overwrite: true,
        attributes_only: true,
        ..CopyOptions::default()
    };
    cpcopy::copy(&source, &destination, &options).unwrap();
    assert_eq!(
        fs::metadata(&destination).unwrap().modified().unwrap(),
        fs::metadata(&source).unwrap().modified().unwrap()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"keep destination");
    let fresh = tree.path().join("fresh");
    cpcopy::copy(&source, &fresh, &options).unwrap();
    assert_eq!(fs::metadata(fresh).unwrap().len(), 0);
}

#[test]
fn exclusion_patterns_create_only_selected_entries() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("parent/source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"keep").unwrap();
    fs::write(source.join("skip.tmp"), b"exclude").unwrap();
    fs::create_dir(source.join("skip-directory")).unwrap();
    fs::write(source.join("skip-directory/child"), b"exclude tree").unwrap();
    let destination = tree.path().join("target/source");
    fs::create_dir(tree.path().join("target")).unwrap();
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            exclusions: vec!["*.tmp".into(), "skip-*".into()],
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(destination.join("keep.txt")).unwrap(), b"keep");
    assert!(!destination.join("skip.tmp").exists());
    assert!(!destination.join("skip-directory").exists());
}

#[test]
fn progress_callback_failure_stops_before_other_files_are_copied() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("first"), b"first").unwrap();
    fs::write(source.join("second"), b"second").unwrap();
    let mut completed = 0;
    let result = cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions::default(),
        &mut |event| {
            if event.kind == EventKind::Completed {
                completed += 1;
                anyhow::bail!("test requested stop");
            }
            Ok(())
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("test requested stop")
    );
    assert_eq!(completed, 1);
    assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
}

#[test]
fn automatic_reflink_falls_back_and_required_reflink_never_reports_false_success() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::write(&source, b"reflink data").unwrap();
    let automatic = tree.path().join("automatic");
    cpcopy::copy(
        &source,
        &automatic,
        &CopyOptions {
            reflink: ReflinkMode::Auto,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(automatic).unwrap(), b"reflink data");
    let required = tree.path().join("required");
    let mut events = Vec::new();
    let result = cpcopy::copy_with_events(
        &source,
        &required,
        &CopyOptions {
            reflink: ReflinkMode::Always,
            ..CopyOptions::default()
        },
        &mut |event| {
            events.push(event.kind);
            Ok(())
        },
    );
    match result {
        Ok(()) => {
            assert_eq!(fs::read(&required).unwrap(), b"reflink data");
            assert_ne!(identity(&source), identity(&required));
        }
        Err(_) => {
            assert!(
                !required.exists(),
                "unsupported cloning must not publish a fresh destination"
            );
            assert!(!events.contains(&EventKind::Done));
        }
    }
}

#[test]
fn sparse_source_logical_contents_and_length_are_preserved() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let mut file = File::create(&source).unwrap();
    file.write_all(b"head").unwrap();
    file.seek(SeekFrom::Start(4 * 1024 * 1024)).unwrap();
    file.write_all(b"tail").unwrap();
    drop(file);
    let destination = tree.path().join("destination");
    cpcopy::copy(&source, &destination, &CopyOptions::default()).unwrap();
    assert_eq!(
        fs::metadata(&destination).unwrap().len(),
        4 * 1024 * 1024 + 4
    );
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
}

#[test]
#[ignore = "requires Windows symlink privilege or Developer Mode"]
fn native_symlinks_preserve_links_and_follow_selected_operands() {
    let tree = tempfile::tempdir().unwrap();
    let file = tree.path().join("file");
    fs::write(&file, b"referent").unwrap();
    let link = tree.path().join("link");
    symlink_file("file", &link).unwrap();
    let copied = tree.path().join("copied");
    cpcopy::copy(&link, &copied, &CopyOptions::default()).unwrap();
    assert_eq!(fs::read_link(&copied).unwrap(), Path::new("file"));
    let followed = tree.path().join("followed");
    cpcopy::copy(
        &link,
        &followed,
        &CopyOptions {
            dereference: Dereference::CommandLine,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert!(
        !fs::symlink_metadata(&followed)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(followed).unwrap(), b"referent");
    let directory = tree.path().join("directory");
    fs::create_dir(&directory).unwrap();
    symlink_file("../file", directory.join("nested")).unwrap();
    let top = tree.path().join("top");
    symlink_dir("directory", &top).unwrap();
    let target = tree.path().join("target");
    cpcopy::copy(
        &top,
        &target,
        &CopyOptions {
            dereference: Dereference::CommandLine,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert!(
        fs::symlink_metadata(target.join("nested"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
#[ignore = "requires Windows directory symlink privilege or Developer Mode"]
fn followed_directory_symlink_cycle_returns_error_without_unbounded_recursion() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("payload"), b"retain source").unwrap();
    symlink_dir(".", source.join("cycle")).unwrap();
    assert!(
        cpcopy::copy(
            &source,
            &tree.path().join("destination"),
            &CopyOptions {
                dereference: Dereference::Always,
                ..CopyOptions::default()
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(source.join("payload")).unwrap(), b"retain source");
}

#[cfg(feature = "cli")]
fn executable() -> OsString {
    std::env::var_os("CPCOPY_BINARY").unwrap_or_else(|| env!("CARGO_BIN_EXE_cpcopy").into())
}

#[cfg(feature = "cli")]
#[test]
fn cli_archive_copies_multiple_sources_and_preserves_native_utf16_progress() {
    use std::{os::windows::ffi::OsStrExt, process::Command};
    let tree = tempfile::tempdir().unwrap();
    let name = OsString::from_wide(&[0x0066, 0xD800, 0x0069, 0x006C, 0x0065]);
    let source = tree.path().join(&name);
    fs::write(&source, b"first").unwrap();
    fs::write(tree.path().join("second"), b"second").unwrap();
    fs::create_dir(tree.path().join("target")).unwrap();
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["-a", "--progress", "--"])
        .arg(&name)
        .args(["second", "target"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(tree.path().join("target").join(&name)).unwrap(),
        b"first"
    );
    assert_eq!(
        fs::read(tree.path().join("target/second")).unwrap(),
        b"second"
    );
    let events = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let native = name.encode_wide().map(u64::from).collect::<Vec<_>>();
    assert!(
        events.iter().any(|event| {
            event["source_utf16"].as_array().is_some_and(|units| {
                units
                    .iter()
                    .map(|unit| unit.as_u64().unwrap())
                    .collect::<Vec<_>>()
                    .ends_with(&native)
            })
        }),
        "native UTF16 progress missing: {events:?}"
    );
}

#[cfg(feature = "cli")]
#[test]
fn cli_parents_maps_relative_source_under_existing_target() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    fs::create_dir_all(tree.path().join("parent/sub")).unwrap();
    fs::write(tree.path().join("parent/sub/source"), b"parents").unwrap();
    fs::create_dir(tree.path().join("target")).unwrap();
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["--parents", "parent/sub/source", "target"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(tree.path().join("target/parent/sub/source")).unwrap(),
        b"parents"
    );
}

#[test]
fn force_and_remove_destination_preserve_readonly_hardlink_alias_and_publish_new_inode() {
    for remove_destination in [false, true] {
        let tree = tempfile::tempdir().unwrap();
        let source = tree.path().join("source");
        let destination = tree.path().join("destination");
        let alias = tree.path().join("alias");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"retained alias").unwrap();
        fs::hard_link(&destination, &alias).unwrap();
        let original = identity(&alias);
        let mut permissions = fs::metadata(&destination).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&destination, permissions).unwrap();
        let result = cpcopy::copy(
            &source,
            &destination,
            &CopyOptions {
                overwrite: true,
                force: true,
                remove_destination,
                ..CopyOptions::default()
            },
        );
        assert!(
            fs::metadata(&alias).unwrap().permissions().readonly(),
            "removing one name changed the shared inode readonly attribute"
        );
        assert_eq!(fs::read(&alias).unwrap(), b"retained alias");
        writable(&alias);
        result.unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert_eq!(identity(&alias), original);
        assert_ne!(identity(&destination), original);
    }
}

#[cfg(feature = "cli")]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetNamedSecurityInfoW(
        name: *const u16,
        object: i32,
        information: u32,
        owner: *mut *mut std::ffi::c_void,
        group: *mut *mut std::ffi::c_void,
        dacl: *mut *mut std::ffi::c_void,
        sacl: *mut *mut std::ffi::c_void,
        descriptor: *mut *mut std::ffi::c_void,
    ) -> u32;
    fn GetLengthSid(sid: *const std::ffi::c_void) -> u32;
    fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut std::ffi::c_void) -> i32;
    fn SetNamedSecurityInfoW(
        name: *const u16,
        object: i32,
        information: u32,
        owner: *const std::ffi::c_void,
        group: *const std::ffi::c_void,
        dacl: *const std::ffi::c_void,
        sacl: *const std::ffi::c_void,
    ) -> u32;
}
#[cfg(feature = "cli")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}
#[cfg(feature = "cli")]
fn owner_and_group(path: &Path) -> (Vec<u8>, Vec<u8>) {
    use std::os::windows::ffi::OsStrExt;
    let name = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut owner = std::ptr::null_mut();
    let mut group = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: Terminated name and writable output pointers; the allocated descriptor owns both SIDs.
    assert_eq!(
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                3,
                &mut owner,
                &mut group,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    // SAFETY: Successful API returned valid SIDs inside the still-live security descriptor.
    let result = unsafe {
        (
            std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize).to_vec(),
            std::slice::from_raw_parts(group.cast::<u8>(), GetLengthSid(group) as usize).to_vec(),
        )
    };
    // SAFETY: Descriptor was allocated with LocalAlloc by GetNamedSecurityInfoW.
    unsafe { LocalFree(descriptor) };
    result
}

#[cfg(feature = "cli")]
#[test]
#[ignore = "requires Windows privilege to assign the Administrators primary-group SID"]
fn cli_preserve_basic_copies_changed_primary_group_and_native_metadata() {
    use std::{os::windows::ffi::OsStrExt, process::Command};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::write(&source, b"security metadata").unwrap();
    set_modified(&source, 1_600_000_000);
    let initial = owner_and_group(&source);
    let text = "S-1-5-32-544"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut sid = std::ptr::null_mut();
    // SAFETY: Terminated SID string and writable output pointer.
    assert_ne!(
        unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) },
        0
    );
    let name = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: Terminated file path and allocated valid group SID, no other descriptor components requested.
    let result = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            1,
            2,
            std::ptr::null(),
            sid,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    // SAFETY: SID was allocated by ConvertStringSidToSidW.
    unsafe { LocalFree(sid) };
    assert_eq!(result, 0, "fixture requires group-assignment privilege");
    let expected = owner_and_group(&source);
    assert_ne!(
        initial.1, expected.1,
        "fixture must change the primary-group SID"
    );
    let mut permissions = fs::metadata(&source).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&source, permissions).unwrap();
    for option in ["-p", "-a"] {
        let destination = tree.path().join(format!("target{option}"));
        let output = Command::new(executable())
            .arg(option)
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{option}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(owner_and_group(&destination), expected);
        assert!(fs::metadata(&destination).unwrap().permissions().readonly());
        assert_eq!(
            fs::metadata(&destination).unwrap().modified().unwrap(),
            fs::metadata(&source).unwrap().modified().unwrap()
        );
        writable(&destination);
    }
    writable(&source);
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCompressedFileSizeW(name: *const u16, high: *mut u32) -> u32;
}
#[test]
fn sparse_always_creates_real_ntfs_holes_without_changing_logical_contents() {
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let mut payload = vec![0; 4 * 1024 * 1024];
    payload[..4].copy_from_slice(b"head");
    payload[4 * 1024 * 1024 - 4..].copy_from_slice(b"tail");
    fs::write(&source, &payload).unwrap();
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            sparse: cpcopy::SparseMode::Always,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_ne!(
        fs::metadata(&destination).unwrap().file_attributes() & 0x200,
        0,
        "destination lacks FILE_ATTRIBUTE_SPARSE_FILE"
    );
    let name = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut high = 0;
    // SAFETY: Terminated existing file path and writable allocation-size output.
    let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
    assert_ne!(low, u32::MAX);
    let allocated = (u64::from(high) << 32) | u64::from(low);
    assert!(
        allocated < payload.len() as u64 / 2,
        "sparse copy allocated {allocated} bytes"
    );
    assert_eq!(fs::read(&destination).unwrap(), payload);
}

#[cfg(feature = "cli")]
#[test]
fn cli_missing_native_source_reports_path_and_continues_later_operands() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    let missing = "missing-é-資料";
    fs::write(tree.path().join("healthy"), b"later operand").unwrap();
    fs::create_dir(tree.path().join("target")).unwrap();
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["--", missing, "healthy", "target"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!("cannot stat '{missing}':")),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert_eq!(
        fs::read(tree.path().join("target/healthy")).unwrap(),
        b"later operand"
    );
    assert!(!tree.path().join("target").join(missing).exists());
}

#[cfg(feature = "cli")]
#[test]
fn cli_rejects_copying_directory_into_descendant_before_creating_entries() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    fs::create_dir(tree.path().join("source")).unwrap();
    fs::write(tree.path().join("source/original"), b"preserve source").unwrap();
    let original_identity = identity(&tree.path().join("source/original"));
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["-RT", "source", "source/nested"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot copy a directory, 'source', into itself, 'source/nested'"),
        "{stderr}"
    );
    assert!(!tree.path().join("source/nested").exists());
    assert_eq!(
        identity(&tree.path().join("source/original")),
        original_identity
    );
    assert_eq!(
        fs::read(tree.path().join("source/original")).unwrap(),
        b"preserve source"
    );
    assert_eq!(fs::read_dir(tree.path().join("source")).unwrap().count(), 1);
}

#[cfg(feature = "cli")]
#[test]
fn cli_missing_destination_parent_reports_path_without_creating_partial_directories() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    fs::write(tree.path().join("source"), b"preserve payload").unwrap();
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["source", "missing-parent/destination"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot create regular file 'missing-parent/destination':"),
        "{stderr}"
    );
    assert!(!tree.path().join("missing-parent").exists());
    assert_eq!(
        fs::read(tree.path().join("source")).unwrap(),
        b"preserve payload"
    );
}

#[cfg(feature = "cli")]
#[test]
fn cli_extended_attributes_and_archive_copy_data_without_warning() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    fs::write(tree.path().join("source"), b"metadata failure payload").unwrap();
    let required = Command::new(executable())
        .current_dir(tree.path())
        .args(["--preserve=xattr", "source", "required"])
        .output()
        .unwrap();
    assert!(
        required.status.success(),
        "{}",
        String::from_utf8_lossy(&required.stderr)
    );
    assert!(required.stderr.is_empty());
    assert_eq!(
        fs::read(tree.path().join("required")).unwrap(),
        b"metadata failure payload"
    );
    let archive = Command::new(executable())
        .current_dir(tree.path())
        .args(["-a", "source", "archive"])
        .output()
        .unwrap();
    assert!(
        archive.status.success(),
        "{}",
        String::from_utf8_lossy(&archive.stderr)
    );
    assert!(
        archive.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&archive.stderr)
    );
    assert_eq!(
        fs::read(tree.path().join("archive")).unwrap(),
        b"metadata failure payload"
    );
}

#[cfg(feature = "cli")]
#[test]
fn cli_readonly_destination_failure_retains_contents_attributes_and_identity() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    let destination = tree.path().join("destination");
    fs::write(tree.path().join("source"), b"new data").unwrap();
    fs::write(&destination, b"old data").unwrap();
    let original_identity = identity(&destination);
    let mut permissions = fs::metadata(&destination).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&destination, permissions).unwrap();
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["source", "destination"])
        .output()
        .unwrap();
    let unchanged_contents = fs::read(&destination).unwrap();
    let unchanged_identity = identity(&destination);
    let unchanged_readonly = fs::metadata(&destination).unwrap().permissions().readonly();
    // Clean up the fixture even when an assertion fails.
    writable(&destination);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot create regular file 'destination':"),
        "{stderr}"
    );
    assert_eq!(unchanged_contents, b"old data");
    assert_eq!(unchanged_identity, original_identity);
    assert!(unchanged_readonly);
    assert_eq!(fs::read(tree.path().join("source")).unwrap(), b"new data");
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DeviceIoControl(
        handle: *mut std::ffi::c_void,
        code: u32,
        input: *const std::ffi::c_void,
        input_size: u32,
        output: *mut std::ffi::c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> i32;
}

#[test]
fn terabyte_sparse_source_copies_allocated_ranges_without_reading_holes() {
    use std::{
        io::Read,
        os::windows::{ffi::OsStrExt, fs::MetadataExt},
        time::Instant,
    };
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let mut file = File::create(&source).unwrap();
    let mut returned = 0;
    // SAFETY: Live writable handle, FSCTL_SET_SPARSE accepts an omitted input
    // to mark sparse; there is no output and returned is a valid writable pointer.
    assert_ne!(
        unsafe {
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
        },
        0,
        "cannot establish an independent sparse fixture: {}",
        std::io::Error::last_os_error()
    );
    let logical_size = 1_u64 << 40;
    file.set_len(logical_size).unwrap();
    file.write_all(b"head").unwrap();
    file.seek(SeekFrom::Start(logical_size - 4)).unwrap();
    file.write_all(b"tail").unwrap();
    drop(file);
    let start = Instant::now();
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "sparse copy read holes instead of skipping allocated ranges: {:?}",
        start.elapsed()
    );
    let metadata = fs::metadata(&destination).unwrap();
    assert_eq!(metadata.len(), logical_size);
    assert_ne!(
        metadata.file_attributes() & 0x200,
        0,
        "destination is not sparse"
    );
    let name = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut high = 0;
    // SAFETY: Terminated native path and initialized writable allocation output.
    let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
    assert_ne!(low, u32::MAX);
    let allocated = (u64::from(high) << 32) | u64::from(low);
    assert!(
        allocated <= 1024 * 1024,
        "sparse destination allocated {allocated} bytes"
    );
    let mut copied = File::open(&destination).unwrap();
    let mut marker = [0; 4];
    copied.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"head");
    copied.seek(SeekFrom::Start(logical_size / 2)).unwrap();
    let mut hole = [1; 4096];
    copied.read_exact(&mut hole).unwrap();
    assert_eq!(hole, [0; 4096]);
    copied.seek(SeekFrom::Start(logical_size - 4)).unwrap();
    copied.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"tail");
}

#[cfg(feature = "cli")]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut std::ffi::c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *const std::ffi::c_void,
        present: *mut i32,
        dacl: *mut *mut std::ffi::c_void,
        defaulted: *mut i32,
    ) -> i32;
}

#[cfg(feature = "cli")]
#[test]
fn cli_denied_source_access_reports_native_path_and_retains_existing_destination() {
    use std::{os::windows::ffi::OsStrExt, process::Command};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::write(&source, b"unreadable source").unwrap();
    fs::write(&destination, b"keep destination").unwrap();
    let destination_identity = identity(&destination);
    let name = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut original_dacl = std::ptr::null_mut();
    let mut original_descriptor = std::ptr::null_mut();
    // SAFETY: Terminated fixture path and writable outputs; the descriptor owns DACL memory.
    assert_eq!(
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                4,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut original_dacl,
                std::ptr::null_mut(),
                &mut original_descriptor,
            )
        },
        0
    );
    // Deny read to Everyone (including SYSTEM), while retaining rights needed to
    // restore this disposable fixture. No token privilege is enabled by the test.
    let sddl = "D:P(D;;GR;;;WD)(A;;FA;;;WD)"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut denied_descriptor = std::ptr::null_mut();
    // SAFETY: Terminated SDDL and a writable descriptor output; revision 1 is supported.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut denied_descriptor,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut denied_dacl = std::ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: Successfully constructed descriptor and writable DACL outputs.
    assert_ne!(
        unsafe {
            GetSecurityDescriptorDacl(
                denied_descriptor,
                &mut present,
                &mut denied_dacl,
                &mut defaulted,
            )
        },
        0
    );
    assert_ne!(present, 0);
    // SAFETY: Fixture-owned path and live DACL. PROTECTED_DACL prevents inherited
    // permissions from changing the explicit denial during this test.
    assert_eq!(
        unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                0x80000004,
                std::ptr::null(),
                std::ptr::null(),
                denied_dacl,
                std::ptr::null(),
            )
        },
        0
    );
    let fixture_denial = File::open(&source)
        .err()
        .and_then(|error| error.raw_os_error());
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args(["source", "destination"])
        .output();
    // Restore before assertions, including after a CLI launch failure.
    // SAFETY: Original descriptor retained throughout, fixture owner can restore its DACL.
    let restored = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            1,
            0x80000004,
            std::ptr::null(),
            std::ptr::null(),
            original_dacl,
            std::ptr::null(),
        )
    };
    // SAFETY: Both descriptors were allocated by the Windows security APIs.
    unsafe {
        LocalFree(original_descriptor);
        LocalFree(denied_descriptor);
    }
    assert_eq!(restored, 0);
    assert_eq!(
        fixture_denial,
        Some(5),
        "fixture must independently establish ERROR_ACCESS_DENIED"
    );
    let output = output.unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("'source'")
            && (stderr.contains("cannot stat") || stderr.contains("cannot open")),
        "{stderr}"
    );
    assert_eq!(fs::read(&source).unwrap(), b"unreadable source");
    assert_eq!(fs::read(&destination).unwrap(), b"keep destination");
    assert_eq!(identity(&destination), destination_identity);
}

#[cfg(feature = "cli")]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityDescriptorControl(
        descriptor: *const std::ffi::c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
}

#[cfg(feature = "cli")]
fn set_protected_test_dacl(path: &Path, sddl: &str) {
    use std::os::windows::ffi::OsStrExt;
    let name = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let text = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: Terminated SDDL and writable allocated-descriptor output.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut dacl = std::ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: Valid constructed security descriptor and initialized output pointers.
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    // SAFETY: Owned fixture path and live ACL; protect it against parent inheritance.
    let result = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            1,
            0x80000004,
            std::ptr::null(),
            std::ptr::null(),
            dacl,
            std::ptr::null(),
        )
    };
    // SAFETY: SDDL conversion allocated this descriptor using LocalAlloc.
    unsafe {
        LocalFree(descriptor);
    }
    assert_eq!(result, 0);
}

#[cfg(feature = "cli")]
fn protected_dacl_and_aces(path: &Path) -> (bool, Vec<u8>) {
    use std::os::windows::ffi::OsStrExt;
    let name = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: Native terminated path and initialized writable ACL/descriptor outputs.
    assert_eq!(
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                4,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    assert!(!dacl.is_null());
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: Successfully queried security descriptor and valid control/revision outputs.
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        0
    );
    // SAFETY: A valid Windows ACL begins with its 8-byte ACL header. ACLSize is
    // a 16-bit field at offset 2 and bounds its header and all ACE entries.
    let bytes = unsafe {
        let header = std::slice::from_raw_parts(dacl.cast::<u8>(), 8);
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        assert!(size >= 8);
        std::slice::from_raw_parts(dacl.cast::<u8>(), size).to_vec()
    };
    // SAFETY: GetNamedSecurityInfoW allocated the descriptor via LocalAlloc.
    unsafe {
        LocalFree(descriptor);
    }
    (control & 0x1000 != 0, bytes)
}

#[cfg(feature = "cli")]
#[test]
fn protected_source_dacl_is_preserved_without_inheriting_destination_parent_aces() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let target = tree.path().join("target");
    fs::write(&source, b"protected DACL payload").unwrap();
    fs::create_dir(&target).unwrap();
    // SYSTEM remains fully permitted. Everyone can read the copied file, and
    // target-parent full control permits fixture cleanup for ordinary users.
    set_protected_test_dacl(&source, "D:P(A;;FA;;;SY)(A;;FR;;;WD)");
    set_protected_test_dacl(&target, "D:P(A;OICI;FA;;;WD)");
    let original = protected_dacl_and_aces(&source);
    assert!(
        original.0,
        "source protection must be independently established"
    );
    let destination = target.join("destination");
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    let copied = protected_dacl_and_aces(&destination);
    assert!(copied.0, "copied DACL must retain SE_DACL_PROTECTED");
    assert_eq!(
        copied.1, original.1,
        "destination parent ACEs must not broaden source permissions"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"protected DACL payload");
}

#[test]
fn dense_large_copy_preserves_odd_tail_progress_and_existing_inode_alias() {
    use cpcopy::SparseMode;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let alias = tree.path().join("alias");
    // Every byte is nonzero, so sparse-auto must preserve a dense transfer,
    // including a tail that is not aligned to any supported buffer size.
    let payload = (0..8 * 1024 * 1024 + 123)
        .map(|index| (index % 251 + 1) as u8)
        .collect::<Vec<_>>();
    fs::write(&source, &payload).unwrap();
    fs::write(&destination, vec![0; payload.len() + 4096]).unwrap();
    fs::hard_link(&destination, &alias).unwrap();
    let original_identity = identity(&destination);
    let mut events = Vec::new();
    cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions {
            overwrite: true,
            reflink: ReflinkMode::Auto,
            sparse: SparseMode::Auto,
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
        &mut |event| {
            events.push(event.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(identity(&destination), original_identity);
    assert_eq!(identity(&alias), original_identity);
    assert_eq!(fs::read(&destination).unwrap(), payload);
    assert_eq!(fs::read(&alias).unwrap(), payload);
    let completed = events
        .iter()
        .filter(|event| event.kind == EventKind::Completed)
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].bytes, payload.len() as u64);
    assert_eq!(completed[0].copied_bytes, payload.len() as u64);
    assert_eq!(completed[0].completed, 1);
    let summary = events.last().unwrap();
    assert_eq!(summary.kind, EventKind::Done);
    assert_eq!(summary.copied_bytes, payload.len() as u64);
}

#[cfg(feature = "cli")]
#[test]
fn cli_small_explicit_buffer_preserves_large_dense_odd_tail_and_reports_exact_bytes() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    let payload = (0..8 * 1024 * 1024 + 123)
        .map(|index| (index % 253 + 1) as u8)
        .collect::<Vec<_>>();
    fs::write(tree.path().join("source"), &payload).unwrap();
    let output = Command::new(executable())
        .current_dir(tree.path())
        .args([
            "--buffer-size=4096",
            "--reflink=never",
            "--progress",
            "source",
            "destination",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(tree.path().join("destination")).unwrap(), payload);
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let completed = events
        .iter()
        .filter(|event| event["event"] == "completed")
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0]["bytes"].as_u64(), Some(payload.len() as u64));
    assert_eq!(
        completed[0]["copied_bytes"].as_u64(),
        Some(payload.len() as u64)
    );
    assert_eq!(events.last().unwrap()["event"], "done");
    assert_eq!(
        events.last().unwrap()["copied_bytes"].as_u64(),
        Some(payload.len() as u64)
    );
}

#[test]
fn sparse_always_large_copy_retains_holes_across_dense_transfer_threshold() {
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let mut payload = vec![0; 8 * 1024 * 1024 + 123];
    payload[..4].copy_from_slice(b"head");
    let tail = payload.len() - 4;
    payload[tail..].copy_from_slice(b"tail");
    fs::write(&source, &payload).unwrap();
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            sparse: cpcopy::SparseMode::Always,
            reflink: ReflinkMode::Never,
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), payload);
    assert_eq!(
        fs::metadata(&destination).unwrap().len(),
        payload.len() as u64
    );
    assert_ne!(
        fs::metadata(&destination).unwrap().file_attributes() & 0x200,
        0
    );
    let name = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut high = 0;
    // SAFETY: Terminated existing native path and writable allocation-size output.
    let low = unsafe { GetCompressedFileSizeW(name.as_ptr(), &mut high) };
    assert_ne!(low, u32::MAX);
    let allocated = (u64::from(high) << 32) | u64::from(low);
    assert!(
        allocated < 1024 * 1024,
        "large sparse-always copy allocated {allocated} bytes"
    );
}

#[test]
fn jobs_four_preserves_tree_native_names_postorder_and_callback_input_order() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::create_dir_all(source.join("nested")).unwrap();
    let large = (0..8 * 1024 * 1024 + 123)
        .map(|index| (index % 251 + 1) as u8)
        .collect::<Vec<_>>();
    for name in ["large-a", "large-b", "large-c", "large-d"] {
        fs::write(source.join(name), &large).unwrap();
    }
    for index in 0..64 {
        fs::write(
            source.join(format!("tiny-{index:03}")),
            format!("tiny payload {index}"),
        )
        .unwrap();
    }
    let native = OsString::from_wide(&[0x006e, 0xd800, 0x0061]);
    fs::write(source.join(&native), b"native payload").unwrap();
    fs::write(source.join("nested/child"), b"nested payload").unwrap();
    let expected_order = fs::read_dir(&source)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    let caller = std::thread::current().id();
    let mut events = Vec::new();
    cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
        &mut |event| {
            assert_eq!(
                std::thread::current().id(),
                caller,
                "callbacks must remain on the caller thread"
            );
            events.push(event.clone());
            Ok(())
        },
    )
    .unwrap();
    for name in ["large-a", "large-b", "large-c", "large-d"] {
        assert_eq!(fs::read(destination.join(name)).unwrap(), large);
    }
    for index in 0..64 {
        assert_eq!(
            fs::read(destination.join(format!("tiny-{index:03}"))).unwrap(),
            format!("tiny payload {index}").as_bytes()
        );
    }
    assert_eq!(
        fs::read(destination.join(&native)).unwrap(),
        b"native payload"
    );
    assert_eq!(
        fs::read(destination.join("nested/child")).unwrap(),
        b"nested payload"
    );
    let completions = events
        .iter()
        .filter(|event| event.kind == EventKind::Completed)
        .collect::<Vec<_>>();
    let regular_order = completions
        .iter()
        .filter(|event| event.source.parent() == Some(source.as_path()) && event.source.is_file())
        .map(|event| event.source.clone())
        .collect::<Vec<_>>();
    assert_eq!(regular_order, expected_order);
    let child = completions
        .iter()
        .position(|event| event.source == source.join("nested/child"))
        .unwrap();
    let parent = completions
        .iter()
        .position(|event| event.source == source.join("nested"))
        .unwrap();
    let root = completions
        .iter()
        .position(|event| event.source == source)
        .unwrap();
    assert!(child < parent && parent < root);
    assert_eq!(events.last().unwrap().kind, EventKind::Done);
    let sum = completions.iter().map(|event| event.bytes).sum::<u64>();
    assert_eq!(events.last().unwrap().copied_bytes, sum);
}

#[test]
fn jobs_four_preserves_hardlink_anchors_and_existing_destination_aliases() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("anchor"), b"shared payload").unwrap();
    fs::hard_link(source.join("anchor"), source.join("linked")).unwrap();
    let destination = tree.path().join("destination");
    cpcopy::copy(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            preserve_links: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(
        identity(&destination.join("anchor")),
        identity(&destination.join("linked"))
    );
    assert_eq!(
        fs::read(destination.join("linked")).unwrap(),
        b"shared payload"
    );
    let overwrite_directory = tree.path().join("overwrite");
    fs::create_dir(&overwrite_directory).unwrap();
    let overwrite = overwrite_directory.join("anchor");
    let alias = tree.path().join("alias");
    fs::write(&overwrite, b"older contents with a long tail").unwrap();
    fs::hard_link(&overwrite, &alias).unwrap();
    let original_identity = identity(&overwrite);
    cpcopy::copy(
        &source,
        &overwrite_directory,
        &CopyOptions {
            jobs: 4,
            overwrite: true,
            merge_directories: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(identity(&overwrite), original_identity);
    assert_eq!(identity(&alias), original_identity);
    assert_eq!(fs::read(alias).unwrap(), b"shared payload");
}

#[test]
fn jobs_four_callback_abort_limits_submitted_work_and_never_reports_done() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::create_dir(&source).unwrap();
    for index in 0..20 {
        fs::write(source.join(format!("file-{index:03}")), b"payload").unwrap();
    }
    let mut kinds = Vec::new();
    let mut completed = 0;
    let result = cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
        &mut |event| {
            kinds.push(event.kind);
            if event.kind == EventKind::Completed {
                completed += 1;
                anyhow::bail!("callback requested abort");
            }
            Ok(())
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("callback requested abort")
    );
    assert_eq!(completed, 1);
    assert!(!kinds.contains(&EventKind::Done));
    assert!(
        fs::read_dir(destination).unwrap().count() <= 8,
        "an abort must not submit unbounded later work"
    );
}

#[test]
fn jobs_four_continues_other_files_after_readonly_destination_error() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&destination).unwrap();
    for name in ["bad", "healthy-a", "healthy-b"] {
        fs::write(source.join(name), name.as_bytes()).unwrap();
    }
    let bad = destination.join("bad");
    fs::write(&bad, b"retained").unwrap();
    let original_identity = identity(&bad);
    let mut permissions = fs::metadata(&bad).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&bad, permissions).unwrap();
    let mut kinds = Vec::new();
    let result = cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            overwrite: true,
            merge_directories: true,
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
        &mut |event| {
            kinds.push(event.kind);
            Ok(())
        },
    );
    let bad_data = fs::read(&bad).unwrap();
    let bad_identity = identity(&bad);
    writable(&bad);
    assert!(result.is_err());
    assert_eq!(bad_data, b"retained");
    assert_eq!(bad_identity, original_identity);
    for name in ["healthy-a", "healthy-b"] {
        assert_eq!(fs::read(destination.join(name)).unwrap(), name.as_bytes());
    }
    assert!(!kinds.contains(&EventKind::Done));
    assert_eq!(kinds.last(), Some(&EventKind::Failed));
}

#[test]
fn invalid_jobs_are_rejected_before_creating_destination_or_emitting_events() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::write(&source, b"payload").unwrap();
    for jobs in [0, 65] {
        let mut events = Vec::new();
        let result = cpcopy::copy_with_events(
            &source,
            &destination,
            &CopyOptions {
                jobs,
                ..CopyOptions::default()
            },
            &mut |event| {
                events.push(event.clone());
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!destination.exists());
        assert!(events.is_empty());
    }
}

#[test]
fn jobs_four_stop_on_error_aborts_after_first_serial_destination_failure() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&destination).unwrap();
    for index in 0..12 {
        fs::write(source.join(format!("file-{index:03}")), b"new payload").unwrap();
    }
    // Select the first entry in native enumeration order; an existing target
    // forms a serial barrier before any later fresh-file work is submitted.
    let first = fs::read_dir(&source)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let bad = destination.join(&first);
    fs::write(&bad, b"retained data").unwrap();
    let mut permissions = fs::metadata(&bad).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&bad, permissions).unwrap();
    let mut kinds = Vec::new();
    let result = cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            stop_on_error: true,
            overwrite: true,
            merge_directories: true,
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
        &mut |event| {
            kinds.push(event.kind);
            Ok(())
        },
    );
    let retained = fs::read(&bad).unwrap();
    writable(&bad);
    assert!(result.is_err());
    assert_eq!(retained, b"retained data");
    assert!(!kinds.contains(&EventKind::Done));
    assert_eq!(
        fs::read_dir(destination).unwrap().count(),
        1,
        "stop-on-error must not dispatch later entries beyond a failing serial barrier"
    );
}

#[test]
fn jobs_four_cooperative_cancellation_has_bounded_work_and_no_success_summary() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    fs::create_dir(&source).unwrap();
    for index in 0..32 {
        fs::write(
            source.join(format!("file-{index:03}")),
            b"cancellable payload",
        )
        .unwrap();
    }
    let cancellation = cpcopy::Cancellation::default();
    let mut kinds = Vec::new();
    let result = cpcopy::copy_with_events(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            cancellation: cancellation.clone(),
            preserve_mode: false,
            preserve_timestamps: false,
            ..CopyOptions::default()
        },
        &mut |event| {
            kinds.push(event.kind);
            if event.kind == EventKind::Completed {
                cancellation.cancel();
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(cancellation.check().is_err());
    assert!(!kinds.contains(&EventKind::Done));
    assert!(
        fs::read_dir(destination).unwrap().count() <= 8,
        "cancellation must prevent submitting work beyond the bounded worker window"
    );
}

#[cfg(feature = "cli")]
#[test]
fn cli_jobs_rejects_zero_and_archive_jobs_four_preserves_hardlink_relationship() {
    use std::process::Command;
    let tree = tempfile::tempdir().unwrap();
    fs::create_dir(tree.path().join("source")).unwrap();
    fs::write(
        tree.path().join("source/anchor"),
        b"hardlinked archive payload",
    )
    .unwrap();
    fs::hard_link(
        tree.path().join("source/anchor"),
        tree.path().join("source/linked"),
    )
    .unwrap();
    let invalid = Command::new(executable())
        .current_dir(tree.path())
        .args(["--jobs=0", "source/anchor", "invalid"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("jobs"));
    assert!(!tree.path().join("invalid").exists());
    let copied = Command::new(executable())
        .current_dir(tree.path())
        .args(["--jobs=4", "-a", "source", "destination"])
        .output()
        .unwrap();
    assert!(
        copied.status.success(),
        "{}",
        String::from_utf8_lossy(&copied.stderr)
    );
    assert_eq!(
        identity(&tree.path().join("destination/anchor")),
        identity(&tree.path().join("destination/linked"))
    );
    assert_eq!(
        fs::read(tree.path().join("destination/linked")).unwrap(),
        b"hardlinked archive payload"
    );
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileInformationByHandle(
        handle: *mut std::ffi::c_void,
        class: u32,
        information: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        handle: *mut std::ffi::c_void,
        class: u32,
        information: *mut std::ffi::c_void,
        size: u32,
    ) -> i32;
}

#[test]
#[ignore = "requires elevated NTFS directory case-sensitivity support"]
fn jobs_four_matches_serial_copy_when_case_sensitive_source_names_collide_at_destination() {
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::create_dir(&source).unwrap();
    let directory = OpenOptions::new()
        .access_mode(0x180)
        .custom_flags(0x02000000)
        .open(&source)
        .unwrap();
    let flags = 1_u32;
    // SAFETY: Live directory attribute-write handle and FILE_CASE_SENSITIVE_INFO
    // layout; class 23 enables per-directory NTFS case sensitivity.
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                directory.as_raw_handle(),
                23,
                (&flags as *const u32).cast(),
                4,
            )
        },
        0,
        "NTFS case-sensitive fixture unsupported: {}",
        std::io::Error::last_os_error()
    );
    drop(directory);
    fs::write(source.join("A"), b"upper payload").unwrap();
    fs::write(source.join("a"), b"lower payload").unwrap();
    assert_ne!(
        identity(&source.join("A")),
        identity(&source.join("a")),
        "fixture must have independent source files"
    );
    let run = |jobs| {
        let destination = tree.path().join(format!("destination-{jobs}"));
        let mut events = Vec::new();
        let result = cpcopy::copy_with_events(
            &source,
            &destination,
            &CopyOptions {
                jobs,
                overwrite: true,
                preserve_mode: false,
                preserve_timestamps: false,
                ..CopyOptions::default()
            },
            &mut |event| {
                events.push((
                    event.kind,
                    event
                        .source
                        .strip_prefix(&source)
                        .unwrap()
                        .as_os_str()
                        .encode_wide()
                        .collect::<Vec<_>>(),
                    event
                        .destination
                        .strip_prefix(&destination)
                        .unwrap()
                        .as_os_str()
                        .encode_wide()
                        .collect::<Vec<_>>(),
                    event.bytes,
                    event.completed,
                    event.copied_bytes,
                ));
                Ok(())
            },
        );
        let directory = OpenOptions::new()
            .access_mode(0x80)
            .custom_flags(0x02000000)
            .open(&destination)
            .unwrap();
        let mut flags = 0_u32;
        // SAFETY: Live directory and writable FILE_CASE_SENSITIVE_INFO output.
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    directory.as_raw_handle(),
                    23,
                    (&mut flags as *mut u32).cast(),
                    4,
                )
            },
            0
        );
        assert_eq!(
            flags & 1,
            0,
            "destination must remain case-insensitive to establish collision"
        );
        let error = result.as_ref().err().map(|error| {
            format!("{error:#}").replace(&destination.display().to_string(), "<destination>")
        });
        let entries = fs::read_dir(&destination)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().encode_wide().collect::<Vec<_>>(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        (result.is_ok(), error, events, entries)
    };
    let serial = run(1);
    let parallel = run(4);
    assert!(
        serial.0,
        "serial baseline must handle overwrite collisions: {:?}",
        serial.1
    );
    assert_eq!(
        parallel, serial,
        "jobs must preserve serial collision outcome, events, and retained payload"
    );
    assert_eq!(parallel.3.len(), 1);
}
