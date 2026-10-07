#![cfg(all(target_os = "linux", feature = "cli"))]
use std::{
    ffi::{CString, OsString},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::Path,
    process::{Command, Output},
};

fn run(source: &Path, destination: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-R")
        .args(["--preserve=timestamps", "--buffer-size", "4096", "--"])
        .arg(source)
        .arg(destination)
        .output()
        .unwrap()
}

#[test]
#[cfg(feature = "live-progress")]
fn live_progress_redirected_output_finishes_and_json_mode_conflicts() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, vec![0x63; 1048576]).unwrap();
    let destination = tree.path().join("destination");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--live-progress", "--reflink=never"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stderr).unwrap();
    assert!(
        rendered.contains("finished:") && rendered.contains("100.0%"),
        "{rendered}"
    );
    assert!(!rendered.contains('\x1b'));
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        std::fs::read(&source).unwrap()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--live-progress", "--progress"])
        .arg(&source)
        .arg(tree.path().join("conflict"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!tree.path().join("conflict").exists());
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("--live-progress")
        .arg(tree.path().join("missing"))
        .arg(tree.path().join("failed"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let rendered = String::from_utf8(output.stderr).unwrap();
    assert!(
        rendered.contains("failed:") && !rendered.contains("finished:"),
        "{rendered}"
    );
}

#[test]
#[cfg(feature = "live-progress")]
fn broken_live_progress_output_does_not_fail_the_copy() {
    use std::process::Stdio;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let payload = vec![0x39; 1048576];
    std::fs::write(&source, &payload).unwrap();
    let destination = tree.path().join("destination");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("--live-progress")
        .arg(&source)
        .arg(&destination)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stderr.take());
    assert!(child.wait().unwrap().success());
    assert_eq!(std::fs::read(destination).unwrap(), payload);
}

#[test]
fn backup_accepts_unambiguous_mode_prefixes_and_short_suffix() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"new").unwrap();
    for (mode, name, backup) in [
        ("si", "simple", "simple.saved"),
        ("num", "numbered", "numbered.~1~"),
        ("ex", "existing", "existing.saved"),
    ] {
        let destination = tree.path().join(name);
        std::fs::write(&destination, b"old").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg(format!("--backup={mode}"))
            .args(["-S", ".saved"])
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(tree.path().join(backup)).unwrap(), b"old");
    }
    let destination = tree.path().join("ambiguous");
    std::fs::write(&destination, b"old").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("--backup=n")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(destination).unwrap(), b"old");

    let destination = tree.path().join("suffix_only");
    std::fs::write(&destination, b"old").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .env("VERSION_CONTROL", "si")
        .args(["-S", ".ignored", "--suffix=.saved"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(tree.path().join("suffix_only.saved")).unwrap(),
        b"old"
    );
}

#[test]
fn strip_trailing_slashes_preserves_source_symlink_and_leaves_destination_operand() {
    let tree = tempfile::tempdir().unwrap();
    let directory = tree.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    let source = tree.path().join("source");
    symlink("directory", &source).unwrap();
    let destination = tree.path().join("destination");
    std::fs::create_dir(&destination).unwrap();
    let mut slashed_source = source.as_os_str().to_os_string();
    slashed_source.push("///");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-a", "--strip-trailing-slashes"])
        .arg(&slashed_source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_link(destination.join("source")).unwrap(),
        Path::new("directory")
    );

    let exact_destination = tree.path().join("exact");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-aT", "--strip-trailing-slashes"])
        .arg(&slashed_source)
        .arg(&exact_destination)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(exact_destination.is_dir());
    assert!(!exact_destination.is_symlink());
}

#[test]
fn archive_allows_foreign_owner_on_symlink_and_parent_directory() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = tempfile::tempdir().unwrap();
    for args in [
        vec!["-a", "/proc/self"],
        vec!["-p", "--parents", "/proc/version"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .args(args)
            .arg(tree.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(tree.path().join("self").is_symlink());
    assert_eq!(
        std::fs::read(tree.path().join("proc/version")).unwrap(),
        std::fs::read("/proc/version").unwrap()
    );
}

#[test]
fn preserve_allows_unprivileged_foreign_owner_on_proc_file() {
    // procfs supplies a readable file owned outside this process's user ID.
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let uid = unsafe { libc::geteuid() };
    let source = Path::new("/proc/version");
    if uid == 0 || std::fs::metadata(source).unwrap().uid() == uid {
        return;
    }
    let tree = tempfile::tempdir().unwrap();
    let destination = tree.path().join("copy");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-p")
        .arg(source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(destination).unwrap(),
        std::fs::read(source).unwrap()
    );
}

#[test]
fn attributes_only_keeps_existing_data_and_creates_empty_new_file() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"source data").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
    for (name, contents) in [
        ("existing", b"retained".as_slice()),
        ("fresh", b"".as_slice()),
    ] {
        let destination = tree.path().join(name);
        if name == "existing" {
            std::fs::write(&destination, contents).unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .args(["--attributes-only", "--preserve=mode"])
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&destination).unwrap(), contents);
        assert_eq!(
            std::fs::metadata(destination).unwrap().mode() & 0o777,
            0o640
        );
    }
}

#[test]
fn no_preserve_mode_uses_default_permissions_instead_of_source_mode() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"payload").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new("sh")
        .args([
            "-c",
            "umask 022; exec \"$1\" --preserve=mode --no-preserve=mode \"$2\" \"$3\"",
            "sh",
            env!("CARGO_BIN_EXE_cpcopy"),
        ])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(destination).unwrap().mode() & 0o777,
        0o644
    );
}

#[test]
fn version_control_applies_to_implicit_backups_and_explicit_mode_overrides_it() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"new").unwrap();
    for (option, name, backup) in [
        ("-b", "short", "short.~1~"),
        ("--backup", "long", "long.~1~"),
        ("--backup=simple", "explicit", "explicit~"),
    ] {
        let destination = tree.path().join(name);
        std::fs::write(&destination, b"old").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .env("VERSION_CONTROL", "numbered")
            .env("SIMPLE_BACKUP_SUFFIX", "~")
            .arg(option)
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(tree.path().join(backup)).unwrap(), b"old");
    }
}

#[test]
fn numbered_backups_retain_previous_versions() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"new").unwrap();
    std::fs::write(&destination, b"original").unwrap();
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg("--backup=numbered")
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        std::fs::read(tree.path().join("destination.~1~")).unwrap(),
        b"original"
    );
    assert_eq!(
        std::fs::read(tree.path().join("destination.~2~")).unwrap(),
        b"new"
    );
}

#[test]
fn simple_backup_retains_old_destination_contents_with_custom_suffix() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"new").unwrap();
    std::fs::write(&destination, b"old").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--backup=simple", "--suffix=.b"])
        .arg(source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(destination).unwrap(), b"new");
    assert_eq!(
        std::fs::read(tree.path().join("destination.b")).unwrap(),
        b"old"
    );
}

#[test]
fn remove_destination_breaks_old_hardlinks_without_modifying_them() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let alias = tree.path().join("alias");
    std::fs::write(&source, b"new").unwrap();
    std::fs::write(&destination, b"retained").unwrap();
    std::fs::hard_link(&destination, &alias).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("--remove-destination")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(destination).unwrap(), b"new");
    assert_eq!(std::fs::read(alias).unwrap(), b"retained");
}

#[test]
fn update_modes_control_overwrite_and_failure_status() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"source").unwrap();
    for (mode, success, contents) in [
        ("none", true, b"retained".as_slice()),
        ("none-fail", false, b"retained".as_slice()),
        ("all", true, b"source".as_slice()),
    ] {
        std::fs::write(&destination, b"retained").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg(format!("--update={mode}"))
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&destination).unwrap(), contents);
    }
}

#[test]
fn update_skips_equal_timestamp_and_no_clobber_keeps_existing_contents() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"source").unwrap();
    std::fs::write(&destination, b"retained").unwrap();
    timestamps(&source);
    timestamps(&destination);
    for option in ["-u", "-n"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg(option)
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"retained");
    }
    std::fs::File::open(&source)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_002),
            ),
        )
        .unwrap();
    assert!(
        Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg("-u")
            .arg(&source)
            .arg(&destination)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(std::fs::read(destination).unwrap(), b"source");
}

#[test]
fn d_and_l_follow_last_policy_flag_while_retaining_link_preservation() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("file"), b"payload").unwrap();
    symlink("file", tree.path().join("one")).unwrap();
    std::fs::hard_link(tree.path().join("one"), tree.path().join("two")).unwrap();
    for (flags, symbolic) in [("-dL", false), ("-Ld", true)] {
        let destination = tree.path().join(if symbolic { "links" } else { "files" });
        std::fs::create_dir(&destination).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .args([flags, "one", "two"])
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let one = std::fs::symlink_metadata(destination.join("one")).unwrap();
        let two = std::fs::symlink_metadata(destination.join("two")).unwrap();
        assert_eq!(one.file_type().is_symlink(), symbolic);
        assert_eq!(one.ino(), two.ino());
    }
}

#[test]
fn preserves_links_across_separate_source_operands() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("one"), b"payload").unwrap();
    std::fs::hard_link(tree.path().join("one"), tree.path().join("two")).unwrap();
    std::fs::create_dir(tree.path().join("dest")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["--preserve=links", "one", "two", "dest"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(tree.path().join("dest/one"))
            .unwrap()
            .ino(),
        std::fs::metadata(tree.path().join("dest/two"))
            .unwrap()
            .ino()
    );
}

#[test]
fn preserve_short_option_restores_mode_times_and_ownership() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"payload").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o751)).unwrap();
    timestamps(&source);
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-p")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let original = std::fs::metadata(source).unwrap();
    let copied = std::fs::metadata(destination).unwrap();
    assert_eq!(
        (
            copied.mode() & 0o7777,
            copied.mtime(),
            copied.uid(),
            copied.gid()
        ),
        (
            original.mode() & 0o7777,
            original.mtime(),
            original.uid(),
            original.gid()
        )
    );
}

#[test]
fn ordinary_copy_masks_new_permissions_and_preserve_mode_restores_them() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"payload").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o777)).unwrap();
    for (name, option, mode) in [
        ("ordinary", "", 0o700),
        ("preserved", "--preserve=mode", 0o777),
    ] {
        let output = Command::new("sh")
            .args([
                "-c",
                "umask 077; exec \"$1\" $2 \"$3\" \"$4\"",
                "sh",
                env!("CARGO_BIN_EXE_cpcopy"),
                option,
            ])
            .arg(&source)
            .arg(tree.path().join(name))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::metadata(tree.path().join(name)).unwrap().mode() & 0o777,
            mode
        );
    }
}

#[test]
fn ordinary_copy_uses_new_timestamp_and_explicit_preserve_retains_source_timestamp() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"payload").unwrap();
    timestamps(&source);
    for (name, preserve) in [("ordinary", false), ("preserved", true)] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cpcopy"));
        if preserve {
            command.arg("--preserve=timestamps");
        }
        let destination = tree.path().join(name);
        assert!(
            command
                .arg(&source)
                .arg(&destination)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            std::fs::metadata(destination).unwrap().mtime() == 1_000_000_001,
            preserve
        );
    }
}

#[test]
fn source_dot_copies_contents_directly_into_destination() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("source/nested")).unwrap();
    std::fs::create_dir(tree.path().join("destination")).unwrap();
    std::fs::write(tree.path().join("source/nested/file"), b"payload").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-R", "source/.", "destination"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(tree.path().join("destination/nested/file")).unwrap(),
        b"payload"
    );
    assert!(!tree.path().join("destination/source").exists());
}

#[test]
fn multiple_sources_are_copied_into_target_directory() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("one"), b"one").unwrap();
    std::fs::write(tree.path().join("two"), b"two").unwrap();
    std::fs::create_dir(tree.path().join("dest")).unwrap();
    for args in [vec!["one", "two", "dest"], vec!["-t", "dest", "one", "two"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg("-R")
            .current_dir(tree.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for name in ["one", "two"] {
            assert_eq!(
                std::fs::read(tree.path().join("dest").join(name)).unwrap(),
                name.as_bytes()
            );
            std::fs::remove_file(tree.path().join("dest").join(name)).unwrap();
        }
    }
}

#[test]
fn failed_source_does_not_prevent_copying_later_operands() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("good"), b"payload").unwrap();
    std::fs::create_dir(tree.path().join("dest")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-R")
        .current_dir(tree.path())
        .args(["missing", "good", "dest"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(tree.path().join("dest/good")).unwrap(),
        b"payload"
    );
}
fn timestamps(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: 1_000_000_000,
            tv_nsec: 123_456_789,
        },
        libc::timespec {
            tv_sec: 1_000_000_001,
            tv_nsec: 987_654_321,
        },
    ];
    // SAFETY: Terminated test path and two initialized timespecs.
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0
    );
}
#[test]
fn fresh_copy_preserves_payload_modes_times_empty_directories_and_native_names() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("dest");
    std::fs::create_dir_all(source.join("nested/empty")).unwrap();
    let native = OsString::from_vec(b"file-\xff".to_vec());
    let file = source.join("nested").join(&native);
    let bytes: Vec<_> = (0..12345).map(|n| (n % 251) as u8).collect();
    std::fs::write(&file, &bytes).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    for path in [
        &file,
        &source.join("nested/empty"),
        &source.join("nested"),
        &source,
    ] {
        timestamps(path);
    }
    let output = run(&source, &destination);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(destination.join("nested").join(&native)).unwrap(),
        bytes
    );
    for relative in [
        Path::new(""),
        Path::new("nested"),
        Path::new("nested/empty"),
        Path::new("nested").join(&native).as_path(),
    ] {
        let before = std::fs::symlink_metadata(source.join(relative)).unwrap();
        let after = std::fs::symlink_metadata(destination.join(relative)).unwrap();
        assert_eq!(
            (after.mode() & 0o7777, after.mtime(), after.mtime_nsec()),
            (before.mode() & 0o7777, before.mtime(), before.mtime_nsec())
        );
    }
}
#[test]
fn copies_relative_dangling_directory_and_cycle_links_without_following_them() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("dest");
    std::fs::create_dir_all(source.join("directory")).unwrap();
    std::fs::write(source.join("file"), b"payload").unwrap();
    for (name, target) in [
        ("relative", "file"),
        ("dangling", "absent"),
        ("directory-link", "directory"),
        ("cycle", "."),
    ] {
        symlink(target, source.join(name)).unwrap();
        timestamps(&source.join(name));
    }
    assert!(run(&source, &destination).status.success());
    for name in ["relative", "dangling", "directory-link", "cycle"] {
        assert_eq!(
            std::fs::read_link(source.join(name)).unwrap(),
            std::fs::read_link(destination.join(name)).unwrap()
        );
        let before = std::fs::symlink_metadata(source.join(name)).unwrap();
        let after = std::fs::symlink_metadata(destination.join(name)).unwrap();
        assert_eq!(
            (after.mtime(), after.mtime_nsec()),
            (before.mtime(), before.mtime_nsec())
        );
    }
}
#[test]
fn merges_existing_destination_and_rejects_nested_destination_without_modifying_source() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("dest");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("retained"), b"unchanged").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-R")
        .arg("-T")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(destination.join("retained")).unwrap(),
        b"unchanged"
    );
    assert!(!run(&source, &source.join("nested")).status.success());
    assert!(!source.join("nested").exists());
}
#[test]
fn recursive_copy_recreates_fifo_without_blocking() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let fifo = CString::new(source.join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: New test path and valid FIFO permissions.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(run(&source, &tree.path().join("dest")).status.success());
    use std::os::unix::fs::FileTypeExt;
    assert!(
        std::fs::metadata(tree.path().join("dest/fifo"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[test]
fn exclusions_prune_directories_and_match_native_basename_bytes() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("dest");
    std::fs::create_dir_all(source.join("pruned")).unwrap();
    std::fs::write(source.join("pruned/hidden"), b"hidden").unwrap();
    std::fs::write(source.join("keep"), b"kept").unwrap();
    let native = OsString::from_vec(b"skip-\xff.tmp".to_vec());
    std::fs::write(source.join(native), b"excluded").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-R")
        .args([
            "--exclude",
            "pruned",
            "--exclude",
            "*.tmp",
            "--progress",
            "--",
        ])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(destination.join("keep")).unwrap(), b"kept");
    assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 1);
    let events: Vec<serde_json::Value> = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "excluded")
            .count(),
        2
    );
    assert_eq!(events.last().unwrap()["event"], "done");
    assert_eq!(events.last().unwrap()["copied_bytes"], 4);
    assert_eq!(events.last().unwrap()["completed"], 2);
}

#[test]
fn failed_copy_emits_failed_summary_without_completion_for_failed_entry() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    symlink("missing", source.join("dangling")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-RL")
        .arg("--progress")
        .arg(&source)
        .arg(tree.path().join("dest"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert_eq!(events[0]["event"], "directory_created");
    assert_eq!(events.last().unwrap()["event"], "failed");
    assert!(events.iter().all(|event| event["completed"] == 0));
}

#[test]
fn archive_preserves_tree_links_and_all_accepts_attribute_selection() {
    use std::os::unix::fs::MetadataExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("file"), b"archive").unwrap();
    std::fs::hard_link(source.join("file"), source.join("alias")).unwrap();
    symlink("file", source.join("link")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-a")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        std::path::Path::new("file")
    );
    assert_eq!(
        std::fs::metadata(destination.join("file")).unwrap().ino(),
        std::fs::metadata(destination.join("alias")).unwrap().ino()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--preserve=all", "--no-preserve=all"])
        .arg(source.join("file"))
        .arg(tree.path().join("plain"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn attributes_only_symlink_requires_explicit_removal_of_existing_data() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&destination, b"retained").unwrap();
    symlink("missing", &source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-a", "--attributes-only"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&destination).unwrap(), b"retained");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-a", "--attributes-only", "--remove-destination"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_link(&destination).unwrap(),
        std::path::Path::new("missing")
    );
}

#[test]
fn archive_update_links_later_operands_to_skipped_newer_destination() {
    use std::os::unix::fs::MetadataExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let alias = tree.path().join("alias");
    let destination = tree.path().join("out");
    std::fs::write(&source, b"source").unwrap();
    std::fs::hard_link(&source, &alias).unwrap();
    std::fs::File::open(&source)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
        .unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("source"), b"retained").unwrap();
    std::fs::write(destination.join("alias"), b"separate").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-au"])
        .arg(&source)
        .arg(&alias)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(destination.join("source")).unwrap().ino(),
        std::fs::metadata(destination.join("alias")).unwrap().ino()
    );
    assert_eq!(
        std::fs::read(destination.join("alias")).unwrap(),
        b"retained"
    );
}

#[test]
fn interactive_copy_obeys_answers_option_order_and_verbose_output() {
    use std::io::Write;
    use std::process::Stdio;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"new").unwrap();
    for (flags, answer, copied, success) in [
        ("-vi", "n\n", false, false),
        ("-vni", "yes\n", true, true),
        ("-vin", "yes\n", false, true),
        ("-vfi", "y\n", true, true),
    ] {
        std::fs::write(&destination, b"old").unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .args([flags, "source", "destination"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answer.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{flags}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            if copied { b"new" } else { b"old" }
        );
        assert_eq!(
            output.stdout,
            if copied {
                b"'source' -> 'destination'\n".as_slice()
            } else {
                b"".as_slice()
            }
        );
        if flags == "-vin" {
            assert!(output.stderr.is_empty());
        }
    }
}

#[test]
fn verbose_directory_merge_is_silent_and_creation_precedes_contents() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir(tree.path().join("source")).unwrap();
    std::fs::create_dir(tree.path().join("existing")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-avT", "source", "existing"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    std::fs::write(tree.path().join("source/file"), b"data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-avT", "source", "new"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        b"'source' -> 'new'\n'source/file' -> 'new/file'\n"
    );
}

#[test]
fn nonrecursive_device_copy_creates_regular_file() {
    let tree = tempfile::tempdir().unwrap();
    let destination = tree.path().join("empty");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("/dev/null")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::fs::symlink_metadata(&destination).unwrap().is_file());
    assert!(std::fs::read(&destination).unwrap().is_empty());
    std::fs::write(&destination, b"replace").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("/dev/null")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::fs::read(&destination).unwrap().is_empty());
}

#[test]
fn ordinary_copy_writes_to_device_destination() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"discarded").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg(&source)
        .arg("/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn progress_counts_proc_contents_instead_of_zero_stat_size() {
    let tree = tempfile::tempdir().unwrap();
    let destination = tree.path().join("version");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--progress", "/proc/version"])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(&destination).unwrap().len() as u64;
    assert!(bytes > 0);
    let events: Vec<serde_json::Value> = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events[0]["bytes"], bytes);
    assert_eq!(events.last().unwrap()["copied_bytes"], bytes);
}

#[test]
fn recursive_copy_contents_reads_device_referent_into_regular_file() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    symlink("/dev/null", source.join("device")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-RL", "--copy-contents"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata = std::fs::symlink_metadata(destination.join("device")).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 0);
}

#[test]
fn reflink_modes_fallback_override_and_remove_failed_new_copy() {
    let tree = tempfile::tempdir().unwrap();
    for (index, flags) in [
        vec!["--reflink=auto"],
        vec!["--reflink=auto", "--reflink=never"],
    ]
    .into_iter()
    .enumerate()
    {
        let destination = tree.path().join(format!("copy-{index}"));
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .args(flags)
            .arg("/proc/version")
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!std::fs::read(&destination).unwrap().is_empty());
    }
    let destination = tree.path().join("failed");
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("--reflink")
        .arg("/proc/version")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!destination.exists());
    let source = tree.path().join("source");
    std::fs::write(&source, b"metadata only").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--reflink=always", "--attributes-only", "--preserve"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::fs::read(&destination).unwrap().is_empty());
}

#[test]
fn sparse_always_creates_holes_and_never_allocates_zero_data() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let mut contents = vec![0_u8; 1024 * 1024 + 1];
    contents[0] = b'x';
    std::fs::write(&source, &contents).unwrap();
    for mode in ["always", "never"] {
        let destination = tree.path().join(mode);
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .arg("--reflink=never")
            .arg(format!("--sparse={mode}"))
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&destination).unwrap(), contents);
    }
    assert!(
        std::fs::metadata(tree.path().join("always"))
            .unwrap()
            .blocks()
            < std::fs::metadata(tree.path().join("never"))
                .unwrap()
                .blocks()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--reflink=always", "--sparse=always"])
        .arg(&source)
        .arg(tree.path().join("invalid"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!tree.path().join("invalid").exists());
}

#[test]
fn sparse_auto_copies_terabyte_hole_without_reading_its_contents() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(1_u64 << 40)
        .unwrap();
    let output = Command::new("timeout")
        .arg("2")
        .arg(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("--reflink=never")
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::metadata(&destination).unwrap().len(), 1_u64 << 40);
    assert_eq!(std::fs::metadata(&destination).unwrap().blocks(), 0);
}

#[test]
fn debug_reports_transfer_policy_and_omits_attributes_only_transfer() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("source"), b"data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args([
            "--debug",
            "--sparse=never",
            "--reflink=never",
            "source",
            "copy",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("copy offload: avoided, reflink: no, sparse detection: no")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["--debug", "--attributes-only", "source", "copy"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("copy offload:")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["--debug", "--update=none", "source", "copy"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"skipped 'copy'\n");
}

#[test]
fn keep_directory_symlink_merges_into_referent_only_when_requested() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("source/nested/empty")).unwrap();
    std::fs::create_dir_all(tree.path().join("destination/referent")).unwrap();
    symlink("referent", tree.path().join("destination/nested")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-RT", "--copy-contents", "source", "destination"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!tree.path().join("destination/referent/empty").exists());
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args([
            "-RT",
            "--copy-contents",
            "--keep-directory-symlink",
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
    assert!(tree.path().join("destination/referent/empty").is_dir());
    assert_eq!(
        std::fs::read_link(tree.path().join("destination/nested")).unwrap(),
        Path::new("referent")
    );
}

#[test]
fn kept_directory_symlink_can_merge_into_sibling_source_directory() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::create_dir_all(source.join("other")).unwrap();
    std::fs::write(source.join("nested/marker"), b"preserved").unwrap();
    std::fs::create_dir(&destination).unwrap();
    symlink(source.join("other"), destination.join("nested")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-RT", "--copy-contents", "--keep-directory-symlink"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(source.join("other/marker")).unwrap(),
        b"preserved"
    );
    assert_eq!(
        std::fs::read(source.join("nested/marker")).unwrap(),
        b"preserved"
    );
}

#[test]
fn recursive_hardlink_defaults_to_following_source_symlink() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("file"), b"data").unwrap();
    symlink("file", tree.path().join("link")).unwrap();
    for (flags, name, follow) in [("-lR", "follow", true), ("-lRP", "keep", false)] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .args([flags, "link", name])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output_info = std::fs::symlink_metadata(tree.path().join(name)).unwrap();
        let expected =
            std::fs::symlink_metadata(tree.path().join(if follow { "file" } else { "link" }))
                .unwrap();
        assert_eq!(output_info.ino(), expected.ino());
    }
    symlink("missing", tree.path().join("dangling")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-lR", "dangling", "output"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        output.stderr,
        b"cpcopy: cannot stat 'dangling': No such file or directory\n"
    );
    assert!(!tree.path().join("output").exists());
}

#[test]
fn permission_failure_finalizes_directory_and_reports_destination_stat_error() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("unreadable"), b"private").unwrap();
    std::fs::write(source.join("readable"), b"copied").unwrap();
    std::fs::set_permissions(
        source.join("unreadable"),
        std::fs::Permissions::from_mode(0o0),
    )
    .unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-pRT"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        std::fs::metadata(&destination).unwrap().mode() & 0o777,
        0o500
    );
    assert_eq!(
        std::fs::read(destination.join("readable")).unwrap(),
        b"copied"
    );
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o0)).unwrap();
    symlink("source/missing", tree.path().join("link")).unwrap();
    std::fs::write(tree.path().join("file"), b"source").unwrap();
    for (flags, expected) in [
        (vec![], "cannot stat"),
        (vec!["-T"], "cannot stat"),
        (vec!["-t", "link"], "target directory"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cpcopy"));
        command.current_dir(tree.path()).args(&flags).arg("file");
        if !flags.contains(&"-t") {
            command.arg("link");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("cpcopy: {expected} 'link': Permission denied\n")
        );
    }
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn parents_creates_source_path_and_restores_parent_modes() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("source/nested")).unwrap();
    std::fs::create_dir(tree.path().join("destination")).unwrap();
    std::fs::write(tree.path().join("source/nested/file"), b"parents").unwrap();
    std::fs::set_permissions(
        tree.path().join("source"),
        std::fs::Permissions::from_mode(0o710),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-p", "--parents", "source/nested/file", "destination"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(tree.path().join("destination/source/nested/file")).unwrap(),
        b"parents"
    );
    assert_eq!(
        std::fs::metadata(tree.path().join("destination/source"))
            .unwrap()
            .mode()
            & 0o777,
        0o710
    );
    std::fs::write(tree.path().join("ordinary"), b"file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["--parents", "ordinary/missing", "destination"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!tree.path().join("destination/ordinary").exists());
}

#[test]
fn parents_rejects_invalid_copy_policy_before_creating_directories() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir(tree.path().join("source")).unwrap();
    std::fs::create_dir(tree.path().join("destination")).unwrap();
    std::fs::write(tree.path().join("source/file"), b"data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args([
            "--parents",
            "--reflink=always",
            "--sparse=always",
            "source/file",
            "destination",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!tree.path().join("destination/source").exists());
}

#[test]
fn one_file_system_creates_cross_device_directory_without_descendants() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("file"), b"local").unwrap();
    let other = Path::new("/proc/sys/kernel/random");
    assert_ne!(
        std::fs::metadata(&source).unwrap().dev(),
        std::fs::metadata(other).unwrap().dev()
    );
    symlink(other, source.join("other")).unwrap();
    let output = Command::new("timeout")
        .arg("2")
        .arg(env!("CARGO_BIN_EXE_cpcopy"))
        .arg("-RLx")
        .arg(&source)
        .arg(tree.path().join("destination"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(tree.path().join("destination/file")).unwrap(),
        b"local"
    );
    assert!(tree.path().join("destination/other").is_dir());
    assert_eq!(
        std::fs::read_dir(tree.path().join("destination/other"))
            .unwrap()
            .count(),
        0
    );
    let output = Command::new("timeout")
        .arg("2")
        .arg(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["-RL", "--one-file-system"])
        .arg(other)
        .arg(tree.path().join("explicit"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(tree.path().join("explicit/uuid").is_file());
}

#[test]
fn copying_symlink_onto_its_referent_preserves_source_data() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("file"), b"source data").unwrap();
    symlink("file", tree.path().join("link")).unwrap();
    for flags in ["-d", "-df"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .args([flags, "link", "file"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            std::fs::read(tree.path().join("file")).unwrap(),
            b"source data"
        );
        assert_eq!(
            output.stderr,
            b"cpcopy: 'link' and 'file' are the same file\n"
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-dl", "link", "file"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(tree.path().join("file")).unwrap(),
        b"source data"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-db", "link", "file"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(tree.path().join("file~")).unwrap(),
        b"source data"
    );
}

#[test]
fn backup_of_distinct_hardlink_alias_retains_both_source_and_backup() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("source"), b"data").unwrap();
    std::fs::hard_link(tree.path().join("source"), tree.path().join("alias")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-b", "source", "alias"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(tree.path().join("source")).unwrap(), b"data");
    assert_eq!(std::fs::read(tree.path().join("alias~")).unwrap(), b"data");
    assert_ne!(
        std::fs::metadata(tree.path().join("source")).unwrap().ino(),
        std::fs::metadata(tree.path().join("alias")).unwrap().ino()
    );
}

#[test]
fn preserving_hardlinked_symlink_alias_is_safe_and_can_be_backed_up() {
    let tree = tempfile::tempdir().unwrap();
    symlink("missing", tree.path().join("source")).unwrap();
    std::fs::hard_link(tree.path().join("source"), tree.path().join("alias")).unwrap();
    for flags in ["-d", "-bd"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .args([flags, "source", "alias"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_link(tree.path().join("source")).unwrap(),
            Path::new("missing")
        );
        assert_eq!(
            std::fs::read_link(tree.path().join("alias")).unwrap(),
            Path::new("missing")
        );
    }
    assert_eq!(
        std::fs::read_link(tree.path().join("alias~")).unwrap(),
        Path::new("missing")
    );
}

#[test]
fn forced_hardlink_backup_of_same_path_creates_backup_link() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("file"), b"data").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-fbl", "file", "file"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(tree.path().join("file")).unwrap().ino(),
        std::fs::metadata(tree.path().join("file~")).unwrap().ino()
    );
    assert_eq!(std::fs::read(tree.path().join("file")).unwrap(), b"data");
}

#[test]
fn later_operand_cannot_write_through_symlink_created_by_this_invocation() {
    let tree = tempfile::tempdir().unwrap();
    for dir in ["first", "second", "destination"] {
        std::fs::create_dir(tree.path().join(dir)).unwrap();
    }
    symlink("../referent", tree.path().join("first/file")).unwrap();
    std::fs::write(tree.path().join("second/file"), b"replacement").unwrap();
    for existing in [false, true] {
        if existing {
            std::fs::write(tree.path().join("referent"), b"retained").unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .args(["-dR", "first/file", "second/file", "destination"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stderr, b"cpcopy: will not copy 'second/file' through just-created symlink 'destination/file'\n");
        if existing {
            assert_eq!(
                std::fs::read(tree.path().join("referent")).unwrap(),
                b"retained"
            );
        } else {
            assert!(!tree.path().join("referent").exists());
        }
    }
}

#[test]
fn jobs_cli_rejects_invalid_counts_and_default_copy_succeeds() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("source"), b"default worker payload").unwrap();
    for jobs in [0, 65] {
        let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
            .current_dir(tree.path())
            .arg(format!("--jobs={jobs}"))
            .args(["source", "invalid"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("jobs"));
        assert!(!tree.path().join("invalid").exists());
    }
    for (destination, explicit_default) in [("default", false), ("explicit", true)] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cpcopy"));
        command.current_dir(tree.path());
        if explicit_default {
            command.arg("--jobs=1");
        }
        let output = command.args(["source", destination]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(tree.path().join(destination)).unwrap(),
            b"default worker payload"
        );
    }
}

#[test]
fn short_jobs_archive_preserves_native_payload_links_and_progress_totals() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let native = OsString::from_vec(b"native-\xff".to_vec());
    std::fs::write(source.join(&native), b"native payload").unwrap();
    std::fs::hard_link(source.join(&native), source.join("linked")).unwrap();
    for index in 0..12 {
        std::fs::write(source.join(format!("tiny-{index:03}")), b"tiny").unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .args(["-j", "4", "-a", "--progress", "source", "destination"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let destination = tree.path().join("destination");
    assert_eq!(
        std::fs::read(destination.join(&native)).unwrap(),
        b"native payload"
    );
    assert_eq!(
        std::fs::metadata(destination.join(&native)).unwrap().ino(),
        std::fs::metadata(destination.join("linked")).unwrap().ino()
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.last().unwrap()["event"], "done");
    let total = events
        .iter()
        .filter(|event| event["event"] == "completed")
        .map(|event| event["bytes"].as_u64().unwrap())
        .sum::<u64>();
    assert_eq!(events.last().unwrap()["copied_bytes"].as_u64(), Some(total));
}

#[cfg(not(feature = "live-progress"))]
#[test]
fn live_progress_flag_requires_cargo_feature() {
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--live-progress", "source", "destination"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--live-progress'")
    );
}

#[cfg(feature = "live-progress")]
#[test]
fn full_stderr_pipe_does_not_hold_up_live_progress_exit() {
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut descriptors = [-1; 2];
    // SAFETY: Storage holds two descriptors; successful pipe2 initializes both.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: Own the distinct descriptors returned by successful pipe2.
    let _reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: Transfer ownership of the other initialized descriptor once.
    let mut writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
    // SAFETY: Set nonblocking mode on the fixture-owned pipe writer.
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    loop {
        match writer.write(&[0; 4096]) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("cannot fill fixture pipe: {error}"),
        }
    }
    // SAFETY: Restore blocking output so the reporter encounters a stalled write.
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, 0) },
        0
    );

    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let payload = vec![0x53; 1048576];
    std::fs::write(&source, &payload).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .args(["--live-progress", "--reflink=never"])
        .arg(&source)
        .arg(&destination)
        .stderr(Stdio::from(writer))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("live progress hung on a full stderr pipe");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    assert_eq!(std::fs::read(destination).unwrap(), payload);
}
