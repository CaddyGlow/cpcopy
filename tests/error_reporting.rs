#![cfg(all(target_os = "linux", feature = "cli"))]
use std::{ffi::OsString, os::unix::ffi::OsStringExt, process::Command};

#[test]
fn missing_source_diagnostics_quote_native_names_like_gnu_cp() {
    let tree = tempfile::tempdir().unwrap();
    for name in [
        b"plain".as_slice(),
        b"a'b",
        b"a\"b",
        b"a'b\"c",
        b"a\nb",
        b"\n\t",
        b"a\xffb",
        b"a\\b",
        b"a\x01b",
    ] {
        let name = OsString::from_vec(name.to_vec());
        let output = |program: &str| {
            Command::new(program)
                .current_dir(tree.path())
                .env("LC_ALL", "C")
                .arg("--")
                .arg(&name)
                .arg("destination")
                .output()
                .unwrap()
        };
        let reference = output("cp");
        let actual = output(env!("CARGO_BIN_EXE_cpcopy"));
        assert_eq!(actual.status.code(), reference.status.code());
        assert_eq!(
            actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
            reference.stderr.strip_prefix(b"cp: ").unwrap(),
            "name {name:?}"
        );
    }
}

#[test]
fn recursive_copy_reports_every_missing_symlink_referent() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    for name in ["first", "second"] {
        std::os::unix::fs::symlink("absent", source.join(name)).unwrap();
    }
    std::fs::write(source.join("healthy"), b"retained").unwrap();
    let reference = Command::new("cp")
        .current_dir(tree.path())
        .env("LC_ALL", "C")
        .args(["-RL", "source", "gnu-destination"])
        .output()
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cpcopy"))
        .current_dir(tree.path())
        .env("LC_ALL", "C")
        .args(["-RL", "source", "destination"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("cannot stat 'source/first'"), "{stderr}");
    assert!(stderr.contains("cannot stat 'source/second'"), "{stderr}");
    assert_eq!(stderr.lines().count(), 2, "{stderr}");
    let mut actual_lines: Vec<_> = stderr
        .lines()
        .map(|line| line.strip_prefix("cpcopy: ").unwrap())
        .collect();
    let reference_text = String::from_utf8(reference.stderr).unwrap();
    let mut reference_lines: Vec<_> = reference_text
        .lines()
        .map(|line| line.strip_prefix("cp: ").unwrap())
        .collect();
    actual_lines.sort_unstable();
    reference_lines.sort_unstable();
    assert_eq!(actual_lines, reference_lines);
    assert_eq!(
        std::fs::read(tree.path().join("destination/healthy")).unwrap(),
        b"retained"
    );
}

#[test]
fn source_open_and_destination_creation_failures_match_gnu_diagnostics() {
    use std::os::unix::fs::PermissionsExt;
    // Root can read the deliberately unreadable fixture.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("source"), b"contents").unwrap();
    std::fs::create_dir(tree.path().join("blocked")).unwrap();
    for (source_mode, directory_mode, destination) in [
        (0, 0o700, "destination"),
        (0o600, 0o500, "blocked/destination"),
    ] {
        std::fs::set_permissions(
            tree.path().join("source"),
            std::fs::Permissions::from_mode(source_mode),
        )
        .unwrap();
        std::fs::set_permissions(
            tree.path().join("blocked"),
            std::fs::Permissions::from_mode(directory_mode),
        )
        .unwrap();
        let output = |program: &str| {
            Command::new(program)
                .current_dir(tree.path())
                .env("LC_ALL", "C")
                .args(["source", destination])
                .output()
                .unwrap()
        };
        let reference = output("cp");
        let actual = output(env!("CARGO_BIN_EXE_cpcopy"));
        assert_eq!(actual.status.code(), reference.status.code());
        assert_eq!(
            actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
            reference.stderr.strip_prefix(b"cp: ").unwrap()
        );
    }
    std::fs::set_permissions(
        tree.path().join("blocked"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

#[test]
fn utf8_locale_keeps_printable_names_and_escapes_invalid_bytes() {
    let tree = tempfile::tempdir().unwrap();
    for bytes in [
        "aé日🦀'b".as_bytes(),
        "a\u{200b}b".as_bytes(),
        b"a\xc3\xa9\xffb",
    ] {
        let name = OsString::from_vec(bytes.to_vec());
        let output = |program: &str| {
            Command::new(program)
                .current_dir(tree.path())
                .env("LC_ALL", "C.UTF-8")
                .arg("--")
                .arg(&name)
                .arg("destination")
                .output()
                .unwrap()
        };
        let reference = output("cp");
        let actual = output(env!("CARGO_BIN_EXE_cpcopy"));
        assert_eq!(
            actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
            reference.stderr.strip_prefix(b"cp: ").unwrap(),
            "{name:?}"
        );
    }
}

#[test]
fn unreadable_directory_reports_its_source_path() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir(tree.path().join("source")).unwrap();
    std::fs::set_permissions(
        tree.path().join("source"),
        std::fs::Permissions::from_mode(0o0),
    )
    .unwrap();
    let output = |program: &str, destination: &str| {
        Command::new(program)
            .current_dir(tree.path())
            .env("LC_ALL", "C")
            .args(["-R", "source", destination])
            .output()
            .unwrap()
    };
    let reference = output("cp", "reference");
    let actual = output(env!("CARGO_BIN_EXE_cpcopy"), "actual");
    // Restore before comparing, so even a failed assertion leaves removable fixtures.
    for path in ["source", "reference", "actual"] {
        std::fs::set_permissions(
            tree.path().join(path),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    assert_eq!(
        actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
        reference.stderr.strip_prefix(b"cp: ").unwrap()
    );
}

#[test]
fn data_read_and_write_failures_identify_the_failing_path() {
    let tree = tempfile::tempdir().unwrap();
    for (source, destination) in [
        ("/dev/zero", "/dev/full"),
        ("/proc/self/mem", "destination"),
    ] {
        let output = |program: &str| {
            Command::new(program)
                .current_dir(tree.path())
                .env("LC_ALL", "C")
                .args(["--reflink=never", source, destination])
                .output()
                .unwrap()
        };
        let reference = output("cp");
        let actual = output(env!("CARGO_BIN_EXE_cpcopy"));
        assert!(!actual.status.success());
        assert_eq!(
            actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
            reference.stderr.strip_prefix(b"cp: ").unwrap()
        );
    }
}
