#![cfg(target_os = "linux")]
use cpcopy::{CopyOptions, EventKind, copy, copy_with_events};

#[test]
#[cfg(feature = "live-progress")]
fn live_progress_counts_concurrent_contents_and_sparse_holes_once() {
    use std::io::{Seek, SeekFrom, Write};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let payload = vec![0x73; 1048576 + 17];
    for index in 0..8 {
        std::fs::write(source.join(format!("file-{index}")), &payload).unwrap();
    }
    let mut sparse = std::fs::File::create(source.join("sparse")).unwrap();
    sparse.seek(SeekFrom::Start(4 * 1048576)).unwrap();
    sparse.write_all(b"end").unwrap();
    drop(sparse);
    let expected = 8 * payload.len() as u64 + 4 * 1048576 + 3;
    for (index, (jobs, mode)) in [
        (1, cpcopy::SparseMode::Never),
        (4, cpcopy::SparseMode::Auto),
        (4, cpcopy::SparseMode::Always),
    ]
    .into_iter()
    .enumerate()
    {
        let progress = cpcopy::LiveProgress::default();
        let mut completed = 0;
        let destination = tree.path().join(format!("destination-{index}"));
        copy_with_events(
            &source,
            &destination,
            &CopyOptions {
                jobs,
                sparse: mode,
                live_progress: Some(progress.clone()),
                ..CopyOptions::default()
            },
            &mut |event| {
                if event.kind == EventKind::Completed {
                    completed += 1;
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(progress.snapshot().bytes, expected);
        assert_eq!(progress.snapshot().completed, completed);
        assert_eq!(std::fs::read(destination.join("file-7")).unwrap(), payload);
        let contents = std::fs::read(destination.join("sparse")).unwrap();
        assert!(contents[..4 * 1048576].iter().all(|byte| *byte == 0));
        assert_eq!(&contents[4 * 1048576..], b"end");
    }
}

#[test]
fn mode_preservation_copies_directory_default_acl() {
    use std::os::unix::ffi::OsStrExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    let source_name = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
    let mut acl = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions) in [(1_u16, 7_u16), (4, 5), (32, 0)] {
        acl.extend(tag.to_le_bytes());
        acl.extend(permissions.to_le_bytes());
        acl.extend(u32::MAX.to_le_bytes());
    }
    // SAFETY: Terminated names and valid Linux default ACL encoding.
    assert_eq!(
        unsafe {
            libc::setxattr(
                source_name.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        },
        0
    );
    copy(&source, &destination, &CopyOptions::default()).unwrap();
    let destination_name = std::ffi::CString::new(destination.as_os_str().as_bytes()).unwrap();
    let mut copied = vec![0; acl.len()];
    // SAFETY: Terminated names and bounded writable ACL buffer.
    assert_eq!(
        unsafe {
            libc::getxattr(
                destination_name.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                copied.as_mut_ptr().cast(),
                copied.len(),
            )
        },
        acl.len() as isize
    );
    assert_eq!(copied, acl);
}

#[test]
fn mode_preservation_copies_named_user_posix_acl() {
    use std::os::unix::ffi::OsStrExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"payload").unwrap();
    let source_name = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
    // SAFETY: getuid has no pointer arguments.
    let named_uid = unsafe { libc::getuid() };
    let mut acl = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1_u16, 6_u16, u32::MAX),
        (2, 4, named_uid),
        (4, 0, u32::MAX),
        (16, 4, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend(tag.to_le_bytes());
        acl.extend(permissions.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    // SAFETY: Terminated path/name and initialized Linux ACL bytes.
    assert_eq!(
        unsafe {
            libc::setxattr(
                source_name.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        },
        0
    );
    copy(&source, &destination, &CopyOptions::default()).unwrap();
    let destination_name = std::ffi::CString::new(destination.as_os_str().as_bytes()).unwrap();
    let mut copied = vec![0; acl.len()];
    // SAFETY: Terminated path/name and bounded output buffer.
    assert_eq!(
        unsafe {
            libc::getxattr(
                destination_name.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                copied.as_mut_ptr().cast(),
                copied.len(),
            )
        },
        acl.len() as isize
    );
    assert_eq!(copied, acl);
}

#[test]
fn preserves_directory_extended_attribute() {
    use std::os::unix::ffi::OsStrExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    let source_name = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
    // SAFETY: Terminated names and initialized attribute bytes.
    assert_eq!(
        unsafe {
            libc::setxattr(
                source_name.as_ptr(),
                c"user.foo".as_ptr(),
                b"directory".as_ptr().cast(),
                9,
                0,
            )
        },
        0
    );
    copy(
        &source,
        &destination,
        &CopyOptions {
            preserve_xattrs: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    let destination_name = std::ffi::CString::new(destination.as_os_str().as_bytes()).unwrap();
    let mut copied = [0; 9];
    // SAFETY: Terminated names and bounded writable attribute output.
    assert_eq!(
        unsafe {
            libc::getxattr(
                destination_name.as_ptr(),
                c"user.foo".as_ptr(),
                copied.as_mut_ptr().cast(),
                copied.len(),
            )
        },
        9
    );
    assert_eq!(&copied, b"directory");
}

// Uses the user.foo binary attribute case exercised by GNU's xattr tests.
#[test]
fn preserves_regular_file_binary_extended_attribute() {
    use std::os::unix::ffi::OsStrExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"payload").unwrap();
    let source_name = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
    let value = b"binary\0value";
    // SAFETY: Terminated path/name and initialized value of the specified size.
    assert_eq!(
        unsafe {
            libc::setxattr(
                source_name.as_ptr(),
                c"user.foo".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        0
    );
    let options = CopyOptions {
        preserve_xattrs: true,
        ..CopyOptions::default()
    };
    copy(&source, &destination, &options).unwrap();
    let destination_name = std::ffi::CString::new(destination.as_os_str().as_bytes()).unwrap();
    let mut copied = [0_u8; 12];
    // SAFETY: Terminated path/name and bounded writable output array.
    assert_eq!(
        unsafe {
            libc::getxattr(
                destination_name.as_ptr(),
                c"user.foo".as_ptr(),
                copied.as_mut_ptr().cast(),
                copied.len(),
            )
        },
        value.len() as isize
    );
    assert_eq!(&copied, value);
}

#[test]
fn session_does_not_link_to_replaced_destination_path() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let first = tree.path().join("first");
    let second = tree.path().join("second");
    std::fs::write(&source, b"source payload").unwrap();
    let options = CopyOptions {
        preserve_links: true,
        ..CopyOptions::default()
    };
    let mut session = cpcopy::CopySession::default();
    session
        .copy_with_events(&source, &first, &options, &mut |_| Ok(()))
        .unwrap();
    std::fs::rename(&first, tree.path().join("saved")).unwrap();
    std::fs::write(&first, b"unrelated").unwrap();
    session
        .copy_with_events(&source, &second, &options, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(std::fs::read(second).unwrap(), b"source payload");
}

#[test]
fn preserves_hardlink_relationships_in_copied_tree() {
    use std::os::unix::fs::MetadataExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::write(source.join("file"), b"payload").unwrap();
    std::fs::hard_link(source.join("file"), source.join("nested/alias")).unwrap();
    let options = CopyOptions {
        preserve_links: true,
        ..CopyOptions::default()
    };
    copy(&source, &destination, &options).unwrap();
    assert_eq!(
        std::fs::metadata(destination.join("file")).unwrap().ino(),
        std::fs::metadata(destination.join("nested/alias"))
            .unwrap()
            .ino()
    );
    assert_ne!(
        std::fs::metadata(source.join("file")).unwrap().ino(),
        std::fs::metadata(destination.join("file")).unwrap().ino()
    );
}

#[test]
fn overwriting_symlink_replaces_link_without_changing_old_referent() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let target = tree.path().join("target");
    std::fs::write(&target, b"retained").unwrap();
    std::os::unix::fs::symlink("missing", &source).unwrap();
    std::os::unix::fs::symlink(&target, &destination).unwrap();
    let options = CopyOptions {
        overwrite: true,
        preserve_mode: false,
        ..CopyOptions::default()
    };
    copy(&source, &destination, &options).unwrap();
    assert_eq!(
        std::fs::read_link(destination).unwrap(),
        std::path::Path::new("missing")
    );
    assert_eq!(std::fs::read(target).unwrap(), b"retained");
}

#[test]
fn merges_existing_directories_without_replacing_their_modes_or_unrelated_entries() {
    use std::os::unix::fs::PermissionsExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::create_dir_all(destination.join("nested")).unwrap();
    std::fs::write(source.join("nested/new"), b"new").unwrap();
    std::fs::write(destination.join("retained"), b"retained").unwrap();
    std::fs::set_permissions(
        destination.join("nested"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let options = CopyOptions {
        merge_directories: true,
        preserve_mode: false,
        preserve_timestamps: false,
        ..CopyOptions::default()
    };
    copy(&source, &destination, &options).unwrap();
    assert_eq!(
        std::fs::read(destination.join("nested/new")).unwrap(),
        b"new"
    );
    assert_eq!(
        std::fs::read(destination.join("retained")).unwrap(),
        b"retained"
    );
    assert_eq!(
        std::fs::metadata(destination.join("nested"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
}

#[test]
fn overwrite_truncates_existing_inode_and_updates_its_hardlinks() {
    use std::os::unix::fs::MetadataExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let alias = tree.path().join("alias");
    std::fs::write(&source, b"new").unwrap();
    std::fs::write(&destination, b"old longer contents").unwrap();
    std::fs::hard_link(&destination, &alias).unwrap();
    let inode = std::fs::metadata(&destination).unwrap().ino();
    let options = CopyOptions {
        overwrite: true,
        preserve_mode: false,
        ..CopyOptions::default()
    };
    copy(&source, &destination, &options).unwrap();
    assert_eq!(std::fs::metadata(&destination).unwrap().ino(), inode);
    assert_eq!(std::fs::read(&alias).unwrap(), b"new");
}

#[test]
fn overwrite_through_source_alias_rejects_before_truncation() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let alias = tree.path().join("alias");
    std::fs::write(&source, b"retained").unwrap();
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    let options = CopyOptions {
        overwrite: true,
        preserve_mode: false,
        ..CopyOptions::default()
    };
    let error = copy(&source, &alias, &options).unwrap_err();
    assert!(format!("{error:#}").contains("same file"));
    assert_eq!(std::fs::read(source).unwrap(), b"retained");
}

#[test]
fn overwrite_through_destination_symlink_preserves_link_and_referent_mode() {
    use std::os::unix::fs::PermissionsExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let target = tree.path().join("target");
    let alias = tree.path().join("alias");
    std::fs::write(&source, b"new").unwrap();
    std::fs::write(&target, b"old longer contents").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let options = CopyOptions {
        overwrite: true,
        preserve_mode: false,
        ..CopyOptions::default()
    };
    copy(&source, &alias, &options).unwrap();
    assert_eq!(std::fs::read_link(alias).unwrap(), target);
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o7777,
        0o640
    );
}

#[test]
fn dereference_detects_ancestor_cycle_before_creating_nested_destination() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    std::os::unix::fs::symlink(".", source.join("cycle")).unwrap();
    let options = CopyOptions {
        dereference: cpcopy::Dereference::Always,
        ..CopyOptions::default()
    };
    let error = copy(&source, &destination, &options).unwrap_err();
    assert!(format!("{error:#}").contains("cyclic symbolic link"));
    assert!(!destination.join("cycle").exists());
}

#[test]
fn copies_regular_file_to_fresh_destination() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"payload").unwrap();
    copy(&source, &destination, &CopyOptions::default()).unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"payload");
}

#[test]
fn copies_top_level_dangling_symlink_without_resolving_it() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::os::unix::fs::symlink("missing", &source).unwrap();
    copy(&source, &destination, &CopyOptions::default()).unwrap();
    assert_eq!(
        std::fs::read_link(destination).unwrap(),
        std::path::Path::new("missing")
    );
}

// Adapted from the unoptioned foo/foo and foo/hardlink cases in GNU
// coreutils v9.7 tests/cp/same-file.sh. Check data as well as the diagnostic:
// accidentally truncating the source is the failure this upstream test guards.
#[test]
fn rejects_same_file_and_hardlink_without_truncating_source() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("foo");
    let alias = tree.path().join("hardlink");
    std::fs::write(&source, b"XYZ\n").unwrap();
    std::fs::hard_link(&source, &alias).unwrap();
    for destination in [&source, &alias] {
        let error = copy(&source, destination, &CopyOptions::default()).unwrap_err();
        assert!(format!("{error:#}").contains("same file"));
        assert_eq!(std::fs::read(&source).unwrap(), b"XYZ\n");
    }
}

#[test]
fn callback_observes_files_after_close_and_directories_after_descendants() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::write(source.join("nested/file"), b"payload").unwrap();
    let mut events = Vec::new();
    copy_with_events(
        &source,
        &destination,
        &CopyOptions::default(),
        &mut |event| {
            if event.kind == EventKind::Completed && event.bytes > 0 {
                assert_eq!(std::fs::read(&event.destination).unwrap(), b"payload");
            }
            events.push(event.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        events.iter().map(|event| event.kind).collect::<Vec<_>>(),
        [
            EventKind::DirectoryCreated,
            EventKind::DirectoryCreated,
            EventKind::Completed,
            EventKind::Completed,
            EventKind::Completed,
            EventKind::Done
        ]
    );
    assert_eq!(events[0].destination, destination);
    assert_eq!(events[1].destination, destination.join("nested"));
    assert_eq!(events[2].destination, destination.join("nested/file"));
    assert_eq!(events[3].destination, destination.join("nested"));
    assert_eq!(events[4].destination, destination);
    assert_eq!(events[5].copied_bytes, 7);
}

#[test]
fn library_validates_buffer_size_before_creating_destination() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    let options = CopyOptions {
        buffer_size: 0,
        ..CopyOptions::default()
    };
    assert!(copy(&source, &destination, &options).is_err());
    assert!(!destination.exists());
}

#[test]
fn callback_failure_stops_copy_without_claiming_success() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("file"), b"payload").unwrap();
    let mut done = false;
    let result = copy_with_events(
        &source,
        &destination,
        &CopyOptions::default(),
        &mut |event| {
            done |= event.kind == EventKind::Done;
            if event.kind == EventKind::Completed {
                anyhow::bail!("consumer stopped");
            }
            Ok(())
        },
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("consumer stopped"));
    assert!(!done);
    assert_eq!(std::fs::read(destination.join("file")).unwrap(), b"payload");
}

#[test]
fn overwrite_policy_refusal_continues_other_directory_entries() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&destination).unwrap();
    for name in ["retain", "replace"] {
        std::fs::write(source.join(name), b"new").unwrap();
        std::fs::write(destination.join(name), b"old").unwrap();
    }
    let mut decisions = Vec::new();
    let mut events = Vec::new();
    let result = cpcopy::CopySession::default().copy_with_overwrite_policy(
        &source,
        &destination,
        &CopyOptions {
            overwrite: true,
            merge_directories: true,
            ..CopyOptions::default()
        },
        &mut |event| {
            events.push(event.clone());
            Ok(())
        },
        &mut |source, _| {
            decisions.push(source.file_name().unwrap().to_owned());
            Ok(source.file_name().unwrap() != "retain")
        },
    );
    assert!(result.is_err());
    assert_eq!(decisions.len(), 2);
    assert_eq!(std::fs::read(destination.join("retain")).unwrap(), b"old");
    assert_eq!(std::fs::read(destination.join("replace")).unwrap(), b"new");
    assert_eq!(events.last().unwrap().kind, EventKind::Failed);
}

#[test]
fn invalid_jobs_fail_before_destination_creation_or_callbacks() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"retained source").unwrap();
    for jobs in [0, 65] {
        let mut callbacks = 0;
        let result = copy_with_events(
            &source,
            &destination,
            &CopyOptions {
                jobs,
                ..CopyOptions::default()
            },
            &mut |_| {
                callbacks += 1;
                Ok(())
            },
        );
        assert!(result.unwrap_err().to_string().contains("jobs"));
        assert_eq!(callbacks, 0);
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"retained source");
    }
}

#[test]
fn jobs_four_matches_serial_native_tree_exclusions_order_and_postorder_totals() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::create_dir(source.join("skip-directory")).unwrap();
    std::fs::write(source.join("skip-directory/hidden"), b"hidden").unwrap();
    let large = (0..1024 * 1024 + 123)
        .map(|index| (index % 251 + 1) as u8)
        .collect::<Vec<_>>();
    for name in ["large-a", "large-b", "large-c", "large-d"] {
        std::fs::write(source.join(name), &large).unwrap();
    }
    for index in 0..32 {
        std::fs::write(
            source.join(format!("tiny-{index:03}")),
            format!("tiny {index}"),
        )
        .unwrap();
    }
    let native = std::ffi::OsString::from_vec(b"native-\xff".to_vec());
    std::fs::write(source.join(&native), b"native payload").unwrap();
    std::fs::write(source.join("ignored.tmp"), b"ignored").unwrap();
    std::fs::write(source.join("nested/child"), b"nested payload").unwrap();
    let run = |jobs| {
        let destination = tree.path().join(format!("destination-{jobs}"));
        let caller = std::thread::current().id();
        let mut events = Vec::new();
        copy_with_events(
            &source,
            &destination,
            &CopyOptions {
                jobs,
                reflink: cpcopy::ReflinkMode::Never,
                preserve_mode: false,
                preserve_timestamps: false,
                exclusions: vec!["*.tmp".into(), "skip-*".into()],
                ..CopyOptions::default()
            },
            &mut |event| {
                assert_eq!(std::thread::current().id(), caller);
                if event.kind == EventKind::Completed && event.source.is_file() {
                    assert_eq!(
                        std::fs::read(&event.destination).unwrap(),
                        std::fs::read(&event.source).unwrap(),
                        "completion must follow the checked close"
                    );
                }
                events.push((
                    event.kind,
                    event
                        .source
                        .strip_prefix(&source)
                        .unwrap()
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                    event
                        .destination
                        .strip_prefix(&destination)
                        .unwrap()
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                    event.bytes,
                    event.completed,
                    event.copied_bytes,
                ));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(destination.join(&native)).unwrap(),
            b"native payload"
        );
        assert!(!destination.join("ignored.tmp").exists());
        assert!(!destination.join("skip-directory").exists());
        let child = events
            .iter()
            .position(|event| event.0 == EventKind::Completed && event.1 == b"nested/child")
            .unwrap();
        let parent = events
            .iter()
            .position(|event| event.0 == EventKind::Completed && event.1 == b"nested")
            .unwrap();
        let root = events
            .iter()
            .position(|event| event.0 == EventKind::Completed && event.1.is_empty())
            .unwrap();
        assert!(child < parent && parent < root);
        let sum = events
            .iter()
            .filter(|event| event.0 == EventKind::Completed)
            .map(|event| event.3)
            .sum::<u64>();
        let summary = events.last().unwrap();
        assert_eq!(summary.0, EventKind::Done);
        assert_eq!(summary.5, sum);
        events
    };
    assert_eq!(
        run(4),
        run(1),
        "workers must retain GNU inode-sorted callback input order and totals"
    );
}

#[test]
fn jobs_four_preserves_source_hardlink_anchors_and_existing_destination_aliases() {
    use std::os::unix::fs::MetadataExt;
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("anchor"), b"shared payload").unwrap();
    std::fs::hard_link(source.join("anchor"), source.join("linked")).unwrap();
    let destination = tree.path().join("destination");
    copy(
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
        std::fs::metadata(destination.join("anchor")).unwrap().ino(),
        std::fs::metadata(destination.join("linked")).unwrap().ino()
    );
    let target = tree.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("anchor"), b"old payload and tail").unwrap();
    let alias = tree.path().join("alias");
    std::fs::hard_link(target.join("anchor"), &alias).unwrap();
    let original = std::fs::metadata(&alias).unwrap().ino();
    copy(
        &source,
        &target,
        &CopyOptions {
            jobs: 4,
            overwrite: true,
            merge_directories: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(target.join("anchor")).unwrap().ino(),
        original
    );
    assert_eq!(std::fs::metadata(&alias).unwrap().ino(), original);
    assert_eq!(std::fs::read(alias).unwrap(), b"shared payload");
}

#[test]
fn jobs_four_abort_and_cooperative_cancellation_bound_work_without_success_summary() {
    for cancel in [false, true] {
        let tree = tempfile::tempdir().unwrap();
        let source = tree.path().join("source");
        let destination = tree.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        for index in 0..32 {
            std::fs::write(source.join(format!("file-{index:03}")), b"payload").unwrap();
        }
        let cancellation = cpcopy::Cancellation::default();
        let mut kinds = Vec::new();
        let result = copy_with_events(
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
                    if cancel {
                        cancellation.cancel();
                    } else {
                        anyhow::bail!("callback requested abort");
                    }
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!kinds.contains(&EventKind::Done));
        assert!(
            std::fs::read_dir(destination).unwrap().count() <= 8,
            "submission must remain within twice the worker count"
        );
        if !cancel {
            assert_eq!(
                kinds
                    .iter()
                    .filter(|kind| **kind == EventKind::Completed)
                    .count(),
                1
            );
        }
    }
}

#[test]
fn jobs_four_readonly_destination_error_continues_or_stops_at_serial_barrier() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Root bypasses ordinary DAC write restrictions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for stop_on_error in [false, true] {
        let tree = tempfile::tempdir().unwrap();
        let source = tree.path().join("source");
        let destination = tree.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&destination).unwrap();
        for index in 0..12 {
            std::fs::write(source.join(format!("file-{index:03}")), b"new payload").unwrap();
        }
        let mut names = std::fs::read_dir(&source)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        names.sort_by_key(|entry| entry.metadata().unwrap().ino());
        let first = names[0].file_name();
        let bad = destination.join(&first);
        std::fs::write(&bad, b"retained payload").unwrap();
        let original = std::fs::metadata(&bad).unwrap().ino();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut kinds = Vec::new();
        let result = copy_with_events(
            &source,
            &destination,
            &CopyOptions {
                jobs: 4,
                stop_on_error,
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
        assert!(result.is_err());
        assert!(!kinds.contains(&EventKind::Done));
        assert_eq!(std::fs::read(&bad).unwrap(), b"retained payload");
        assert_eq!(std::fs::metadata(&bad).unwrap().ino(), original);
        for entry in names.iter().skip(1) {
            if stop_on_error {
                assert!(!destination.join(entry.file_name()).exists());
            } else {
                assert_eq!(
                    std::fs::read(destination.join(entry.file_name())).unwrap(),
                    b"new payload"
                );
            }
        }
    }
}

#[test]
fn jobs_four_reports_multiple_worker_source_open_errors_and_copies_healthy_siblings() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    for name in ["bad-a", "healthy-a", "bad-b", "healthy-b"] {
        std::fs::write(source.join(name), name.as_bytes()).unwrap();
    }
    for name in ["bad-a", "bad-b"] {
        std::fs::set_permissions(source.join(name), std::fs::Permissions::from_mode(0o0)).unwrap();
    }
    let mut kinds = Vec::new();
    let error = copy_with_events(
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
            Ok(())
        },
    )
    .unwrap_err();
    let report = format!("{error:#}");
    assert!(
        report.contains("bad-a") && report.contains("bad-b"),
        "{report}"
    );
    for name in ["healthy-a", "healthy-b"] {
        assert_eq!(
            std::fs::read(destination.join(name)).unwrap(),
            name.as_bytes()
        );
    }
    for name in ["bad-a", "bad-b"] {
        assert!(!destination.join(name).exists());
    }
    assert!(!kinds.contains(&EventKind::Done));
    assert_eq!(kinds.last(), Some(&EventKind::Failed));
}

#[test]
fn jobs_four_preserves_independent_file_acls_binary_xattrs_and_nanosecond_times() {
    use std::{
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        time::{Duration, UNIX_EPOCH},
    };
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::create_dir(&source).unwrap();
    // SAFETY: getuid has no pointer arguments or preconditions.
    let uid = unsafe { libc::getuid() };
    let mut acl = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1_u16, 6_u16, u32::MAX),
        (2, 4, uid),
        (4, 0, u32::MAX),
        (16, 4, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend(tag.to_le_bytes());
        acl.extend(permissions.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    let binary = b"binary\0value\xff";
    let mut expected = Vec::new();
    for index in 0..3 {
        let filename = format!("file-{index}");
        let path = source.join(&filename);
        std::fs::write(&path, filename.as_bytes()).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: Terminated native path/attribute and initialized kernel ACL bytes.
        assert_eq!(
            unsafe {
                libc::setxattr(
                    name.as_ptr(),
                    c"system.posix_acl_access".as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            },
            0
        );
        // SAFETY: Terminated names and bounded initialized binary attribute bytes.
        assert_eq!(
            unsafe {
                libc::setxattr(
                    name.as_ptr(),
                    c"user.cpcopy_threads".as_ptr(),
                    binary.as_ptr().cast(),
                    binary.len(),
                    0,
                )
            },
            0
        );
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(UNIX_EPOCH + Duration::new(1_100_000_000 + index, 123_456_789))
                    .set_modified(UNIX_EPOCH + Duration::new(1_200_000_000 + index, 987_654_321)),
            )
            .unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        expected.push((
            filename,
            metadata.mode() & 0o7777,
            metadata.atime(),
            metadata.atime_nsec(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        ));
    }
    copy(
        &source,
        &destination,
        &CopyOptions {
            jobs: 4,
            preserve_mode: true,
            preserve_xattrs: true,
            preserve_timestamps: true,
            ..CopyOptions::default()
        },
    )
    .unwrap();
    for (filename, mode, atime, atime_nsec, mtime, mtime_nsec) in expected {
        let path = destination.join(&filename);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, mode);
        assert_eq!(
            (
                metadata.atime(),
                metadata.atime_nsec(),
                metadata.mtime(),
                metadata.mtime_nsec()
            ),
            (atime, atime_nsec, mtime, mtime_nsec)
        );
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut copied_acl = vec![0; acl.len()];
        let mut copied_binary = vec![0; binary.len()];
        // SAFETY: Terminated native names and initialized bounded ACL output storage.
        assert_eq!(
            unsafe {
                libc::getxattr(
                    name.as_ptr(),
                    c"system.posix_acl_access".as_ptr(),
                    copied_acl.as_mut_ptr().cast(),
                    copied_acl.len(),
                )
            },
            acl.len() as isize
        );
        // SAFETY: Terminated names and initialized bounded binary attribute output.
        assert_eq!(
            unsafe {
                libc::getxattr(
                    name.as_ptr(),
                    c"user.cpcopy_threads".as_ptr(),
                    copied_binary.as_mut_ptr().cast(),
                    copied_binary.len(),
                )
            },
            binary.len() as isize
        );
        assert_eq!(copied_acl, acl);
        assert_eq!(copied_binary, binary);
        assert_eq!(std::fs::read(path).unwrap(), filename.as_bytes());
    }
}

#[test]
fn parallel_replacement_invalidates_preserved_link_session_anchor() {
    use std::os::unix::fs::MetadataExt;
    let tree = tempfile::tempdir().unwrap();
    let original = tree.path().join("original");
    std::fs::write(&original, b"original payload").unwrap();
    let destination = tree.path().join("destination");
    std::fs::create_dir(&destination).unwrap();
    let anchor = destination.join("anchor");
    let preserve = CopyOptions {
        preserve_links: true,
        ..CopyOptions::default()
    };
    let mut session = cpcopy::CopySession::default();
    session
        .copy_with_events(&original, &anchor, &preserve, &mut |_| Ok(()))
        .unwrap();
    // Keep the old inode allocated so the replacement cannot accidentally reuse it.
    std::fs::rename(&anchor, tree.path().join("saved-original")).unwrap();
    let replacement = tree.path().join("replacement");
    std::fs::create_dir(&replacement).unwrap();
    std::fs::write(replacement.join("anchor"), b"replacement payload").unwrap();
    std::fs::write(replacement.join("sibling"), b"independent sibling").unwrap();
    session
        .copy_with_events(
            &replacement,
            &destination,
            &CopyOptions {
                jobs: 4,
                merge_directories: true,
                preserve_links: false,
                ..CopyOptions::default()
            },
            &mut |_| Ok(()),
        )
        .unwrap();
    let later = tree.path().join("later-original");
    session
        .copy_with_events(&original, &later, &preserve, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(std::fs::read(&later).unwrap(), b"original payload");
    assert_eq!(std::fs::read(&anchor).unwrap(), b"replacement payload");
    assert_ne!(
        std::fs::metadata(&later).unwrap().ino(),
        std::fs::metadata(&anchor).unwrap().ino()
    );
}
