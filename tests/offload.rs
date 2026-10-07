#![cfg(target_os = "linux")]

use cpcopy::{CopyOptions, EventKind, ReflinkMode, SparseMode, copy_with_events};

#[test]
fn regular_copy_attempts_offload_when_reflinks_are_allowed() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    let data: Vec<u8> = (0..2_000_000).map(|index| (index % 251) as u8).collect();
    std::fs::write(&source, &data).unwrap();
    let mut diagnostics = None;
    let options = CopyOptions {
        reflink: ReflinkMode::Auto,
        sparse: SparseMode::Auto,
        ..CopyOptions::default()
    };
    copy_with_events(
        &source,
        &destination,
        &options,
        &mut |event: &cpcopy::CopyEvent| {
            if event.kind == EventKind::Completed {
                diagnostics = event.diagnostics;
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), data);
    let diagnostics = diagnostics.unwrap();
    assert!(diagnostics.cloned || diagnostics.offload_attempted);
}

#[test]
fn disabling_reflinks_also_disables_implicit_offload_cloning() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    let destination = tree.path().join("destination");
    std::fs::write(&source, b"ordinary data").unwrap();
    copy_with_events(
        &source,
        &destination,
        &CopyOptions::default(),
        &mut |event: &cpcopy::CopyEvent| {
            if let Some(diagnostics) = event.diagnostics {
                assert!(!diagnostics.offload_attempted);
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn zero_sized_proc_stat_does_not_lose_readable_contents() {
    let tree = tempfile::tempdir().unwrap();
    let destination = tree.path().join("version");
    let expected = std::fs::read("/proc/version").unwrap();
    let options = CopyOptions {
        reflink: ReflinkMode::Auto,
        preserve_timestamps: false,
        ..CopyOptions::default()
    };
    copy_with_events(
        std::path::Path::new("/proc/version"),
        &destination,
        &options,
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), expected);
}
