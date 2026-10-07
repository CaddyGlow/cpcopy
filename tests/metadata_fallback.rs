#![cfg(all(target_os = "linux", feature = "cli"))]

use std::{ffi::CString, os::unix::ffi::OsStrExt, process::Command};

#[test]
fn unsupported_destination_xattrs_are_optional_for_archive_but_required_explicitly() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"metadata fallback payload").unwrap();
    let name = CString::new(source.as_os_str().as_bytes()).unwrap();
    // SAFETY: Terminated path and attribute name, initialized three-byte value.
    assert_eq!(
        unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"user.cpcopy_test".as_ptr(),
                b"yes".as_ptr().cast(),
                3,
                0,
            )
        },
        0
    );
    let shim = tree.path().join("shim.c");
    let library = tree.path().join("shim.so");
    std::fs::write(&shim, "#include <errno.h>\n#include <stddef.h>\nint fsetxattr(int fd,const char *n,const void *v,size_t s,int f){errno=EOPNOTSUPP;return -1;}\nint setxattr(const char *p,const char *n,const void *v,size_t s,int f){errno=EOPNOTSUPP;return -1;}\n").unwrap();
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&shim)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    for (arguments, succeeds, silent) in [
        (vec!["-a"], true, true),
        (vec!["--preserve=all"], true, true),
        (vec!["--preserve=xattr"], false, false),
        (vec!["-a", "--preserve=xattr"], false, false),
        (vec!["--preserve=xattr", "-a"], false, false),
        (
            vec!["--preserve=xattr", "--no-preserve=xattr", "-a"],
            true,
            true,
        ),
        (vec!["--attributes-only", "--preserve=all"], true, false),
    ] {
        for executable in ["cp", env!("CARGO_BIN_EXE_cpcopy")] {
            let destination = tree.path().join("destination");
            let _ = std::fs::remove_file(&destination);
            let output = Command::new(executable)
                .env("LD_PRELOAD", &library)
                .env("LC_ALL", "C")
                .args(&arguments)
                .arg(&source)
                .arg(&destination)
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                succeeds,
                "{executable} {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stderr.is_empty(),
                silent,
                "{executable} {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if !arguments.contains(&"--attributes-only") {
                assert_eq!(
                    std::fs::read(&destination).unwrap(),
                    b"metadata fallback payload"
                );
            }
        }
    }
}

#[test]
fn unavailable_acl_interface_falls_back_to_permission_bits() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"acl fallback").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o754)).unwrap();
    let shim = tree.path().join("acl.c");
    let library = tree.path().join("acl.so");
    std::fs::write(&shim, "#include <errno.h>\n#include <stddef.h>\n#include <sys/types.h>\nssize_t fgetxattr(int fd,const char *n,void *v,size_t s){errno=ENOSYS;return -1;}\nint fremovexattr(int fd,const char *n){errno=ENOSYS;return -1;}\nssize_t getxattr(const char *p,const char *n,void *v,size_t s){errno=ENOSYS;return -1;}\nint removexattr(const char *p,const char *n){errno=ENOSYS;return -1;}\n").unwrap();
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&shim)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    let directory = tree.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o754)).unwrap();
    for source in [&source, &directory] {
        for executable in ["cp", env!("CARGO_BIN_EXE_cpcopy")] {
            let destination = tree.path().join(if source.is_dir() {
                "directory_destination"
            } else {
                "file_destination"
            });
            let output = Command::new(executable)
                .env("LD_PRELOAD", &library)
                .args(["-R", "--preserve=mode", "--reflink=never"])
                .arg(source)
                .arg(&destination)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{executable}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
                0o754
            );
        }
    }
}

#[test]
fn optional_xattr_failure_does_not_prevent_later_attributes() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"continue metadata").unwrap();
    let source_name = CString::new(source.as_os_str().as_bytes()).unwrap();
    for attribute in [c"user.fail", c"user.ok"] {
        // SAFETY: Terminated names and initialized value with exact length.
        assert_eq!(
            unsafe {
                libc::setxattr(
                    source_name.as_ptr(),
                    attribute.as_ptr(),
                    b"yes".as_ptr().cast(),
                    3,
                    0,
                )
            },
            0
        );
    }
    let shim = tree.path().join("continue.c");
    let library = tree.path().join("continue.so");
    std::fs::write(&shim, "#define _GNU_SOURCE\n#include <errno.h>\n#include <stddef.h>\n#include <string.h>\n#include <dlfcn.h>\nint fsetxattr(int fd,const char *n,const void *v,size_t s,int f){if(!strcmp(n,\"user.fail\")){errno=EPERM;return -1;}int (*real)(int,const char*,const void*,size_t,int)=dlsym(RTLD_NEXT,\"fsetxattr\");return real(fd,n,v,s,f);}\n").unwrap();
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&shim)
            .args(["-ldl", "-o"])
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    for option in ["-a", "--preserve=all"] {
        for executable in ["cp", env!("CARGO_BIN_EXE_cpcopy")] {
            let destination = tree.path().join("destination");
            let _ = std::fs::remove_file(&destination);
            let output = Command::new(executable)
                .env("LD_PRELOAD", &library)
                .arg(option)
                .arg(&source)
                .arg(&destination)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{executable} {option}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stderr.is_empty(),
                option == "-a",
                "{executable} {option}"
            );
            let name = CString::new(destination.as_os_str().as_bytes()).unwrap();
            let mut value = [0u8; 3];
            // SAFETY: Terminated names and writable bounded value buffer.
            assert_eq!(
                unsafe {
                    libc::getxattr(
                        name.as_ptr(),
                        c"user.ok".as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                },
                3,
                "{executable} {option}"
            );
            assert_eq!(&value, b"yes");
        }
    }
}

#[test]
fn unsupported_source_xattr_enumeration_is_not_a_preservation_failure() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    std::fs::write(&source, b"no xattr support").unwrap();
    let shim = tree.path().join("enumerate.c");
    let library = tree.path().join("enumerate.so");
    std::fs::write(&shim, "#include <errno.h>\n#include <stddef.h>\n#include <sys/types.h>\nssize_t flistxattr(int fd,char*n,size_t s){errno=EOPNOTSUPP;return -1;}\n").unwrap();
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&shim)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    for executable in ["cp", env!("CARGO_BIN_EXE_cpcopy")] {
        let output = Command::new(executable)
            .env("LD_PRELOAD", &library)
            .arg("--preserve=xattr")
            .arg(&source)
            .arg(tree.path().join("destination"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{executable}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{executable}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
