#![cfg(all(target_os = "linux", feature = "cli"))]
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::symlink},
    process::Command,
};

#[test]
fn uncommon_traversal_failures_match_gnu_diagnostics() {
    let tree = tempfile::tempdir().unwrap();
    let shim = tree.path().join("shim.c");
    let library = tree.path().join("shim.so");
    std::fs::write(&shim, r#"
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#define MATCH(n) (getenv("CPCOPY_FAULT") && !strcmp(getenv("CPCOPY_FAULT"),n))
#define WRAP(name, args, actual, err) int name args {if(MATCH(#name)){errno=err;return -1;}int(*real) args=dlsym(RTLD_NEXT,#name);return real actual;}
ssize_t readlink(const char*p,char*b,size_t s){if(MATCH("readlink")){errno=EIO;return -1;}ssize_t(*real)(const char*,char*,size_t)=dlsym(RTLD_NEXT,"readlink");return real(p,b,s);}
ssize_t readlinkat(int d,const char*p,char*b,size_t s){if(MATCH("readlink")){errno=EIO;return -1;}ssize_t(*real)(int,const char*,char*,size_t)=dlsym(RTLD_NEXT,"readlinkat");return real(d,p,b,s);}
ssize_t __readlink_chk(const char*p,char*b,size_t s,size_t bs){return readlink(p,b,s);}
ssize_t __readlinkat_chk(int d,const char*p,char*b,size_t s,size_t bs){return readlinkat(d,p,b,s);}
WRAP(symlink,(const char*a,const char*b),(a,b),ENOSPC)
int symlinkat(const char*a,int d,const char*b){if(MATCH("symlink")){errno=ENOSPC;return -1;}int(*real)(const char*,int,const char*)=dlsym(RTLD_NEXT,"symlinkat");return real(a,d,b);}
WRAP(mkdir,(const char*p,mode_t m),(p,m),EACCES)
int mkdirat(int d,const char*p,mode_t m){if(MATCH("mkdir")){errno=EACCES;return -1;}int(*real)(int,const char*,mode_t)=dlsym(RTLD_NEXT,"mkdirat");return real(d,p,m);}
struct dirent* readdir(DIR*d){if(MATCH("readdir")){errno=EIO;return NULL;}struct dirent*(*real)(DIR*)=dlsym(RTLD_NEXT,"readdir");return real(d);}
WRAP(chmod,(const char*p,mode_t m),(p,m),EPERM)
WRAP(utimensat,(int d,const char*p,const struct timespec*t,int f),(d,p,t,f),EPERM)
WRAP(rename,(const char*a,const char*b),(a,b),EACCES)
int renameat(int a,const char*b,int c,const char*d){if(MATCH("rename")){errno=EACCES;return -1;}int(*real)(int,const char*,int,const char*)=dlsym(RTLD_NEXT,"renameat");return real(a,b,c,d);}
int renameat2(int a,const char*b,int c,const char*d,unsigned f){if(MATCH("rename")){errno=EACCES;return -1;}int(*real)(int,const char*,int,const char*,unsigned)=dlsym(RTLD_NEXT,"renameat2");return real(a,b,c,d,f);}
WRAP(unlink,(const char*p),(p),EACCES)
int unlinkat(int d,const char*p,int f){if(MATCH("unlink")){errno=EACCES;return -1;}int(*real)(int,const char*,int)=dlsym(RTLD_NEXT,"unlinkat");return real(d,p,f);}
int mkfifo(const char*p,mode_t m){if(MATCH("mknod")){errno=EPERM;return -1;}int(*real)(const char*,mode_t)=dlsym(RTLD_NEXT,"mkfifo");return real(p,m);}
int mkfifoat(int d,const char*p,mode_t m){if(MATCH("mknod")){errno=EPERM;return -1;}int(*real)(int,const char*,mode_t)=dlsym(RTLD_NEXT,"mkfifoat");return real(d,p,m);}
WRAP(mknod,(const char*p,mode_t m,dev_t v),(p,m,v),EPERM)
int mknodat(int d,const char*p,mode_t m,dev_t v){if(MATCH("mknod")){errno=EPERM;return -1;}int(*real)(int,const char*,mode_t,dev_t)=dlsym(RTLD_NEXT,"mknodat");return real(d,p,m,v);}
"#).unwrap();
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
    for (fault, arguments) in [
        ("readlink", vec!["-P", "source", "destination"]),
        ("symlink", vec!["-P", "source", "destination"]),
        ("mkdir", vec!["-R", "source", "destination"]),
        ("readdir", vec!["-R", "source", "destination"]),
        (
            "unlink",
            vec!["--remove-destination", "source", "destination"],
        ),
        ("mknod", vec!["-R", "source", "destination"]),
        ("rename", vec!["-b", "source", "destination"]),
        (
            "chmod",
            vec!["-R", "--preserve=mode", "source", "destination"],
        ),
        (
            "utimensat",
            vec!["-P", "--preserve=timestamps", "source", "destination"],
        ),
        (
            "utimensat",
            vec!["-R", "--preserve=mode,timestamps", "source", "destination"],
        ),
        (
            "mkdir_parents",
            vec!["--parents", "parent/source", "destination"],
        ),
    ] {
        let mut outputs = Vec::new();
        for (index, executable) in ["cp", env!("CARGO_BIN_EXE_cpcopy")].into_iter().enumerate() {
            let directory = tree
                .path()
                .join(format!("{fault}_{index}_{}", arguments.contains(&"-R")));
            std::fs::create_dir(&directory).unwrap();
            match fault {
                "mkdir_parents" => {
                    std::fs::create_dir(directory.join("parent")).unwrap();
                    std::fs::write(directory.join("parent/source"), b"new").unwrap();
                    std::fs::create_dir(directory.join("destination")).unwrap();
                }
                "readlink" | "symlink" => symlink("referent", directory.join("source")).unwrap(),
                "utimensat" if arguments.contains(&"-P") => {
                    symlink("referent", directory.join("source")).unwrap()
                }
                "mkdir" | "chmod" | "readdir" | "utimensat" => {
                    std::fs::create_dir(directory.join("source")).unwrap()
                }
                "mknod" => {
                    let path =
                        CString::new(directory.join("source").as_os_str().as_bytes()).unwrap();
                    // SAFETY: Terminated pathname and valid FIFO permissions.
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => {
                    std::fs::write(directory.join("source"), b"new").unwrap();
                    std::fs::write(directory.join("destination"), b"old").unwrap();
                }
            }
            if directory.join("source").is_dir() {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    directory.join("source"),
                    std::fs::Permissions::from_mode(0o754),
                )
                .unwrap();
            }
            let output = Command::new(executable)
                .current_dir(&directory)
                .env("LD_PRELOAD", &library)
                .env(
                    "CPCOPY_FAULT",
                    if fault == "mkdir_parents" {
                        "mkdir"
                    } else {
                        fault
                    },
                )
                .env("LC_ALL", "C")
                .args(&arguments)
                .output()
                .unwrap();
            assert!(!output.status.success(), "{executable} {fault}");
            if fault == "utimensat" && arguments.contains(&"-R") {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(directory.join("destination"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o754,
                    "{executable}"
                );
            }
            outputs.push(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .replace("cpcopy:", "cp:"),
            );
        }
        assert_eq!(outputs[0], outputs[1], "{fault}");
    }
}
