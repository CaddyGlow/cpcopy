#![cfg(all(target_os = "linux", feature = "cli"))]
use std::process::Command;

#[test]
fn uncommon_regular_file_failures_match_gnu_diagnostics() {
    let tree = tempfile::tempdir().unwrap();
    let shim = tree.path().join("shim.c");
    let library = tree.path().join("shim.so");
    std::fs::write(&shim, r#"
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
static int fault(const char *name){return !strcmp(getenv("FAULT"),name);}
static int named(int fd,const char *name){char link[80],path[4096];snprintf(link,sizeof link,"/proc/self/fd/%d",fd);ssize_t n=readlink(link,path,sizeof path-1);if(n<0)return 0;path[n]=0;char *base=strrchr(path,'/');return base && !strcmp(base+1,name);}
int fstat(int fd,struct stat *s){int r=((int(*)(int,struct stat*))dlsym(RTLD_NEXT,"fstat"))(fd,s);if(r)return r;if((fault("source-stat") && named(fd,"source")) || (fault("dest-stat") && named(fd,"destination"))){errno=EIO;return -1;}if(fault("replaced") && named(fd,"source"))s->st_ino++;if(fault("owner") && named(fd,"source"))s->st_uid=0;return 0;}
int fstat64(int fd,struct stat64 *s){int r=((int(*)(int,struct stat64*))dlsym(RTLD_NEXT,"fstat64"))(fd,s);if(r)return r;if((fault("source-stat") && named(fd,"source")) || (fault("dest-stat") && named(fd,"destination"))){errno=EIO;return -1;}if(fault("replaced") && named(fd,"source"))s->st_ino++;if(fault("owner") && named(fd,"source"))s->st_uid=0;return 0;}
int ftruncate(int fd,off_t size){if(fault("truncate") && size==0){errno=EIO;return -1;}return ((int(*)(int,off_t))dlsym(RTLD_NEXT,"ftruncate"))(fd,size);}
int ftruncate64(int fd,off64_t size){return ftruncate(fd,size);}
int acl_set_fd(int fd,void*acl){if(fault("acl-write")){errno=EIO;return -1;}return ((int(*)(int,void*))dlsym(RTLD_NEXT,"acl_set_fd"))(fd,acl);}
int fsetxattr(int fd,const char*n,const void*v,size_t size,int flags){if(fault("acl-write") && !strcmp(n,"system.posix_acl_access")){errno=EIO;return -1;}return ((int(*)(int,const char*,const void*,size_t,int))dlsym(RTLD_NEXT,"fsetxattr"))(fd,n,v,size,flags);}
void *acl_get_fd(int fd){if(fault("acl-read")){errno=EIO;return NULL;}return ((void*(*)(int))dlsym(RTLD_NEXT,"acl_get_fd"))(fd);}
ssize_t getxattr(const char*p,const char*n,void*v,size_t size){if(fault("acl-read") && !strcmp(n,"system.posix_acl_access")){errno=EIO;return -1;}return ((ssize_t(*)(const char*,const char*,void*,size_t))dlsym(RTLD_NEXT,"getxattr"))(p,n,v,size);}
ssize_t fgetxattr(int fd,const char*n,void*v,size_t size){if(fault("acl-read") && !strcmp(n,"system.posix_acl_access")){errno=EIO;return -1;}return ((ssize_t(*)(int,const char*,void*,size_t))dlsym(RTLD_NEXT,"fgetxattr"))(fd,n,v,size);}
int fchown(int fd,uid_t u,gid_t g){if(fault("owner")){errno=EIO;return -1;}return ((int(*)(int,uid_t,gid_t))dlsym(RTLD_NEXT,"fchown"))(fd,u,g);}
int futimens(int fd,const struct timespec times[2]){if(fault("times")){errno=EIO;return -1;}return ((int(*)(int,const struct timespec*))dlsym(RTLD_NEXT,"futimens"))(fd,times);}
int fchmod(int fd,mode_t mode){if(fault("mode")){errno=EIO;return -1;}return ((int(*)(int,mode_t))dlsym(RTLD_NEXT,"fchmod"))(fd,mode);}
int open(const char*p,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}if(fault("truncate") && (flags&O_TRUNC)){errno=EIO;return -1;}if((fault("remove") || fault("remove-gone")) && (!strcmp(p,"destination") || (strrchr(p,'/') && !strcmp(strrchr(p,'/')+1,"destination"))) && !(flags&O_EXCL) && (flags&O_ACCMODE)!=O_RDONLY){errno=EACCES;return -1;}return ((int(*)(const char*,int,...))dlsym(RTLD_NEXT,"open"))(p,flags,mode);}
int open64(const char*p,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}if(fault("truncate") && (flags&O_TRUNC)){errno=EIO;return -1;}if((fault("remove") || fault("remove-gone")) && (!strcmp(p,"destination") || (strrchr(p,'/') && !strcmp(strrchr(p,'/')+1,"destination"))) && !(flags&O_EXCL) && (flags&O_ACCMODE)!=O_RDONLY){errno=EACCES;return -1;}return ((int(*)(const char*,int,...))dlsym(RTLD_NEXT,"open64"))(p,flags,mode);}
int openat(int fd,const char*p,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}if(fault("truncate") && (flags&O_TRUNC)){errno=EIO;return -1;}if((fault("remove") || fault("remove-gone")) && (!strcmp(p,"destination") || (strrchr(p,'/') && !strcmp(strrchr(p,'/')+1,"destination"))) && !(flags&O_EXCL) && (flags&O_ACCMODE)!=O_RDONLY){errno=EACCES;return -1;}return ((int(*)(int,const char*,int,...))dlsym(RTLD_NEXT,"openat"))(fd,p,flags,mode);}
int ioctl(int fd,unsigned long request,...){if(fault("clone-partial")){if(write(fd,"partial",7)!=7)_exit(120);}errno=EIO;return -1;}
int unlink(const char*p){if(fault("clone-gone") || fault("remove-gone")){((int(*)(const char*))dlsym(RTLD_NEXT,"unlink"))(p);errno=ENOENT;return -1;}if(fault("clone-remove")){errno=EACCES;return -1;}if(fault("remove")){errno=EIO;return -1;}return ((int(*)(const char*))dlsym(RTLD_NEXT,"unlink"))(p);}
int unlinkat(int fd,const char*p,int flags){if(fault("clone-gone") || fault("remove-gone")){((int(*)(int,const char*,int))dlsym(RTLD_NEXT,"unlinkat"))(fd,p,flags);errno=ENOENT;return -1;}if(fault("clone-remove")){errno=EACCES;return -1;}if(fault("remove")){errno=EIO;return -1;}return ((int(*)(int,const char*,int))dlsym(RTLD_NEXT,"unlinkat"))(fd,p,flags);}
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
        ("source-stat", vec!["--reflink=never"]),
        ("dest-stat", vec!["--reflink=never"]),
        ("replaced", vec!["--reflink=never"]),
        ("owner", vec!["-p", "--reflink=never"]),
        ("times", vec!["-p", "--reflink=never"]),
        ("mode", vec!["-p", "--reflink=never"]),
        ("remove", vec!["-f", "--reflink=never"]),
        ("remove-gone", vec!["-f", "--reflink=never"]),
        ("truncate", vec!["--reflink=never"]),
        ("acl-read", vec!["-p", "--reflink=never"]),
        ("acl-write", vec!["-p", "--reflink=never"]),
        ("clone-remove", vec!["--reflink=always"]),
        ("clone-partial", vec!["--reflink=always"]),
        ("clone-gone", vec!["--reflink=always"]),
    ] {
        let output = |program: &str| {
            std::fs::write(tree.path().join("source"), b"payload").unwrap();
            if matches!(fault, "acl-read" | "acl-write") {
                use std::os::unix::ffi::OsStrExt;
                let name =
                    std::ffi::CString::new(tree.path().join("source").as_os_str().as_bytes())
                        .unwrap();
                let mut acl = 2_u32.to_le_bytes().to_vec();
                for (tag, permissions, id) in [
                    (1_u16, 6_u16, u32::MAX),
                    (2, 4, unsafe { libc::getuid() }),
                    (4, 0, u32::MAX),
                    (16, 4, u32::MAX),
                    (32, 0, u32::MAX),
                ] {
                    acl.extend(tag.to_le_bytes());
                    acl.extend(permissions.to_le_bytes());
                    acl.extend(id.to_le_bytes());
                }
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
            }
            let _ = std::fs::remove_file(tree.path().join("destination"));
            if matches!(fault, "remove" | "remove-gone" | "truncate") {
                std::fs::write(tree.path().join("destination"), b"keep").unwrap();
            }
            Command::new(program)
                .current_dir(tree.path())
                .env("LC_ALL", "C")
                .env("LD_PRELOAD", &library)
                .env("FAULT", fault)
                .args(&arguments)
                .args(["source", "destination"])
                .output()
                .unwrap()
        };
        let state = || {
            use std::os::unix::fs::MetadataExt;
            (
                std::fs::read(tree.path().join("destination")).ok(),
                std::fs::metadata(tree.path().join("destination"))
                    .ok()
                    .map(|metadata| metadata.mode() & 0o7777),
            )
        };
        let reference = output("cp");
        let reference_state = state();
        let actual = output(env!("CARGO_BIN_EXE_cpcopy"));
        assert_eq!(
            state(),
            reference_state,
            "{fault}: retained destination state"
        );
        assert!(
            reference.status.success() == (fault == "remove-gone"),
            "{fault}: GNU fixture did not inject failure {}",
            String::from_utf8_lossy(&reference.stderr)
        );
        assert_eq!(
            actual.status.code(),
            reference.status.code(),
            "{fault}: {}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&actual.stderr).replace("cpcopy: ", "cp: "),
            String::from_utf8_lossy(&reference.stderr),
            "{fault}"
        );
    }
}
