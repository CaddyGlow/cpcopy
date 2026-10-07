#![cfg(all(target_os = "linux", feature = "cli"))]
use std::process::Command;

#[test]
fn terminal_transfer_failures_match_gnu_operation_diagnostics() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("source"), b"transfer failure payload").unwrap();
    let shim = tree.path().join("shim.c");
    let library = tree.path().join("shim.so");
    std::fs::write(&shim, r#"
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
static int target(int fd) {
 char link[80], path[4096]; snprintf(link,sizeof link,"/proc/self/fd/%d",fd);
 ssize_t n=readlink(link,path,sizeof path-1); if(n<0)return 0;path[n]=0;
 char *name=strrchr(path,'/');return name && !strcmp(name+1,"destination");
}
int close(int fd) {
 int fail=target(fd) && !strcmp(getenv("FAULT"),"close");
 int result=((int(*)(int))dlsym(RTLD_NEXT,"close"))(fd);
 if(fail){errno=EIO;return -1;} return result;
}
int ftruncate(int fd,off_t size) {
 if(target(fd) && !strcmp(getenv("FAULT"),"extend")){errno=EIO;return -1;}
 return ((int(*)(int,off_t))dlsym(RTLD_NEXT,"ftruncate"))(fd,size);
}
int ftruncate64(int fd,off64_t size){return ftruncate(fd,size);}
off_t lseek(int fd,off_t offset,int whence) {
 if(!strcmp(getenv("FAULT"),"seek") && (whence==SEEK_DATA || whence==SEEK_HOLE)){errno=EIO;return -1;}
 return ((off_t(*)(int,off_t,int))dlsym(RTLD_NEXT,"lseek"))(fd,offset,whence);
}
off64_t lseek64(int fd,off64_t offset,int whence){return lseek(fd,offset,whence);}
int ioctl(int fd,unsigned long request,...) {
 errno=!strcmp(getenv("FAULT"),"clone")?EIO:EOPNOTSUPP;return -1;
}
ssize_t copy_file_range(int a,off64_t*b,int c,off64_t*d,size_t n,unsigned int f){errno=EIO;return -1;}
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
        ("close", vec!["--reflink=never"]),
        ("clone", vec!["--reflink=always"]),
        ("offload", vec!["--reflink=auto"]),
        ("extend", vec!["--reflink=never", "--sparse=always"]),
        ("seek", vec!["--reflink=never"]),
    ] {
        std::fs::write(
            tree.path().join("source"),
            if fault == "extend" {
                vec![0; 8192]
            } else {
                b"transfer failure payload".to_vec()
            },
        )
        .unwrap();
        if fault == "seek" {
            std::fs::File::create(tree.path().join("source"))
                .unwrap()
                .set_len(8192)
                .unwrap();
        }
        let output = |program: &str| {
            let _ = std::fs::remove_file(tree.path().join("destination"));
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
        let reference = output("cp");
        let actual = output(env!("CARGO_BIN_EXE_cpcopy"));
        assert!(
            !reference.status.success(),
            "{fault}: missing injected failure"
        );
        assert_eq!(actual.status.code(), reference.status.code(), "{fault}");
        assert_eq!(
            actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
            reference.stderr.strip_prefix(b"cp: ").unwrap(),
            "{fault}"
        );
    }
}
