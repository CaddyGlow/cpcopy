#![cfg(all(target_os = "linux", feature = "cli"))]

use std::process::Command;

#[test]
fn zero_byte_write_reports_no_space_like_gnu_cp() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("source"), b"payload").unwrap();
    let shim = tree.path().join("zero.c");
    let library = tree.path().join("zero.so");
    std::fs::write(
        &shim,
        r#"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
ssize_t write(int fd,const void *data,size_t size) {
 char link[80],path[4096];
 snprintf(link,sizeof link,"/proc/self/fd/%d",fd);
 ssize_t n=readlink(link,path,sizeof path-1);
 if(n>=0) {
  path[n]=0; char *base=strrchr(path,'/');
  if(base && !strcmp(base+1,"destination")) return 0;
 }
 return ((ssize_t(*)(int,const void*,size_t))dlsym(RTLD_NEXT,"write"))(fd,data,size);
}
"#,
    )
    .unwrap();
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
    let run = |program: &str| {
        let _ = std::fs::remove_file(tree.path().join("destination"));
        Command::new(program)
            .current_dir(tree.path())
            .env("LC_ALL", "C")
            .env("LD_PRELOAD", &library)
            .args(["--reflink=never", "source", "destination"])
            .output()
            .unwrap()
    };
    let reference = run("cp");
    let actual = run(env!("CARGO_BIN_EXE_cpcopy"));
    assert!(!reference.status.success());
    assert_eq!(actual.status.code(), reference.status.code());
    assert_eq!(
        actual.stderr.strip_prefix(b"cpcopy: ").unwrap(),
        reference.stderr.strip_prefix(b"cp: ").unwrap()
    );
}
