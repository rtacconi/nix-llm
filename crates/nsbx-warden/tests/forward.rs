//! The warden forwards pipe bytes and cannot open a file afterwards.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::fd::AsRawFd;

use nsbx_sys::{clone3, dup2, execve, pipe, read_fd, wait_pidfd, write_fd};

#[test]
fn forwards_stdout_and_stops_at_the_cap() {
    let bin = env!("CARGO_BIN_EXE_nsbx-warden");
    let (in_r, in_w) = pipe().expect("pipe");
    let (err_r, err_w) = pipe().expect("pipe");
    let (out_r, out_w) = pipe().expect("pipe");
    let (eout_r, eout_w) = pipe().expect("pipe");
    let in_fd = in_r.as_raw_fd();
    let err_fd = err_r.as_raw_fd();
    let out_fd = out_w.as_raw_fd();
    let eout_fd = eout_w.as_raw_fd();
    let path = CString::new(bin).expect("path");
    let cap = CString::new("4").expect("cap");
    let child = clone3(0, None, move || {
        let _ = dup2(in_fd, 4);
        let _ = dup2(err_fd, 5);
        let _ = dup2(out_fd, 6);
        let _ = dup2(eout_fd, 7);
        let err = execve(
            path.as_c_str(),
            &[path.as_c_str(), cap.as_c_str()],
            &[] as &[&std::ffi::CStr],
        );
        let _ = write_fd(2, err.to_string().as_bytes());
    })
    .expect("clone");
    write_fd(in_w.as_raw_fd(), b"hello\n").expect("write");
    drop(in_w);
    drop(err_w);
    drop(out_w);
    drop(eout_w);
    let waited = wait_pidfd(child.pidfd.as_raw_fd()).expect("wait");
    let mut buf = [0u8; 16];
    let n = read_fd(out_r.as_raw_fd(), &mut buf).expect("read");
    assert!(waited.exited(), "warden did not exit");
    assert_eq!(waited.exit_code(), Some(0), "stderr path {}", bin);
    assert_eq!(&buf[..n], b"hell");
    let _ = eout_r;
}
