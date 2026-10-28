//! M0 experiments E1–E7. Each subcommand prints one JSON object.
//!
//! `cargo run --manifest-path experiments/m0/Cargo.toml --release -- e1`

mod sys;

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::RawFd;
use std::process::ExitCode;

use serde_json::{json, Value};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(which) = args.next() else {
        eprintln!("usage: nsbx-m0 <e1|e2|e3|e4|e5|e6|e7>");
        return ExitCode::from(2);
    };
    if which == "e1-child" {
        println!("{}", json!({"probe":"e1-child","euid":unsafe { libc::geteuid() }}));
        return ExitCode::SUCCESS;
    }
    let result = match which.as_str() {
        "e1" => e1(),
        "e2" => e2(),
        "e3" => e3(),
        "e4" => e4(),
        "e5" => e5(),
        "e6" => e6(),
        "e7" => e7(),
        other => Err(format!("unknown experiment {other}")),
    };
    match result {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", json!({"experiment": which, "error": e}));
            ExitCode::from(1)
        }
    }
}

fn status_ok(status: i32) -> bool {
    unsafe { libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 }
}

fn e1() -> Result<Value, String> {
    let exe = CString::new("/proc/self/exe").map_err(|e| e.to_string())?;
    let path_fd = unsafe { libc::open(exe.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if path_fd < 0 {
        return Err(format!("open O_PATH: {}", std::io::Error::last_os_error()));
    }
    let rd_fd = unsafe { libc::open(exe.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if rd_fd < 0 {
        return Err(format!("open O_RDONLY: {}", std::io::Error::last_os_error()));
    }
    let before = exec_trial(path_fd, false)?;
    let after_path = exec_trial(path_fd, true)?;
    let after_rd = exec_trial(rd_fd, true)?;
    unsafe {
        libc::close(path_fd);
        libc::close(rd_fd);
    }
    Ok(json!({
        "experiment": "e1",
        "question": "execveat(AT_EMPTY_PATH) of an O_PATH fd from a fresh clone3 child",
        "opath_before_uid_map": before,
        "opath_after_uid_map": after_path,
        "ordonly_after_uid_map": after_rd,
    }))
}

fn exec_trial(fd: RawFd, map: bool) -> Result<Value, String> {
    let argv0 = CString::new("nsbx-m0").unwrap();
    let argv1 = CString::new("e1-child").unwrap();
    let (status, output) = sys::run_child(sys::CLONE_NEWPID, map, move || {
        let err = sys::execveat_empty(fd, &[argv0.as_c_str(), argv1.as_c_str()], &[]);
        eprintln!("execveat: {err}");
        unsafe { libc::_exit(127) };
    })
    .map_err(|e| e.to_string())?;
    Ok(json!({
        "mapped_first": map,
        "exited_ok": status_ok(status),
        "status": status,
        "output": output.trim(),
    }))
}

fn e2() -> Result<Value, String> {
    let python = std::env::var("E2_STORE").unwrap_or_else(|_| {
        "/nix/store/fcqcsdj8fp07d35w0m16bdywf1vhs2c7-python3-3.13.15-env".into()
    });
    let closure = store_closure(&python)?;
    let mut samples = Vec::new();
    for n in [1usize, 10, 40, 80] {
        if n > closure.len() {
            break;
        }
        let started = std::time::Instant::now();
        let (status, output) = bind_n(&closure[..n])?;
        samples.push(json!({
            "paths": n,
            "wall_ms": started.elapsed().as_secs_f64() * 1000.0,
            "exited_ok": status_ok(status),
            "output": output.trim(),
        }));
    }
    Ok(json!({
        "experiment": "e2",
        "question": "per-path bind cost versus closure size",
        "closure_len": closure.len(),
        "samples": samples,
        "note": "one run on this host; not an M8 benchmark",
    }))
}

fn store_closure(path: &str) -> Result<Vec<String>, String> {
    let out = std::process::Command::new("nix-store")
        .args(["--query", "--requisites", path])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("/nix/store/"))
        .map(str::to_owned)
        .collect())
}

fn bind_n(paths: &[String]) -> Result<(i32, String), String> {
    let owned = paths.to_vec();
    sys::run_child(sys::CLONE_NEWNS, true, move || {
        let outcome = (|| -> std::io::Result<()> {
            sys::mount(c"none", c"/", c"none", (libc::MS_REC | libc::MS_PRIVATE) as u64, None)?;
            let base = "/tmp/nsbx-e2-root";
            let _ = std::fs::remove_dir_all(base);
            std::fs::create_dir_all(base)?;
            let base_c = sys::cstring(base);
            sys::mount(c"tmpfs", &base_c, c"tmpfs", 0, Some(c"size=64m,mode=755"))?;
            for (i, p) in owned.iter().enumerate() {
                attach(p, &format!("{base}/b{i}"))?;
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => println!("ok"),
            Err(ref e) => println!("err {e}"),
        }
        unsafe { libc::_exit(if outcome.is_ok() { 0 } else { 1 }) };
    })
    .map_err(|e| e.to_string())
}

fn attach(src: &str, dest: &str) -> std::io::Result<()> {
    let meta = std::fs::metadata(src)?;
    if meta.is_dir() {
        std::fs::create_dir_all(dest)?;
    } else {
        if let Some(parent) = std::path::Path::new(dest).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::File::create(dest)?;
    }
    let tree = sys::open_tree_clone(&sys::cstring(src))?;
    let attr = sys::MOUNT_ATTR_RDONLY | sys::MOUNT_ATTR_NOSUID | sys::MOUNT_ATTR_NODEV;
    sys::mount_setattr_fd(tree, attr, meta.is_dir())?;
    let dest_fd = unsafe {
        libc::open(
            sys::cstring(dest).as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if dest_fd < 0 {
        return Err(sys::io_err("open dest"));
    }
    sys::move_mount_fd(tree, dest_fd)?;
    unsafe {
        libc::close(tree);
        libc::close(dest_fd);
    }
    Ok(())
}

fn e3() -> Result<Value, String> {
    let host_before = read_sysctl("max_user_namespaces");
    let (status, output) = sys::run_child(sys::CLONE_NEWNS | sys::CLONE_NEWPID, true, || {
        let inside = read_sysctl("max_user_namespaces");
        let write0 = write_sysctl("max_user_namespaces", "0");
        let after = read_sysctl("max_user_namespaces");
        let nested = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        let nested_errno = if nested < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let private = sys::mount(
            c"none",
            c"/",
            c"none",
            (libc::MS_REC | libc::MS_PRIVATE) as u64,
            None,
        );
        let _ = std::fs::create_dir_all("/tmp/nsbx-e3-proc");
        let plain = sys::mount(c"proc", c"/tmp/nsbx-e3-proc", c"proc", 0, None);
        let _ = unsafe { libc::umount2(c"/tmp/nsbx-e3-proc".as_ptr(), libc::MNT_DETACH) };
        let subset = sys::mount(
            c"proc",
            c"/tmp/nsbx-e3-proc",
            c"proc",
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as u64,
            Some(c"hidepid=invisible,subset=pid"),
        );
        let visible = std::fs::metadata("/tmp/nsbx-e3-proc/sys/user/max_user_namespaces").is_ok();
        let self_visible = std::fs::metadata("/tmp/nsbx-e3-proc/self").is_ok();
        unsafe { libc::umount2(c"/tmp/nsbx-e3-proc".as_ptr(), libc::MNT_DETACH) };
        println!(
            "{}",
            json!({
                "inside_before": inside,
                "write_zero": write0,
                "inside_after": after,
                "nested_unshare_errno": nested_errno,
                "private": private.map(|_| "ok".to_owned()).unwrap_or_else(|e| e.to_string()),
                "proc_plain": plain.map(|_| "ok".to_owned()).unwrap_or_else(|e| e.to_string()),
                "subset_mount": subset.map(|_| "ok".to_owned()).unwrap_or_else(|e| e.to_string()),
                "sysctl_visible_under_subset_pid": visible,
                "proc_self_visible": self_visible,
            })
        );
        unsafe { libc::_exit(0) };
    })
    .map_err(|e| e.to_string())?;
    let host_after = read_sysctl("max_user_namespaces");
    let child: Value = serde_json::from_str(output.trim()).unwrap_or(json!({"raw": output, "status": status}));
    Ok(json!({
        "experiment": "e3",
        "host_before": host_before,
        "host_after": host_after,
        "child": child,
    }))
}

fn read_sysctl(name: &str) -> String {
    std::fs::read_to_string(format!("/proc/sys/user/{name}"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|e| format!("err:{e}"))
}

fn write_sysctl(name: &str, value: &str) -> String {
    match std::fs::write(format!("/proc/sys/user/{name}"), value) {
        Ok(()) => "ok".into(),
        Err(e) => e.to_string(),
    }
}

fn e4() -> Result<Value, String> {
    let mut orders = Vec::new();
    for order in ["drop_then_uid_then_lock", "lock_fixup_then_uid", "drop_lock_then_uid", "capset_zero_at_uid0", "setuid_1000_only"] {
        let (status, output) = run_e4(order)?;
        let parsed: Value = serde_json::from_str(output.trim()).unwrap_or(json!({"raw": output}));
        orders.push(json!({"order": order, "status": status, "result": parsed}));
    }
    Ok(json!({"experiment":"e4","orders":orders}))
}

fn run_e4(order: &str) -> Result<(i32, String), String> {
    let order = order.to_owned();
    sys::run_child(0, true, move || {
        println!("{}", apply_order(&order));
        unsafe { libc::_exit(0) };
    })
    .map_err(|e| e.to_string())
}

fn apply_order(order: &str) -> Value {
    let steps: &[&str] = match order {
        "drop_then_uid_then_lock" => &["drop", "clear", "uid", "lock", "nnp"],
        "lock_fixup_then_uid" => &["drop", "clear", "lock_fixup", "uid", "nnp"],
        "drop_lock_then_uid" => &["drop", "clear", "lock", "uid", "nnp"],
        "capset_zero_at_uid0" => &["drop", "clear", "lock", "clear_all", "nnp"],
        "setuid_1000_only" => &["uid1000"],
        _ => &[],
    };
    let mut errors = Vec::new();
    for s in steps {
        if let Err(e) = step(s) {
            errors.push(format!("{s}: {e}"));
        }
    }
    json!({"errors": errors, "status": sys::read_status_caps()})
}

fn step(name: &str) -> Result<(), String> {
    match name {
        "drop" => drop_bounding(),
        "uid" => switch_ids(true),
        "uid1000" => switch_ids(false),
        "clear_all" => capset_zero(),
        "lock" => lock_securebits(false),
        "lock_fixup" => lock_securebits(true),
        "clear" => clear_ambient_inheritable(),
        "nnp" => {
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
                Err(format!("nnp {}", std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
        other => Err(format!("bad step {other}")),
    }
}

fn switch_ids(drop_groups: bool) -> Result<(), String> {
    if drop_groups && unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
        return Err(format!("setgroups {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::setresgid(1000, 1000, 1000) } < 0 {
        return Err(format!("setresgid {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::setresuid(1000, 1000, 1000) } < 0 {
        return Err(format!("setresuid {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn capset_zero() -> Result<(), String> {
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = Hdr { version: 0x2008_0522, pid: 0 };
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) };
    if rc < 0 {
        Err(format!("capset {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn drop_bounding() -> Result<(), String> {
    for cap in 0..64 {
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(format!("cap {cap}: {err}"));
            }
        }
    }
    Ok(())
}

fn lock_securebits(no_setuid_fixup: bool) -> Result<(), String> {
    const NOROOT: u64 = 1;
    const NOROOT_LOCKED: u64 = 2;
    const NO_SETUID_FIXUP: u64 = 4;
    const NO_SETUID_FIXUP_LOCKED: u64 = 8;
    const KEEP_CAPS_LOCKED: u64 = 0x20;
    const NO_CAP_AMBIENT_RAISE: u64 = 0x40;
    const NO_CAP_AMBIENT_RAISE_LOCKED: u64 = 0x80;
    let mut bits = NOROOT
        | NOROOT_LOCKED
        | NO_SETUID_FIXUP_LOCKED
        | KEEP_CAPS_LOCKED
        | NO_CAP_AMBIENT_RAISE
        | NO_CAP_AMBIENT_RAISE_LOCKED;
    if no_setuid_fixup {
        bits |= NO_SETUID_FIXUP;
    }
    if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0) } < 0 {
        Err(format!("{}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn clear_ambient_inheritable() -> Result<(), String> {
    const PR_CAP_AMBIENT: i32 = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
    if unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } < 0 {
        return Err(format!("ambient {}", std::io::Error::last_os_error()));
    }
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = Hdr { version: 0x2008_0522, pid: 0 };
    let data = [
        Data { effective: !0, permitted: !0, inheritable: 0 },
        Data { effective: !0, permitted: !0, inheritable: 0 },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) };
    if rc < 0 {
        Err(format!("capset {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn e5() -> Result<Value, String> {
    let mut tools = Vec::new();
    let python = "/nix/store/fcqcsdj8fp07d35w0m16bdywf1vhs2c7-python3-3.13.15-env";
    let py_bin = format!("{python}/bin/python3.13");
    tools.push(run_tool("python", &py_bin, &[py_bin.as_str(), "-c", "print(1)"], python)?);
    let node = "/nix/store/k3nz3s314bipvqbcbw3faq823hxpwbn1-nodejs-slim-24.19.0";
    let node_bin = format!("{node}/bin/node");
    tools.push(run_tool("node", &node_bin, &[node_bin.as_str(), "-e", "process.exit(0)"], node)?);
    tools.push(run_gcc()?);
    Ok(json!({
        "experiment": "e5",
        "question": "python, node and gcc with clone3 ENOSYS, subset=pid and no /sys",
        "tools": tools,
    }))
}

fn run_tool(name: &str, bin: &str, argv: &[&str], closure_root: &str) -> Result<Value, String> {
    let closure = store_closure(closure_root)?;
    let argv: Vec<CString> = argv.iter().map(|s| sys::cstring(s)).collect();
    let bin = bin.to_owned();
    let (status, output) = sys::run_child(
        sys::CLONE_NEWNS | sys::CLONE_NEWPID | sys::CLONE_NEWNET | sys::CLONE_NEWIPC | sys::CLONE_NEWUTS,
        true,
        move || {
            if let Err(e) = sandbox_exec(&closure, &bin, &argv) {
                println!("setup {e}");
                unsafe { libc::_exit(99) };
            }
            unsafe { libc::_exit(127) };
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({
        "tool": name,
        "exited_ok": status_ok(status),
        "status": status,
        "output": output.trim(),
    }))
}

fn run_gcc() -> Result<Value, String> {
    let gcc = "/nix/store/w88q44gqd1qg5wmkk7v0h97rpiqvam0l-gcc-wrapper-15.3.0";
    let closure = store_closure(gcc)?;
    let (status, output) = sys::run_child(
        sys::CLONE_NEWNS | sys::CLONE_NEWPID | sys::CLONE_NEWNET | sys::CLONE_NEWIPC | sys::CLONE_NEWUTS,
        true,
        move || {
            let bin = format!("{gcc}/bin/gcc");
            if let Err(e) = sandbox_then(&closure, &bin, |root| {
                let src = format!("{root}/tmp/t.c");
                std::fs::write(&src, b"int main(void){return 0;}\n")?;
                Ok(())
            }) {
                println!("setup {e}");
                unsafe { libc::_exit(99) };
            }
            unsafe { libc::_exit(127) };
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({
        "tool": "gcc",
        "exited_ok": status_ok(status),
        "status": status,
        "output": output.trim(),
    }))
}

fn sandbox_exec(closure: &[String], bin: &str, argv: &[CString]) -> std::io::Result<()> {
    pivot_sandbox(closure, |root| {
        let _ = root;
        Ok(())
    })?;
    install_clone3_enosys()?;
    Err(exec_argv(&sys::cstring(bin), argv))
}

fn sandbox_then<F>(closure: &[String], bin: &str, prep: F) -> std::io::Result<()>
where
    F: FnOnce(&str) -> std::io::Result<()>,
{
    pivot_sandbox(closure, prep)?;
    install_clone3_enosys()?;
    // Compile, then run the result. Both happen after the restrictions.
    let gcc = sys::cstring(bin);
    let args = [
        sys::cstring(bin),
        sys::cstring("-x"),
        sys::cstring("c"),
        sys::cstring("-o"),
        sys::cstring("/tmp/t"),
        sys::cstring("/tmp/t.c"),
    ];
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(sys::io_err("fork"));
    }
    if pid == 0 {
        let err = exec_argv(&gcc, &args);
        eprintln!("gcc exec: {err}");
        unsafe { libc::_exit(127) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if !status_ok(status) {
        println!("gcc status {status}");
        unsafe { libc::_exit(98) };
    }
    let out = sys::cstring("/tmp/t");
    let run = [sys::cstring("/tmp/t")];
    Err(exec_argv(&out, &run))
}

fn pivot_sandbox<F>(closure: &[String], prep: F) -> std::io::Result<()>
where
    F: FnOnce(&str) -> std::io::Result<()>,
{
    sys::mount(c"none", c"/", c"none", (libc::MS_REC | libc::MS_PRIVATE) as u64, None)?;
    let root = "/tmp/nsbx-e5-root";
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root)?;
    let root_c = sys::cstring(root);
    sys::mount(c"tmpfs", &root_c, c"tmpfs", 0, Some(c"size=512m,mode=755"))?;
    for p in closure {
        attach(p, &format!("{root}{p}"))?;
    }
    std::fs::create_dir_all(format!("{root}/dev"))?;
    for dev in ["null", "zero", "full", "random", "urandom"] {
        attach(&format!("/dev/{dev}"), &format!("{root}/dev/{dev}"))?;
    }
    std::fs::create_dir_all(format!("{root}/tmp"))?;
    std::fs::create_dir_all(format!("{root}/proc"))?;
    let proc = sys::cstring(&format!("{root}/proc"));
    sys::mount(
        c"proc",
        &proc,
        c"proc",
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as u64,
        Some(c"hidepid=invisible,subset=pid"),
    )?;
    let tmp = sys::cstring(&format!("{root}/tmp"));
    sys::mount(c"tmpfs", &tmp, c"tmpfs", 0, Some(c"size=64m,mode=1777"))?;
    prep(root)?;
    unsafe {
        if libc::chdir(root_c.as_ptr()) < 0 {
            return Err(sys::io_err("chdir"));
        }
        if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) < 0 {
            return Err(sys::io_err("pivot_root"));
        }
        if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) < 0 {
            return Err(sys::io_err("umount old root"));
        }
        if libc::chdir(c"/".as_ptr()) < 0 {
            return Err(sys::io_err("chdir /"));
        }
    }
    Ok(())
}

fn exec_argv(path: &CStr, argv: &[CString]) -> std::io::Error {
    let mut av: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = Vec::new();
    ev.push(std::ptr::null());
    unsafe { libc::execve(path.as_ptr(), av.as_ptr(), ev.as_ptr()) };
    std::io::Error::last_os_error()
}

fn install_clone3_enosys() -> std::io::Result<()> {
    use seccompiler::{SeccompAction, SeccompFilter};
    use std::convert::TryInto;
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| std::io::Error::other(e.to_string()))?;
    let filter: seccompiler::BpfProgram = SeccompFilter::new(
        vec![(libc::SYS_clone3, vec![])].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?
    .try_into()
    .map_err(|e: seccompiler::BackendError| std::io::Error::other(e.to_string()))?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(sys::io_err("nnp"));
    }
    seccompiler::apply_filter(&filter).map_err(|e| std::io::Error::other(e.to_string()))
}

fn e6() -> Result<Value, String> {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<()>(),
            0usize,
            1u32,
        )
    };
    let hard = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3));
    let missing = rustix::mount::open_tree(
        rustix::fs::CWD,
        c"/no/such/nsbx-e6",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE,
    );
    Ok(json!({
        "experiment": "e6",
        "landlock_crate": "0.4.7",
        "landlock_abi_syscall": abi,
        "hard_requirement_v3": hard.is_ok(),
        "hard_requirement_error": hard.err().map(|e| e.to_string()),
        "rustix_version": "1.1.6",
        "rustix_open_tree": missing.err().map(|e| e.to_string()),
        "rustix_has": ["open_tree", "move_mount", "mount", "unmount", "pivot_root", "openat2", "pidfd_open", "pidfd_send_signal", "waitid P_PIDFD", "unsafe execveat"],
        "rustix_missing": ["mount_setattr", "clone3", "close_range"],
    }))
}

fn e7() -> Result<Value, String> {
    const KVMIO: u64 = 0xAE;
    let get_api = (KVMIO << 8) | 0x00;
    let create_vm = (KVMIO << 8) | 0x01;
    let host = kvm_try(get_api, create_vm);
    let (status, output) = sys::run_child(0, true, move || {
        println!("{}", kvm_try(get_api, create_vm));
        unsafe { libc::_exit(0) };
    })
    .map_err(|e| e.to_string())?;
    let inside: Value = serde_json::from_str(output.trim()).unwrap_or(json!({"raw": output, "status": status}));
    Ok(json!({
        "experiment": "e7",
        "question": "user namespace plus /dev/kvm",
        "host": host,
        "inside_userns": inside,
    }))
}

fn kvm_try(get_api: u64, create_vm: u64) -> Value {
    let fd = unsafe { libc::open(c"/dev/kvm".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return json!({"open": std::io::Error::last_os_error().to_string()});
    }
    let api = unsafe { libc::ioctl(fd, get_api, 0) };
    let vm = unsafe { libc::ioctl(fd, create_vm, 0) };
    let vm_err = if vm < 0 {
        Some(std::io::Error::last_os_error().to_string())
    } else {
        None
    };
    if vm >= 0 {
        unsafe { libc::close(vm) };
    }
    unsafe { libc::close(fd) };
    json!({"api": api, "create_vm": vm, "create_vm_error": vm_err})
}

// Silence the unused import if Write is only used by the compiler in macros.
#[allow(dead_code)]
fn _write_marker(mut w: impl Write) {
    let _ = w.write_all(b"");
}
