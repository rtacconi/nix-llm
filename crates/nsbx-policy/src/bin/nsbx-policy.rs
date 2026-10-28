//! `nsbx-policy`: closure audit and co-built policy.json.

use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprintln!("usage: nsbx-policy closure-audit|policy-json ...");
        return ExitCode::from(2);
    };
    let result = match cmd.as_str() {
        "closure-audit" => closure_audit(&mut args),
        "policy-json" => policy_json(&mut args),
        _ => Err(format!("unknown command {cmd}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    let got = args.next().ok_or_else(|| format!("missing {flag}"))?;
    if got != flag {
        return Err(format!("expected {flag}, got {got}"));
    }
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn closure_audit(args: &mut impl Iterator<Item = String>) -> Result<(), String> {
    let allow_path = arg(args, "--allowlist")?;
    let bin = arg(args, "--bin")?;
    let allow = nsbx_policy::audit::load_allowlist(Path::new(&allow_path))?;
    let found = nsbx_policy::audit::names_in(Path::new(&bin))?;
    nsbx_policy::audit::diff(&allow, &found)
}

fn policy_json(args: &mut impl Iterator<Item = String>) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        return Err("policy-json requires Linux".into());
    }
    #[cfg(target_os = "linux")]
    {
        let profile_toml = arg(args, "--profile-toml")?;
        let seccomp_dir = arg(args, "--seccomp-dir")?;
        let store_paths = arg(args, "--store-paths")?;
        let runtime = arg(args, "--runtime")?;
        let out = arg(args, "--out")?;
        write_policy(&profile_toml, &seccomp_dir, &store_paths, &runtime, &out)
    }
}

#[cfg(target_os = "linux")]
fn write_policy(
    profile_toml: &str,
    seccomp_dir: &str,
    store_paths: &str,
    runtime: &str,
    out: &str,
) -> Result<(), String> {
    let text = std::fs::read_to_string(profile_toml).map_err(|e| e.to_string())?;
    let profile = nsbx_policy::Profile::from_toml(&text)?;
    let sources =
        nsbx_policy::bpf::load_sources(Path::new(seccomp_dir)).map_err(|e| e.to_string())?;
    let resolved =
        nsbx_policy::seccomp::resolve(&profile.seccomp, &sources).map_err(|e| e.to_string())?;
    let programs = nsbx_policy::bpf::compile(&resolved).map_err(|e| e.to_string())?;
    let paths_text = std::fs::read_to_string(store_paths).map_err(|e| e.to_string())?;
    let paths: Vec<String> = paths_text
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let doc = nsbx_policy::document::PolicyDocument {
        schema: 1,
        runtime: runtime.to_string(),
        profile: profile.name,
        profile_version: profile.version,
        bpf_hash: format!("{:016x}", nsbx_policy::bpf::fingerprint(&programs)),
        landlock_digest: format!("{:016x}", nsbx_policy::document::landlock_digest(&paths)),
    };
    nsbx_policy::document::binds(&doc, runtime)?;
    let json = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(out, json + "\n").map_err(|e| e.to_string())
}
