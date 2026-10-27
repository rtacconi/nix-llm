#![allow(clippy::unwrap_used)]
//! Validates the policy files committed under `policy/` and property-tests
//! `narrow()` against them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use nsbx_policy::seccomp::{SeccompSource, resolve};
use nsbx_policy::{LimitCap, NetworkMode, Principal, Profile, Request, narrow};
use proptest::prelude::*;

fn policy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy")
}

fn load_profiles() -> Vec<Profile> {
    let mut out = Vec::new();
    for entry in fs::read_dir(policy_dir().join("profiles")).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        out.push(Profile::from_toml(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display())));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn load_seccomp() -> BTreeMap<String, SeccompSource> {
    fs::read_dir(policy_dir().join("seccomp"))
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let s: SeccompSource = toml::from_str(&fs::read_to_string(&path).unwrap())
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (s.name.clone(), s)
        })
        .collect()
}

#[test]
fn committed_profiles_are_valid_and_reference_known_seccomp_sources() {
    let profiles = load_profiles();
    assert!(!profiles.is_empty());
    let seccomp = load_seccomp();
    for p in &profiles {
        assert!(
            seccomp.contains_key(&p.seccomp),
            "{} references unknown seccomp `{}`",
            p.name,
            p.seccomp
        );
    }
}

#[test]
fn committed_seccomp_sources_resolve() {
    let seccomp = load_seccomp();
    for name in seccomp.keys() {
        let r = resolve(name, &seccomp).unwrap_or_else(|e| panic!("{e}"));
        assert!(r.kill.contains("bpf") && r.kill.contains("ptrace"));
        assert!(r.enosys.contains("clone3"));
    }
    let node = resolve("node", &seccomp).unwrap();
    assert!(node.enosys.contains("io_uring_setup") && !node.kill.contains("io_uring_setup"));
    assert_eq!(node.chain, ["base", "python", "node"]);
}

fn principal_for(p: &Profile) -> Principal {
    Principal {
        id: "agent-a".into(),
        profiles: BTreeSet::from([p.name.clone()]),
        limits: LimitCap::default(),
        network_max: NetworkMode::EgressProxy,
        egress_domains: None,
    }
}

fn minimal_request(p: &Profile) -> Request {
    Request {
        profile: p.name.clone(),
        argv: vec![p.executables.first().unwrap().clone()],
        ..Request::default()
    }
}

#[test]
fn minimal_request_gets_profile_defaults() {
    for p in load_profiles() {
        let e = narrow(&p, &principal_for(&p), &minimal_request(&p)).unwrap();
        assert_eq!(e.network, NetworkMode::None);
        assert!(e.limits.within(&p.limits));
        if let Some(w) = p.defaults.wall_ms {
            assert_eq!(e.limits.wall_ms, w);
        }
    }
}

#[test]
fn denials_name_the_field_and_the_bound() {
    let p = load_profiles()
        .into_iter()
        .find(|p| p.name == "python-compute")
        .unwrap();
    let pr = principal_for(&p);

    let mut r = minimal_request(&p);
    r.limits.memory_bytes = Some(p.limits.memory_bytes + 1);
    let d = narrow(&p, &pr, &r).unwrap_err();
    assert_eq!(
        (d.code, d.field.as_str()),
        ("limit_exceeds_allowed", "limits.memory_bytes")
    );
    assert_eq!(d.allowed, Some(p.limits.memory_bytes.to_string()));

    let mut r = minimal_request(&p);
    r.argv = vec!["sh".into()];
    assert_eq!(
        narrow(&p, &pr, &r).unwrap_err().code,
        "executable_not_in_runtime"
    );

    let mut r = minimal_request(&p);
    r.env.insert("LD_PRELOAD".into(), "x".into());
    assert_eq!(narrow(&p, &pr, &r).unwrap_err().code, "env_key_not_allowed");

    let mut r = minimal_request(&p);
    r.network = Some(NetworkMode::EgressProxy);
    assert_eq!(narrow(&p, &pr, &r).unwrap_err().code, "network_not_allowed");

    let mut r = minimal_request(&p);
    r.collect = vec![".git/hooks/pre-commit".into()];
    assert_eq!(
        narrow(&p, &pr, &r).unwrap_err().code,
        "collect_outside_prefix"
    );

    let mut r = minimal_request(&p);
    r.collect = vec!["out/.envrc".into()];
    assert_eq!(
        narrow(&p, &pr, &r).unwrap_err().code,
        "collect_host_executable"
    );

    let mut r = minimal_request(&p);
    r.files = vec!["../escape".into()];
    assert_eq!(narrow(&p, &pr, &r).unwrap_err().code, "path_invalid");

    let other = Principal {
        profiles: BTreeSet::from(["cli-text".into()]),
        ..pr
    };
    assert_eq!(
        narrow(&p, &other, &minimal_request(&p)).unwrap_err().code,
        "profile_not_allowed"
    );
}

#[test]
fn principal_cap_narrows_defaults() {
    let p = load_profiles()
        .into_iter()
        .find(|p| p.name == "python-compute")
        .unwrap();
    let mut pr = principal_for(&p);
    pr.limits.wall_ms = Some(1_000);
    let e = narrow(&p, &pr, &minimal_request(&p)).unwrap();
    assert_eq!(e.limits.wall_ms, 1_000);
}

fn opt_u64(max: u64) -> impl Strategy<Value = Option<u64>> {
    prop_oneof![Just(None), (0..=max.saturating_mul(2)).prop_map(Some)]
}

fn cap_strategy(l: nsbx_policy::Limits) -> impl Strategy<Value = LimitCap> {
    (
        opt_u64(l.wall_ms),
        opt_u64(l.cpu_ms),
        opt_u64(l.memory_bytes),
        opt_u64(u64::from(l.pids)),
        opt_u64(l.output_bytes),
    )
        .prop_map(|(w, c, m, p, o)| LimitCap {
            wall_ms: w,
            cpu_ms: c,
            memory_bytes: m,
            pids: p.map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
            output_bytes: o,
        })
}

fn case() -> impl Strategy<Value = (Profile, LimitCap, LimitCap)> {
    let profiles = load_profiles();
    (0..profiles.len()).prop_flat_map(move |i| {
        let p = profiles[i].clone();
        let l = p.limits;
        (Just(p), cap_strategy(l), cap_strategy(l))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The narrow-only invariant: whatever the request and principal, an
    /// accepted job never exceeds the request, the principal or the profile.
    #[test]
    fn accepted_jobs_are_within_request_principal_and_profile(
        (p, pr_cap, req_cap) in case(),
        net in prop_oneof![Just(None), Just(Some(NetworkMode::None)), Just(Some(NetworkMode::EgressProxy))],
        net_max in prop_oneof![Just(NetworkMode::None), Just(NetworkMode::EgressProxy)],
        collect in proptest::collection::vec("(out|src|\\.git)(/[a-z.]{1,6}){0,2}", 0..3),
        files in proptest::collection::vec("[a-z.]{1,5}(/[a-z.]{1,5}){0,2}", 0..4),
        grace in prop_oneof![Just(None), (0u32..10_000).prop_map(Some)],
    ) {
        let principal = Principal { limits: pr_cap, network_max: net_max, ..principal_for(&p) };
        let req = Request { limits: req_cap, network: net, collect, files, grace_ms: grace, ..minimal_request(&p) };

        if let Ok(e) = narrow(&p, &principal, &req) {
            prop_assert!(e.within_profile(&p), "not within profile: {e:?}");
            prop_assert!(e.within_principal(&principal), "not within principal: {e:?}");
            prop_assert!(e.within_request(&req), "not within request: {e:?}");
        }
    }
}
