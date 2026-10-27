//! `nsbx_policy` Python module: a thin wrapper over `nsbx_policy::PolicyBundle`.
//!
//! JSON strings cross the boundary in both directions, which keeps this layer
//! free of policy logic: the orchestrator and the supervisor run the same
//! `narrow()`.

use std::path::Path;

use nsbx_policy::{BundleError, PolicyBundle};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyKeyError, PyValueError};
use pyo3::prelude::*;

create_exception!(
    nsbx_policy,
    PolicyDenied,
    PyException,
    "A request was narrowed to nothing; args[0] is the denial as JSON."
);

fn to_py(e: BundleError) -> PyErr {
    match e {
        BundleError::Denied(d) => {
            let body = serde_json::to_string(&d).unwrap_or_else(|_| "{}".to_owned());
            PolicyDenied::new_err(body)
        }
        other => PyValueError::new_err(other.to_string()),
    }
}

/// Loaded, validated admin profiles.
#[pyclass(frozen, module = "nsbx_policy")]
struct Policy {
    bundle: PolicyBundle,
}

#[pymethods]
impl Policy {
    /// Load every `*.toml` profile in `path`.
    #[staticmethod]
    fn from_dir(path: &str) -> PyResult<Self> {
        Ok(Self {
            bundle: PolicyBundle::load_dir(Path::new(path)).map_err(to_py)?,
        })
    }

    /// Build from a list of TOML documents (used by tests).
    #[staticmethod]
    fn from_tomls(texts: Vec<String>) -> PyResult<Self> {
        let items = texts
            .into_iter()
            .enumerate()
            .map(|(i, t)| (format!("<toml {i}>"), t));
        Ok(Self {
            bundle: PolicyBundle::from_tomls(items).map_err(to_py)?,
        })
    }

    fn profile_names(&self) -> Vec<String> {
        self.bundle.names().map(str::to_owned).collect()
    }

    /// Narrow `request_json` for `principal_json`; returns the effective job
    /// as JSON or raises `PolicyDenied`.
    fn narrow(&self, principal_json: &str, request_json: &str) -> PyResult<String> {
        let effective = self
            .bundle
            .narrow_json(principal_json, request_json)
            .map_err(to_py)?;
        Ok(effective.to_string())
    }

    /// JSON description of a profile's sandbox environment for agents.
    fn environment(&self, name: &str) -> PyResult<String> {
        self.bundle
            .environment(name)
            .map(|v| v.to_string())
            .ok_or_else(|| PyKeyError::new_err(name.to_owned()))
    }
}

#[pymodule]
#[pyo3(name = "nsbx_policy")]
fn nsbx_policy_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Policy>()?;
    m.add("PolicyDenied", m.py().get_type::<PolicyDenied>())?;
    Ok(())
}
