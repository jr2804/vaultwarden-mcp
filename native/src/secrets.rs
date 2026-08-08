//! secretspec 0.18 runtime integration.
//!
//! Resolves `secret://NAME` references found in `vaultwarden-mcp.toml` against
//! the secretspec manifest (`secretspec.toml`). The provider is selected by the
//! existing `--secretspec-provider` flag (default `env`); the profile by
//! `--secretspec-profile` (default `default`).
//!
//! This closes the gap documented in `config.rs`: `secret://` URIs are now
//! resolved to real values before any account connects, instead of being passed
//! through as raw strings (which always failed login).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use secretspec::{ResolveResponse, Secrets};

/// Marker for parsed `secret://` references. Kept in sync with `config.rs`.
pub const SECRET_SCHEME: &str = "secret://";

/// Load the secretspec manifest and resolve it against the selected provider
/// and profile.
///
/// `manifest_path`: explicit override; when `None`, secretspec's own discovery
/// walks the current dir and parents for `secretspec.toml` (and honors
/// `SECRETSPEC_MANIFEST`).
///
/// Returns the resolution so callers can look up individual secret values.
pub fn resolve(
    manifest_path: Option<&Path>,
    provider: &str,
    profile: &str,
) -> Result<ResolveResponse> {
    let mut spec = match manifest_path {
        Some(p) => Secrets::load_from(p)
            .with_context(|| format!("loading secretspec manifest {}", p.display()))?,
        None => Secrets::load().context(
            "discovering secretspec.toml (set --secretspec-manifest or SECRETSPEC_MANIFEST)",
        )?,
    };
    spec.set_provider(provider);
    spec.set_profile(profile);
    let resp = spec.resolve().with_context(|| {
        format!("resolving secretspec profile '{profile}' via provider '{provider}'")
    })?;
    if !resp.missing_required.is_empty() {
        return Err(anyhow!(
            "secretspec resolution is missing required secrets: {}",
            resp.missing_required.join(", ")
        ));
    }
    Ok(resp)
}

/// Look up a `secret://NAME` URI in the resolution, returning its value.
/// Non-`secret://` values are returned unchanged (plaintext passthrough).
///
/// `secret://NAME` with no provider prefix resolves against the active provider
/// set in [`resolve`]. A provider-prefixed URI like `secret://env/NAME` is not
/// supported in v1 — the provider is selected globally at startup, matching the
/// `--secretspec-provider` flag semantics.
pub fn resolve_value(value: &str, resp: &ResolveResponse) -> Result<String> {
    let Some(name) = value.strip_prefix(SECRET_SCHEME) else {
        return Ok(value.to_string());
    };
    if name.is_empty() {
        return Err(anyhow!("empty secret:// reference"));
    }
    resp.secrets
        .get(name)
        .and_then(|s| s.value.clone())
        .ok_or_else(|| anyhow!("secret '{name}' not found in resolved secretspec profile"))
}

/// Discover the manifest path secretspec would use. Exposed for diagnostics
/// (e.g. `print-config`).
#[allow(dead_code)]
pub fn discover_manifest(explicit: Option<&Path>) -> Option<PathBuf> {
    explicit.map(|p| p.to_path_buf()).or_else(|| {
        // secretspec::Secrets::load() does its own discovery; we only mirror it
        // for error messages. A missing file returns None here.
        PathBuf::from("secretspec.toml")
            .exists()
            .then_some(PathBuf::from("secretspec.toml"))
    })
}
