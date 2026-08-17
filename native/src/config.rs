//! Config file loader.
//!
//! See `.agents/plans/01-config.md` for the design.
//!
//! ## secretspec integration
//!
//! The `secret://NAME` URI scheme is resolved against the secretspec 0.18
//! runtime by [`secrets::resolve`] before any account connects. The provider
//! is selected by `--secretspec-provider` (default `env`); the profile by
//! `--secretspec-profile` (default `default`). Supported providers include
//! `env`, `dotenv:<path>`, `keyring`, and `bw` (Bitwarden CLI). Plaintext
//! values pass through untouched; a `secret://` reference that cannot be
//! resolved fails the load with a clear error rather than reaching the server.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

/// Read-only environment accessor.
///
/// Production code reads the real process environment ([`ProcessEnv`]); tests
/// inject an in-memory map ([`MapEnv`]) so parallel test threads never race on
/// global env vars. `std::env::set_var` is process-global and not thread-safe,
/// so config code must never mutate it — it only reads through this trait.
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

/// Reads from the real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        env::var(key).ok()
    }
}

/// In-memory environment for tests and deterministic callers.
#[derive(Debug, Clone, Default)]
pub struct MapEnv(pub BTreeMap<String, String>);

impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

/// Config-file structure on disk.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Default server options applied to every account unless overridden.
    #[serde(default)]
    pub server: ServerDefaults,
    /// Account list. Empty when only env vars are used.
    #[serde(default)]
    pub accounts: Vec<AccountConfigFile>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerDefaults {
    #[serde(default)]
    pub default_transport: Option<String>,
    #[serde(default)]
    pub allow_http: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfigFile {
    pub label: String,
    pub server: String,
    pub client_id: String,
    /// Plaintext or `secret://provider/key` reference (see module docs).
    pub client_secret: String,
    /// Plaintext or `secret://provider/key` reference (see module docs).
    pub password: String,
    #[serde(default)]
    pub allow_http: Option<bool>,
}

/// Marker for parsed `secret://` references. The runtime resolution is
/// deferred to the secretspec-integration milestone.
pub const SECRET_SCHEME: &str = "secret://";

impl AccountConfigFile {
    /// Returns true if any field looks like a secretspec reference.
    pub fn uses_secretspec(&self) -> bool {
        self.client_secret.starts_with(SECRET_SCHEME) || self.password.starts_with(SECRET_SCHEME)
    }

    /// Strip `secret://` prefixes from any field. If a `secret://` reference
    /// is present, it is left as-is — the caller is responsible for resolving
    /// via secretspec. This function validates that the reference is well-
    /// formed and returns an error for malformed URIs.
    pub fn validate_secret_uris(&self) -> Result<()> {
        for (field, value) in [
            ("client_secret", &self.client_secret),
            ("password", &self.password),
        ] {
            if let Some(reference) = value.strip_prefix(SECRET_SCHEME)
                && reference.is_empty()
            {
                return Err(anyhow!(
                    "account '{}': {field} has an empty secret:// reference",
                    self.label
                ));
            }
        }
        Ok(())
    }
}

/// Discover the config file path.
///
/// Order: explicit override → `<cwd>/vaultwarden-mcp.toml` →
/// `~/.config/vaultwarden-mcp/config.toml`.
///
/// `cwd` and `env` are injected so tests never mutate process-global state
/// (`set_current_dir` / `env::set_var`) — see [`EnvSource`].
pub fn discover_config_path(
    explicit: Option<&Path>,
    cwd: &Path,
    env: &dyn EnvSource,
) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let cwd_file = cwd.join("vaultwarden-mcp.toml");
    if cwd_file.exists() {
        return Some(cwd_file);
    }
    if let Some(home) = env.get("HOME") {
        let p = PathBuf::from(home)
            .join(".config")
            .join("vaultwarden-mcp")
            .join("config.toml");
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(home) = env.get("USERPROFILE") {
        let p = PathBuf::from(home)
            .join(".config")
            .join("vaultwarden-mcp")
            .join("config.toml");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Load a config file from disk. Returns `Default` if no path was found.
pub fn load(path: Option<&Path>) -> Result<ConfigFile> {
    let cwd = env::current_dir().unwrap_or_default();
    let Some(path) = discover_config_path(path, &cwd, &ProcessEnv) else {
        return Ok(ConfigFile::default());
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let cfg: ConfigFile =
        toml::from_str(&text).with_context(|| format!("parsing config file {}", path.display()))?;
    Ok(cfg)
}

/// Merge priority: env var > config file. Per-field override.
pub fn merge_field(env_value: Option<String>, file_value: String) -> String {
    env_value.unwrap_or(file_value)
}

/// Return true if any `secret://` reference is present in the config file.
pub fn has_secret_uris(file: &ConfigFile) -> bool {
    file.accounts.iter().any(|a| a.uses_secretspec())
}

/// Effective account list after merging config + env, resolving any
/// `secret://NAME` references against the secretspec runtime.
///
/// Resolution order per field: env var > `secret://` resolution > config file
/// plaintext. If a `secret://` reference is present but secretspec cannot
/// resolve it (missing manifest, missing secret, missing-required failure),
/// the whole load fails with a clear error — we never pass a raw `secret://`
/// string to the server.
pub fn resolve_accounts(
    file: ConfigFile,
    secretspec_provider: &str,
    secretspec_profile: &str,
    secretspec_manifest: Option<&Path>,
    env: &dyn EnvSource,
) -> Result<Vec<AccountConfigFile>> {
    // Resolve the secretspec manifest once (not per-account) if any field uses
    // a secret:// reference. Secrets::load() walks the cwd and parents for
    // secretspec.toml and honors SECRETSPEC_MANIFEST.
    let secrets = if has_secret_uris(&file) {
        Some(crate::secrets::resolve(
            secretspec_manifest,
            secretspec_provider,
            secretspec_profile,
        )?)
    } else {
        None
    };

    let resolve_field = |env_value: Option<String>, file_value: String| -> Result<String> {
        let merged = merge_field(env_value, file_value);
        match (&secrets, merged.starts_with(crate::secrets::SECRET_SCHEME)) {
            (Some(resp), true) => crate::secrets::resolve_value(&merged, resp),
            (None, true) => Err(anyhow!(
                "field references '{merged}' but no secretspec.toml was loaded; \
                 set --secretspec-provider or provide a secretspec.toml manifest"
            )),
            _ => Ok(merged),
        }
    };

    let mut out: Vec<AccountConfigFile> = Vec::new();

    for account in file.accounts.clone() {
        account.validate_secret_uris()?;
        let label_upper = account.label.to_uppercase();
        let env_get = |suffix: &str| -> Option<String> {
            env.get(&format!("VAULTWARDEN_ACCOUNT_{label_upper}_{suffix}"))
                .or_else(|| env.get(&format!("VAULTWARDEN_{suffix}")))
        };
        out.push(AccountConfigFile {
            label: account.label.clone(),
            server: resolve_field(env_get("SERVER"), account.server)?,
            client_id: resolve_field(env_get("CLIENT_ID"), account.client_id)?,
            client_secret: resolve_field(env_get("CLIENT_SECRET"), account.client_secret)?,
            password: resolve_field(env_get("PASSWORD"), account.password)?,
            allow_http: account.allow_http.or_else(|| {
                env.get("VAULTWARDEN_ALLOW_HTTP")
                    .map(|v| v == "1" || v.to_lowercase() == "true")
            }),
        });
    }

    if out.is_empty() {
        out.extend(accounts_from_env_only(env));
    }

    validate_required_fields(&out)?;
    Ok(out)
}

/// Build accounts purely from env vars (no config file).
pub fn accounts_from_env_only(env: &dyn EnvSource) -> Vec<AccountConfigFile> {
    let env_list: Vec<String> = env
        .get("VAULTWARDEN_ACCOUNTS")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    if env_list.is_empty() {
        let server = env
            .get("VAULTWARDEN_SERVER")
            .or_else(|| env.get("VAULTWARDEN_URL"));
        let client_id = env
            .get("VAULTWARDEN_CLIENT_ID")
            .or_else(|| env.get("BW_CLIENT_ID"));
        let client_secret = env
            .get("VAULTWARDEN_CLIENT_SECRET")
            .or_else(|| env.get("BW_CLIENT_SECRET"));
        let password = env
            .get("VAULTWARDEN_PASSWORD")
            .or_else(|| env.get("BW_PASSWORD"));

        if server.is_none() && client_id.is_none() && client_secret.is_none() && password.is_none()
        {
            return Vec::new();
        }
        return vec![AccountConfigFile {
            label: env
                .get("VAULTWARDEN_ACCOUNT_NAME")
                .unwrap_or_else(|| "default".to_string()),
            server: server.unwrap_or_default(),
            client_id: client_id.unwrap_or_default(),
            client_secret: client_secret.unwrap_or_default(),
            password: password.unwrap_or_default(),
            allow_http: env
                .get("VAULTWARDEN_ALLOW_HTTP")
                .map(|v| v == "1" || v.to_lowercase() == "true"),
        }];
    }

    env_list
        .iter()
        .filter_map(|label| {
            let prefix = format!("VAULTWARDEN_ACCOUNT_{}_", label.to_uppercase());
            let get = |key: &str| -> Option<String> {
                env.get(&format!("{prefix}{key}")).or_else(|| env.get(key))
            };
            Some(AccountConfigFile {
                server: get("SERVER").or_else(|| get("URL"))?,
                client_id: get("CLIENT_ID")?,
                client_secret: get("CLIENT_SECRET")?,
                password: get("PASSWORD")?,
                allow_http: get("ALLOW_HTTP").map(|v| v == "1" || v.to_lowercase() == "true"),
                label: label.clone(),
            })
        })
        .collect()
}

/// Validate that every account has all required fields populated.
pub fn validate_required_fields(accounts: &[AccountConfigFile]) -> Result<()> {
    if accounts.is_empty() {
        return Err(anyhow!(
            "no accounts configured: provide a TOML config file (--config) or set VAULTWARDEN_PASSWORD + VAULTWARDEN_SERVER + VAULTWARDEN_CLIENT_ID + VAULTWARDEN_CLIENT_SECRET"
        ));
    }
    for a in accounts {
        let missing: Vec<&str> = [
            ("server", a.server.as_str()),
            ("client_id", a.client_id.as_str()),
            ("client_secret", a.client_secret.as_str()),
            ("password", a.password.as_str()),
        ]
        .iter()
        .filter_map(|(name, v)| if v.is_empty() { Some(*name) } else { None })
        .collect();
        if !missing.is_empty() {
            return Err(anyhow!(
                "account '{}' is missing required field(s): {}",
                a.label,
                missing.join(", ")
            ));
        }
    }
    Ok(())
}

/// Diagnostics summary for `--print-config`.
#[derive(Debug, Clone, Default)]
pub struct ProviderInfo {
    pub source: String,
}

pub fn summarize(profiles: &BTreeMap<String, ProviderInfo>) -> String {
    let mut s = String::new();
    s.push_str("vaultwarden-mcp — effective config:\n");
    for (label, info) in profiles {
        s.push_str(&format!("  [{label}]\n    source: {}\n", info.source));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample_file(label: &str) -> AccountConfigFile {
        AccountConfigFile {
            label: label.into(),
            server: "https://x".into(),
            client_id: "id".into(),
            client_secret: "sec".into(),
            password: "pw".into(),
            allow_http: None,
        }
    }

    /// Build an in-memory env map from pairs. No process-global mutation —
    /// parallel tests never race on `std::env`.
    fn map_env(pairs: &[(&str, &str)]) -> MapEnv {
        MapEnv(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn merge_field_prefers_env() {
        assert_eq!(merge_field(Some("ENV".into()), "FILE".into()), "ENV");
        assert_eq!(merge_field(None, "FILE".into()), "FILE");
    }

    #[test]
    fn discover_returns_explicit_path() {
        let p = PathBuf::from("__definitely__missing__config.toml");
        let got = discover_config_path(Some(&p), Path::new("."), &MapEnv::default());
        assert_eq!(got, Some(p));
    }

    #[test]
    fn discover_does_not_panic_for_no_path() {
        let _ = discover_config_path(None, Path::new("."), &MapEnv::default());
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
            [[accounts]]
            label = "p"
            server = "https://x"
            client_id = "id"
            client_secret = "sec"
            password = "pw"
        "#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        assert_eq!(cfg.accounts.len(), 1);
        assert_eq!(cfg.accounts[0].label, "p");
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = r#"
            unknown = true
            [[accounts]]
            label = "p"
            server = "https://x"
            client_id = "id"
            client_secret = "sec"
            password = "pw"
        "#;
        let r: Result<ConfigFile, _> = toml::from_str(toml);
        assert!(r.is_err(), "should reject unknown top-level field");
    }

    #[test]
    fn reject_empty_secret_uri() {
        let a = AccountConfigFile {
            client_secret: "secret://".into(),
            ..sample_file("p")
        };
        assert!(a.validate_secret_uris().is_err());
    }

    #[test]
    fn accept_secret_uri_with_reference() {
        let a = AccountConfigFile {
            client_secret: "secret://VAULTWARDEN_CLIENT_SECRET".into(),
            password: "secret://VAULTWARDEN_PASSWORD".into(),
            ..sample_file("p")
        };
        assert!(a.validate_secret_uris().is_ok());
        assert!(a.uses_secretspec());
    }

    #[test]
    fn accept_plaintext() {
        let a = sample_file("p");
        assert!(a.validate_secret_uris().is_ok());
        assert!(!a.uses_secretspec());
    }

    #[test]
    fn merges_per_field_from_env() {
        let toml = r#"
            [[accounts]]
            label = "p"
            server = "https://file"
            client_id = "file_id"
            client_secret = "file_secret"
            password = "file_pw"
        "#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        let env = map_env(&[
            ("VAULTWARDEN_ACCOUNT_P_PASSWORD", "env_pw"),
            ("VAULTWARDEN_ACCOUNT_P_CLIENT_ID", "env_id"),
        ]);
        let result = resolve_accounts(cfg, "env", "default", None, &env).unwrap();
        assert_eq!(result[0].password, "env_pw");
        assert_eq!(result[0].client_id, "env_id");
        assert_eq!(result[0].server, "https://file");
        assert_eq!(result[0].client_secret, "file_secret");
    }

    #[test]
    fn write_and_load_sample_file() {
        let dir = std::env::temp_dir().join(format!("vwmcp-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vaultwarden-mcp.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
            [[accounts]]
            label = "p"
            server = "https://x"
            client_id = "id"
            client_secret = "sec"
            password = "pw"
            "#
        )
        .unwrap();
        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.accounts.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_required_fields_ok() {
        let a = sample_file("p");
        assert!(validate_required_fields(&[a]).is_ok());
    }

    #[test]
    fn validate_required_fields_missing() {
        let a = AccountConfigFile {
            label: "p".into(),
            server: "".into(),
            client_id: "id".into(),
            client_secret: "sec".into(),
            password: "pw".into(),
            allow_http: None,
        };
        let err = validate_required_fields(&[a]).unwrap_err().to_string();
        assert!(
            err.contains("server"),
            "expected error mentioning 'server', got: {err}"
        );
    }

    #[test]
    fn validate_required_fields_empty_list() {
        let err = validate_required_fields(&[]).unwrap_err().to_string();
        assert!(err.contains("no accounts"), "got: {err}");
    }

    // ── accounts_from_env_only ──────────────────────────────────────────

    #[test]
    fn env_only_single_account() {
        let env = map_env(&[
            ("VAULTWARDEN_SERVER", "https://env.example.com"),
            ("VAULTWARDEN_CLIENT_ID", "env.user"),
            ("VAULTWARDEN_CLIENT_SECRET", "env.secret"),
            ("VAULTWARDEN_PASSWORD", "env.pw"),
        ]);
        let accounts = accounts_from_env_only(&env);
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].server, "https://env.example.com");
        assert_eq!(accounts[0].client_id, "env.user");
        assert_eq!(accounts[0].client_secret, "env.secret");
        assert_eq!(accounts[0].password, "env.pw");
        assert_eq!(accounts[0].label, "default");
    }

    #[test]
    fn env_only_multi_account() {
        let env = map_env(&[
            ("VAULTWARDEN_ACCOUNTS", "jan,work"),
            ("VAULTWARDEN_ACCOUNT_JAN_SERVER", "https://jan.example.com"),
            ("VAULTWARDEN_ACCOUNT_JAN_CLIENT_ID", "jan.id"),
            ("VAULTWARDEN_ACCOUNT_JAN_CLIENT_SECRET", "jan.sec"),
            ("VAULTWARDEN_ACCOUNT_JAN_PASSWORD", "jan.pw"),
            ("VAULTWARDEN_ACCOUNT_WORK_SERVER", "https://work.example.com"),
            ("VAULTWARDEN_ACCOUNT_WORK_CLIENT_ID", "work.id"),
            ("VAULTWARDEN_ACCOUNT_WORK_CLIENT_SECRET", "work.sec"),
            ("VAULTWARDEN_ACCOUNT_WORK_PASSWORD", "work.pw"),
        ]);
        let accounts = accounts_from_env_only(&env);
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].label, "jan");
        assert_eq!(accounts[0].server, "https://jan.example.com");
        assert_eq!(accounts[1].label, "work");
        assert_eq!(accounts[1].server, "https://work.example.com");
    }

    #[test]
    fn env_only_no_vars_returns_empty() {
        let accounts = accounts_from_env_only(&MapEnv::default());
        assert!(accounts.is_empty());
    }

    // ── resolve_accounts fallback ───────────────────────────────────────

    #[test]
    fn resolve_accounts_empty_config_falls_back_to_env() {
        let env = map_env(&[
            ("VAULTWARDEN_SERVER", "https://fallback.example.com"),
            ("VAULTWARDEN_CLIENT_ID", "fallback.id"),
            ("VAULTWARDEN_CLIENT_SECRET", "fallback.sec"),
            ("VAULTWARDEN_PASSWORD", "fallback.pw"),
        ]);
        let cfg = ConfigFile::default();
        let result = resolve_accounts(cfg, "env", "default", None, &env).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "https://fallback.example.com");
    }

    // ── discover_config_path ────────────────────────────────────────────

    #[test]
    fn discover_config_path_finds_cwd_file() {
        let dir = std::env::temp_dir().join(format!("vwmcp-cwd-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("vaultwarden-mcp.toml");
        std::fs::write(
            &config_path,
            "[[accounts]]\nlabel = \"t\"\nserver = \"https://x\"\nclient_id = \"id\"\nclient_secret = \"sec\"\npassword = \"pw\"\n",
        )
        .unwrap();

        let found = discover_config_path(None, &dir, &MapEnv::default());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(found.is_some(), "should find vaultwarden-mcp.toml in cwd");
        if let Some(ref p) = found {
            assert!(
                p.ends_with("vaultwarden-mcp.toml"),
                "path should end with vaultwarden-mcp.toml, got: {}",
                p.display()
            );
        }
    }

    #[test]
    fn discover_config_path_finds_home_dir() {
        let dir = std::env::temp_dir().join(format!("vwmcp-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let config_dir = dir.join(".config").join("vaultwarden-mcp");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[[accounts]]\nlabel = \"t\"\nserver = \"https://x\"\nclient_id = \"id\"\nclient_secret = \"sec\"\npassword = \"pw\"\n",
        )
        .unwrap();

        let home = dir.to_str().unwrap();
        let env = map_env(&[("HOME", home), ("USERPROFILE", home)]);
        let found = discover_config_path(None, &dir, &env);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(found.is_some(), "should find config.toml in home dir");
    }

    // ── validate_required_fields per-field ──────────────────────────────

    #[test]
    fn validate_required_fields_missing_client_id() {
        let a = AccountConfigFile {
            label: "p".into(),
            server: "https://x".into(),
            client_id: "".into(),
            client_secret: "sec".into(),
            password: "pw".into(),
            allow_http: None,
        };
        let err = validate_required_fields(&[a]).unwrap_err().to_string();
        assert!(
            err.contains("client_id"),
            "expected 'client_id', got: {err}"
        );
    }

    #[test]
    fn validate_required_fields_missing_client_secret() {
        let a = AccountConfigFile {
            label: "p".into(),
            server: "https://x".into(),
            client_id: "id".into(),
            client_secret: "".into(),
            password: "pw".into(),
            allow_http: None,
        };
        let err = validate_required_fields(&[a]).unwrap_err().to_string();
        assert!(
            err.contains("client_secret"),
            "expected 'client_secret', got: {err}"
        );
    }

    #[test]
    fn validate_required_fields_missing_password() {
        let a = AccountConfigFile {
            label: "p".into(),
            server: "https://x".into(),
            client_id: "id".into(),
            client_secret: "sec".into(),
            password: "".into(),
            allow_http: None,
        };
        let err = validate_required_fields(&[a]).unwrap_err().to_string();
        assert!(err.contains("password"), "expected 'password', got: {err}");
    }

    // ── secretspec resolution ───────────────────────────────────────────

    /// Write a temp secretspec.toml and resolve a secret:// reference against
    /// it via the env provider. Returns the temp dir so the caller controls
    /// cleanup.
    fn write_temp_manifest(content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("secretspec.toml"), content).expect("write manifest");
        dir
    }

    /// Write a temp `.env` file and return the `dotenv:<path>` provider URI.
    /// File-backed provider → tests never mutate process-global env vars.
    fn dotenv_provider(dir: &tempfile::TempDir, content: &str) -> String {
        let path = dir.path().join(".env");
        std::fs::write(&path, content).expect("write .env");
        format!("dotenv:{}", path.display())
    }

    #[test]
    fn resolve_value_resolves_secret_uri_via_env_provider() {
        let dir = write_temp_manifest(
            "[project]\nname = \"t\"\nrevision = \"1.0\"\n\n[profiles.default]\nVWMCP_TEST_PRESENT = { description = \"pw\" }\n",
        );
        let manifest = dir.path().join("secretspec.toml");
        let provider = dotenv_provider(&dir, "VWMCP_TEST_PRESENT=super-secret\n");

        let resp = crate::secrets::resolve(Some(&manifest), &provider, "default").expect("resolve");

        let val =
            crate::secrets::resolve_value("secret://VWMCP_TEST_PRESENT", &resp).expect("lookup");
        assert_eq!(val, "super-secret");
    }

    #[test]
    fn resolve_value_passes_plaintext_through_unchanged() {
        // No secret:// refs in the config → secretspec is never loaded.
        let toml = "\n            [[accounts]]\n            label = \"p\"\n            server = \"https://x\"\n            client_id = \"id\"\n            client_secret = \"plaintext-secret\"\n            password = \"plaintext-pw\"\n        ";
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        // resolve_accounts with no secret:// refs must not touch secretspec.
        let accounts =
            resolve_accounts(cfg, "env", "default", None, &MapEnv::default()).expect("resolve plaintext");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].client_secret, "plaintext-secret");
        assert_eq!(accounts[0].password, "plaintext-pw");
    }

    #[test]
    fn resolve_value_errors_on_missing_secret() {
        let dir = write_temp_manifest(
            "[project]\nname = \"t\"\nrevision = \"1.0\"\n\n[profiles.default]\nVWMCP_TEST_ABSENT = { description = \"pw\", required = true }\n",
        );
        let manifest = dir.path().join("secretspec.toml");
        // Empty .env → the required secret is absent, resolution must error.
        let provider = dotenv_provider(&dir, "");
        let err = crate::secrets::resolve(Some(&manifest), &provider, "default");
        assert!(err.is_err(), "missing required secret must error");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("missing") || msg.contains("VWMCP_TEST_ABSENT"),
            "error should name the missing secret, got: {msg}"
        );
    }

    #[test]
    fn resolve_manifest_override() {
        let dir = write_temp_manifest(
            "[project]\nname = \"t\"\nrevision = \"1.0\"\n\n[profiles.default]\nVWMCP_TEST_MANIFEST = { description = \"pw\" }\n",
        );
        let manifest = dir.path().join("secretspec.toml");
        let provider = dotenv_provider(&dir, "VWMCP_TEST_MANIFEST=manifest-pass\n");
        let toml = "\n            [[accounts]]\n            label = \"p\"\n            server = \"https://x\"\n            client_id = \"id\"\n            client_secret = \"secret://VWMCP_TEST_MANIFEST\"\n            password = \"sec\"\n        ";
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        let accounts =
            resolve_accounts(cfg, &provider, "default", Some(&manifest), &MapEnv::default())
                .unwrap();
        assert_eq!(accounts[0].client_secret, "manifest-pass");
    }
}
