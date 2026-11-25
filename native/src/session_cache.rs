//! Owner-only on-disk cache for short-lived tokens and derived vault keys.
//!
//! The cache avoids repeating the OAuth client-credentials grant and the
//! expensive password KDF on every process start. Vault contents are never
//! persisted: each start still syncs the vault and decrypts it in memory.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vaultwarden_cli::{crypto::CryptoKeys, models::TokenResponse};

const CACHE_VERSION: u32 = 1;
const REFRESH_MARGIN_SECONDS: i64 = 60;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Controls persistence of authenticated session material.
#[derive(Debug, Clone)]
pub struct SessionCacheOptions {
    directory: Option<PathBuf>,
    ttl: Duration,
}

impl SessionCacheOptions {
    /// Resolve the cache directory from the environment.
    ///
    /// Precedence is `VAULTWARDEN_MCP_CACHE_DIR`, `XDG_CACHE_HOME`, the
    /// platform local-data directory, then `~/.cache`. A zero TTL disables
    /// persistence regardless of the directory.
    pub fn from_env(ttl: Duration) -> Self {
        let directory = nonempty_env("VAULTWARDEN_MCP_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                nonempty_env("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .map(|path| path.join("vaultwarden-mcp"))
            })
            .or_else(|| {
                nonempty_env("LOCALAPPDATA")
                    .map(PathBuf::from)
                    .map(|path| path.join("vaultwarden-mcp"))
            })
            .or_else(|| {
                nonempty_env("HOME")
                    .or_else(|| nonempty_env("USERPROFILE"))
                    .map(PathBuf::from)
                    .map(|path| path.join(".cache").join("vaultwarden-mcp"))
            });
        Self { directory, ttl }
    }

    /// Disable cache reads and writes.
    pub fn disabled() -> Self {
        Self {
            directory: None,
            ttl: Duration::ZERO,
        }
    }

    /// Use an explicit directory. Primarily useful for embedders and tests.
    pub fn in_directory(directory: PathBuf, ttl: Duration) -> Self {
        Self {
            directory: Some(directory),
            ttl,
        }
    }
}

fn nonempty_env(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
pub(crate) struct AuthState {
    pub(crate) access_token: String,
    pub(crate) refresh_token: Option<String>,
    pub(crate) expires_at_unix: i64,
}

impl AuthState {
    pub(crate) fn from_token(
        token: &TokenResponse,
        previous_refresh: Option<String>,
    ) -> Result<Self> {
        if token.expires_in <= 0 {
            bail!("server returned invalid token lifetime: expires_in must be positive");
        }
        let expires_at_unix = unix_timestamp()?
            .checked_add(token.expires_in)
            .ok_or_else(|| anyhow!("token expiry overflow"))?;
        Ok(Self {
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone().or(previous_refresh),
            expires_at_unix,
        })
    }

    pub(crate) fn needs_refresh(&self, now: i64) -> bool {
        self.expires_at_unix <= now.saturating_add(REFRESH_MARGIN_SECONDS)
    }
}

pub(crate) struct CachedSession {
    pub(crate) auth: AuthState,
    pub(crate) email: String,
    pub(crate) crypto_keys: CryptoKeys,
    pub(crate) encrypted_key_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct CacheIdentity {
    server: String,
    client_id: String,
    label: String,
}

#[derive(Serialize, Deserialize)]
struct CacheRecord {
    version: u32,
    server: String,
    client_id: String,
    label: String,
    email: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at_unix: i64,
    saved_at_unix: i64,
    password_verifier: [u8; 32],
    encrypted_key_hash: [u8; 32],
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

pub(crate) struct SessionCache {
    path: Option<PathBuf>,
    ttl: Duration,
    identity: CacheIdentity,
    password_verifier: [u8; 32],
}

impl SessionCache {
    pub(crate) fn new(
        options: SessionCacheOptions,
        server: &str,
        client_id: &str,
        label: &str,
        password: &str,
    ) -> Self {
        let identity = CacheIdentity {
            server: server.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            label: label.to_string(),
        };
        let password_verifier = password_verifier(password, &identity);
        let path = if options.ttl.is_zero() {
            None
        } else {
            options
                .directory
                .map(|directory| directory.join(format!("{}.json", cache_filename(&identity))))
        };
        Self {
            path,
            ttl: options.ttl,
            identity,
            password_verifier,
        }
    }

    pub(crate) fn load(&self) -> Result<Option<CachedSession>> {
        let Some(path) = self.path.as_ref() else {
            return Ok(None);
        };
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("failed to inspect session cache"),
        };
        if !metadata.file_type().is_file() {
            bail!("session cache is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o777 != 0o600 {
                bail!("session cache has insecure permissions (expected 0600)");
            }
        }

        let contents = fs::read_to_string(path).context("failed to read session cache")?;
        let record: CacheRecord =
            serde_json::from_str(&contents).context("failed to parse session cache")?;
        if record.version != CACHE_VERSION
            || record.server != self.identity.server
            || record.client_id != self.identity.client_id
            || record.label != self.identity.label
        {
            bail!("session cache identity does not match this account");
        }
        verify_password_verifier(&record.password_verifier, &self.password_verifier)?;

        let now = unix_timestamp()?;
        if record.saved_at_unix <= 0 || record.saved_at_unix > now {
            bail!("session cache has an invalid save timestamp");
        }
        if now - record.saved_at_unix > self.ttl.as_secs() as i64 {
            bail!("session cache has expired");
        }
        if record.access_token.is_empty() || record.email.is_empty() {
            bail!("session cache is missing required account data");
        }

        Ok(Some(CachedSession {
            auth: AuthState {
                access_token: record.access_token,
                refresh_token: record.refresh_token,
                expires_at_unix: record.expires_at_unix,
            },
            email: record.email,
            crypto_keys: CryptoKeys::from_key_bytes(record.enc_key, record.mac_key),
            encrypted_key_hash: record.encrypted_key_hash,
        }))
    }

    pub(crate) fn save(
        &self,
        auth: &AuthState,
        email: &str,
        encrypted_key_hash: [u8; 32],
        crypto_keys: &CryptoKeys,
    ) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let record = CacheRecord {
            version: CACHE_VERSION,
            server: self.identity.server.clone(),
            client_id: self.identity.client_id.clone(),
            label: self.identity.label.clone(),
            email: email.to_string(),
            access_token: auth.access_token.clone(),
            refresh_token: auth.refresh_token.clone(),
            expires_at_unix: auth.expires_at_unix,
            saved_at_unix: unix_timestamp()?,
            password_verifier: self.password_verifier,
            encrypted_key_hash,
            enc_key: *crypto_keys.enc_key_bytes(),
            mac_key: *crypto_keys.mac_key_bytes(),
        };
        let contents = serde_json::to_vec(&record).context("failed to serialize session cache")?;
        if let Some(parent) = path.parent() {
            prepare_directory(parent)?;
        }
        write_atomic(path, &contents).context("failed to write session cache")?;
        Ok(())
    }

    pub(crate) fn invalidate(&self) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to remove session cache"),
        }
    }
}

fn password_verifier(password: &str, identity: &CacheIdentity) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(password.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(b"vaultwarden-mcp session-cache password verifier v1\0");
    update_identity(&mut mac, identity);
    mac.finalize().into_bytes().into()
}

fn verify_password_verifier(actual: &[u8; 32], expected: &[u8; 32]) -> Result<()> {
    let key = b"vaultwarden-mcp session-cache verifier check v1";
    let mut actual_mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    actual_mac.update(actual);
    let actual = actual_mac.finalize();
    let mut expected_mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    expected_mac.update(expected);
    let expected = expected_mac.finalize();
    if actual != expected {
        bail!("session cache password verifier does not match");
    }
    Ok(())
}

fn update_identity(mac: &mut Hmac<Sha256>, identity: &CacheIdentity) {
    for part in [
        identity.server.as_str(),
        identity.client_id.as_str(),
        identity.label.as_str(),
    ] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
}

fn cache_filename(identity: &CacheIdentity) -> String {
    let mut hash = Sha256::new();
    hash.update(b"vaultwarden-mcp session-cache account v1\0");
    for part in [
        identity.server.as_str(),
        identity.client_id.as_str(),
        identity.label.as_str(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hex(&hash.finalize())
}

pub(crate) fn encrypted_key_hash(encrypted_key: &str) -> [u8; 32] {
    Sha256::digest(encrypted_key.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn unix_timestamp() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs(),
    )
    .context("Unix timestamp is out of range")
}

pub(crate) fn is_auth_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("(401 Unauthorized)") || message.contains("invalid_grant")
    })
}

fn prepare_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("failed to create session cache directory")?;
    let metadata = fs::symlink_metadata(path).context("failed to inspect cache directory")?;
    if !metadata.file_type().is_dir() {
        bail!("session cache directory is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("failed to secure session cache directory")?;
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp-{}-{counter}", std::process::id()));
    let write_result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .context("failed to create temporary session cache")?;
        file.write_all(contents)
            .context("failed to write temporary session cache")?;
        file.sync_all()
            .context("failed to sync temporary session cache")?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
                .context("failed to secure session cache")?;
        }
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path).context("failed to replace session cache")?;
        }
        fs::rename(&temp, path).context("failed to replace session cache")?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_filename_is_stable_and_account_specific() {
        let identity = CacheIdentity {
            server: "https://vault.example.com".into(),
            client_id: "client".into(),
            label: "work".into(),
        };
        assert_eq!(cache_filename(&identity), cache_filename(&identity));
        let mut other = identity.clone();
        other.label = "personal".into();
        assert_ne!(cache_filename(&identity), cache_filename(&other));
    }

    #[test]
    fn token_expiry_rejects_nonpositive_lifetime() {
        let token = TokenResponse {
            access_token: "access".into(),
            expires_in: 0,
            token_type: "Bearer".into(),
            refresh_token: None,
            scope: None,
            key: None,
            private_key: None,
            kdf: None,
            kdf_iterations: None,
        };
        assert!(AuthState::from_token(&token, None).is_err());
    }
}
