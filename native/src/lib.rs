//! Vaultwarden MCP — pure Rust backend for vault operations.
//!
//! Provides the vaultwarden API client wrapper and crypto types needed
//! by the MCP server, all using the vaultwarden-cli library.

use std::future::Future;
use std::sync::Arc;

use anyhow::{Context, Result};
use session_cache::{
    AuthState, SessionCache, SessionCacheOptions, encrypted_key_hash, is_auth_error, unix_timestamp,
};
use vaultwarden_cli::models::{Cipher, CipherData, FieldType, Folder, SyncResponse, TokenResponse};
use vaultwarden_cli::{
    api::ApiClient,
    crypto::{CryptoKeys, KdfIterations, MasterKey},
};

pub mod api_write;
pub mod config;
pub mod crypto;
pub mod mcp;
pub mod secrets;
pub mod session_cache;

/// A connected vaultwarden session with decrypted cipher access.
pub struct VaultwardenSession {
    api: Arc<ApiClient>,
    auth: tokio::sync::RwLock<Option<AuthState>>,
    client_id: String,
    client_secret: String,
    cache: SessionCache,
    email: String,
    encrypted_key_hash: [u8; 32],
    server_url: String,
    crypto_keys: CryptoKeys,
    ciphers: tokio::sync::RwLock<Vec<CipherEntry>>,
    folders: tokio::sync::RwLock<Vec<FolderEntry>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FolderEntry {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CipherEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub fields: Option<Vec<FieldEntry>>,
    pub ssh_public_key: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FieldEntry {
    pub name: String,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncSummary {
    pub email: String,
    pub cipher_count: usize,
}

impl VaultwardenSession {
    /// Connect, authenticate, derive master key, decrypt symmetric key,
    /// and verify vault by decrypting a cipher. Aborts if password is wrong.
    pub async fn new(
        server: &str,
        client_id: &str,
        client_secret: &str,
        password: &str,
        allow_http: bool,
    ) -> Result<Self> {
        Self::new_with_cache(
            server,
            client_id,
            client_secret,
            password,
            allow_http,
            "default",
            SessionCacheOptions::disabled(),
        )
        .await
    }

    /// Connect using an optional persistent token/key cache.
    pub async fn new_with_cache(
        server: &str,
        client_id: &str,
        client_secret: &str,
        password: &str,
        allow_http: bool,
        label: &str,
        cache_options: SessionCacheOptions,
    ) -> Result<Self> {
        let api = Arc::new(
            ApiClient::new_with_flags(server, allow_http).context("failed to create API client")?,
        );
        let server_url = server.to_string();
        let cache = SessionCache::new(cache_options, server, client_id, label, password);
        let now = unix_timestamp()?;
        let mut cached = match cache.load() {
            Ok(cached) => cached,
            Err(error) => {
                tracing::warn!("ignoring session cache for account '{label}': {error:#}");
                None
            }
        };
        let mut refreshed = false;

        let (auth, sync, crypto_keys, encrypted_key, from_cache) = loop {
            let Some(mut current) = cached.take() else {
                let (auth, sync, crypto_keys, encrypted_key) =
                    Self::authenticate_and_sync(&api, client_id, client_secret, password).await?;
                break (auth, sync, crypto_keys, encrypted_key, false);
            };

            if current.auth.needs_refresh(now) {
                let refresh_token = current.auth.refresh_token.clone();
                let Some(refresh_token) = refresh_token else {
                    cache
                        .invalidate()
                        .context("failed to invalidate session cache")?;
                    cached = None;
                    continue;
                };
                match api.refresh_token(&refresh_token).await {
                    Ok(token) => {
                        current.auth = AuthState::from_token(&token, Some(refresh_token))?;
                        refreshed = true;
                    }
                    Err(error) if is_auth_error(&error) => {
                        cache
                            .invalidate()
                            .context("failed to invalidate session cache")?;
                        cached = None;
                        continue;
                    }
                    Err(error) => {
                        return Err(error).context("failed to refresh vaultwarden session");
                    }
                }
            }

            match api.sync(&current.auth.access_token).await {
                Ok(sync)
                    if sync.profile.email == current.email
                        && sync.profile.key.as_deref().is_some_and(|key| {
                            encrypted_key_hash(key) == current.encrypted_key_hash
                        }) =>
                {
                    let encrypted_key = sync
                        .profile
                        .key
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("no encrypted key in profile"))?;
                    break (current.auth, sync, current.crypto_keys, encrypted_key, true);
                }
                Ok(_) => {
                    cache
                        .invalidate()
                        .context("failed to invalidate session cache")?;
                    cached = None;
                }
                Err(error) if is_auth_error(&error) => {
                    cache
                        .invalidate()
                        .context("failed to invalidate session cache")?;
                    cached = None;
                }
                Err(error) => {
                    return Err(error).context("failed to sync vault — cached session");
                }
            }
        };

        let email = sync.profile.email.clone();
        let encrypted_key_hash = encrypted_key_hash(&encrypted_key);
        let folder_entries = Self::decrypt_folders(&sync.folders, &crypto_keys);
        let entries =
            Self::decrypt_ciphers_with_folders(&sync.ciphers, &crypto_keys, &folder_entries);
        let folder_count = folder_entries.len();
        if from_cache {
            tracing::info!(
                "vault restored from session cache: {}@{} ({} ciphers, {} folders decrypted)",
                email,
                server_url,
                entries.len(),
                folder_count
            );
        } else {
            tracing::info!(
                "vault verification OK: {}@{} ({} ciphers, {} folders decrypted)",
                email,
                server_url,
                entries.len(),
                folder_count
            );
        }

        if (!from_cache || refreshed)
            && let Err(error) = cache.save(&auth, &email, encrypted_key_hash, &crypto_keys)
        {
            tracing::warn!("failed to persist session cache for account '{label}': {error:#}");
        }

        Ok(Self {
            api,
            auth: tokio::sync::RwLock::new(Some(auth)),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            cache,
            email,
            encrypted_key_hash,
            server_url,
            crypto_keys,
            ciphers: tokio::sync::RwLock::new(entries),
            folders: tokio::sync::RwLock::new(folder_entries),
        })
    }

    async fn authenticate_and_sync(
        api: &ApiClient,
        client_id: &str,
        client_secret: &str,
        password: &str,
    ) -> Result<(AuthState, SyncResponse, CryptoKeys, String)> {
        let token: TokenResponse = api
            .login(client_id, client_secret)
            .await
            .context("failed to authenticate (client_credentials) with vaultwarden")?;
        let auth = AuthState::from_token(&token, None)?;
        let kdf_iterations = token.kdf_iterations.unwrap_or(600_000);

        let sync: SyncResponse = api
            .sync(&auth.access_token)
            .await
            .context("failed to sync vault — credential verification step")?;
        let email = sync.profile.email.clone();
        let master_key = MasterKey::derive(
            password,
            &email,
            KdfIterations::new(kdf_iterations)
                .ok_or_else(|| anyhow::anyhow!("invalid KDF iterations: {}", kdf_iterations))?,
        );
        let encrypted_key = sync
            .profile
            .key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no encrypted key in profile"))?;
        let crypto_keys = master_key.decrypt_symmetric_key(&encrypted_key).context(
            "failed to decrypt symmetric key — vault password is wrong (HMAC verification)",
        )?;
        Ok((auth, sync, crypto_keys, encrypted_key))
    }

    /// Decrypt all folders from a sync response.
    ///
    /// Public so integration tests can exercise the decrypt path against
    /// fixture `Folder` values without a live server.
    pub fn decrypt_folders(folders: &[Folder], keys: &CryptoKeys) -> Vec<FolderEntry> {
        folders
            .iter()
            .map(|f| FolderEntry {
                id: f.id.to_string(),
                name: decrypt_str(keys, &f.name).unwrap_or_else(|| f.id.to_string()),
            })
            .collect()
    }

    /// Resolve a folder id to its decrypted name, or None if not found.
    pub fn folder_name_for_id(&self, folder_id: &str) -> Option<String> {
        self.folders
            .try_read()
            .ok()
            .and_then(|f| f.iter().find(|f| f.id == folder_id).map(|f| f.name.clone()))
    }

    /// Resolve a folder name to its id, or None if not found.
    pub fn folder_id_for_name(&self, name: &str) -> Option<String> {
        self.folders
            .try_read()
            .ok()
            .and_then(|f| f.iter().find(|f| f.name == name).map(|f| f.id.clone()))
    }

    /// Resolve a folder name to its id, creating the folder if it doesn't
    /// exist. Uses a write lock around the check-and-create so concurrent
    /// calls don't create duplicate folders for the same name.
    async fn ensure_folder_id(&self, name: &str) -> Result<String> {
        // Fast path: already cached.
        if let Some(id) = self.folder_id_for_name(name) {
            return Ok(id);
        }

        // Acquire write lock to serialize folder creation.
        let enc_name = self.encrypt_str(name)?;
        let client = self.write_client()?;
        let body = serde_json::json!({ "name": enc_name });
        let created = self
            .authenticated(|access_token| async move {
                crate::api_write::create_folder(&client, &self.server_url, &access_token, &body)
                    .await
            })
            .await
            .context("failed to auto-create folder")?;

        let folder_id = created["id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("folder create response missing id"))?;
        let decrypted_name =
            decrypt_str(&self.crypto_keys, &enc_name).unwrap_or_else(|| name.to_string());

        // Update cache under write lock.
        let mut folders = self.folders.write().await;
        // Double-check: another writer may have created it while we were
        // encrypting/calling the API.
        if !folders.iter().any(|f| f.id == folder_id) {
            folders.push(FolderEntry {
                id: folder_id.clone(),
                name: decrypted_name,
            });
        }
        Ok(folder_id)
    }

    /// List all folders with their decrypted names.
    pub fn list_folders(&self) -> Vec<FolderEntry> {
        self.folders
            .try_read()
            .ok()
            .map(|f| f.clone())
            .unwrap_or_default()
    }

    /// Decrypt all ciphers from a sync response.
    ///
    /// Public so integration tests can exercise the decrypt path against
    /// fixture `Cipher` values without a live server.
    pub fn decrypt_ciphers(ciphers: &[Cipher], keys: &CryptoKeys) -> Vec<CipherEntry> {
        Self::decrypt_ciphers_with_folders(ciphers, keys, &[])
    }

    fn decrypt_ciphers_with_folders(
        ciphers: &[Cipher],
        keys: &CryptoKeys,
        folders: &[FolderEntry],
    ) -> Vec<CipherEntry> {
        let folder_map: std::collections::HashMap<&str, &str> = folders
            .iter()
            .map(|f| (f.id.as_str(), f.name.as_str()))
            .collect();
        ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .filter_map(|c| {
                c.cipher_data
                    .as_ref()
                    .map(|d| Self::cipher_to_entry_with_folders(c, d, keys, &folder_map))
            })
            .collect()
    }

    /// Decrypt a single cipher into a [`CipherEntry`].
    ///
    /// Public for the same reason as [`decrypt_ciphers`](Self::decrypt_ciphers).
    /// Folder info is resolved from the folder map (limited to the folder_map lifetime).
    pub fn cipher_to_entry(cipher: &Cipher, data: &CipherData, keys: &CryptoKeys) -> CipherEntry {
        Self::cipher_to_entry_with_folders(cipher, data, keys, &std::collections::HashMap::new())
    }

    fn cipher_to_entry_with_folders<'a>(
        cipher: &'a Cipher,
        data: &'a CipherData,
        keys: &'a CryptoKeys,
        folder_map: &std::collections::HashMap<&'a str, &'a str>,
    ) -> CipherEntry {
        // The top-level cipher name is encrypted — decrypt it. Fall back to the
        // cipher id if absent or undecryptable (never expose raw ciphertext).
        let cipher_name = cipher
            .name
            .as_deref()
            .and_then(|n| decrypt_str(keys, n))
            .unwrap_or_else(|| cipher.id.to_string());

        // Determine cipher type string
        let cipher_type_str = match data {
            CipherData::Login(_) => "login",
            CipherData::SecureNote(_) => "note",
            CipherData::Card(_) => "card",
            CipherData::Identity(_) => "identity",
            CipherData::SshKey(_) => "ssh",
        };

        // Extract fields based on cipher data type
        let (username, password, uri, notes, totp, ssh_pub, ssh_priv, ssh_fp) = match data {
            CipherData::Login(login) => {
                let uri_opt = login
                    .uris
                    .as_ref()
                    .and_then(|u| u.first())
                    .and_then(|u| u.uri.as_deref())
                    .and_then(|enc| decrypt_str(keys, enc))
                    .or_else(|| {
                        Self::decrypt_str_opt(cipher.data.as_ref(), keys, |d| d.uri.as_deref())
                    });
                (
                    Self::decrypt_str_opt(Some(login), keys, |l| l.username.as_deref()),
                    Self::decrypt_str_opt(Some(login), keys, |l| l.password.as_deref()),
                    uri_opt,
                    Self::decrypt_str_opt(Some(cipher), keys, |c| c.notes.as_deref()),
                    login.totp.clone(),
                    None,
                    None,
                    None,
                )
            }
            CipherData::SshKey(ssh) => (
                None,
                None,
                None,
                Self::decrypt_str_opt(Some(cipher), keys, |c| c.notes.as_deref()),
                None,
                ssh.public_key.clone(),
                ssh.private_key.clone(),
                ssh.fingerprint.clone(),
            ),
            _ => (
                None,
                None,
                None,
                Self::decrypt_str_opt(Some(cipher), keys, |c| c.notes.as_deref()),
                None,
                None,
                None,
                None,
            ),
        };

        // Fields
        let fields = cipher.get_fields().map(|fs| {
            fs.iter()
                .filter_map(|f| {
                    Some(FieldEntry {
                        name: f.name.clone()?,
                        value: Self::decrypt_str_opt_inner(keys, f.value.as_deref()),
                        field_type: match f.r#type {
                            FieldType::Text => "text",
                            FieldType::Hidden => "hidden",
                            FieldType::Boolean => "boolean",
                            FieldType::Linked => "linked",
                        }
                        .to_string(),
                    })
                })
                .collect()
        });

        // Resolve folder name from folder_id
        let folder_id_str = cipher.folder_id.as_ref().map(|fid| fid.to_string());
        let folder_name = folder_id_str
            .as_deref()
            .and_then(|fid| folder_map.get(fid).copied())
            .map(String::from);

        CipherEntry {
            id: cipher.id.to_string(),
            cipher_type: cipher_type_str.to_string(),
            name: cipher_name,
            username,
            password,
            uri,
            notes,
            totp,
            fields,
            ssh_public_key: ssh_pub,
            ssh_private_key: ssh_priv,
            ssh_fingerprint: ssh_fp,
            folder: folder_name,
            folder_id: folder_id_str,
        }
    }

    /// Decrypt an optional string field that may be encrypted.
    /// Takes the encrypted value directly (not a closure) to avoid lifetime issues.
    fn decrypt_str_opt<T>(
        obj: Option<&T>,
        keys: &CryptoKeys,
        getter: impl Fn(&T) -> Option<&str>,
    ) -> Option<String> {
        let obj = obj?;
        let encrypted = getter(obj)?;
        if encrypted.is_empty() {
            return None;
        }
        decrypt_str(keys, encrypted)
    }

    fn decrypt_str_opt_inner(keys: &CryptoKeys, encrypted: Option<&str>) -> Option<String> {
        let s = encrypted.filter(|s| !s.is_empty())?;
        decrypt_str(keys, s)
    }
}

/// Decrypt an encrypted string using CryptoKeys
fn decrypt_str(keys: &CryptoKeys, encrypted: &str) -> Option<String> {
    keys.decrypt(encrypted)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

impl VaultwardenSession {
    async fn persist_auth(&self, auth: &AuthState) {
        if let Err(error) = self.cache.save(
            auth,
            &self.email,
            self.encrypted_key_hash,
            &self.crypto_keys,
        ) {
            tracing::warn!("failed to persist refreshed session cache: {error:#}");
        }
    }

    async fn ensure_access_token(&self) -> Result<String> {
        let now = unix_timestamp()?;
        {
            let auth = self.auth.read().await;
            if let Some(auth) = auth.as_ref()
                && !auth.needs_refresh(now)
            {
                return Ok(auth.access_token.clone());
            }
        }

        let mut auth = self.auth.write().await;
        if let Some(current) = auth.as_ref()
            && !current.needs_refresh(now)
        {
            return Ok(current.access_token.clone());
        }

        let current = auth.clone();
        let result = if let Some(refresh_token) = current
            .as_ref()
            .and_then(|current| current.refresh_token.as_deref())
        {
            self.api.refresh_token(refresh_token).await
        } else {
            self.api.login(&self.client_id, &self.client_secret).await
        };
        match result {
            Ok(token) => {
                let previous_refresh = current.and_then(|current| current.refresh_token);
                let updated = match AuthState::from_token(&token, previous_refresh) {
                    Ok(updated) => updated,
                    Err(error) => {
                        if let Err(error) = self.cache.invalidate() {
                            tracing::warn!("failed to invalidate session cache: {error:#}");
                        }
                        *auth = None;
                        return Err(error);
                    }
                };
                self.persist_auth(&updated).await;
                let access_token = updated.access_token.clone();
                *auth = Some(updated);
                Ok(access_token)
            }
            Err(error) if is_auth_error(&error) => {
                if let Err(error) = self.cache.invalidate() {
                    tracing::warn!("failed to invalidate session cache: {error:#}");
                }
                *auth = None;
                Err(error).context("vaultwarden session authentication expired")
            }
            Err(error) => Err(error).context("failed to renew vaultwarden session"),
        }
    }

    async fn authenticated<T, F, Fut>(&self, request: F) -> Result<T>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let access_token = self.ensure_access_token().await?;
        match request(access_token).await {
            Ok(value) => Ok(value),
            Err(error) => {
                if is_auth_error(&error) {
                    if let Err(error) = self.cache.invalidate() {
                        tracing::warn!("failed to invalidate session cache: {error:#}");
                    }
                    *self.auth.write().await = None;
                }
                Err(error)
            }
        }
    }

    /// Search ciphers by name, URI, or username (case-insensitive)
    pub async fn search(&self, query: &str) -> Result<Vec<CipherEntry>> {
        let lower = query.to_lowercase();
        let ciphers = self.ciphers.read().await;
        Ok(ciphers
            .iter()
            .filter(|c| {
                c.name.to_lowercase().contains(&lower)
                    || c.uri
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&lower)
                    || c.username
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&lower)
            })
            .cloned()
            .collect())
    }

    /// Get a specific cipher by ID
    pub async fn get_cipher(&self, id: &str) -> Result<CipherEntry> {
        let ciphers = self.ciphers.read().await;
        ciphers
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("cipher '{}' not found", id))
    }

    /// Synchronize the vault and return a summary with decrypted ciphers
    pub async fn sync(&self) -> Result<SyncSummary> {
        let sync_resp: SyncResponse = self
            .authenticated(|access_token| async move { self.api.sync(&access_token).await })
            .await
            .context("failed to sync vault")?;
        let entries = Self::decrypt_ciphers(&sync_resp.ciphers, &self.crypto_keys);
        let cipher_count = entries.len();
        *self.ciphers.write().await = entries;
        Ok(SyncSummary {
            email: sync_resp.profile.email,
            cipher_count,
        })
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }
    pub fn email(&self) -> &str {
        &self.email
    }
}

// ── Write path: cipher create / edit / delete ───────────────────────────
//
// The read `ApiClient` is private to its fields, so writes go through our own
// `api_write` client. Every string field is individually encrypted with the
// session symmetric key; the body shape matches the Bitwarden CipherRequest.

/// Cipher type accepted by `create_cipher`. v1 create supports login + secure
/// note; `edit_cipher` accepts **all** types (login, note, card, identity,
/// ssh) because it overlays the raw cipher instead of rebuilding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WriteCipherType {
    Login,
    Note,
}

impl WriteCipherType {
    /// Numeric value the Bitwarden API expects in the `type` field.
    fn as_u8(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::Note => 2,
        }
    }
}

/// Map the read-path cipher-type string ("login", "note", "card", "identity",
/// "ssh") to the numeric value the Bitwarden API expects in the `type` field.
/// Unknown types fall back to login (1) for backward compatibility.
fn cipher_type_u8(cipher_type: &str) -> u8 {
    match cipher_type {
        "note" => 2,
        "card" => 3,
        "identity" => 4,
        "ssh" => 5,
        _ => 1, // "login" (and any unknown/legacy value)
    }
}

/// Plaintext field input for create. Every field except `name` and `cipher_type`
/// is optional and is omitted from the request body when `None`.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct CipherInput {
    /// Cipher type: "login" or "note" (create v1 scope).
    pub cipher_type: WriteCipherType,
    /// Display name (required).
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<FieldInput>>,
    /// Folder name to place the entry in. None = "No Folder" (default).
    /// Auto-creates the folder if it doesn't exist.
    #[serde(default)]
    pub folder: Option<String>,
}

/// One custom field. `field_type` defaults to "text"; "hidden" marks it as a
/// secret in the Bitwarden UI.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct FieldInput {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    /// "text" (default), "hidden", "boolean", or "linked".
    #[serde(default)]
    pub field_type: Option<String>,
}

/// Edit input: every field is optional and `None` means "leave unchanged".
/// `cipher_type` cannot change via edit (Bitwarden disallows type mutation).
#[derive(Debug, Clone, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct CipherEdit {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<Option<String>>,
    #[serde(default)]
    pub password: Option<Option<String>>,
    #[serde(default)]
    pub uri: Option<Option<String>>,
    #[serde(default)]
    pub totp: Option<Option<String>>,
    #[serde(default)]
    pub notes: Option<Option<String>>,
    #[serde(default)]
    pub fields: Option<Vec<FieldInput>>,
    /// Folder name. None = keep current; Some(None) = clear/"No Folder";
    /// Some("name") = move to folder (auto-create if needed).
    #[serde(default)]
    pub folder: Option<Option<String>>,
}

impl VaultwardenSession {
    /// Encrypt one string field. Always succeeds or returns an encryption error.
    fn encrypt_str(&self, s: &str) -> Result<String> {
        crate::crypto::encrypt_string(
            s,
            self.crypto_keys.enc_key_bytes(),
            self.crypto_keys.mac_key_bytes(),
        )
    }

    /// Encrypt one optional string field. `None` stays `None`.
    fn enc_opt(&self, s: Option<&str>) -> Result<Option<String>> {
        s.map(|v| self.encrypt_str(v)).transpose()
    }

    /// Build the encrypted JSON body for a create request.
    fn build_create_body(&self, input: &CipherInput) -> Result<serde_json::Value> {
        let mut body = serde_json::json!({
            "type": input.cipher_type.as_u8(),
            "name": self.encrypt_str(&input.name)?,
        });

        if let Some(notes) = input.notes.as_deref() {
            body["notes"] = serde_json::Value::String(self.encrypt_str(notes)?);
        }

        let mut login = serde_json::Map::new();
        if let Some(u) = input.username.as_deref() {
            login.insert(
                "username".into(),
                serde_json::Value::String(self.encrypt_str(u)?),
            );
        }
        if let Some(p) = input.password.as_deref() {
            login.insert(
                "password".into(),
                serde_json::Value::String(self.encrypt_str(p)?),
            );
        }
        if let Some(t) = input.totp.as_deref() {
            login.insert(
                "totp".into(),
                serde_json::Value::String(self.encrypt_str(t)?),
            );
        }
        if let Some(uri) = input.uri.as_deref() {
            let enc_uri = self.encrypt_str(uri)?;
            login.insert(
                "uris".into(),
                serde_json::json!([{ "uri": enc_uri, "match": null }]),
            );
        }

        if !login.is_empty() {
            body["login"] = serde_json::Value::Object(login);
        }

        if let Some(fields) = &input.fields {
            body["fields"] = serde_json::Value::Array(self.encrypt_fields(fields)?);
        }

        Ok(body)
    }

    /// Encrypt a field list into the Bitwarden `fields` array shape.
    fn encrypt_fields(&self, fields: &[FieldInput]) -> Result<Vec<serde_json::Value>> {
        fields
            .iter()
            .map(|f| {
                let ftype = match f.field_type.as_deref().unwrap_or("text") {
                    "hidden" => 1,
                    "boolean" => 2,
                    "linked" => 3,
                    _ => 0,
                };
                Ok(serde_json::json!({
                    "name": self.encrypt_str(&f.name)?,
                    "value": self.enc_opt(f.value.as_deref())?.unwrap_or_default(),
                    "type": ftype,
                    "linkedId": null,
                }))
            })
            .collect()
    }

    /// Lazily build the write HTTP client. Mirrors the read client's HTTP policy.
    fn write_client(&self) -> Result<reqwest::Client> {
        crate::api_write::build_write_client(
            // The read client already validated the scheme; reuse the same
            // relaxed flag so a server that allows http:// reads allows writes.
            self.server_url.starts_with("http://"),
        )
    }

    /// Refresh the in-memory cipher cache after a successful write so the next
    /// `search` / `get_cipher` reflects the change without a manual `sync`.
    /// The cipher JSON returned by the server is decrypted and spliced in.
    ///
    /// Soft-deleted ciphers (those carrying a `deletedDate`) are removed from
    /// the active cache rather than added, mirroring `decrypt_ciphers`' filter.
    async fn refresh_after_write(&self, cipher_json: serde_json::Value) -> Result<CipherEntry> {
        let cipher: Cipher = serde_json::from_value(cipher_json)
            .context("failed to parse cipher returned by server")?;

        // Build folder map from cached folders, keeping the guard alive long
        // enough for the folder_map references to remain valid.
        let (entry, folder_id_str) = {
            let folder_guard = self.folders.try_read();
            let folder_map: std::collections::HashMap<&str, &str> = folder_guard
                .as_ref()
                .map(|f| {
                    f.iter()
                        .map(|fe| (fe.id.as_str(), fe.name.as_str()))
                        .collect()
                })
                .unwrap_or_default();

            let e = cipher
                .cipher_data
                .as_ref()
                .map(|d| {
                    Self::cipher_to_entry_with_folders(&cipher, d, &self.crypto_keys, &folder_map)
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("server returned cipher with no decryptable data")
                })?;

            let fid = cipher.folder_id.as_ref().map(|fid| fid.to_string());
            (e, fid)
        };

        let mut entry = entry;
        // Ensure the returned entry has folder_id even when the map lookup failed.
        if entry.folder_id.is_none() {
            entry.folder_id = folder_id_str;
        }

        let mut ciphers = self.ciphers.write().await;
        if cipher.deleted_date.is_some() {
            // Trashed: drop from the active cache (matches decrypt_ciphers).
            ciphers.retain(|c| c.id != entry.id);
        } else {
            match ciphers.iter().position(|c| c.id == entry.id) {
                Some(i) => ciphers[i] = entry.clone(),
                None => ciphers.push(entry.clone()),
            }
        }
        Ok(entry)
    }

    /// Create a new cipher. Returns the created entry.
    pub async fn create_cipher(&self, input: CipherInput) -> Result<CipherEntry> {
        let client = self.write_client()?;
        let mut body = self.build_create_body(&input)?;
        // Inject folderId if a folder was requested.
        if let Some(ref folder_name) = input.folder {
            let fid = self.ensure_folder_id(folder_name).await?;
            body["folderId"] = serde_json::Value::String(fid);
        }
        let created = self
            .authenticated(|access_token| async move {
                crate::api_write::create_cipher(&client, &self.server_url, &access_token, &body)
                    .await
            })
            .await
            .context("failed to create cipher")?;
        self.refresh_after_write(created).await
    }

    /// Edit an existing cipher. `None` on every field means "unchanged"; the
    /// `Option<Option<T>>` shape lets a caller explicitly clear a field by
    /// passing `Some(None)`.
    ///
    /// PUT is a full replace, so we fetch the raw (encrypted) cipher JSON from
    /// the server and overlay only the edited fields. Type-specific data
    /// (card, identity, ssh, secure-note) passes through verbatim, which makes
    /// editing work for every cipher type — not just login/note.
    pub async fn edit_cipher(&self, cipher_id: &str, edit: CipherEdit) -> Result<CipherEntry> {
        let client = self.write_client()?;
        let read_client = client.clone();

        // 1. Fetch the current cipher verbatim (fields still encrypted). This
        //    preserves the type discriminator and all type-specific data.
        let mut body = self
            .authenticated(|access_token| async move {
                crate::api_write::get_cipher_raw(
                    &read_client,
                    &self.server_url,
                    &access_token,
                    cipher_id,
                )
                .await
            })
            .await
            .with_context(|| format!("failed to fetch cipher '{cipher_id}' for edit"))?;

        let cipher_type = body.get("type").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

        // 2. Overlay plaintext edits, re-encrypting only changed values.
        //    Name: Some(name) = set, None = keep.
        if let Some(name) = edit.name.as_deref() {
            body["name"] = serde_json::Value::String(self.enc_opt(Some(name))?.unwrap());
        }

        //    Notes: Some(Some) = set, Some(None) = clear, None = keep.
        match &edit.notes {
            Some(Some(notes)) => {
                body["notes"] = serde_json::Value::String(self.enc_opt(Some(notes))?.unwrap());
            }
            Some(None) => {
                body["notes"] = serde_json::Value::Null;
            }
            None => {}
        }

        //    Folder: Some(Some(name)) = move (auto-create), Some(None) = clear,
        //    None = keep. folderId is plaintext on the wire (not encrypted).
        match &edit.folder {
            Some(Some(name)) => {
                let fid = self.ensure_folder_id(name).await?;
                body["folderId"] = serde_json::Value::String(fid);
            }
            Some(None) => {
                body["folderId"] = serde_json::Value::Null;
            }
            None => {}
        }

        //    Login-only fields apply to login ciphers only; for other types
        //    there is no `login` object to edit, so they are ignored.
        if cipher_type == 1 {
            for (key, value) in [
                ("username", &edit.username),
                ("password", &edit.password),
                ("totp", &edit.totp),
            ] {
                match value {
                    Some(Some(v)) => {
                        body["login"][key] =
                            serde_json::Value::String(self.enc_opt(Some(v))?.unwrap());
                    }
                    Some(None) => {
                        body["login"][key] = serde_json::Value::Null;
                    }
                    None => {}
                }
            }
            match &edit.uri {
                Some(Some(uri)) => {
                    let enc_uri = crate::crypto::encrypt_string(
                        uri,
                        self.crypto_keys.enc_key_bytes(),
                        self.crypto_keys.mac_key_bytes(),
                    )?;
                    body["login"]["uris"] = serde_json::json!([{ "uri": enc_uri, "match": null }]);
                }
                Some(None) => {
                    body["login"]["uris"] = serde_json::Value::Null;
                }
                None => {}
            }
        }

        //    Custom fields: Some = replace the whole list, None = keep.
        if let Some(fields) = &edit.fields {
            body["fields"] = serde_json::Value::Array(self.encrypt_fields(fields)?);
        }

        // 3. Full-replace PUT with the merged body.
        let updated = self
            .authenticated(|access_token| async move {
                crate::api_write::edit_cipher(
                    &client,
                    &self.server_url,
                    &access_token,
                    cipher_id,
                    &body,
                )
                .await
            })
            .await
            .context("failed to edit cipher")?;
        self.refresh_after_write(updated).await
    }

    /// Soft-delete a cipher (reversible via [`Self::restore_cipher`]).
    pub async fn soft_delete_cipher(&self, cipher_id: &str) -> Result<CipherEntry> {
        let client = self.write_client()?;
        // The /delete endpoint expects the current cipher body (type + name).
        let current = self.get_cipher(cipher_id).await?;
        let body = serde_json::json!({
        "type": cipher_type_u8(&current.cipher_type),
            "name": self.encrypt_str(&current.name)?,
        });
        let updated = self
            .authenticated(|access_token| async move {
                crate::api_write::soft_delete_cipher(
                    &client,
                    &self.server_url,
                    &access_token,
                    cipher_id,
                    &body,
                )
                .await
            })
            .await
            .context("failed to soft-delete cipher")?;
        // refresh_after_write drops the cipher from the active cache because the
        // server returns it with a deletedDate.
        self.refresh_after_write(updated).await
    }

    /// Restore a soft-deleted cipher.
    pub async fn restore_cipher(&self, cipher_id: &str) -> Result<CipherEntry> {
        let client = self.write_client()?;
        let current = self.get_cipher(cipher_id).await.ok();
        let body = match current {
            Some(c) => serde_json::json!({
            "type": cipher_type_u8(&c.cipher_type),
                "name": self.encrypt_str(&c.name)?,
            }),
            None => serde_json::json!({}),
        };
        let updated = self
            .authenticated(|access_token| async move {
                crate::api_write::restore_cipher(
                    &client,
                    &self.server_url,
                    &access_token,
                    cipher_id,
                    &body,
                )
                .await
            })
            .await
            .context("failed to restore cipher")?;
        self.refresh_after_write(updated).await
    }

    /// Hard-delete a cipher (permanent). Returns `Ok(())`.
    pub async fn delete_cipher(&self, cipher_id: &str) -> Result<()> {
        let client = self.write_client()?;
        self.authenticated(|access_token| async move {
            crate::api_write::delete_cipher(&client, &self.server_url, &access_token, cipher_id)
                .await
        })
        .await
        .context("failed to hard-delete cipher")?;
        let mut ciphers = self.ciphers.write().await;
        ciphers.retain(|c| c.id != cipher_id);
        Ok(())
    }

    /// Create a new folder. Returns the decrypted `FolderEntry`.
    pub async fn create_folder(&self, name: &str) -> Result<FolderEntry> {
        let enc_name = self.encrypt_str(name)?;
        let client = self.write_client()?;
        let body = serde_json::json!({ "name": enc_name });
        let created = self
            .authenticated(|access_token| async move {
                crate::api_write::create_folder(&client, &self.server_url, &access_token, &body)
                    .await
            })
            .await
            .context("failed to create folder")?;

        let folder_id = created["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("folder create response missing id"))?
            .to_string();
        let decrypted_name =
            decrypt_str(&self.crypto_keys, &enc_name).unwrap_or_else(|| name.to_string());
        let entry = FolderEntry {
            id: folder_id.clone(),
            name: decrypted_name,
        };
        let mut folders = self.folders.write().await;
        folders.push(entry.clone());
        Ok(entry)
    }

    /// Rename a folder. `name` is the current name (resolved to id). Returns
    /// the updated `FolderEntry`.
    pub async fn edit_folder(&self, name: &str, new_name: &str) -> Result<FolderEntry> {
        let folder_id = self
            .folder_id_for_name(name)
            .ok_or_else(|| anyhow::anyhow!("folder not found: {}", name))?;
        let enc_name = self.encrypt_str(new_name)?;
        let client = self.write_client()?;
        let request_folder_id = folder_id.clone();
        let body = serde_json::json!({ "name": enc_name });
        let _updated = self
            .authenticated(|access_token| async move {
                crate::api_write::rename_folder(
                    &client,
                    &self.server_url,
                    &access_token,
                    &request_folder_id,
                    &body,
                )
                .await
            })
            .await
            .context("failed to rename folder")?;

        let decrypted_name =
            decrypt_str(&self.crypto_keys, &enc_name).unwrap_or_else(|| new_name.to_string());
        let entry = FolderEntry {
            id: folder_id.clone(),
            name: decrypted_name.clone(),
        };
        let mut folders = self.folders.write().await;
        if let Some(f) = folders.iter_mut().find(|f| f.id == folder_id) {
            f.name = decrypted_name;
        }
        Ok(entry)
    }

    /// Delete a folder by name. The server moves its entries to "No Folder".
    /// Entries are never auto-deleted.
    pub async fn delete_folder(&self, name: &str) -> Result<()> {
        let folder_id = self
            .folder_id_for_name(name)
            .ok_or_else(|| anyhow::anyhow!("folder not found: {}", name))?;
        let client = self.write_client()?;
        let request_folder_id = folder_id.clone();
        self.authenticated(|access_token| async move {
            crate::api_write::delete_folder(
                &client,
                &self.server_url,
                &access_token,
                &request_folder_id,
            )
            .await
        })
        .await
        .context("failed to delete folder")?;
        let mut folders = self.folders.write().await;
        folders.retain(|f| f.id != folder_id);
        Ok(())
    }
}
