//! Vaultwarden MCP — pure Rust backend for vault operations.
//!
//! Provides the vaultwarden API client wrapper and crypto types needed
//! by the MCP server, all using the vaultwarden-cli library.

use std::sync::Arc;

use anyhow::{Context, Result};
use vaultwarden_cli::models::{
    Cipher, CipherData, FieldType, Folder, KdfType, SyncResponse, TokenResponse,
};
use vaultwarden_cli::{
    api::ApiClient,
    crypto::{CryptoKeys, KdfIterations, MasterKey},
};

pub mod api_write;
pub mod config;
pub mod crypto;
pub mod mcp;
pub mod secrets;

/// A connected vaultwarden session with decrypted cipher access.
pub struct VaultwardenSession {
    api: Arc<ApiClient>,
    access_token: String,
    email: String,
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
        let api = Arc::new(
            ApiClient::new_with_flags(server, allow_http).context("failed to create API client")?,
        );
        let server_url = server.to_string();

        // 1. Authenticate
        let token: TokenResponse = api
            .login(client_id, client_secret)
            .await
            .context("failed to authenticate (client_credentials) with vaultwarden")?;

        let access_token = token.access_token.clone();
        let _kdf = token.kdf.unwrap_or(KdfType::Pbkdf2);
        let kdf_iterations = token.kdf_iterations.unwrap_or(600_000);

        // 2. Sync to fetch vault data
        let sync: SyncResponse = api
            .sync(&access_token)
            .await
            .context("failed to sync vault — credential verification step")?;

        let email = sync.profile.email.clone();

        // 3. Derive master key from password + email + kdf iterations
        let master_key = MasterKey::derive(
            password,
            &email,
            KdfIterations::new(kdf_iterations)
                .ok_or_else(|| anyhow::anyhow!("invalid KDF iterations: {}", kdf_iterations))?,
        );

        // 4. Decrypt encrypted symmetric key (verifies password — HMAC check)
        let encrypted_key = sync
            .profile
            .key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no encrypted key in profile"))?;
        let crypto_keys = master_key.decrypt_symmetric_key(encrypted_key).context(
            "failed to decrypt symmetric key — vault password is wrong (HMAC verification)",
        )?;

        // 5. Decrypt folders from sync
        let folder_entries = Self::decrypt_folders(&sync.folders, &crypto_keys);

        // 6. Verify by attempting to decrypt ciphers
        let entries =
            Self::decrypt_ciphers_with_folders(&sync.ciphers, &crypto_keys, &folder_entries);
        let folder_count = folder_entries.len();
        tracing::info!(
            "vault verification OK: {}@{} ({} ciphers, {} folders decrypted)",
            email,
            server_url,
            entries.len(),
            folder_count
        );

        Ok(Self {
            api,
            access_token,
            email,
            server_url,
            crypto_keys,
            ciphers: tokio::sync::RwLock::new(entries),
            folders: tokio::sync::RwLock::new(folder_entries),
        })
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
        let created =
            crate::api_write::create_folder(&client, &self.server_url, &self.access_token, &body)
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
            .api
            .sync(&self.access_token)
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

/// Cipher type accepted by the write tools. v1 supports login + secure note;
// card/identity/ssh remain read-only (consistent with the read path).
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

/// Plaintext field input for create. Every field except `name` and `cipher_type`
/// is optional and is omitted from the request body when `None`.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct CipherInput {
    /// Cipher type: "login" or "note".
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
        let created =
            crate::api_write::create_cipher(&client, &self.server_url, &self.access_token, &body)
                .await
                .context("failed to create cipher")?;
        self.refresh_after_write(created).await
    }

    /// Edit an existing cipher. `None` on every field means "unchanged"; the
    /// `Option<Option<T>>` shape lets a caller explicitly clear a field by
    /// passing `Some(None)`. PUT is a full replace, so we fetch the current
    /// cipher, overlay the provided fields, and re-encrypt the whole body.
    pub async fn edit_cipher(&self, cipher_id: &str, edit: CipherEdit) -> Result<CipherEntry> {
        // 1. Fetch the current plaintext state.
        let current = self.get_cipher(cipher_id).await?;

        // 2. Overlay edits onto the current values.
        let input = CipherInput {
            cipher_type: match current.cipher_type.as_str() {
                "note" => WriteCipherType::Note,
                _ => WriteCipherType::Login,
            },
            name: edit.name.unwrap_or(current.name),
            username: overlay_opt(edit.username, current.username),
            password: overlay_opt(edit.password, current.password),
            uri: overlay_opt(edit.uri, current.uri),
            totp: overlay_opt(edit.totp, current.totp),
            notes: overlay_opt(edit.notes, current.notes),
            fields: edit.fields.map(|fs| {
                fs.into_iter()
                    .map(|f| FieldInput {
                        name: f.name,
                        value: f.value,
                        field_type: f.field_type,
                    })
                    .collect()
            }),
            folder: current.folder.clone(),
        };

        // 3. Resolve folder for the edit body: None = unchanged, Some(None) =
        //    clear, Some(Some(name)) = move/resolve.
        //    Handle here because edit needs explicit null in the body.
        let folder_id: Option<Option<String>> = match &edit.folder {
            None => None,
            Some(None) => Some(None),
            Some(Some(name)) => {
                let fid = self.ensure_folder_id(name).await?;
                Some(Some(fid))
            }
        };

        // 4. Build the full encrypted body and PUT it.
        let client = self.write_client()?;
        let mut body = self.build_create_body(&input)?;

        // Inject folderId after body build: null = clear, id = set, omit = keep.
        match &folder_id {
            Some(Some(fid)) => {
                body["folderId"] = serde_json::Value::String(fid.clone());
            }
            Some(None) => {
                body["folderId"] = serde_json::Value::Null;
            }
            None => {}
        }

        let updated = crate::api_write::edit_cipher(
            &client,
            &self.server_url,
            &self.access_token,
            cipher_id,
            &body,
        )
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
            "type": match current.cipher_type.as_str() {
                "note" => 2u8,
                _ => 1u8,
            },
            "name": self.encrypt_str(&current.name)?,
        });
        let updated = crate::api_write::soft_delete_cipher(
            &client,
            &self.server_url,
            &self.access_token,
            cipher_id,
            &body,
        )
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
                "type": match c.cipher_type.as_str() {
                    "note" => 2u8,
                    _ => 1u8,
                },
                "name": self.encrypt_str(&c.name)?,
            }),
            None => serde_json::json!({}),
        };
        let updated = crate::api_write::restore_cipher(
            &client,
            &self.server_url,
            &self.access_token,
            cipher_id,
            &body,
        )
        .await
        .context("failed to restore cipher")?;
        self.refresh_after_write(updated).await
    }

    /// Hard-delete a cipher (permanent). Returns `Ok(())`.
    pub async fn delete_cipher(&self, cipher_id: &str) -> Result<()> {
        let client = self.write_client()?;
        crate::api_write::delete_cipher(&client, &self.server_url, &self.access_token, cipher_id)
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
        let created =
            crate::api_write::create_folder(&client, &self.server_url, &self.access_token, &body)
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
        let body = serde_json::json!({ "name": enc_name });
        let _updated = crate::api_write::rename_folder(
            &client,
            &self.server_url,
            &self.access_token,
            &folder_id,
            &body,
        )
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
        crate::api_write::delete_folder(&client, &self.server_url, &self.access_token, &folder_id)
            .await
            .context("failed to delete folder")?;
        let mut folders = self.folders.write().await;
        folders.retain(|f| f.id != folder_id);
        Ok(())
    }
}

/// Apply an edit overlay: `None` (not provided in the edit) keeps the current
/// value; `Some(new)` replaces it; `Some(None)` clears it.
fn overlay_opt(edit: Option<Option<String>>, current: Option<String>) -> Option<String> {
    match edit {
        None => current,
        Some(new) => new,
    }
}
