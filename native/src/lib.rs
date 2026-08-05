//! Vaultwarden MCP — pure Rust backend for vault operations.
//!
//! Provides the vaultwarden API client wrapper and crypto types needed
//! by the MCP server, all using the vaultwarden-cli library.

use std::sync::Arc;

use anyhow::{Context, Result};
use vaultwarden_cli::{
    api::ApiClient,
    crypto::{CryptoKeys, KdfIterations, MasterKey},
};
use vaultwarden_cli::models::{
    Cipher, CipherData, FieldType, KdfType, SyncResponse, TokenResponse,
};

pub mod mcp;

/// A connected vaultwarden session with decrypted cipher access.
pub struct VaultwardenSession {
    api: Arc<ApiClient>,
    access_token: String,
    email: String,
    server_url: String,
    crypto_keys: CryptoKeys,
    ciphers: tokio::sync::RwLock<Vec<CipherEntry>>,
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
            ApiClient::new_with_flags(server, allow_http)
                .context("failed to create API client")?
        );
        let server_url = server.to_string();

        // 1. Authenticate
        let token: TokenResponse = api.login(client_id, client_secret)
            .await
            .context("failed to authenticate (client_credentials) with vaultwarden")?;

        let access_token = token.access_token.clone();
        let kdf = token.kdf.unwrap_or(KdfType::Pbkdf2);
        let kdf_iterations = token.kdf_iterations.unwrap_or(600_000);

        // 2. Sync to fetch vault data
        let sync: SyncResponse = api.sync(&access_token)
            .await
            .context("failed to sync vault — credential verification step")?;

        let email = sync.profile.email.clone();

        // 3. Derive master key from password + email + kdf iterations
        let master_key = MasterKey::derive(
            password, &email,
            KdfIterations::new(kdf_iterations)
                .ok_or_else(|| anyhow::anyhow!("invalid KDF iterations: {}", kdf_iterations))?,
        );

        // 4. Decrypt encrypted symmetric key (verifies password — HMAC check)
        let encrypted_key = sync.profile.key.as_deref()
            .ok_or_else(|| anyhow::anyhow!("no encrypted key in profile"))?;
        let crypto_keys = master_key.decrypt_symmetric_key(encrypted_key)
            .context("failed to decrypt symmetric key — vault password is wrong (HMAC verification)")?;

        // 5. Verify by attempting to decrypt ciphers
        let entries = Self::decrypt_ciphers(&sync.ciphers, &crypto_keys);
        tracing::info!(
            "vault verification OK: {}@{} ({} ciphers decrypted)",
            email, server_url, entries.len()
        );

        Ok(Self {
            api,
            access_token,
            email,
            server_url,
            crypto_keys,
            ciphers: tokio::sync::RwLock::new(entries),
        })
    }

    /// Decrypt all ciphers from a sync response.
    fn decrypt_ciphers(ciphers: &[Cipher], keys: &CryptoKeys) -> Vec<CipherEntry> {
        ciphers.iter()
            .filter(|c| c.deleted_date.is_none())
            .filter_map(|c| {
                c.cipher_data.as_ref().map(|d| Self::cipher_to_entry(c, d, keys))
            })
            .collect()
    }

    fn cipher_to_entry(cipher: &Cipher, data: &CipherData, keys: &CryptoKeys) -> CipherEntry {
        // Determine cipher type string and name
        let (cipher_type_str, cipher_name) = match data {
            CipherData::Login(l) => {
                ("login", cipher.name.clone()
                    .or_else(|| l.username.clone())
                    .unwrap_or_else(|| cipher.id.to_string()))
            }
            CipherData::SecureNote(_) => {
                ("note", cipher.name.clone().unwrap_or_else(|| cipher.id.to_string()))
            }
            CipherData::Card(card) => {
                ("card", cipher.name.clone()
                    .or_else(|| card.cardholder_name.clone())
                    .unwrap_or_else(|| cipher.id.to_string()))
            }
            CipherData::Identity(identity) => {
                ("identity", cipher.name.clone()
                    .or(identity.company.clone())
                    .or(identity.email.clone())
                    .unwrap_or_else(|| cipher.id.to_string()))
            }
            CipherData::SshKey(_) => {
                ("ssh", cipher.name.clone().unwrap_or_else(|| cipher.id.to_string()))
            }
        };

        // Extract fields based on cipher data type
        let (username, password, uri, notes, totp, ssh_pub, ssh_priv, ssh_fp) = match data {
            CipherData::Login(login) => {
                let uri_opt = login.uris.as_ref()
                    .and_then(|u| u.first())
                    .and_then(|u| u.uri.clone())
                    .or_else(|| Self::decrypt_str_opt(cipher.data.as_ref(), keys, |d| d.uri.as_deref()));
                (
                    Self::decrypt_str_opt(Some(login), keys, |l| l.username.as_deref()),
                    Self::decrypt_str_opt(Some(login), keys, |l| l.password.as_deref()),
                    uri_opt,
                    Self::decrypt_str_opt(Some(cipher), keys, |c| c.notes.as_deref()),
                    login.totp.clone(),
                    None, None, None,
                )
            }
            CipherData::SshKey(ssh) => {
                (None, None, None,
                 Self::decrypt_str_opt(Some(cipher), keys, |c| c.notes.as_deref()),
                 None, ssh.public_key.clone(), ssh.private_key.clone(), ssh.fingerprint.clone())
            }
            _ => {
                (None, None, None,
                 Self::decrypt_str_opt(Some(cipher), keys, |c| c.notes.as_deref()),
                 None, None, None, None)
            }
        };

        // Fields
        let fields = cipher.get_fields()
            .map(|fs| fs.iter().filter_map(|f| {
                Some(FieldEntry {
                    name: f.name.clone()?,
                    value: Self::decrypt_str_opt_inner(keys, f.value.as_deref()),
                    field_type: match f.r#type {
                        FieldType::Text => "text",
                        FieldType::Hidden => "hidden",
                        FieldType::Boolean => "boolean",
                        FieldType::Linked => "linked",
                    }.to_string(),
                })
            }).collect());

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
        Ok(ciphers.iter()
            .filter(|c| {
                c.name.to_lowercase().contains(&lower)
                    || c.uri.as_deref().unwrap_or("").to_lowercase().contains(&lower)
                    || c.username.as_deref().unwrap_or("").to_lowercase().contains(&lower)
            })
            .cloned()
            .collect())
    }

    /// Get a specific cipher by ID
    pub async fn get_cipher(&self, id: &str) -> Result<CipherEntry> {
        let ciphers = self.ciphers.read().await;
        ciphers.iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("cipher '{}' not found", id))
    }

    /// Synchronize the vault and return a summary with decrypted ciphers
    pub async fn sync(&self) -> Result<SyncSummary> {
        let sync_resp: SyncResponse = self.api.sync(&self.access_token)
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

    pub fn server_url(&self) -> &str { &self.server_url }
    pub fn email(&self) -> &str { &self.email }
}
