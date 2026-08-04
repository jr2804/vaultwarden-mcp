use anyhow::{Context, Result};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::Serialize;
use tokio::runtime::Runtime;
use vaultwarden_cli::api::ApiClient;
use vaultwarden_cli::crypto::{CryptoKeys, KdfIterations, MasterKey};
use vaultwarden_cli::models::{
    Cipher, CipherData, CipherOutput, FieldOutput, SyncResponse, TokenResponse,
};

/// Global tokio runtime for async operations.
fn runtime() -> &'static Runtime {
    static RUNTIME: std::sync::OnceLock<Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

/// Per-account session holding API client, tokens, and decrypted keys.
///
/// Each instance is isolated — supports multi-account by creating
/// one session per account.  The credential-verification safeguard
/// (master key derivation + test cipher decrypt) runs at construction
/// time so a wrong-password/credential-mismatch is caught immediately.
#[pyclass(name = "VaultwardenSession")]
struct VaultwardenSession {
    #[allow(dead_code)]
    api: ApiClient,
    access_token: String,
    refresh_token: Option<String>,
    server: String,
    client_id: String,
    email: String,
    /// Decrypted crypto keys (None when locked)
    crypto_keys: Option<CryptoKeys>,
    /// Encrypted vault key from token response (for unlock() re-verification)
    encrypted_key: String,
    /// KDF iterations from token response (for unlock() re-verification)
    kdf_iterations: Option<KdfIterations>,
}

#[pymethods]
impl VaultwardenSession {
    /// Create a new session by logging in and verifying credentials.
    ///
    /// Steps:
    /// 1. `client_credentials` grant auth → access token + encrypted vault key
    /// 2. Sync → profile (email) + ciphers
    /// 3. Master key derivation from password+email
    /// 4. Decrypt vault key via master key (fails if password wrong for this vault)
    /// 5. Verification: decrypt one cipher as a test (fails if HMAC mismatch)
    #[new]
    #[pyo3(signature = (server, client_id, client_secret, master_password, allow_http=false))]
    fn new(
        server: &str,
        client_id: &str,
        client_secret: &str,
        master_password: &str,
        allow_http: bool,
    ) -> PyResult<Self> {
        let rt = runtime();
        let result = rt.block_on(async {
            Self::login_and_verify(server, client_id, client_secret, master_password, allow_http).await
        });
        match result {
            Ok(s) => Ok(s),
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }

    /// Sync the vault and return a summary (ciphers count, profile email).
    fn sync(&mut self) -> PyResult<SyncSummary> {
        let access_token = self.access_token.clone();
        let api = &self.api;
        let result = runtime().block_on(async { api.sync(&access_token).await });
        match result {
            Ok(sync_resp) => Ok(SyncSummary {
                email: sync_resp.profile.email,
                cipher_count: sync_resp.ciphers.len(),
            }),
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }

    /// Search ciphers by name or URI — returns metadata only (no secrets).
    fn search(&mut self, query: &str) -> PyResult<Vec<PyCipherEntry>> {
        let access_token = self.access_token.clone();
        let api = &self.api;
        let result = runtime().block_on(async { api.sync(&access_token).await });
        match result {
            Ok(sync_resp) => {
                let keys = self.crypto_keys.as_ref()
                    .ok_or_else(|| PyRuntimeError::new_err("vault is locked"))?;
                let q = query.to_lowercase();
                let mut entries = Vec::new();
                for cipher in &sync_resp.ciphers {
                    let matches = cipher.get_name().map_or(false, |n| n.to_lowercase().contains(&q))
                        || cipher.get_uri().map_or(false, |u| u.to_lowercase().contains(&q));
                    if matches {
                        let output = decrypt_cipher_metadata(cipher, keys)
                            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                        entries.push(PyCipherEntry::from_output(output));
                    }
                }
                Ok(entries)
            }
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }

    /// Get a specific cipher by ID — returns full decrypted data including secrets.
    fn get_cipher(&mut self, cipher_id: &str) -> PyResult<PyCipherEntry> {
        let access_token = self.access_token.clone();
        let api = &self.api;
        let result = runtime().block_on(async { api.sync(&access_token).await });
        match result {
            Ok(sync_resp) => {
                let cipher = sync_resp.ciphers.iter()
                    .find(|c| c.id.to_string() == cipher_id)
                    .cloned()
                    .ok_or_else(|| PyValueError::new_err(format!("cipher not found: {cipher_id}")))?;
                let keys = self.crypto_keys.as_ref()
                    .ok_or_else(|| PyRuntimeError::new_err("vault is locked"))?;
                let output = decrypt_cipher_full(&cipher, keys)
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                Ok(PyCipherEntry::from_output(output))
            }
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }

    /// Refresh the access token using the refresh token.
    fn refresh_token(&mut self) -> PyResult<()> {
        let api = &self.api;
        let refresh = self.refresh_token.clone()
            .ok_or_else(|| PyRuntimeError::new_err("no refresh token available"))?;
        let result = runtime().block_on(async { api.refresh_token(&refresh).await });
        match result {
            Ok(token_resp) => {
                self.access_token = token_resp.access_token;
                self.refresh_token = token_resp.refresh_token;
                Ok(())
            }
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }

    /// Lock the vault (clear decrypted keys from memory).
    fn lock(&mut self) -> PyResult<()> {
        self.crypto_keys = None;
        Ok(())
    }

    /// Unlock the vault with a master password (re-verify credentials, re-derive keys).
    ///
    /// This re-runs the credential-verification safeguard: derives the master key
    /// and decrypts the vault key, then decrypts a test cipher to confirm HMAC integrity.
    /// If the master password is wrong for this vault, it fails before any secrets are exposed.
    fn unlock(&mut self, master_password: &str) -> PyResult<()> {
        let access_token = self.access_token.clone();
        let api = &self.api;
        let sync_result = runtime().block_on(async { api.sync(&access_token).await });
        match sync_result {
            Ok(sync_resp) => {
                let email = &sync_resp.profile.email;
                let kdf_iterations = self.kdf_iterations;

                let master_key = MasterKey::derive(
                    master_password,
                    email,
                    kdf_iterations.unwrap_or_default(),
                );

                let crypto_keys = master_key
                    .decrypt_symmetric_key(&self.encrypted_key)
                    .map_err(|e| PyRuntimeError::new_err(format!(
                        "Failed to decrypt vault key. Check your master password: {e}"
                    )))?;

                // Verification: decrypt first cipher to confirm HMAC integrity
                if let Some(first_cipher) = sync_resp.ciphers.first() {
                    decrypt_cipher_metadata(first_cipher, &crypto_keys)
                        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                }

                self.crypto_keys = Some(crypto_keys);
                Ok(())
            }
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }

    /// Account email (read-only)
    #[getter]
    fn email(&self) -> PyResult<String> {
        Ok(self.email.clone())
    }

    /// Server URL (read-only)
    #[getter]
    fn server(&self) -> PyResult<String> {
        Ok(self.server.clone())
    }

    /// Client ID (read-only)
    #[getter]
    fn client_id(&self) -> PyResult<String> {
        Ok(self.client_id.clone())
    }

    /// Whether the vault keys are currently decrypted (unlocked)
    #[getter]
    fn is_unlocked(&self) -> bool {
        self.crypto_keys.is_some()
    }
}

impl VaultwardenSession {
    /// Login flow: client_credentials → sync → derive master key → decrypt vault key → verify.
    ///
    /// The credential verification safeguard runs here: if the master password
    /// or client credentials belong to a different vault, the master key
    /// derivation + vault key decryption will fail at step 4, and the test
    /// cipher decrypt at step 5 provides a second layer of HMAC integrity check.
    async fn login_and_verify(
        server: &str,
        client_id: &str,
        client_secret: &str,
        master_password: &str,
        allow_http: bool,
    ) -> Result<Self> {
        let api = ApiClient::new_with_flags(server, allow_http)?;

        // Step 1: client_credentials grant
        let token_response: TokenResponse = api.login(client_id, client_secret).await?;

        // Step 2: sync to get profile + ciphers
        let sync_response: SyncResponse = api.sync(&token_response.access_token).await?;

        let email = sync_response.profile.email.clone();

        // Step 3-4: derive master key from password + email, decrypt vault key.
        // This is the critical safeguard — if credentials are wrong for this
        // vault, decrypt_symmetric_key fails immediately.
        let kdf_iterations = token_response.kdf_iterations
            .and_then(KdfIterations::new);

        let master_key = MasterKey::derive(
            master_password,
            &email,
            kdf_iterations.unwrap_or_default(),
        );

        let encrypted_key = token_response.key.as_ref()
            .ok_or_else(|| anyhow::anyhow!(
                "Token response has no encrypted vault key (Key field). \
                 The client_credentials grant may not have the 'api' scope."
            ))?;

        let crypto_keys = master_key
            .decrypt_symmetric_key(encrypted_key)
            .map_err(|e| anyhow::anyhow!(
                "Failed to decrypt vault key. The master password or client \
                 credentials may be for a different vault. Error: {e}"
            ))?;

        // Step 5: verification — decrypt the first cipher as a test.
        // If HMAC fails (wrong vault credentials silently swapped), we abort here.
        // This prevents the 'badly encrypted entries' scenario.
        if let Some(first_cipher) = sync_response.ciphers.first() {
            decrypt_cipher_metadata(first_cipher, &crypto_keys)?;
        }

        Ok(Self {
            api,
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            server: server.to_string(),
            client_id: client_id.to_string(),
            email,
            crypto_keys: Some(crypto_keys),
            encrypted_key: encrypted_key.clone(),
            kdf_iterations,
        })
    }
}

/// Python-facing sync summary
#[pyclass(name = "SyncSummary")]
#[derive(Clone, Serialize)]
struct SyncSummary {
    #[pyo3(get)]
    email: String,
    #[pyo3(get)]
    cipher_count: usize,
}

/// Python-facing cipher entry (metadata + optional secrets)
#[pyclass(name = "CipherEntry")]
#[derive(Clone)]
struct PyCipherEntry {
    #[pyo3(get)]
    id: String,
    #[pyo3(get)]
    cipher_type: String,
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    username: Option<String>,
    #[pyo3(get)]
    password: Option<String>,
    #[pyo3(get)]
    uri: Option<String>,
    #[pyo3(get)]
    notes: Option<String>,
    #[pyo3(get)]
    fields: Option<Vec<PyFieldOutput>>,
    #[pyo3(get)]
    ssh_public_key: Option<String>,
    #[pyo3(get)]
    ssh_private_key: Option<String>,
    #[pyo3(get)]
    ssh_fingerprint: Option<String>,
}

/// Python-serializable version of FieldOutput
#[pyclass(name = "FieldOutput")]
#[derive(Clone, Serialize)]
struct PyFieldOutput {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    value: String,
    #[pyo3(get)]
    hidden: bool,
}

impl PyCipherEntry {
    fn from_output(output: CipherOutput) -> Self {
        let fields = output.fields.map(|fo| {
            fo.into_iter().map(|f| PyFieldOutput {
                name: f.name,
                value: f.value,
                hidden: f.hidden,
            }).collect()
        });
        Self {
            id: output.id,
            cipher_type: output.cipher_type,
            name: output.name,
            username: output.username,
            password: output.password,
            uri: output.uri,
            notes: output.notes,
            fields,
            ssh_public_key: output.ssh_public_key,
            ssh_private_key: output.ssh_private_key,
            ssh_fingerprint: output.ssh_fingerprint,
        }
    }
}

/// Decrypt cipher metadata only (name, username) — NO secret fields.
/// Used for listing/searching without exposing secrets.
fn decrypt_cipher_metadata(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    let name = cipher.get_name()
        .context("cipher has no name")
        .and_then(|n| keys.decrypt_to_string(n).context("failed to decrypt cipher name"))?;

    let username = decrypt_optional(cipher.get_username(), keys)?;

    Ok(CipherOutput {
        id: cipher.id.to_string(),
        cipher_type: cipher_type_string(cipher),
        name,
        username,
        password: None,
        uri: None,
        notes: None,
        fields: None,
        ssh_public_key: None,
        ssh_private_key: None,
        ssh_fingerprint: None,
    })
}

/// Decrypt full cipher data including all secrets.
/// Used when a user explicitly requests a specific entry.
fn decrypt_cipher_full(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    let name = cipher.get_name()
        .context("cipher has no name")
        .and_then(|n| keys.decrypt_to_string(n).context("failed to decrypt cipher name"))?;

    let username = decrypt_optional(cipher.get_username(), keys)?;
    let password = decrypt_optional(cipher.get_password(), keys)?;
    let uri = decrypt_optional(cipher.get_uri(), keys)?;
    let notes = decrypt_optional(cipher.get_notes(), keys)?;

    let fields = if let Some(cipher_fields) = cipher.get_fields() {
        let mut out = Vec::new();
        for (idx, field) in cipher_fields.iter().enumerate() {
            let field_name = field.name.as_ref()
                .ok_or_else(|| anyhow::anyhow!("field at index {idx} has no name"))?;
            let decrypted_name = keys.decrypt_to_string(field_name)
                .with_context(|| format!("failed to decrypt field name at index {idx}"))?;

            let decrypted_value = if let Some(encrypted_value) = &field.value {
                Some(keys.decrypt_to_string(encrypted_value).with_context(|| {
                    format!("failed to decrypt field value for field '{decrypted_name}'")
                })?)
            } else {
                None
            };

            out.push(FieldOutput {
                name: decrypted_name,
                value: decrypted_value.unwrap_or_default(),
                hidden: field.r#type.is_hidden(),
            });
        }
        Some(out)
    } else {
        None
    };

    // SSH key fields
    let ssh_key_data = cipher.cipher_data.as_ref().and_then(|cd| {
        if let CipherData::SshKey(s) = cd { Some(s) } else { None }
    });

    let ssh_public_key = decrypt_optional(
        ssh_key_data.and_then(|s| s.public_key.as_deref()),
        keys,
    )?;
    let ssh_private_key = decrypt_optional(
        ssh_key_data.and_then(|s| s.private_key.as_deref()),
        keys,
    )?;
    let ssh_fingerprint = decrypt_optional(
        ssh_key_data.and_then(|s| s.fingerprint.as_deref()),
        keys,
    )?;

    Ok(CipherOutput {
        id: cipher.id.to_string(),
        cipher_type: cipher_type_string(cipher),
        name,
        username,
        password,
        uri,
        notes,
        fields,
        ssh_public_key,
        ssh_private_key,
        ssh_fingerprint,
    })
}

fn decrypt_optional(encrypted: Option<&str>, keys: &CryptoKeys) -> Result<Option<String>> {
    match encrypted {
        Some(enc) => Ok(Some(keys.decrypt_to_string(enc)?)),
        None => Ok(None),
    }
}

fn cipher_type_string(cipher: &Cipher) -> String {
    cipher.cipher_data.as_ref()
        .map(|cd| cd.cipher_type().to_string())
        .unwrap_or_default()
}

/// Error type for cipher operations
#[pyclass(name = "CipherError", extends = PyValueError)]
struct CipherError;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> pyo3::PyResult<()> {
    m.add_class::<VaultwardenSession>()?;
    m.add_class::<PyCipherEntry>()?;
    m.add_class::<PyFieldOutput>()?;
    m.add_class::<SyncSummary>()?;
    m.add_class::<CipherError>()?;
    m.add("__doc__", "Native PyO3 bindings for Vaultwarden MCP server")?;
    Ok(())
}
