//! Thin write client for the Bitwarden/Vaultwarden cipher and folder REST endpoints.
//!
//! The `vaultwarden-cli` `ApiClient` exposes read endpoints only and keeps its
//! `reqwest::Client` / `base_url` private, so create/edit/delete go through
//! this small client. It mirrors the upstream client's bearer-auth + JSON body
//! conventions and the same `bitwarden-client-version` header so Vaultwarden
//! doesn't log a warning per write.
//!
//! Endpoints (all under `/api/ciphers` or `/api/folders`):
//!   POST   /api/ciphers                  create
//!   PUT    /api/ciphers/{id}              edit (full replace)
//!   PUT    /api/ciphers/{id}/delete       soft-delete (sets deletedDate, reversible)
//!   PUT    /api/ciphers/{id}/restore      restore a soft-deleted cipher
//!   DELETE /api/ciphers/{id}              hard-delete (permanent)
//!   POST   /api/folders                   create folder
//!   PUT    /api/folders/{id}              rename folder
//!   DELETE /api/folders/{id}              delete folder

use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Response};
use serde_json::Value;

/// Builds the shared `reqwest::Client` for write requests. Callers pass the
/// same `allow_http` flag used for the read `ApiClient` so the security policy
/// (https-only unless explicitly relaxed) is consistent across read/write.
pub fn build_write_client(allow_http: bool) -> Result<Client> {
    // Match the upstream crate: install a rustls crypto provider once so TLS
    // works regardless of which feature the top-level crate picked.
    // vaultwarden-cli::install_rustls_crypto_provider() is pub(crate); we rely
    // on reqwest's `rustls-no-provider` feature having already been activated
    // by the read ApiClient construction earlier in the process.

    let mut builder =
        Client::builder().user_agent(concat!("vaultwarden-mcp/", env!("CARGO_PKG_VERSION")));

    if allow_http {
        // Only accept plain HTTP when the operator explicitly opted in. This
        // mirrors ApiClient::new_with_flags; we don't re-validate the scheme
        // here because the read client already gated it at startup.
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder.build().context("failed to build write HTTP client")
}

/// Handle a non-2xx response: extract a bounded snippet of the body so the
/// surfaced error is actionable instead of "request failed".
async fn ensure_success(response: Response, operation: &str) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    let snippet = body.chars().take(4096).collect::<String>();
    // ponytail: 4 KiB snippet cap matches upstream's API_ERROR_BODY_LIMIT_BYTES;
    // we don't need the full body to diagnose a write failure.
    Err(anyhow!("{operation} failed ({status}): {snippet}"))
}

/// POST or PUT an encrypted cipher body, returning the server's `Cipher` JSON.
async fn send_json(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    access_token: &str,
    body: &Value,
    operation: &str,
) -> Result<Value> {
    let resp = client
        .request(method, url)
        .bearer_auth(access_token)
        .header(
            "bitwarden-client-version",
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .json(body)
        .send()
        .await
        .with_context(|| format!("failed to send {operation} request"))?;

    let resp = ensure_success(resp, operation).await?;
    resp.json::<Value>()
        .await
        .with_context(|| format!("failed to parse {operation} response"))
}

/// `POST /api/ciphers` — create a new cipher. Returns the created cipher JSON.
pub async fn create_cipher(
    client: &Client,
    base_url: &str,
    access_token: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!("{}/api/ciphers", base_url.trim_end_matches('/'));
    send_json(
        client,
        reqwest::Method::POST,
        &url,
        access_token,
        body,
        "create cipher",
    )
    .await
}

/// `GET /api/ciphers/{id}` — fetch a single cipher's raw (encrypted) JSON.
///
/// `edit_cipher` uses this before its full-replace PUT so type-specific data
/// (card, identity, ssh, secure-note) can be preserved verbatim instead of
/// being rebuilt from the decrypted `CipherEntry` (which only carries
/// login/note/ssh fields).
pub async fn get_cipher_raw(
    client: &Client,
    base_url: &str,
    access_token: &str,
    cipher_id: &str,
) -> Result<Value> {
    let url = format!("{}/api/ciphers/{cipher_id}", base_url.trim_end_matches('/'));
    let resp = client
        .request(reqwest::Method::GET, &url)
        .bearer_auth(access_token)
        .header(
            "bitwarden-client-version",
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .send()
        .await
        .with_context(|| format!("failed to send get cipher request for {cipher_id}"))?;
    let resp = ensure_success(resp, "get cipher").await?;
    resp.json::<Value>()
        .await
        .with_context(|| format!("failed to parse get cipher response for {cipher_id}"))
}

/// `PUT /api/ciphers/{id}` — full-replace edit. Returns the updated cipher JSON.
pub async fn edit_cipher(
    client: &Client,
    base_url: &str,
    access_token: &str,
    cipher_id: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!("{}/api/ciphers/{cipher_id}", base_url.trim_end_matches('/'));
    send_json(
        client,
        reqwest::Method::PUT,
        &url,
        access_token,
        body,
        "edit cipher",
    )
    .await
}

/// `PUT /api/ciphers/{id}/delete` — soft-delete (sets deletedDate; reversible
/// via [`restore_cipher`]). Returns the updated cipher JSON.
pub async fn soft_delete_cipher(
    client: &Client,
    base_url: &str,
    access_token: &str,
    cipher_id: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!(
        "{}/api/ciphers/{cipher_id}/delete",
        base_url.trim_end_matches('/')
    );
    send_json(
        client,
        reqwest::Method::PUT,
        &url,
        access_token,
        body,
        "soft-delete cipher",
    )
    .await
}

/// `PUT /api/ciphers/{id}/restore` — undo a soft-delete. Returns the restored
/// cipher JSON.
pub async fn restore_cipher(
    client: &Client,
    base_url: &str,
    access_token: &str,
    cipher_id: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!(
        "{}/api/ciphers/{cipher_id}/restore",
        base_url.trim_end_matches('/')
    );
    send_json(
        client,
        reqwest::Method::PUT,
        &url,
        access_token,
        body,
        "restore cipher",
    )
    .await
}

/// `DELETE /api/ciphers/{id}` — hard-delete (permanent). Returns `Ok(())`.
pub async fn delete_cipher(
    client: &Client,
    base_url: &str,
    access_token: &str,
    cipher_id: &str,
) -> Result<()> {
    let url = format!("{}/api/ciphers/{cipher_id}", base_url.trim_end_matches('/'));
    let resp = client
        .request(reqwest::Method::DELETE, &url)
        .bearer_auth(access_token)
        .header(
            "bitwarden-client-version",
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .send()
        .await
        .context("failed to send hard-delete request")?;
    ensure_success(resp, "hard-delete cipher").await?;
    Ok(())
}

/// `POST /api/folders` — create a folder. Returns the created folder JSON.
pub async fn create_folder(
    client: &Client,
    base_url: &str,
    access_token: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!("{}/api/folders", base_url.trim_end_matches('/'));
    send_json(
        client,
        reqwest::Method::POST,
        &url,
        access_token,
        body,
        "create folder",
    )
    .await
}

/// `PUT /api/folders/{id}` — rename a folder. Returns the updated folder JSON.
pub async fn rename_folder(
    client: &Client,
    base_url: &str,
    access_token: &str,
    folder_id: &str,
    body: &Value,
) -> Result<Value> {
    let url = format!("{}/api/folders/{folder_id}", base_url.trim_end_matches('/'));
    send_json(
        client,
        reqwest::Method::PUT,
        &url,
        access_token,
        body,
        "rename folder",
    )
    .await
}

/// `DELETE /api/folders/{id}` — delete a folder. Returns `Ok(())`.
/// The server moves the folder's entries to "No Folder".
pub async fn delete_folder(
    client: &Client,
    base_url: &str,
    access_token: &str,
    folder_id: &str,
) -> Result<()> {
    let url = format!("{}/api/folders/{folder_id}", base_url.trim_end_matches('/'));
    let resp = client
        .request(reqwest::Method::DELETE, &url)
        .bearer_auth(access_token)
        .header(
            "bitwarden-client-version",
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .send()
        .await
        .context("failed to send folder delete request")?;
    ensure_success(resp, "delete folder").await?;
    Ok(())
}
