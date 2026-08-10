//! Vaultwarden MCP server — ServerHandler implementation.
//!
//! Implements the MCP v3.0 (2026-07-28) server protocol via `rmcp`,
//! exposing vault search, read, sync, and account listing as tools.

use std::sync::Arc;

use anyhow::Result;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{CipherEdit, CipherInput, VaultwardenSession};

/// Account configuration for connecting to a Vaultwarden instance.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    pub server: String,
    pub client_id: String,
    pub client_secret: String,
    pub password: String,
    pub label: String,
    pub allow_http: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    query: String,
    account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetCipherParams {
    cipher_id: String,
    account: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SyncParams {
    account: Option<String>,
}

/// Params for cipher-create / write tools. `account` selects the session.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateCipherParams {
    #[serde(flatten)]
    pub input: CipherInput,
    pub account: String,
}

/// Params for edit. `input` is the partial overlay (None = unchanged).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EditCipherParams {
    pub cipher_id: String,
    pub account: String,
    #[serde(flatten)]
    pub input: CipherEdit,
}

/// Params for delete / soft-delete / restore.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CipherIdParams {
    pub cipher_id: String,
    pub account: String,
}

// ── Folder tool params ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListFoldersParams {
    account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetFolderIdParams {
    account: String,
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateFolderParams {
    account: String,
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EditFolderParams {
    account: String,
    name: String,
    new_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteFolderParams {
    account: String,
    name: String,
}

/// Generate JSON schema for a type implementing JsonSchema as JsonObject.
fn schema_for<T: schemars::JsonSchema>() -> Arc<JsonObject> {
    let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap_or_default();
    let map = match schema {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    Arc::new(map)
}

#[derive(Clone)]
pub struct VaultwardenMcpServer {
    sessions: Arc<tokio::sync::Mutex<Vec<(String, VaultwardenSession)>>>,
    tools: Vec<Tool>,
}

impl VaultwardenMcpServer {
    pub async fn new(configs: Vec<AccountConfig>) -> Result<Self, McpError> {
        let mut sessions = Vec::with_capacity(configs.len());
        for config in configs {
            let session = VaultwardenSession::new(
                &config.server,
                &config.client_id,
                &config.client_secret,
                &config.password,
                config.allow_http,
            )
            .await
            .map_err(|e| {
                let msg = format!("failed to log in account '{}': {}", config.label, e);
                McpError::invalid_request(msg, None)
            })?;
            sessions.push((config.label, session));
        }

        let tools = vec![
            Tool::new(
                "search",
                "Search vault entries by name, URI, or username (case-insensitive).",
                schema_for::<SearchParams>(),
            ),
            Tool::new(
                "get_cipher",
                "Get full decrypted contents of a specific vault entry by cipher ID.",
                schema_for::<GetCipherParams>(),
            ),
            Tool::new(
                "sync",
                "Synchronize vault with server and get summary (email, cipher count).",
                schema_for::<SyncParams>(),
            ),
            Tool::new(
                "list_accounts",
                "List all configured vaultwarden accounts.",
                Arc::new(Map::new()),
            ),
            Tool::new(
                "create_cipher",
                "Create a new vault entry (login or secure note). Returns the created entry.",
                schema_for::<CreateCipherParams>(),
            ),
            Tool::new(
                "edit_cipher",
                "Edit an existing vault entry. Every field is optional; omit a field to leave it unchanged, or pass null to clear it. cipher_type cannot change.",
                schema_for::<EditCipherParams>(),
            ),
            Tool::new(
                "soft_delete_cipher",
                "Move a vault entry to the trash (reversible via restore_cipher).",
                schema_for::<CipherIdParams>(),
            ),
            Tool::new(
                "delete_cipher",
                "Permanently delete a vault entry. This cannot be undone.",
                schema_for::<CipherIdParams>(),
            ),
            Tool::new(
                "restore_cipher",
                "Restore a soft-deleted (trashed) vault entry.",
                schema_for::<CipherIdParams>(),
            ),
            Tool::new(
                "list_folders",
                "List all folders with their decrypted names.",
                schema_for::<ListFoldersParams>(),
            ),
            Tool::new(
                "get_folder_id",
                "Resolve a folder name to its id. Errors if the folder doesn't exist.",
                schema_for::<GetFolderIdParams>(),
            ),
            Tool::new(
                "create_folder",
                "Create a new folder with the given name.",
                schema_for::<CreateFolderParams>(),
            ),
            Tool::new(
                "edit_folder",
                "Rename a folder. Takes the current name and a new name.",
                schema_for::<EditFolderParams>(),
            ),
            Tool::new(
                "delete_folder",
                "Delete a folder by name. The server moves its entries to 'No Folder'; entries are never auto-deleted.",
                schema_for::<DeleteFolderParams>(),
            ),
        ];

        Ok(Self {
            sessions: Arc::new(tokio::sync::Mutex::new(sessions)),
            tools,
        })
    }

    pub async fn sessions_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

impl ServerHandler for VaultwardenMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(Implementation::new("vaultwarden-mcp", env!("CARGO_PKG_VERSION")))
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
        .with_instructions(
            "MCP server for Vaultwarden. Read tools: search, get_cipher, sync, list_accounts. Write tools: create_cipher, edit_cipher, soft_delete_cipher, delete_cipher, restore_cipher."
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            next_cursor: None,
            meta: None,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let args = request.arguments.unwrap_or_default();
        let args_value = serde_json::Value::Object(args);

        match &*request.name {
            "search" => {
                let params: SearchParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let mut results = Vec::new();
                for (label, session) in guard.iter() {
                    if let Some(ref a) = params.account
                        && a != label
                    {
                        continue;
                    }
                    let entries = session
                        .search(&params.query)
                        .await
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                    for entry in entries {
                        results.push(serde_json::to_value(entry.clone()).unwrap_or(
                            serde_json::json!({"id": entry.id, "error": "serialization failed"}),
                        ));
                    }
                }
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&results).unwrap_or_else(|_| "[]".into()),
                )])
                .into())
            }

            "get_cipher" => {
                let params: GetCipherParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = guard
                    .iter()
                    .find(|(l, _)| l == &params.account)
                    .ok_or_else(|| {
                        let msg = format!("account '{}' not found", params.account);
                        McpError::invalid_params(msg, None)
                    })?;
                let entry = session
                    .1
                    .get_cipher(&params.cipher_id)
                    .await
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "sync" => {
                let params: SyncParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let mut summaries = Vec::new();
                for (label, session) in guard.iter() {
                    if let Some(ref a) = params.account
                        && a != label
                    {
                        continue;
                    }
                    let summary = session
                        .sync()
                        .await
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                    summaries.push(serde_json::json!({
                        "account": label,
                        "email": summary.email,
                        "cipher_count": summary.cipher_count,
                    }));
                }
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&summaries).unwrap_or_else(|_| "[]".into()),
                )])
                .into())
            }

            "list_accounts" => {
                let guard = self.sessions.lock().await;
                let accounts: Vec<Value> = guard
                    .iter()
                    .map(|(label, session)| {
                        serde_json::json!({
                            "label": label,
                            "server": session.server_url(),
                            "email": session.email(),
                        })
                    })
                    .collect();
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&accounts).unwrap_or_else(|_| "[]".into()),
                )])
                .into())
            }

            "create_cipher" => {
                let params: CreateCipherParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let entry = session
                    .create_cipher(params.input)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "edit_cipher" => {
                let params: EditCipherParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let entry = session
                    .edit_cipher(&params.cipher_id, params.input)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "soft_delete_cipher" => {
                let params: CipherIdParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let entry = session
                    .soft_delete_cipher(&params.cipher_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "delete_cipher" => {
                let params: CipherIdParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                session
                    .delete_cipher(&params.cipher_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                let msg = serde_json::json!({"cipher_id": params.cipher_id, "deleted": true});
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&msg).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "restore_cipher" => {
                let params: CipherIdParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let entry = session
                    .restore_cipher(&params.cipher_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "list_folders" => {
                let params: ListFoldersParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let mut results = Vec::new();
                for (label, session) in guard.iter() {
                    if let Some(ref a) = params.account
                        && a != label
                    {
                        continue;
                    }
                    for folder in session.list_folders() {
                        results.push(serde_json::json!({
                            "account": label,
                            "id": folder.id,
                            "name": folder.name,
                        }));
                    }
                }
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&results).unwrap_or_else(|_| "[]".into()),
                )])
                .into())
            }

            "get_folder_id" => {
                let params: GetFolderIdParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let folder_id = session.folder_id_for_name(&params.name).ok_or_else(|| {
                    McpError::invalid_params(format!("folder '{}' not found", params.name), None)
                })?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&serde_json::json!({
                        "folder_id": folder_id,
                        "name": params.name,
                    }))
                    .unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "create_folder" => {
                let params: CreateFolderParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let entry = session
                    .create_folder(&params.name)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "edit_folder" => {
                let params: EditFolderParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                let entry = session
                    .edit_folder(&params.name, &params.new_name)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            "delete_folder" => {
                let params: DeleteFolderParams = serde_json::from_value(args_value)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                let guard = self.sessions.lock().await;
                let session = find_session(&guard, &params.account)?;
                session
                    .delete_folder(&params.name)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                drop(guard);
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&serde_json::json!({"deleted": true}))
                        .unwrap_or_else(|_| "{}".into()),
                )])
                .into())
            }

            name => {
                let msg = format!("unknown tool: {}", name);
                Err(McpError::invalid_params(msg, None))
            }
        }
    }
}

/// Look up a session by exact label, returning an MCP error if not found.
/// Write tools require a single explicit account (unlike read tools, which
/// can fan out across all accounts), because a write must target one vault.
fn find_session<'a>(
    sessions: &'a [(String, VaultwardenSession)],
    account: &str,
) -> Result<&'a VaultwardenSession, McpError> {
    sessions
        .iter()
        .find(|(label, _)| label == account)
        .map(|(_, s)| s)
        .ok_or_else(|| McpError::invalid_params(format!("account '{account}' not found"), None))
}
