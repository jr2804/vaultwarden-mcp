//! Vaultwarden MCP server — ServerHandler implementation.
//!
//! Implements the MCP v3.0 (2026-07-28) server protocol via `rmcp`,
//! exposing vault search, read, sync, and account listing as tools.

use std::sync::Arc;

use anyhow::Result;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::VaultwardenSession;

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
            "MCP server for Vaultwarden. Available tools: search, get_cipher, sync, list_accounts."
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

            name => {
                let msg = format!("unknown tool: {}", name);
                Err(McpError::invalid_params(msg, None))
            }
        }
    }
}
