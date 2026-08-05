//! Vaultwarden MCP server — CLI entrypoint.
//!
//! Usage:
//!   vaultwarden-mcp serve --transport stdio
//!   vaultwarden-mcp serve --transport http --host 127.0.0.1 --port 8080
//!
//! Accounts are configured via environment variables:
//!   VAULTWARDEN_SERVER, VAULTWARDEN_CLIENT_ID, VAULTWARDEN_CLIENT_SECRET,
//!   VAULTWARDEN_PASSWORD, VAULTWARDEN_ACCOUNT_NAME, VAULTWARDEN_ALLOW_HTTP
//!
//! Multiple accounts: VAULTWARDEN_ACCOUNTS=jan,openclaw + per-account prefixed vars.

use clap::Parser;
use std::env;
use tracing_subscriber::EnvFilter;
use vaultwarden_mcp::mcp::{AccountConfig, VaultwardenMcpServer};

/// Vaultwarden MCP server
#[derive(Parser, Debug)]
#[command(name = "vaultwarden-mcp", version, about = "MCP server for Vaultwarden")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Run the MCP server
    Serve {
        /// Transport: 'stdio' for Claude Desktop, 'http' for Streamable HTTP
        #[arg(long, default_value = "stdio", value_parser = ["stdio", "http"])]
        transport: String,
        /// Bind host (only for http transport)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Bind port (only for http transport)
        #[arg(long, default_value = "8080")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let account_configs = parse_accounts()?;

    match &cli.command {
        Commands::Serve { transport, host, port } => {
            let server = VaultwardenMcpServer::new(account_configs).await?;
            let n = server.sessions_count().await;
            tracing::info!("Starting vaultwarden-mcp with {} account(s)", n);

            if transport == "http" {
                serve_http(server, host, *port).await?;
            } else {
                serve_stdio(server).await?;
            }
        }
    }
    Ok(())
}

#[cfg(feature = "http")]
async fn serve_http(server: VaultwardenMcpServer, host: &str, port: u16) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::net::SocketAddr;

    let svc = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", svc);
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    println!("Listening on http://{}/mcp", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await?,
        router,
    ).await?;
    Ok(())
}

async fn serve_stdio(server: VaultwardenMcpServer) -> anyhow::Result<()> {
    use rmcp::{transport::stdio, ServiceExt};
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

fn parse_accounts() -> anyhow::Result<Vec<AccountConfig>> {
    let accounts: Vec<String> = env::var("VAULTWARDEN_ACCOUNTS")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let configs = if accounts.is_empty() {
        // Single-account from direct env vars
        vec![AccountConfig {
            server: env::var("VAULTWARDEN_SERVER")
                .or_else(|_| env::var("VAULTWARDEN_URL"))
                .map_err(|_| anyhow::anyhow!("VAULTWARDEN_SERVER is required"))?,
            client_id: env::var("VAULTWARDEN_CLIENT_ID")
                .or_else(|_| env::var("BW_CLIENT_ID"))
                .map_err(|_| anyhow::anyhow!("VAULTWARDEN_CLIENT_ID is required"))?,
            client_secret: env::var("VAULTWARDEN_CLIENT_SECRET")
                .or_else(|_| env::var("BW_CLIENT_SECRET"))
                .map_err(|_| anyhow::anyhow!("VAULTWARDEN_CLIENT_SECRET is required"))?,
            password: env::var("VAULTWARDEN_PASSWORD")
                .or_else(|_| env::var("BW_PASSWORD"))
                .map_err(|_| anyhow::anyhow!("VAULTWARDEN_PASSWORD is required"))?,
            allow_http: env::var("VAULTWARDEN_ALLOW_HTTP")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            label: env::var("VAULTWARDEN_ACCOUNT_NAME").unwrap_or_else(|_| "default".to_string()),
        }]
    } else {
        // Multi-account mode
        accounts.iter().map(|label| {
            let prefix = format!("VAULTWARDEN_ACCOUNT_{}_", label.to_uppercase());
            let get = |key: &str| -> Option<String> {
                env::var(format!("{}{}", prefix, key)).ok()
                    .or_else(|| env::var(key).ok())
            };
            Ok(AccountConfig {
                server: get("SERVER")
                    .or_else(|| get("URL"))
                    .ok_or_else(|| anyhow::anyhow!(
                        "missing VAULTWARDEN_ACCOUNT_{}_SERVER for '{}'", label.to_uppercase(), label))?,
                client_id: get("CLIENT_ID")
                    .ok_or_else(|| anyhow::anyhow!(
                        "missing VAULTWARDEN_ACCOUNT_{}_CLIENT_ID for '{}'", label.to_uppercase(), label))?,
                client_secret: get("CLIENT_SECRET")
                    .ok_or_else(|| anyhow::anyhow!(
                        "missing VAULTWARDEN_ACCOUNT_{}_CLIENT_SECRET for '{}'", label.to_uppercase(), label))?,
                password: get("PASSWORD")
                    .ok_or_else(|| anyhow::anyhow!(
                        "missing VAULTWARDEN_ACCOUNT_{}_PASSWORD for '{}'", label.to_uppercase(), label))?,
                allow_http: get("ALLOW_HTTP")
                    .map(|v| v == "1" || v.to_lowercase() == "true")
                    .unwrap_or(false),
                label: label.clone(),
            })
        }).collect::<anyhow::Result<Vec<_>>>()?
    };

    Ok(configs)
}
