//! Vaultwarden MCP server — CLI entrypoint.
//!
//! Usage:
//!   vaultwarden-mcp serve --transport stdio
//!   vaultwarden-mcp serve --transport http --host 127.0.0.1 --port 8080
//!   vaultwarden-mcp serve --config ./vaultwarden-mcp.toml
//!
//! Configuration is loaded from a TOML file (--config) and merged with
//! environment variables. Env vars win per-field. Secret references in the
//! TOML use the `secret://NAME` syntax and are resolved against the secretspec
//! runtime (provider via `--secretspec-provider`, default `env`; manifest via
//! `--secretspec-manifest` or `SECRETSPEC_MANIFEST`).
//! See `.agents/plans/01-config.md` for the full design.
//!
//! For env-var-only mode, set: VAULTWARDEN_SERVER, VAULTWARDEN_CLIENT_ID,
//! VAULTWARDEN_CLIENT_SECRET, VAULTWARDEN_PASSWORD, VAULTWARDEN_ACCOUNT_NAME,
//! VAULTWARDEN_ALLOW_HTTP. Multi-account env-var mode: VAULTWARDEN_ACCOUNTS=jan,work
//! plus per-account VAULTWARDEN_ACCOUNT_<NAME>_* vars.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use vaultwarden_mcp::config::{self, AccountConfigFile, ConfigFile};
use vaultwarden_mcp::mcp::{AccountConfig, VaultwardenMcpServer};
use vaultwarden_mcp::session_cache::SessionCacheOptions;

/// Vaultwarden MCP server
#[derive(Parser, Debug)]
#[command(
    name = "vaultwarden-mcp",
    version,
    about = "MCP server for Vaultwarden"
)]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum PrintFormat {
    Text,
    Json,
    JsonPretty,
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
        /// Path to a TOML config file. Defaults to a lookup chain
        /// (./vaultwarden-mcp.toml → ~/.config/vaultwarden-mcp/config.toml).
        #[arg(long)]
        config: Option<PathBuf>,
        /// secretspec profile name (default: "default").
        #[arg(long, default_value = "default")]
        secretspec_profile: String,
        /// secretspec provider (default: "env"). Also: dotenv:<path>, keyring,
        /// bw (Bitwarden CLI). See https://secretspec.dev/providers/
        #[arg(long, default_value = "env")]
        secretspec_provider: String,
        /// Path to a secretspec.toml manifest file. Defaults to SECRETSPEC_MANIFEST
        /// env var or auto-discovery (walking cwd and parent directories).
        #[arg(long, env = "SECRETSPEC_MANIFEST")]
        secretspec_manifest: Option<PathBuf>,
        /// Persistent session-cache lifetime in seconds (0 disables it).
        #[arg(
            long,
            env = "VAULTWARDEN_SESSION_CACHE_TTL",
            default_value_t = 1_800,
            value_name = "SECONDS"
        )]
        session_cache_ttl: u64,
    },
    /// Print the effective config (after env-var merge) and exit.
    PrintConfig {
        /// Path to a TOML config file
        #[arg(long)]
        config: Option<PathBuf>,
        /// secretspec profile name (default: "default").
        #[arg(long, default_value = "default")]
        secretspec_profile: String,
        /// secretspec provider (default: "env").
        #[arg(long, default_value = "env")]
        secretspec_provider: String,
        /// Path to a secretspec.toml manifest file.
        #[arg(long, env = "SECRETSPEC_MANIFEST")]
        secretspec_manifest: Option<PathBuf>,
        /// Output format (default: text).
        #[arg(long, value_enum, default_value = "text")]
        format: PrintFormat,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match &cli.command {
        Commands::Serve {
            transport,
            host,
            port,
            config,
            secretspec_profile,
            secretspec_provider,
            secretspec_manifest,
            session_cache_ttl,
        } => {
            let account_configs = load_accounts(
                config.as_deref(),
                secretspec_provider,
                secretspec_profile,
                secretspec_manifest.as_deref(),
            )?;
            let cache = SessionCacheOptions::from_env(Duration::from_secs(*session_cache_ttl));
            let server = VaultwardenMcpServer::with_cache(account_configs, cache).await?;
            let n = server.sessions_count().await;
            tracing::info!("Starting vaultwarden-mcp with {} account(s)", n);

            if transport == "http" {
                serve_http(server, host, *port).await?;
            } else {
                serve_stdio(server).await?;
            }
        }
        Commands::PrintConfig {
            config,
            secretspec_profile,
            secretspec_provider,
            secretspec_manifest,
            format,
        } => {
            let accounts = load_accounts(
                config.as_deref(),
                secretspec_provider,
                secretspec_profile,
                secretspec_manifest.as_deref(),
            )?;
            match format {
                PrintFormat::Text => {
                    tracing::info!("vaultwarden-mcp — effective config:");
                    for a in &accounts {
                        tracing::info!("  [{}]", a.label);
                        tracing::info!("    server:        {}", a.server);
                        tracing::info!("    client_id:     {}", a.client_id);
                        tracing::info!("    client_secret: {}", redact(&a.client_secret));
                        tracing::info!("    password:      {}", redact(&a.password));
                        tracing::info!("    allow_http:    {}", a.allow_http);
                    }
                }
                PrintFormat::Json => print_accounts_json(&accounts, false)?,
                PrintFormat::JsonPretty => print_accounts_json(&accounts, true)?,
            }
        }
    }
    Ok(())
}

fn redact(s: &str) -> String {
    if s.is_empty() {
        "<empty>".into()
    } else {
        "***".into()
    }
}

#[derive(serde::Serialize)]
struct RedactedAccount<'a> {
    label: &'a str,
    server: &'a str,
    client_id: &'a str,
    client_secret: String,
    password: String,
    allow_http: bool,
}

fn print_accounts_json(accounts: &[AccountConfig], pretty: bool) -> anyhow::Result<()> {
    let redacted: Vec<RedactedAccount<'_>> = accounts
        .iter()
        .map(|a| RedactedAccount {
            label: &a.label,
            server: &a.server,
            client_id: &a.client_id,
            client_secret: redact(&a.client_secret),
            password: redact(&a.password),
            allow_http: a.allow_http,
        })
        .collect();
    let json = if pretty {
        serde_json::to_string_pretty(&redacted)?
    } else {
        serde_json::to_string(&redacted)?
    };
    println!("{json}");
    Ok(())
}

#[cfg(feature = "http")]
async fn serve_http(server: VaultwardenMcpServer, host: &str, port: u16) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };
    use std::net::SocketAddr;

    let svc = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", svc);
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    tracing::info!("Listening on http://{}/mcp", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, router).await?;
    Ok(())
}

async fn serve_stdio(server: VaultwardenMcpServer) -> anyhow::Result<()> {
    use rmcp::{ServiceExt, transport::stdio};
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Load accounts from the config file + env vars. Order:
/// 1. If the config file declares `[[accounts]]`, use those (with env-var
///    override per field).
/// 2. Otherwise, fall back to env-var mode (single or multi-account).
fn load_accounts(
    config_path: Option<&std::path::Path>,
    secretspec_provider: &str,
    secretspec_profile: &str,
    secretspec_manifest: Option<&std::path::Path>,
) -> anyhow::Result<Vec<AccountConfig>> {
    let file: ConfigFile = config::load(config_path)?;

    let resolved = config::resolve_accounts(
        file,
        secretspec_provider,
        secretspec_profile,
        secretspec_manifest,
        &config::ProcessEnv,
    )?;
    Ok(resolved.into_iter().map(to_mcp_account).collect())
}

fn to_mcp_account(a: AccountConfigFile) -> AccountConfig {
    AccountConfig {
        server: a.server,
        client_id: a.client_id,
        client_secret: a.client_secret,
        password: a.password,
        label: a.label,
        allow_http: a.allow_http.unwrap_or(false),
    }
}
