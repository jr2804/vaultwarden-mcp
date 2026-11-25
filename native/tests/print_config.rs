//! CLI coverage for `print-config` output formats and secret redaction.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use tempfile::TempDir;

static SECRET_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn synthetic_secret(kind: &str) -> String {
    format!(
        "synthetic-{kind}-{}-{}",
        std::process::id(),
        SECRET_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn fixture() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        r#"
[[accounts]]
label = "human"
server = "https://vault.human.example.com"
client_id = "user.human"
client_secret = ""
password = ""
allow_http = false

[[accounts]]
label = "agent"
server = "http://vault.agent.example.com"
client_id = "user.agent"
client_secret = ""
password = ""
allow_http = true
"#,
    )
    .unwrap();
    dir
}

fn command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vaultwarden-mcp"));
    command.current_dir(dir);
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if key.starts_with("VAULTWARDEN_") || key.starts_with("SECRETSPEC_") || key == "RUST_LOG" {
            command.env_remove(key.as_ref());
        }
    }
    command
}

fn run(dir: &Path, args: &[&str], secrets: &[(&str, String)]) -> Output {
    let mut command = command(dir);
    command
        .arg("print-config")
        .arg("--config")
        .arg("config.toml");
    command.args(args);
    for (key, value) in secrets {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn default_text_output_is_preserved_and_redacted() {
    let dir = fixture();
    let client_secret = synthetic_secret("client-secret");
    let password = synthetic_secret("password");
    let output = run(
        dir.path(),
        &[],
        &[
            (
                "VAULTWARDEN_ACCOUNT_HUMAN_CLIENT_SECRET",
                client_secret.clone(),
            ),
            ("VAULTWARDEN_ACCOUNT_HUMAN_PASSWORD", password.clone()),
            (
                "VAULTWARDEN_ACCOUNT_AGENT_CLIENT_SECRET",
                synthetic_secret("agent-client"),
            ),
            (
                "VAULTWARDEN_ACCOUNT_AGENT_PASSWORD",
                synthetic_secret("agent-password"),
            ),
        ],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("vaultwarden-mcp — effective config:"));
    assert!(stdout.contains("  [human]"));
    assert!(stdout.contains("    server:        https://vault.human.example.com"));
    assert!(stdout.contains("    client_secret: ***"));
    assert!(stdout.contains("    password:      ***"));
    assert!(!stdout.contains(&client_secret));
    assert!(!stdout.contains(&password));
}

#[test]
fn compact_json_is_machine_readable_and_redacted() {
    let dir = fixture();
    let client_secret = synthetic_secret("client-secret");
    let password = synthetic_secret("password");
    let output = run(
        dir.path(),
        &["--format", "json"],
        &[
            ("RUST_LOG", "off".into()),
            (
                "VAULTWARDEN_ACCOUNT_HUMAN_CLIENT_ID",
                "user.env-human".into(),
            ),
            (
                "VAULTWARDEN_ACCOUNT_HUMAN_CLIENT_SECRET",
                client_secret.clone(),
            ),
            ("VAULTWARDEN_ACCOUNT_HUMAN_PASSWORD", password.clone()),
            (
                "VAULTWARDEN_ACCOUNT_AGENT_CLIENT_SECRET",
                synthetic_secret("agent-client"),
            ),
            (
                "VAULTWARDEN_ACCOUNT_AGENT_PASSWORD",
                synthetic_secret("agent-password"),
            ),
        ],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert_eq!(stdout.lines().count(), 1, "compact JSON must be one line");
    let parsed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed,
        json!([
            {
                "label": "human",
                "server": "https://vault.human.example.com",
                "client_id": "user.env-human",
                "client_secret": "***",
                "password": "***",
                "allow_http": false,
            },
            {
                "label": "agent",
                "server": "http://vault.agent.example.com",
                "client_id": "user.agent",
                "client_secret": "***",
                "password": "***",
                "allow_http": true,
            },
        ])
    );
    assert!(!stdout.contains(&client_secret));
    assert!(!stdout.contains(&password));
    assert!(!stderr(&output).contains(&client_secret));
    assert!(!stderr(&output).contains(&password));
}

#[test]
fn pretty_json_has_the_same_shape() {
    let dir = fixture();
    let output = run(
        dir.path(),
        &["--format", "json-pretty"],
        &[
            (
                "VAULTWARDEN_ACCOUNT_HUMAN_CLIENT_SECRET",
                synthetic_secret("client-secret"),
            ),
            (
                "VAULTWARDEN_ACCOUNT_HUMAN_PASSWORD",
                synthetic_secret("password"),
            ),
            (
                "VAULTWARDEN_ACCOUNT_AGENT_CLIENT_SECRET",
                synthetic_secret("agent-client"),
            ),
            (
                "VAULTWARDEN_ACCOUNT_AGENT_PASSWORD",
                synthetic_secret("agent-password"),
            ),
        ],
    );

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("\n  {\n"), "pretty JSON must be indented");
    let parsed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 2);
    assert_eq!(parsed[0]["client_secret"], "***");
    assert_eq!(parsed[0]["password"], "***");
    assert_eq!(parsed[1]["allow_http"], true);
}

#[test]
fn invalid_format_is_rejected_by_clap() {
    let dir = fixture();
    let output = run(dir.path(), &["--format", "yaml"], &[]);

    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("invalid value 'yaml'"));
    assert!(stderr.contains("possible values: text, json, json-pretty"));
}
