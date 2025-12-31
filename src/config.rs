use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime};
use clap::Parser;
use colored::*;
use reqwest::Client;
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tempfile::NamedTempFile;
use tracing::info;

#[derive(Parser, Debug, Clone)]
pub struct AppArgs {
    /// API endpoint URL
    #[arg(short, long, default_value = "https://example-mock.com/api/auth/")]
    pub api: String,

    /// Local SOCKS5 port
    #[arg(short, long, default_value = "1080")]
    pub local_port: u16,

    /// Request timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Force use of a local private key file (Overrides API auth)
    #[arg(short = 'k', long)]
    pub private_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Password,
    Key,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SshConfig {
    pub user: String,
    pub host: String,

    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,

    pub password: Option<String>,
    pub private_key: Option<String>,

    #[serde(default = "default_port")]
    pub port: String,

    pub comment: Option<String>,
    pub exp_at: Option<String>,
}

fn default_port() -> String { "22".to_string() }
fn default_auth_type() -> AuthType { AuthType::Password }

/// Fetches and parses SSH config from the API.

pub async fn fetch_ssh_config(api_url: &str, timeout_secs: u64) -> Result<SshConfig> {
    info!("Fetching credentials...");

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;

    let resp = client.get(api_url).send().await.context("API request failed")?;
    let text = resp.text().await.context("Failed to get response text")?;
    let config: SshConfig = match serde_json::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to parse JSON. Raw response content:\n{}", text);
            return Err(anyhow::anyhow!("JSON parse error: {}", e));
        }
    };

    info!("Node: {}@{}:{} ({:?})", config.user, config.host, config.port, config.auth_type);

    if let Some(ref cmt) = config.comment {
        info!("Comment: {}", cmt);
    }

    check_expiration(&config.exp_at);

    Ok(config)
}

/// Prepares the private key.
/// - If input contains "PRIVATE KEY", writes it to a temp file.
/// - If input is a path, verifies existence.
/// Returns (path_string, Option<TempFileGuard>).
pub fn prepare_private_key(key_input: &str) -> Result<(String, Option<NamedTempFile>)> {
    if key_input.contains("PRIVATE KEY") {
        // Handle raw content
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(key_input.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp_file.as_file().metadata()?.permissions();
            perms.set_mode(0o600);
            temp_file.as_file().set_permissions(perms)?;
        }

        let path = temp_file.path().to_string_lossy().to_string();
        Ok((path, Some(temp_file)))
    } else {
        // Handle local path
        let path = Path::new(key_input);
        if path.exists() && path.is_file() {
            Ok((key_input.to_string(), None))
        } else {
            Err(anyhow!("Private key file not found: {}", key_input))
        }
    }
}

fn parse_flexible_date(date_str: &str) -> Option<NaiveDateTime> {
    let formats = [
        "%Y-%m-%d / %H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S",
    ];

    for fmt in formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, fmt) {
            return Some(dt);
        }
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
        return Some(dt.naive_local());
    }
    if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        return date.and_hms_opt(23, 59, 59);
    }
    None
}

fn check_expiration(exp_at: &Option<String>) {
    let date_str = match exp_at {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };

    match parse_flexible_date(date_str) {
        Some(expire_dt) => {
            let now = Local::now().naive_local();
            let hours_left = (expire_dt - now).num_hours();

            if hours_left < 0 {
                println!("\n{}\n", "!!! ACCOUNT EXPIRED !!!".on_red().white().bold());
                println!("Expired at: {}", date_str.red());
            } else if hours_left < 24 {
                println!("\n{}", "==========================================".yellow());
                println!("{} {}", "!!! WARNING: EXPIRING SOON !!!".red().bold(), "(< 24h)".yellow());
                println!("Remaining: {} hours (Until: {})", hours_left.to_string().red().bold(), date_str);
                println!("{}", "==========================================\n".yellow());
            } else {
                info!("Valid until: {}", date_str.green());
            }
        },
        None => tracing::warn!("Unknown date format: {}", date_str),
    }
}
