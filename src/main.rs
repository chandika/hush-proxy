mod audit;
mod config;
mod faker;
mod patterns;
mod providers;
mod proxy;
mod redactor;
mod session;
mod setup;
mod stats;
mod vault;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::net::SocketAddr;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tracing::{error, info};

use audit::AuditLog;
use config::Config;
use proxy::{handle_request, ProxyState};
use session::SessionManager;
use stats::Stats;
use vault::Vault;

#[derive(Parser, Debug)]
#[command(
    name = "mirage-proxy",
    version,
    about = "Invisible sensitive data filter for LLM APIs",
    long_about = "Mirage sits between your LLM client and provider, silently replacing \
    secrets, credentials, and sensitive data with plausible fakes. The LLM never knows. \
    Sub-millisecond overhead. Zero config. Works with any OpenAI-compatible client."
)]
struct Args {
    /// Target LLM API base URL (e.g. https://api.openai.com)
    #[arg(short, long)]
    target: Option<String>,

    /// Port to listen on
    #[arg(short, long)]
    port: Option<u16>,

    /// Bind address
    #[arg(short, long)]
    bind: Option<String>,

    /// Config file path
    #[arg(short, long)]
    config: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Dry run: log what would be redacted without redacting
    #[arg(long)]
    dry_run: bool,

    /// Sensitivity level (low, medium, high, paranoid)
    #[arg(long)]
    sensitivity: Option<String>,

    /// Vault encryption key (passphrase). Can also use MIRAGE_VAULT_KEY env var.
    #[arg(long)]
    vault_key: Option<String>,

    /// Vault file path
    #[arg(long, default_value = "./mirage-vault.enc")]
    vault_path: String,

    /// Flush vault after N new mappings (0 = manual only)
    #[arg(long, default_value = "50")]
    vault_flush_threshold: usize,

    /// Run setup wizard to auto-configure LLM tools
    #[arg(long)]
    setup: bool,

    /// Remove mirage configuration from all tools
    #[arg(long)]
    uninstall: bool,

    /// List all built-in provider routes
    #[arg(long)]
    list_providers: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Default to warn — normal output uses direct stderr writes for clean TUI
    let default_level = if args.log_level == "info" { "warn" } else { &args.log_level };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();

    // List providers
    if args.list_providers {
        eprintln!();
        eprintln!("  Built-in provider routes ({} providers)", providers::PROVIDERS.len());
        eprintln!("  ─────────────────────────────────────────────────");
        for p in providers::PROVIDERS {
            eprintln!("  {:16} {:14} → {}", p.name, p.prefix, p.upstream);
        }
        eprintln!();
        eprintln!("  Usage: set your tool's base URL to http://localhost:8686{{prefix}}");
        eprintln!("  Example: ANTHROPIC_BASE_URL=http://localhost:8686/anthropic");
        eprintln!();
        return Ok(());
    }

    // Handle setup command
    if args.setup || args.uninstall {
        let port = args.port.unwrap_or(8686);
        setup::run_setup(port, args.uninstall);
        return Ok(());
    }

    // Load config, then override with CLI args
    let mut cfg = Config::load(args.config.as_deref());

    if let Some(target) = args.target {
        cfg.target = target;
    }
    if let Some(port) = args.port {
        cfg.port = port;
    }
    if let Some(bind) = args.bind {
        cfg.bind = bind;
    }
    if args.dry_run {
        cfg.dry_run = true;
    }
    if let Some(ref s) = args.sensitivity {
        cfg.sensitivity = match s.as_str() {
            "low" => config::Sensitivity::Low,
            "high" => config::Sensitivity::High,
            "paranoid" => config::Sensitivity::Paranoid,
            _ => config::Sensitivity::Medium,
        };
    }

    let audit_log = if cfg.audit.enabled {
        Some(Arc::new(AuditLog::new(cfg.audit.path.clone(), cfg.audit.log_values)))
    } else {
        None
    };

    let vault_key = args.vault_key.or_else(|| std::env::var("MIRAGE_VAULT_KEY").ok());
    let vault = vault_key.as_ref().map(|passphrase| {
        let key = Vault::key_from_passphrase(passphrase);
        let v = Vault::new(
            std::path::PathBuf::from(&args.vault_path),
            &key,
            args.vault_flush_threshold,
        );
        Arc::new(v)
    });

    let stats = Stats::new();

    let state = Arc::new(ProxyState {
        target_url: cfg.target.clone(),
        client: Client::new(),
        sessions: SessionManager::new(vault.clone()),
        config: cfg.clone(),
        audit_log,
        stats: stats.clone(),
        seen_pii: Mutex::new(HashSet::new()),
    });

    let addr: SocketAddr = format!("{}:{}", cfg.bind, cfg.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    eprintln!();
    eprintln!("  \x1b[1mmirage-proxy\x1b[0m v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  ─────────────────────────────────────");
    eprintln!("  listen:  http://{}", addr);
    if cfg.target.is_empty() {
        eprintln!("  target:  \x1b[36mmulti-provider\x1b[0m (use path prefixes)");
        eprintln!("           /anthropic → api.anthropic.com");
        eprintln!("           /openai    → api.openai.com");
        eprintln!("           /google    → generativelanguage.googleapis.com");
        eprintln!("           /deepseek  → api.deepseek.com");
        eprintln!("           ... and {} more (--list-providers)", providers::PROVIDERS.len() - 4);
    } else {
        eprintln!("  target:  {}", cfg.target);
    }
    eprintln!("  mode:    {}{}", if cfg.dry_run { "dry-run " } else { "" }, format!("{:?}", cfg.sensitivity).to_lowercase());
    if cfg.audit.enabled {
        eprintln!("  audit:   {}", cfg.audit.path.display());
    }
    if vault.is_some() {
        eprintln!("  vault:   {} (encrypted)", args.vault_path);
    }
    eprintln!("  ─────────────────────────────────────");
    eprintln!();

    // Live stats ticker
    let stats_handle = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let reqs = stats_handle.requests.load(std::sync::atomic::Ordering::Relaxed);
            if reqs > 0 {
                eprint!("\r\x1b[2K  📊 {}", stats_handle.display());
            }
        }
    });

    loop {
        let (stream, remote) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                if !err.to_string().contains("connection closed") {
                    error!("Connection error from {}: {}", remote, err);
                }
            }
        });
    }
}
