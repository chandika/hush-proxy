mod audit;
mod config;
mod faker;
mod proxy;
mod redactor;
mod session;
mod vault;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

use audit::AuditLog;
use config::Config;
use proxy::{handle_request, ProxyState};
use session::SessionManager;
use vault::Vault;

#[derive(Parser, Debug)]
#[command(
    name = "hush-proxy",
    version,
    about = "A fast PII redaction proxy for LLM APIs",
    long_about = "Hush sits between your LLM client and provider, automatically redacting \
    PII and secrets from requests and rehydrating them in responses. \
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

    /// Vault encryption key (passphrase). Can also use HUSH_VAULT_KEY env var.
    #[arg(long)]
    vault_key: Option<String>,

    /// Vault file path
    #[arg(long, default_value = "./hush-vault.enc")]
    vault_path: String,

    /// Flush vault after N new mappings (0 = manual only)
    #[arg(long, default_value = "50")]
    vault_flush_threshold: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

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

    let vault_key = args.vault_key.or_else(|| std::env::var("HUSH_VAULT_KEY").ok());
    let vault = vault_key.as_ref().map(|passphrase| {
        let key = Vault::key_from_passphrase(passphrase);
        let v = Vault::new(
            std::path::PathBuf::from(&args.vault_path),
            &key,
            args.vault_flush_threshold,
        );
        Arc::new(v)
    });

    let state = Arc::new(ProxyState {
        target_url: cfg.target.clone(),
        client: Client::new(),
        sessions: SessionManager::new(vault.clone()),
        config: cfg.clone(),
        audit_log,
    });

    let addr: SocketAddr = format!("{}:{}", cfg.bind, cfg.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    info!("hush-proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("  Listening:    http://{}", addr);
    info!("  Forwarding:   {}", cfg.target);
    info!("  Sensitivity:  {:?}", cfg.sensitivity);
    info!("  Dry run:      {}", cfg.dry_run);
    if cfg.audit.enabled {
        info!("  Audit log:    {}", cfg.audit.path.display());
    }
    if vault.is_some() {
        info!("  Vault:        {} (encrypted)", args.vault_path);
    }

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
