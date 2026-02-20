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
mod update;
mod vault;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::collections::HashSet;
use std::net::SocketAddr;
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

    /// Disable automatic version update check
    #[arg(long)]
    no_update_check: bool,

    /// Wrap a command: start proxy, run command with proxy env vars, stop on exit.
    /// No permanent config changes. Example: mirage-proxy --wrap "claude"
    #[arg(long, value_name = "COMMAND")]
    wrap: Option<String>,

    /// Extra args to pass to the wrapped command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    wrap_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Default to warn — normal output uses direct stderr writes for clean TUI
    let default_level = if args.log_level == "info" {
        "warn"
    } else {
        &args.log_level
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();

    // List providers
    if args.list_providers {
        eprintln!();
        eprintln!(
            "  Built-in provider routes ({} providers)",
            providers::PROVIDERS.len()
        );
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

    // Handle --wrap mode: start proxy, run command, stop on exit
    if let Some(ref wrap_cmd) = args.wrap {
        return run_wrap_mode(&args, wrap_cmd).await;
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
    if args.no_update_check {
        cfg.update_check.enabled = false;
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
        Some(Arc::new(AuditLog::new(
            cfg.audit.path.clone(),
            cfg.audit.log_values,
        )))
    } else {
        None
    };

    let vault_key = args
        .vault_key
        .or_else(|| std::env::var("MIRAGE_VAULT_KEY").ok());
    let vault = vault_key.as_ref().map(|passphrase| {
        let key = Vault::key_from_passphrase(passphrase);
        let legacy_key = Vault::key_from_passphrase_legacy(passphrase);
        let v = Vault::new_with_legacy(
            std::path::PathBuf::from(&args.vault_path),
            &key,
            Some(&legacy_key),
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
    eprintln!(
        "  \x1b[1mmirage-proxy\x1b[0m v{}",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("  ─────────────────────────────────────");
    eprintln!("  listen:  http://{}", addr);
    if cfg.target.is_empty() {
        eprintln!("  target:  \x1b[36mmulti-provider\x1b[0m (use path prefixes)");
        eprintln!("           /anthropic → api.anthropic.com");
        eprintln!("           /openai    → api.openai.com");
        eprintln!("           /google    → generativelanguage.googleapis.com");
        eprintln!("           /deepseek  → api.deepseek.com");
        eprintln!(
            "           ... and {} more (--list-providers)",
            providers::PROVIDERS.len() - 4
        );
    } else {
        eprintln!("  target:  {}", cfg.target);
    }
    eprintln!(
        "  mode:    {}{}",
        if cfg.dry_run { "dry-run " } else { "" },
        format!("{:?}", cfg.sensitivity).to_lowercase()
    );
    if cfg.audit.enabled {
        eprintln!("  audit:   {}", cfg.audit.path.display());
    }
    if vault.is_some() {
        eprintln!("  vault:   {} (encrypted)", args.vault_path);
    }
    eprintln!("  ─────────────────────────────────────");
    eprintln!();

    if cfg.update_check.enabled && !disable_update_check_from_env() {
        let timeout_ms = cfg.update_check.timeout_ms;
        tokio::spawn(async move {
            if let Some(update) = update::check_for_update(timeout_ms).await {
                eprintln!(
                    "  update:  v{} available (current v{})",
                    update.latest, update.current
                );
                eprintln!("           Update now? brew update && brew upgrade mirage-proxy");
                eprintln!("           {}", update.release_url);
            }
        });
    }

    // Live stats ticker
    let stats_handle = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let reqs = stats_handle
                .requests
                .load(std::sync::atomic::Ordering::Relaxed);
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

fn disable_update_check_from_env() -> bool {
    match std::env::var("MIRAGE_NO_UPDATE_CHECK") {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            s == "1" || s == "true" || s == "yes" || s == "on"
        }
        Err(_) => false,
    }
}

/// Wrap mode: start proxy in background, run a command with proxy env vars, stop on exit.
/// Nothing is written to disk. When the child exits, the proxy stops.
async fn run_wrap_mode(args: &Args, cmd: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Stdio;
    use tokio::signal;

    let port = args.port.unwrap_or(8686);
    let bind = args.bind.as_deref().unwrap_or("127.0.0.1");
    let base = format!("http://{}:{}", bind, port);

    // Build the proxy args (reuse current binary)
    let exe = std::env::current_exe()?;
    let mut proxy_args = vec![
        "--port".to_string(), port.to_string(),
        "--bind".to_string(), bind.to_string(),
    ];
    if let Some(ref target) = args.target {
        proxy_args.push("--target".to_string());
        proxy_args.push(target.clone());
    }
    if let Some(ref config) = args.config {
        proxy_args.push("--config".to_string());
        proxy_args.push(config.clone());
    }
    if let Some(ref sensitivity) = args.sensitivity {
        proxy_args.push("--sensitivity".to_string());
        proxy_args.push(sensitivity.clone());
    }
    if let Some(ref vault_key) = args.vault_key {
        proxy_args.push("--vault-key".to_string());
        proxy_args.push(vault_key.clone());
    }
    if args.dry_run {
        proxy_args.push("--dry-run".to_string());
    }
    proxy_args.push("--no-update-check".to_string());

    // Start the proxy as a child process
    eprintln!("  🔄 Starting mirage-proxy on :{} ...", port);
    let mut proxy_proc = tokio::process::Command::new(&exe)
        .args(&proxy_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Wait for proxy to be ready (poll health endpoint)
    let client = reqwest::Client::new();
    let health_url = format!("{}/", base);
    let mut ready = false;
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        if let Ok(resp) = client.get(&health_url).send().await {
            let status = resp.status().as_u16();
            // 502 or 404 means proxy is running (no matching route, which is expected)
            if status == 502 || status == 404 || status == 200 {
                ready = true;
                break;
            }
        }
    }

    if !ready {
        eprintln!("  ✗ mirage-proxy failed to start within 6 seconds");
        proxy_proc.kill().await.ok();
        std::process::exit(1);
    }

    eprintln!("  ✓ Proxy ready");
    eprintln!();

    // Build env vars for the child — set all known base URLs to point at proxy
    let env_vars: Vec<(&str, String)> = vec![
        ("ANTHROPIC_BASE_URL", format!("{}/anthropic", base)),
        ("OPENAI_BASE_URL", base.clone()),
        ("GOOGLE_API_BASE_URL", format!("{}/google", base)),
        ("MISTRAL_API_BASE_URL", format!("{}/mistral", base)),
        ("DEEPSEEK_BASE_URL", format!("{}/deepseek", base)),
        ("COHERE_API_BASE_URL", format!("{}/cohere", base)),
        ("GROQ_BASE_URL", format!("{}/groq", base)),
        ("TOGETHER_BASE_URL", format!("{}/together", base)),
        ("OPENROUTER_BASE_URL", format!("{}/openrouter", base)),
        ("XAI_BASE_URL", format!("{}/xai", base)),
    ];

    // Parse the command — split on spaces (simple), or use shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let full_cmd = if args.wrap_args.is_empty() {
        cmd.to_string()
    } else {
        format!("{} {}", cmd, args.wrap_args.join(" "))
    };

    eprintln!("  ▶ Running: {}", full_cmd);
    eprintln!();

    let mut child = tokio::process::Command::new(&shell)
        .arg("-c")
        .arg(&full_cmd)
        .envs(env_vars.iter().map(|(k, v)| (*k, v.as_str())))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .spawn()?;

    // Wait for either child exit or Ctrl+C
    let exit_code = tokio::select! {
        status = child.wait() => {
            status.map(|s| s.code().unwrap_or(1)).unwrap_or(1)
        }
        _ = signal::ctrl_c() => {
            eprintln!("\n  ⏹ Interrupted — stopping...");
            child.kill().await.ok();
            130
        }
    };

    // Stop the proxy
    eprintln!();
    eprintln!("  ⏹ Stopping mirage-proxy...");
    proxy_proc.kill().await.ok();
    proxy_proc.wait().await.ok();
    eprintln!("  ✓ Clean exit");

    std::process::exit(exit_code);
}
