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

    /// Install mirage as a system service (launchd on macOS, systemd on Linux)
    #[arg(long)]
    service_install: bool,

    /// Uninstall mirage system service
    #[arg(long)]
    service_uninstall: bool,

    /// Show service status
    #[arg(long)]
    service_status: bool,
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

    // Handle service commands
    if args.service_install {
        return service_install(&args);
    }
    if args.service_uninstall {
        return service_uninstall();
    }
    if args.service_status {
        return service_status();
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

// ─── Service management ───────────────────────────────────────────────

fn mirage_dir() -> std::path::PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".mirage")
}

fn service_install(args: &Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy();
    let mirage_home = mirage_dir();
    std::fs::create_dir_all(&mirage_home)?;

    let port = args.port.unwrap_or(8686);

    #[cfg(target_os = "macos")]
    {
        let plist_path = dirs_next::home_dir()
            .unwrap()
            .join("Library/LaunchAgents/com.mirage-proxy.plist");

        let plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mirage-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--port</string>
        <string>{port}</string>
        <string>--no-update-check</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{home}/mirage-proxy.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/mirage-proxy.log</string>
    <key>WorkingDirectory</key>
    <string>{home}</string>
</dict>
</plist>"#,
            exe = exe_str,
            port = port,
            home = mirage_home.to_string_lossy(),
        );

        std::fs::write(&plist_path, &plist)?;

        // Load the service
        let status = std::process::Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&plist_path)
            .status()?;

        if status.success() {
            eprintln!("  ✓ Installed launchd service");
            eprintln!("    Plist: {}", plist_path.display());
            eprintln!("    Log:   {}/mirage-proxy.log", mirage_home.display());
        } else {
            eprintln!("  ✗ Failed to load launchd service");
            return Ok(());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let unit_dir = dirs_next::home_dir()
            .unwrap()
            .join(".config/systemd/user");
        std::fs::create_dir_all(&unit_dir)?;
        let unit_path = unit_dir.join("mirage-proxy.service");

        let unit = format!(r#"[Unit]
Description=mirage-proxy — invisible secrets filter for LLM APIs
After=network.target

[Service]
Type=simple
ExecStart={exe} --port {port} --no-update-check
WorkingDirectory={home}
Restart=always
RestartSec=2
StandardOutput=append:{home}/mirage-proxy.log
StandardError=append:{home}/mirage-proxy.log

[Install]
WantedBy=default.target
"#,
            exe = exe_str,
            port = port,
            home = mirage_home.to_string_lossy(),
        );

        std::fs::write(&unit_path, &unit)?;

        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();

        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "mirage-proxy"])
            .status()?;

        if status.success() {
            eprintln!("  ✓ Installed systemd user service");
            eprintln!("    Unit: {}", unit_path.display());
            eprintln!("    Log:  {}/mirage-proxy.log", mirage_home.display());
        } else {
            eprintln!("  ✗ Failed to enable systemd service");
            return Ok(());
        }
    }

    // Install the shell function
    install_shell_function(port)?;

    eprintln!();
    eprintln!("  🛡️  mirage-proxy is running on :{}", port);
    eprintln!();
    eprintln!("  Usage:");
    eprintln!("    mirage on       # route LLM traffic through mirage");
    eprintln!("    mirage off      # go direct");
    eprintln!("    mirage status   # check if active");
    eprintln!();
    eprintln!("  Restart your shell or run: source ~/.zshrc");

    Ok(())
}

fn service_uninstall() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = dirs_next::home_dir()
            .unwrap()
            .join("Library/LaunchAgents/com.mirage-proxy.plist");

        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", "-w"])
                .arg(&plist_path)
                .status();
            std::fs::remove_file(&plist_path)?;
            eprintln!("  ✓ Removed launchd service");
        } else {
            eprintln!("  ⚠ No launchd service found");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "mirage-proxy"])
            .status();

        let unit_path = dirs_next::home_dir()
            .unwrap()
            .join(".config/systemd/user/mirage-proxy.service");
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            eprintln!("  ✓ Removed systemd service");
        } else {
            eprintln!("  ⚠ No systemd service found");
        }
    }

    // Remove shell function
    remove_shell_function()?;

    eprintln!("  ✓ Done. Restart your shell to complete removal.");
    Ok(())
}

fn service_status() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check if daemon is running
    let running = match std::net::TcpStream::connect("127.0.0.1:8686") {
        Ok(_) => true,
        Err(_) => false,
    };

    // Check if env vars are set (i.e., mirage on)
    let active = std::env::var("ANTHROPIC_BASE_URL")
        .map(|v| v.contains("8686"))
        .unwrap_or(false);

    eprintln!();
    eprintln!("  mirage-proxy status");
    eprintln!("  ─────────────────────────────────────");
    eprintln!("  daemon:  {}", if running { "✓ running on :8686" } else { "✗ not running" });
    eprintln!("  filter:  {}", if active { "✓ on (traffic routing through mirage)" } else { "✗ off (traffic going direct)" });
    eprintln!();
    if running && !active {
        eprintln!("  Run `mirage on` to start filtering.");
    } else if !running {
        eprintln!("  Run `mirage-proxy --service-install` to start the daemon.");
    }

    Ok(())
}

// ─── Shell function installer ─────────────────────────────────────────

const SHELL_FUNCTION: &str = r#"
# mirage-proxy: invisible secrets filter for LLM APIs
# https://github.com/chandika/mirage-proxy
mirage() {
  local port="${MIRAGE_PORT:-8686}"
  local base="http://127.0.0.1:${port}"
  case "${1:-status}" in
    on)
      # Check daemon is running
      if ! curl -sf -o /dev/null -w '' "${base}/" 2>/dev/null; then
        echo "  ✗ mirage-proxy daemon not running on :${port}"
        echo "  Run: mirage-proxy --service-install"
        return 1
      fi
      export ANTHROPIC_BASE_URL="${base}/anthropic"
      export OPENAI_BASE_URL="${base}"
      export GOOGLE_API_BASE_URL="${base}/google"
      export MISTRAL_API_BASE_URL="${base}/mistral"
      export DEEPSEEK_BASE_URL="${base}/deepseek"
      export COHERE_API_BASE_URL="${base}/cohere"
      export GROQ_BASE_URL="${base}/groq"
      export TOGETHER_BASE_URL="${base}/together"
      export OPENROUTER_BASE_URL="${base}/openrouter"
      export XAI_BASE_URL="${base}/xai"
      echo "  🛡️  mirage on — LLM traffic now filtered"
      ;;
    off)
      unset ANTHROPIC_BASE_URL OPENAI_BASE_URL GOOGLE_API_BASE_URL \
            MISTRAL_API_BASE_URL DEEPSEEK_BASE_URL COHERE_API_BASE_URL \
            GROQ_BASE_URL TOGETHER_BASE_URL OPENROUTER_BASE_URL XAI_BASE_URL
      echo "  mirage off — traffic going direct"
      ;;
    status)
      local running=false active=false
      curl -sf -o /dev/null -w '' "${base}/" 2>/dev/null && running=true
      [ -n "${ANTHROPIC_BASE_URL:-}" ] && [[ "${ANTHROPIC_BASE_URL}" == *"8686"* ]] && active=true
      echo ""
      echo "  mirage-proxy"
      echo "  ─────────────────────────────"
      if $running; then echo "  daemon:  ✓ running"; else echo "  daemon:  ✗ not running"; fi
      if $active; then echo "  filter:  ✓ on"; else echo "  filter:  ✗ off"; fi
      echo ""
      ;;
    *)
      echo "Usage: mirage [on|off|status]"
      ;;
  esac
}
"#;

const SHELL_MARKER_START: &str = "# >>> mirage-proxy >>>";
const SHELL_MARKER_END: &str = "# <<< mirage-proxy <<<";

fn install_shell_function(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let home = dirs_next::home_dir().unwrap();

    // Detect shell RC files
    let rc_files: Vec<std::path::PathBuf> = vec![
        home.join(".zshrc"),
        home.join(".bashrc"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect();

    if rc_files.is_empty() {
        // Create .zshrc if nothing exists
        let zshrc = home.join(".zshrc");
        std::fs::write(&zshrc, "")?;
        write_shell_block(&zshrc, port)?;
        eprintln!("  ✓ Created ~/.zshrc with mirage shell function");
        return Ok(());
    }

    for rc in &rc_files {
        write_shell_block(rc, port)?;
        eprintln!("  ✓ Added mirage shell function to {}", rc.display());
    }

    Ok(())
}

fn write_shell_block(path: &std::path::Path, _port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let contents = std::fs::read_to_string(path).unwrap_or_default();

    // Remove existing block if present
    let cleaned = remove_shell_block(&contents);

    let new_contents = format!(
        "{}\n{}\n{}\n{}\n",
        cleaned.trim_end(),
        SHELL_MARKER_START,
        SHELL_FUNCTION.trim(),
        SHELL_MARKER_END,
    );

    std::fs::write(path, new_contents)?;
    Ok(())
}

fn remove_shell_block(contents: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    for line in contents.lines() {
        if line.trim() == SHELL_MARKER_START {
            in_block = true;
            continue;
        }
        if line.trim() == SHELL_MARKER_END {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

fn remove_shell_function() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let home = dirs_next::home_dir().unwrap();
    for name in &[".zshrc", ".bashrc"] {
        let path = home.join(name);
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            if contents.contains(SHELL_MARKER_START) {
                let cleaned = remove_shell_block(&contents);
                std::fs::write(&path, cleaned)?;
                eprintln!("  ✓ Removed mirage shell function from {}", path.display());
            }
        }
    }
    Ok(())
}
