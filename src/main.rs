mod audit;
mod config;
mod faker;
mod patterns;
mod providers;
mod proxy;
mod redactor;
mod session;
mod stats;
mod update;
mod vault;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tracing::error;

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
    Sub-millisecond overhead."
)]
struct Args {
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

    /// Dry run: log what would be redacted without modifying traffic
    #[arg(long)]
    dry_run: bool,

    /// Shadow mode: alias of --dry-run. Pass traffic through unchanged but
    /// print the substitutions Mirage *would* have made. Recommended for the
    /// first 24 hours after install so you can spot false positives before
    /// they block your workflow.
    #[arg(long)]
    shadow: bool,

    /// Explain a decoy/fake value: queries the running daemon's `/why` endpoint
    /// and prints the kind, session, and md5 fingerprint of the original.
    /// Does not start the proxy. Example: `mirage-proxy --why chris.hall456@gmail.com`.
    #[arg(long, value_name = "DECOY")]
    why: Option<String>,

    /// Flag a decoy/fake value: queries the running daemon's `/flag` endpoint
    /// so the underlying original is no longer substituted in this session.
    /// Persisted to ~/.mirage/flags.jsonl. Does not start the proxy.
    #[arg(long, value_name = "DECOY")]
    flag: Option<String>,

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

    /// List all built-in provider routes
    #[arg(long)]
    list_providers: bool,

    /// Disable automatic version update check
    #[arg(long)]
    no_update_check: bool,

    /// Install as background service + shell integration (launchd/systemd/Task Scheduler)
    #[arg(long)]
    service_install: bool,

    /// Skip interactive confirmation prompts during install
    #[arg(long)]
    yes: bool,

    /// Uninstall background service + shell integration
    #[arg(long)]
    service_uninstall: bool,

    /// Show service and filter status
    #[arg(long)]
    service_status: bool,

    /// Install wrapper launchers (wrapper-first; no shell profile mutation)
    #[arg(long)]
    wrapper_install: bool,

    /// Uninstall wrapper launchers
    #[arg(long)]
    wrapper_uninstall: bool,

    /// Interactive setup: detect installed tools, select which to wrap
    #[arg(long)]
    setup: bool,

    /// Uninstall everything: wrappers + daemon
    #[arg(long)]
    uninstall: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

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
        return Ok(());
    }

    if args.setup {
        return setup_interactive(args.port.unwrap_or(8686), args.yes, args.dry_run, args.sensitivity.as_deref());
    }
    if args.uninstall {
        return uninstall_all();
    }
    if args.wrapper_install {
        return wrapper_install(args.port.unwrap_or(8686));
    }
    if args.wrapper_uninstall {
        return wrapper_uninstall();
    }
    if args.service_install {
        return service_install(&args);
    }
    if args.service_uninstall {
        return service_uninstall();
    }
    if args.service_status {
        return service_status();
    }
    if let Some(ref decoy) = args.why {
        return query_daemon("why", decoy, &args).await;
    }
    if let Some(ref decoy) = args.flag {
        return query_daemon("flag", decoy, &args).await;
    }

    // Load config, override with CLI args
    let mut cfg = Config::load(args.config.as_deref());

    if let Some(port) = args.port {
        cfg.port = port;
    }
    if let Some(bind) = args.bind {
        cfg.bind = bind;
    }
    if args.dry_run || args.shadow {
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
        client: Client::new(),
        sessions: SessionManager::new(vault.clone()),
        config: cfg.clone(),
        audit_log,
        stats: stats.clone(),
        seen_pii: Mutex::new(HashSet::new()),
        flagged_originals: Mutex::new(HashSet::new()),
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
    eprintln!("  target:  \x1b[36mmulti-provider\x1b[0m (auto-route)");
    eprintln!("           /anthropic → api.anthropic.com");
    eprintln!("           /openai    → api.openai.com");
    eprintln!("           /google    → generativelanguage.googleapis.com");
    eprintln!("           /deepseek  → api.deepseek.com");
    eprintln!(
        "           ... and {} more (--list-providers)",
        providers::PROVIDERS.len() - 4
    );
    if cfg.dry_run {
        eprintln!(
            "  mode:    \x1b[33mSHADOW\x1b[0m ({} sensitivity) — detections logged, traffic not modified",
            format!("{:?}", cfg.sensitivity).to_lowercase()
        );
    } else {
        eprintln!(
            "  mode:    \x1b[32menforce\x1b[0m ({} sensitivity)",
            format!("{:?}", cfg.sensitivity).to_lowercase()
        );
    }
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
                eprintln!("           brew update && brew upgrade mirage-proxy");
                eprintln!("           {}", update.release_url);
            }
        });
    }

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

/// Send a `why` or `flag` query to the running daemon and pretty-print the result.
/// Used by `mirage-proxy --why <decoy>` and `mirage-proxy --flag <decoy>`.
async fn query_daemon(
    op: &str,
    decoy: &str,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = args.port.unwrap_or(8686);
    let bind = args.bind.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    let encoded: String = decoy
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect();
    let url = format!("http://{}:{}/{}?decoy={}", bind, port, op, encoded);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    let req = if op == "flag" {
        client.post(&url)
    } else {
        client.get(&url)
    };

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!();
            eprintln!("  could not reach mirage daemon at {}", url);
            eprintln!("  is it running?  mirage-proxy --service-status");
            eprintln!("  ({})", e);
            std::process::exit(2);
        }
    };
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let parsed: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::Value::String(text.clone()));

    eprintln!();
    if op == "why" {
        eprintln!("  \x1b[1mmirage why\x1b[0m {}", short_decoy(decoy));
        eprintln!("  ─────────────────────────────────────");
        if parsed.get("found").and_then(|v| v.as_bool()) == Some(true) {
            eprintln!(
                "  session:  {}",
                parsed.get("session").and_then(|v| v.as_str()).unwrap_or("?")
            );
            eprintln!(
                "  length:   {} chars",
                parsed.get("original_length").and_then(|v| v.as_u64()).unwrap_or(0)
            );
            eprintln!(
                "  md5:      {}",
                parsed.get("original_md5").and_then(|v| v.as_str()).unwrap_or("?")
            );
            eprintln!();
            eprintln!("  to forgive this substitution, run:");
            eprintln!("    mirage-proxy --flag '{}'", decoy);
        } else {
            eprintln!(
                "  no record. {}",
                parsed.get("hint").and_then(|v| v.as_str()).unwrap_or("")
            );
        }
    } else {
        eprintln!("  \x1b[1mmirage flag\x1b[0m {}", short_decoy(decoy));
        eprintln!("  ─────────────────────────────────────");
        if parsed.get("flagged").and_then(|v| v.as_bool()) == Some(true) {
            eprintln!("  ✓ flagged. mirage will pass this value through unchanged.");
            eprintln!(
                "  scope: {}",
                parsed.get("scope").and_then(|v| v.as_str()).unwrap_or("session")
            );
        } else {
            eprintln!(
                "  ✗ {}",
                parsed.get("reason").and_then(|v| v.as_str()).unwrap_or("not flagged")
            );
        }
    }
    eprintln!();
    if !status.is_success() {
        std::process::exit(1);
    }
    Ok(())
}

fn short_decoy(s: &str) -> String {
    if s.len() <= 24 {
        s.to_string()
    } else {
        format!("{}...{}", &s[..10], &s[s.len() - 6..])
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

// ─── Wrapper-first design ─────────────────────────────────────────────
// Instead of mutating shell profiles globally, create small per-tool
// wrapper scripts in ~/.mirage/bin/ that set only the needed env vars
// and exec the real binary. Users prepend ~/.mirage/bin to PATH.

struct WrapperTool {
    name: &'static str,
    env_vars: &'static [(&'static str, &'static str)], // (VAR, path suffix)
}

const WRAPPER_TOOLS: &[WrapperTool] = &[
    WrapperTool {
        name: "claude",
        env_vars: &[("ANTHROPIC_BASE_URL", "/anthropic")],
    },
    WrapperTool {
        name: "codex",
        env_vars: &[("OPENAI_BASE_URL", "")],
    },
    WrapperTool {
        name: "cursor",
        env_vars: &[("OPENAI_BASE_URL", "")],
    },
    WrapperTool {
        name: "aider",
        env_vars: &[
            ("ANTHROPIC_BASE_URL", "/anthropic"),
            ("OPENAI_BASE_URL", ""),
        ],
    },
    WrapperTool {
        name: "opencode",
        env_vars: &[("OPENAI_BASE_URL", "")],
    },
];

fn find_tool_in_path(name: &str, skip_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if dir == skip_dir { continue; }
            let candidate = dir.join(name);
            if candidate.exists() { return Some(candidate); }
            #[cfg(windows)] {
                let exe = dir.join(format!("{}.exe", name));
                if exe.exists() { return Some(exe); }
            }
        }
    }
    None
}

fn setup_interactive(port: u16, assume_yes: bool, dry_run: bool, sensitivity: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::{IsTerminal, Write};
    let bin_dir = mirage_dir().join("bin");

    eprintln!();
    eprintln!("  \x1b[1mmirage-proxy — setup\x1b[0m");
    eprintln!("  ─────────────────────────────────────");
    eprintln!("  Scanning for installed LLM tools...");
    eprintln!();

    let found: Vec<&WrapperTool> = WRAPPER_TOOLS.iter()
        .filter(|t| find_tool_in_path(t.name, &bin_dir).is_some())
        .collect();

    if found.is_empty() {
        eprintln!("  No supported tools found in PATH.");
        eprintln!("  Supported: {}", WRAPPER_TOOLS.iter().map(|t| t.name).collect::<Vec<_>>().join(", "));
        eprintln!();
        return Ok(());
    }

    eprintln!("  Found:");
    for (i, tool) in found.iter().enumerate() {
        let real = find_tool_in_path(tool.name, &bin_dir).unwrap();
        eprintln!("    [{}] {}  →  {}", i + 1, tool.name, real.display());
    }
    eprintln!();

    let selected: Vec<&&WrapperTool> = if assume_yes {
        eprintln!("  --yes: wrapping all found tools.");
        found.iter().collect()
    } else if std::io::stdin().is_terminal() {
        eprint!("  Which to wrap? Enter numbers (e.g. 1,2) or press Enter for all: ");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        if input.is_empty() || input == "all" {
            found.iter().collect()
        } else {
            let mut sel = Vec::new();
            for part in input.split(',') {
                if let Ok(n) = part.trim().parse::<usize>() {
                    if n >= 1 && n <= found.len() { sel.push(&found[n - 1]); }
                }
            }
            if sel.is_empty() {
                eprintln!("  No valid selection. Aborting.");
                return Ok(());
            }
            sel
        }
    } else {
        found.iter().collect()
    };

    eprintln!();
    std::fs::create_dir_all(&bin_dir)?;
    let mut installed_names: Vec<String> = Vec::new();

    for tool in &selected {
        let wrapper_path = if cfg!(windows) { bin_dir.join(format!("{}.cmd", tool.name)) }
                           else { bin_dir.join(tool.name) };
        let script = if cfg!(windows) { generate_windows_wrapper(tool, port) }
                     else { generate_unix_wrapper(tool, port) };
        std::fs::write(&wrapper_path, &script)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&wrapper_path)?.permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&wrapper_path, p)?;
        }

        // -direct bypass
        let direct_path = if cfg!(windows) { bin_dir.join(format!("{}-direct.cmd", tool.name)) }
                          else { bin_dir.join(format!("{}-direct", tool.name)) };
        std::fs::write(&direct_path, generate_direct_wrapper(tool.name))?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&direct_path)?.permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&direct_path, p)?;
        }

        eprintln!("  ✓ {}  +  {}-direct (bypass)", tool.name, tool.name);
        installed_names.push(tool.name.to_string());
    }

    // Install daemon service so it's always running in background
    eprintln!();
    eprintln!("  Installing background daemon...");
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy().to_string();
    let mirage_home = mirage_dir();
    std::fs::create_dir_all(&mirage_home)?;

    let mut extra_args = Vec::new();
    if dry_run {
        extra_args.push("--dry-run".to_string());
    }
    if let Some(s) = sensitivity {
        extra_args.push("--sensitivity".to_string());
        extra_args.push(s.to_string());
    }

    install_daemon(&exe_str, port, &extra_args, &mirage_home)?;

    eprintln!();
    eprintln!("  ─────────────────────────────────────");
    eprintln!("  \x1b[1mDone.\x1b[0m Daemon running + wrappers installed.");
    eprintln!();
    eprintln!("  Add to your PATH once:");
    if cfg!(windows) {
        eprintln!("    $env:PATH = \"$HOME\\.mirage\\bin;\" + $env:PATH");
    } else {
        eprintln!("    export PATH=\"$HOME/.mirage/bin:$PATH\"");
        eprintln!("    # Add to ~/.zshrc or ~/.bashrc to persist");
    }
    eprintln!();
    for name in &installed_names {
        eprintln!("    {}           → filtered through mirage", name);
        eprintln!("    {}-direct    → bypasses mirage completely", name);
    }
    eprintln!();
    eprintln!("  The daemon runs automatically in the background.");
    eprintln!("  Wrappers control which tools route through it.");
    eprintln!();
    eprintln!("  To uninstall everything:  mirage-proxy --uninstall");
    eprintln!();
    Ok(())
}

fn uninstall_all() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!();
    eprintln!("  \x1b[1mmirage-proxy — uninstall\x1b[0m");
    eprintln!("  ─────────────────────────────────────");

    let bin_dir = mirage_dir().join("bin");
    if bin_dir.exists() {
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&bin_dir)? {
            let path = entry?.path();
            if path.is_file() {
                std::fs::remove_file(&path)?;
                eprintln!("  ✓ Removed {}", path.display());
                removed += 1;
            }
        }
        if removed == 0 { eprintln!("  (no wrapper scripts found)"); }
        if std::fs::read_dir(&bin_dir)?.next().is_none() { std::fs::remove_dir(&bin_dir)?; }
    } else {
        eprintln!("  (no wrapper directory found)");
    }

    if std::net::TcpStream::connect("127.0.0.1:8686").is_ok() {
        eprintln!();
        eprintln!("  Stopping daemon...");
        #[cfg(unix)] { let _ = std::process::Command::new("pkill").args(["-f", "mirage-proxy"]).output(); }
        #[cfg(windows)] { let _ = std::process::Command::new("taskkill").args(["/IM", "mirage-proxy.exe", "/F"]).output(); }
        eprintln!("  ✓ Daemon stopped");
    }

    eprintln!();
    eprintln!("  Done. If you added ~/.mirage/bin to PATH, remove that line from your shell config.");
    eprintln!();
    // Also uninstall the daemon service
    let _ = uninstall_daemon();
    Ok(())
}

fn generate_direct_wrapper(name: &str) -> String {
    if cfg!(windows) {
        format!("@echo off\r\nrem {n}-direct: bypass mirage\r\nfor /f \"tokens=*\" %%i in ('where {n} 2^>nul') do (\r\n    echo %%i | findstr /i /c:\".mirage\\bin\" >nul || ( %%i %* & exit /b %errorlevel% )\r\n)\r\necho could not find real '{n}' 1>&2\r\nexit /b 127\r\n", n = name)
    } else {
        format!(r#"#!/bin/sh
# {n}-direct: run {n} without mirage
WRAPPER_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL=""; OLDIFS="$IFS"; IFS=:
for dir in $PATH; do
  [ "$dir" = "$WRAPPER_DIR" ] && continue
  [ -x "$dir/{n}" ] && REAL="$dir/{n}" && break
done
IFS="$OLDIFS"
[ -z "$REAL" ] && {{ echo "could not find real '{n}' in PATH" >&2; exit 127; }}
exec "$REAL" "$@"
"#, n = name)
    }
}

fn wrapper_install(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bin_dir = mirage_dir().join("bin");
    std::fs::create_dir_all(&bin_dir)?;

    eprintln!();
    eprintln!("  \x1b[1mmirage-proxy\x1b[0m — installing wrappers + daemon");
    eprintln!("  ─────────────────────────────────────");

    let mut installed = Vec::new();

    for tool in WRAPPER_TOOLS {
        let wrapper_path = if cfg!(windows) {
            bin_dir.join(format!("{}.cmd", tool.name))
        } else {
            bin_dir.join(tool.name)
        };

        let script = if cfg!(windows) {
            generate_windows_wrapper(tool, port)
        } else {
            generate_unix_wrapper(tool, port)
        };

        std::fs::write(&wrapper_path, &script)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&wrapper_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&wrapper_path, perms)?;
        }

        installed.push(tool.name);
        eprintln!("  ✓ {}", wrapper_path.display());
    }

    eprintln!();
    eprintln!("  Installed wrappers: {}", installed.join(", "));
    eprintln!();
    eprintln!("  Installing background daemon...");
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy().to_string();
    let mirage_home = mirage_dir();
    std::fs::create_dir_all(&mirage_home)?;
    install_daemon(&exe_str, port, &[], &mirage_home)?;

    eprintln!();
    eprintln!("  Add to your PATH (once):");
    if cfg!(windows) {
        eprintln!(
            "    $env:PATH = \"{}\" + \";\" + $env:PATH",
            bin_dir.display()
        );
        eprintln!("    # Or add permanently via System > Environment Variables");
    } else {
        eprintln!(
            "    export PATH=\"{}:$PATH\"",
            bin_dir.display()
        );
        eprintln!("    # Add that line to ~/.zshrc or ~/.bashrc to persist");
    }
    eprintln!();
    eprintln!("  Done. Daemon runs in background. Wrappers control which tools use it.");
    eprintln!("    claude          → filtered through mirage");
    eprintln!("    claude-direct   → bypasses mirage");
    eprintln!();

    Ok(())
}

fn wrapper_uninstall() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bin_dir = mirage_dir().join("bin");

    eprintln!();
    eprintln!("  Removing wrappers...");

    if !bin_dir.exists() {
        eprintln!("  ⚠ No wrapper directory found at {}", bin_dir.display());
        return Ok(());
    }

    for tool in WRAPPER_TOOLS {
        let wrapper_path = if cfg!(windows) {
            bin_dir.join(format!("{}.cmd", tool.name))
        } else {
            bin_dir.join(tool.name)
        };
        if wrapper_path.exists() {
            std::fs::remove_file(&wrapper_path)?;
            eprintln!("  ✓ Removed {}", wrapper_path.display());
        }
    }

    // Remove bin dir if empty
    if bin_dir.exists() {
        if std::fs::read_dir(&bin_dir)?.next().is_none() {
            std::fs::remove_dir(&bin_dir)?;
            eprintln!("  ✓ Removed empty {}", bin_dir.display());
        }
    }

    eprintln!();
    eprintln!("  Remove the PATH entry from your shell config if you added one.");
    eprintln!();

    Ok(())
}

fn generate_unix_wrapper(tool: &WrapperTool, port: u16) -> String {
    let mut script = format!(
        r#"#!/bin/sh
# mirage-proxy wrapper for {name} — routes LLM traffic through mirage
# Generated by: mirage-proxy --wrapper-install
# Remove with:  mirage-proxy --wrapper-uninstall
set -e
MIRAGE_PORT="${{MIRAGE_PORT:-{port}}}"
"#,
        name = tool.name,
        port = port,
    );

    for (var, suffix) in tool.env_vars {
        script.push_str(&format!(
            "export {var}=\"http://127.0.0.1:${{MIRAGE_PORT}}{suffix}\"\n",
            var = var,
            suffix = suffix,
        ));
    }

    // Find real binary by searching PATH, skipping our wrapper dir
    script.push_str(&format!(
        r#"
# Find the real '{name}' binary, skipping this wrapper's directory
WRAPPER_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL=""
OLDIFS="$IFS"
IFS=:
for dir in $PATH; do
  [ "$dir" = "$WRAPPER_DIR" ] && continue
  [ -x "$dir/{name}" ] && REAL="$dir/{name}" && break
done
IFS="$OLDIFS"

if [ -z "$REAL" ]; then
  echo "mirage-proxy: could not find real '{name}' in PATH (looked everywhere except $WRAPPER_DIR)" >&2
  exit 127
fi

exec "$REAL" "$@"
"#,
        name = tool.name,
    ));

    script
}

fn generate_windows_wrapper(tool: &WrapperTool, port: u16) -> String {
    let mut script = format!(
        "@echo off\r\nrem mirage-proxy wrapper for {name}\r\nrem Generated by: mirage-proxy --wrapper-install\r\n",
        name = tool.name,
    );

    for (var, suffix) in tool.env_vars {
        script.push_str(&format!(
            "set {var}=http://127.0.0.1:{port}{suffix}\r\n",
            var = var,
            port = port,
            suffix = suffix,
        ));
    }

    // On Windows, .cmd wrappers in PATH take priority over .exe in later PATH entries.
    // We use `where` to find the real binary, skipping our wrapper.
    script.push_str(&format!(
        r#"rem Find real {name} binary (skip this wrapper)
for /f "tokens=*" %%i in ('where {name} 2^>nul') do (
    echo %%i | findstr /i /c:".mirage\bin" >nul || (
        %%i %*
        exit /b %errorlevel%
    )
)
echo mirage-proxy: could not find real '{name}' in PATH 1>&2
exit /b 127
"#,
        name = tool.name,
    ));

    script
}

fn service_install(args: &Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy().to_string();
    let mirage_home = mirage_dir();
    std::fs::create_dir_all(&mirage_home)?;

    let port = args.port.unwrap_or(8686);

    eprintln!();
    eprintln!("  \x1b[1mmirage-proxy\x1b[0m — installing service");
    eprintln!("  ─────────────────────────────────────");

    let shell_targets = shell_install_targets();
    let mut effective_dry_run = args.dry_run;
    match confirm_shell_integration(&shell_targets, &mirage_home, args.yes)? {
        InstallDecision::Proceed => {}
        InstallDecision::ProceedDryRun => {
            effective_dry_run = true;
            eprintln!("  Continuing with dry-run mode by request.");
        }
        InstallDecision::Cancel => {
            eprintln!("  Install cancelled before making changes.");
            return Ok(());
        }
    }

    let mut extra_args = Vec::new();
    if effective_dry_run {
        extra_args.push("--dry-run".to_string());
    }
    if let Some(ref s) = args.sensitivity {
        extra_args.push("--sensitivity".to_string());
        extra_args.push(s.clone());
    }

    // Platform-specific daemon install
    install_daemon(&exe_str, port, &extra_args, &mirage_home)?;

    // Shell integration (env vars + mirage function + startup message)
    let shell_changes = install_shell(port, &mirage_home, &shell_targets)?;

    eprintln!();
    eprintln!("  🛡️  mirage-proxy installed and running on :{}", port);
    eprintln!();
    eprintln!("  Every new terminal will route LLM traffic through mirage.");
    eprintln!("  To turn it off in a terminal:  mirage off");
    eprintln!("  To check status:               mirage status");
    if effective_dry_run {
        eprintln!();
        eprintln!("  ⚠️  Running in dry-run mode — detections logged but traffic not modified");
    }
    eprintln!();
    eprintln!("  Restart your shell or run:");

    // Detect which shell profiles were modified
    let changed_paths: Vec<&std::path::PathBuf> = shell_changes
        .iter()
        .filter(|c| c.changed)
        .map(|c| &c.path)
        .collect();
    if changed_paths.iter().any(|p| p.ends_with(".zshrc")) {
        eprintln!("    source ~/.zshrc");
    } else if changed_paths.iter().any(|p| p.ends_with(".bashrc")) {
        eprintln!("    source ~/.bashrc");
    }
    if cfg!(windows) {
        eprintln!("    . $PROFILE");
    }
    if !shell_changes.is_empty() {
        eprintln!();
        eprintln!("  Rollback options:");
        eprintln!("    mirage-proxy --service-uninstall");
        eprintln!("    or restore backups from {}", mirage_home.join("backups").display());
    }

    // Show live tail of detections
    eprintln!();
    eprintln!("  Watching for detections... (launch your LLM tool to see it in action)");
    eprintln!("  Press Ctrl+C to exit this view — the daemon keeps running.");
    eprintln!();

    tail_log(&mirage_home)?;

    Ok(())
}

fn service_uninstall() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!();
    eprintln!("  Removing mirage-proxy...");

    uninstall_daemon()?;
    uninstall_shell()?;

    eprintln!("  ✓ Done. Restart your shell to complete removal.");
    Ok(())
}

fn service_status() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let running = std::net::TcpStream::connect("127.0.0.1:8686").is_ok();
    let active = std::env::var("ANTHROPIC_BASE_URL")
        .map(|v| v.contains("8686"))
        .unwrap_or(false);

    let binary_ver = env!("CARGO_PKG_VERSION");
    let daemon_ver = {
        let log_path = mirage_dir().join("mirage-proxy.log");
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            contents
                .lines()
                .find(|l| l.contains("mirage-proxy v"))
                .and_then(|l| {
                    l.split('v')
                        .nth(1)
                        .map(|s| s.split_whitespace().next().unwrap_or("unknown").to_string())
                })
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        }
    };

    eprintln!();
    eprintln!("  mirage-proxy");
    eprintln!("  ─────────────────────────────");
    eprintln!(
        "  daemon:   {}",
        if running {
            "✓ running on :8686"
        } else {
            "✗ not running"
        }
    );
    eprintln!(
        "  filter:   {}",
        if active {
            "✓ on (LLM traffic routed through mirage)"
        } else {
            "✗ off (traffic going direct)"
        }
    );
    eprintln!("  binary:   v{}", binary_ver);
    eprintln!("  daemon v: v{}", daemon_ver);
    eprintln!();
    if running && !active {
        eprintln!("  Run `mirage on` or open a new terminal.");
    } else if !running {
        eprintln!("  Run `mirage-proxy --service-install` to set up.");
    }

    Ok(())
}

// ─── Daemon install (platform-specific) ───────────────────────────────

#[cfg(target_os = "macos")]
fn install_daemon(
    exe: &str,
    port: u16,
    extra_args: &[String],
    mirage_home: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let plist_path = dirs_next::home_dir()
        .unwrap()
        .join("Library/LaunchAgents/com.mirage-proxy.plist");

    let extra_xml: String = extra_args
        .iter()
        .map(|a| format!("        <string>{}</string>", a))
        .collect::<Vec<_>>()
        .join("\n");

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
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
{extra}
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
        exe = exe,
        port = port,
        extra = extra_xml,
        home = mirage_home.to_string_lossy(),
    );

    // Unload existing if present
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&plist_path)
            .output();
    }

    std::fs::write(&plist_path, &plist)?;

    let status = std::process::Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .status()?;

    if status.success() {
        eprintln!("  ✓ launchd service installed (auto-starts on boot)");
    } else {
        eprintln!("  ✗ Failed to load launchd service");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_daemon(
    exe: &str,
    port: u16,
    extra_args: &[String],
    mirage_home: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let unit_dir = dirs_next::home_dir()
        .unwrap()
        .join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let unit_path = unit_dir.join("mirage-proxy.service");

    let extra_str = if extra_args.is_empty() {
        String::new()
    } else {
        format!(" {}", extra_args.join(" "))
    };

    let unit = format!(
        r#"[Unit]
Description=mirage-proxy — invisible secrets filter for LLM APIs
After=network.target

[Service]
Type=simple
ExecStart={exe} --port {port} --no-update-check{extra}
WorkingDirectory={home}
Restart=always
RestartSec=2
StandardOutput=append:{home}/mirage-proxy.log
StandardError=append:{home}/mirage-proxy.log

[Install]
WantedBy=default.target
"#,
        exe = exe,
        port = port,
        extra = extra_str,
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
        eprintln!("  ✓ systemd user service installed (auto-starts on boot)");
    } else {
        eprintln!("  ✗ Failed to enable systemd service");
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn install_daemon(
    exe: &str,
    port: u16,
    extra_args: &[String],
    mirage_home: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let extra_str = if extra_args.is_empty() {
        String::new()
    } else {
        format!(" {}", extra_args.join(" "))
    };

    // Create a Task Scheduler XML
    let task_xml_path = mirage_home.join("mirage-proxy-task.xml");
    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>mirage-proxy — invisible secrets filter for LLM APIs</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT10S</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions>
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--port {port} --no-update-check{extra}</Arguments>
      <WorkingDirectory>{home}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#,
        exe = exe,
        port = port,
        extra = extra_str,
        home = mirage_home.to_string_lossy(),
    );

    std::fs::write(&task_xml_path, &task_xml)?;

    // Delete existing task if present
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", "mirage-proxy", "/F"])
        .output();

    let status = std::process::Command::new("schtasks")
        .args([
            "/Create",
            "/TN",
            "mirage-proxy",
            "/XML",
            &task_xml_path.to_string_lossy(),
        ])
        .status()?;

    if status.success() {
        eprintln!("  ✓ Task Scheduler job installed (auto-starts on logon)");
        // Start it now
        let _ = std::process::Command::new("schtasks")
            .args(["/Run", "/TN", "mirage-proxy"])
            .status();
    } else {
        eprintln!("  ✗ Failed to create scheduled task");
    }

    Ok(())
}

// Fallback for other platforms
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn install_daemon(
    _exe: &str,
    _port: u16,
    _extra_args: &[String],
    _mirage_home: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("  ⚠ Unsupported platform for service install.");
    eprintln!("  Run `mirage-proxy` manually in the background.");
    Ok(())
}

// ─── Daemon uninstall (platform-specific) ─────────────────────────────

#[cfg(target_os = "macos")]
fn uninstall_daemon() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_daemon() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_daemon() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", "mirage-proxy", "/F"])
        .status()?;
    if status.success() {
        eprintln!("  ✓ Removed Task Scheduler job");
    } else {
        eprintln!("  ⚠ No scheduled task found");
    }
    // Kill running instance
    let _ = std::process::Command::new("taskkill")
        .args(["/IM", "mirage-proxy.exe", "/F"])
        .output();
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn uninstall_daemon() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("  ⚠ Unsupported platform");
    Ok(())
}

// ─── Shell integration ────────────────────────────────────────────────

const SHELL_MARKER_START: &str = "# >>> mirage-proxy >>>";
const SHELL_MARKER_END: &str = "# <<< mirage-proxy <<<";

const BASH_ZSH_BLOCK: &str = r#"
# Env vars — route LLM traffic through mirage (default: on)
export ANTHROPIC_BASE_URL="http://127.0.0.1:8686/anthropic"
export OPENAI_BASE_URL="http://127.0.0.1:8686"
export GOOGLE_API_BASE_URL="http://127.0.0.1:8686/google"
export MISTRAL_API_BASE_URL="http://127.0.0.1:8686/mistral"
export DEEPSEEK_BASE_URL="http://127.0.0.1:8686/deepseek"
export COHERE_API_BASE_URL="http://127.0.0.1:8686/cohere"
export GROQ_BASE_URL="http://127.0.0.1:8686/groq"
export TOGETHER_BASE_URL="http://127.0.0.1:8686/together"
export OPENROUTER_BASE_URL="http://127.0.0.1:8686/openrouter"
export XAI_BASE_URL="http://127.0.0.1:8686/xai"

_mirage_version() {
  command mirage-proxy --version 2>/dev/null | awk '{print $2}'
}

# Startup message
if [ -z "${MIRAGE_QUIET:-}" ]; then
  if curl -so /dev/null -w '%{http_code}' "http://127.0.0.1:8686/" 2>/dev/null | grep -qE '^(200|404|502)$'; then
    echo "🛡️ mirage active (v$(_mirage_version))"
  fi
fi

# Toggle function
mirage() {
  local port="${MIRAGE_PORT:-8686}"
  local base="http://127.0.0.1:${port}"
  local ver="$(_mirage_version)"
  case "${1:-status}" in
    on)
      if ! curl -so /dev/null -w '%{http_code}' "${base}/" 2>/dev/null | grep -qE '^(200|404|502)$'; then
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
      echo "  🛡️ mirage on (v${ver}) — LLM traffic filtered"
      ;;
    off)
      unset ANTHROPIC_BASE_URL OPENAI_BASE_URL GOOGLE_API_BASE_URL             MISTRAL_API_BASE_URL DEEPSEEK_BASE_URL COHERE_API_BASE_URL             GROQ_BASE_URL TOGETHER_BASE_URL OPENROUTER_BASE_URL XAI_BASE_URL
      echo "  mirage off — traffic going direct"
      ;;
    logs)
      local logp="$HOME/.mirage/mirage-proxy.log"
      if [ ! -f "$logp" ]; then
        echo "  ✗ no log file at $logp"
        return 1
      fi
      echo "  tailing $logp (ctrl+c to stop)"
      tail -f "$logp" | grep --line-buffered -E '🛡️|⚠️|📎|📊|mirage-proxy v'
      ;;
    status)
      local running=false active=false daemon_ver="unknown"
      curl -so /dev/null -w '%{http_code}' "${base}/" 2>/dev/null | grep -qE '^(200|404|502)$' && running=true
      [ -n "${ANTHROPIC_BASE_URL:-}" ] && echo "${ANTHROPIC_BASE_URL}" | grep -q "8686" && active=true
      if [ -f "$HOME/.mirage/mirage-proxy.log" ]; then
        daemon_ver=$(grep -m1 -E 'mirage-proxy v[0-9]' "$HOME/.mirage/mirage-proxy.log" | sed -E 's/.*v([0-9]+\.[0-9]+\.[0-9]+).*//' )
      fi
      echo ""
      echo "  mirage-proxy"
      echo "  ─────────────────────────────"
      if $running; then echo "  daemon:   ✓ running"; else echo "  daemon:   ✗ not running"; fi
      if $active; then echo "  filter:   ✓ on"; else echo "  filter:   ✗ off"; fi
      echo "  binary:   v${ver}"
      echo "  daemon v: v${daemon_ver}"
      echo ""
      ;;
    *)
      echo "Usage: mirage [on|off|status|logs]"
      ;;
  esac
}
"#;

const POWERSHELL_BLOCK: &str = r#"
# Env vars — route LLM traffic through mirage (default: on)
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8686/anthropic"
$env:OPENAI_BASE_URL = "http://127.0.0.1:8686"
$env:GOOGLE_API_BASE_URL = "http://127.0.0.1:8686/google"
$env:MISTRAL_API_BASE_URL = "http://127.0.0.1:8686/mistral"
$env:DEEPSEEK_BASE_URL = "http://127.0.0.1:8686/deepseek"
$env:COHERE_API_BASE_URL = "http://127.0.0.1:8686/cohere"
$env:GROQ_BASE_URL = "http://127.0.0.1:8686/groq"
$env:TOGETHER_BASE_URL = "http://127.0.0.1:8686/together"
$env:OPENROUTER_BASE_URL = "http://127.0.0.1:8686/openrouter"
$env:XAI_BASE_URL = "http://127.0.0.1:8686/xai"

function _MirageVersion {
    try { return (mirage-proxy --version).Split(' ')[1] } catch { return "unknown" }
}

# Startup message
if (-not $env:MIRAGE_QUIET) {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8686/" -TimeoutSec 1 -UseBasicParsing -ErrorAction SilentlyContinue
        Write-Host "🛡️ mirage active (v$(_MirageVersion))"
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { Write-Host "🛡️ mirage active (v$(_MirageVersion))" }
    } catch {}
}

# Toggle function
function mirage {
    param([string]$Action = "status")
    $port = if ($env:MIRAGE_PORT) { $env:MIRAGE_PORT } else { "8686" }
    $base = "http://127.0.0.1:$port"
    $ver = _MirageVersion

    switch ($Action) {
        "on" {
            $daemon_up = $false
            try {
                $null = Invoke-WebRequest -Uri "$base/" -TimeoutSec 1 -UseBasicParsing -ErrorAction SilentlyContinue
                $daemon_up = $true
            } catch [System.Net.WebException] {
                if ($_.Exception.Response) { $daemon_up = $true }
            } catch {}
            if (-not $daemon_up) {
                Write-Host "  ✗ mirage-proxy daemon not running on :$port"
                Write-Host "  Run: mirage-proxy --service-install"
                return
            }
            $env:ANTHROPIC_BASE_URL = "$base/anthropic"
            $env:OPENAI_BASE_URL = "$base"
            $env:GOOGLE_API_BASE_URL = "$base/google"
            $env:MISTRAL_API_BASE_URL = "$base/mistral"
            $env:DEEPSEEK_BASE_URL = "$base/deepseek"
            $env:COHERE_API_BASE_URL = "$base/cohere"
            $env:GROQ_BASE_URL = "$base/groq"
            $env:TOGETHER_BASE_URL = "$base/together"
            $env:OPENROUTER_BASE_URL = "$base/openrouter"
            $env:XAI_BASE_URL = "$base/xai"
            Write-Host "  🛡️ mirage on (v$ver) — LLM traffic filtered"
        }
        "off" {
            Remove-Item Env:ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:OPENAI_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:GOOGLE_API_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:MISTRAL_API_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:DEEPSEEK_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:COHERE_API_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:GROQ_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:TOGETHER_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:OPENROUTER_BASE_URL -ErrorAction SilentlyContinue
            Remove-Item Env:XAI_BASE_URL -ErrorAction SilentlyContinue
            Write-Host "  mirage off — traffic going direct"
        }
        "logs" {
            $log = Join-Path $HOME ".mirage/mirage-proxy.log"
            if (-not (Test-Path $log)) { Write-Host "  ✗ no log file at $log"; return }
            Write-Host "  tailing $log (ctrl+c to stop)"
            Get-Content -Path $log -Wait | Select-String -Pattern "🛡️|⚠️|📎|📊|mirage-proxy v"
        }
        "status" {
            $running = $false
            try {
                $null = Invoke-WebRequest -Uri "$base/" -TimeoutSec 1 -UseBasicParsing -ErrorAction SilentlyContinue
                $running = $true
            } catch [System.Net.WebException] {
                if ($_.Exception.Response) { $running = $true }
            } catch {}
            $active = $env:ANTHROPIC_BASE_URL -and $env:ANTHROPIC_BASE_URL.Contains("8686")
            $daemonVer = "unknown"
            $log = Join-Path $HOME ".mirage/mirage-proxy.log"
            if (Test-Path $log) {
                $line = Select-String -Path $log -Pattern "mirage-proxy v[0-9]" | Select-Object -First 1
                if ($line) { $daemonVer = ($line.Line -replace '.*v([0-9]+\.[0-9]+\.[0-9]+).*','$1') }
            }
            Write-Host ""
            Write-Host "  mirage-proxy"
            Write-Host "  ─────────────────────────────"
            if ($running) { Write-Host "  daemon:   ✓ running" } else { Write-Host "  daemon:   ✗ not running" }
            if ($active) { Write-Host "  filter:   ✓ on" } else { Write-Host "  filter:   ✗ off" }
            Write-Host "  binary:   v$ver"
            Write-Host "  daemon v: v$daemonVer"
            Write-Host ""
        }
        default {
            Write-Host "Usage: mirage [on|off|status|logs]"
        }
    }
}
"#;

const PS_MARKER_START: &str = "# >>> mirage-proxy >>>";
const PS_MARKER_END: &str = "# <<< mirage-proxy <<<";

struct ShellTarget {
    path: std::path::PathBuf,
    marker_start: &'static str,
    marker_end: &'static str,
    block: &'static str,
}

struct ShellWriteResult {
    path: std::path::PathBuf,
    changed: bool,
    backup_path: Option<std::path::PathBuf>,
}

enum InstallDecision {
    Proceed,
    ProceedDryRun,
    Cancel,
}

fn shell_install_targets() -> Vec<ShellTarget> {
    let home = dirs_next::home_dir().unwrap();
    let mut targets = Vec::new();
    let mut installed_any = false;

    // bash/zsh profiles (create ~/.zshrc if neither exists)
    for rc in &[home.join(".zshrc"), home.join(".bashrc")] {
        if rc.exists() || !installed_any {
            targets.push(ShellTarget {
                path: rc.clone(),
                marker_start: SHELL_MARKER_START,
                marker_end: SHELL_MARKER_END,
                block: BASH_ZSH_BLOCK,
            });
            installed_any = true;
        }
    }

    // PowerShell profile (when pwsh is available)
    if let Some(ps_profile) = get_powershell_profile() {
        targets.push(ShellTarget {
            path: ps_profile,
            marker_start: PS_MARKER_START,
            marker_end: PS_MARKER_END,
            block: POWERSHELL_BLOCK,
        });
    }

    targets
}

fn confirm_shell_integration(
    targets: &[ShellTarget],
    mirage_home: &std::path::Path,
    assume_yes: bool,
) -> Result<InstallDecision, Box<dyn std::error::Error + Send + Sync>> {
    let backup_dir = mirage_home.join("backups");

    eprintln!("  This install will:");
    eprintln!("    1) Install a background service for auto-start");
    eprintln!("    2) Add a managed shell block to enable mirage by default");
    eprintln!("  Managed block markers:");
    eprintln!("    {}", SHELL_MARKER_START);
    eprintln!("    {}", SHELL_MARKER_END);
    eprintln!("  Files that may be modified:");
    for target in targets {
        eprintln!("    {}", target.path.display());
    }
    eprintln!(
        "  Backups for changed files are written to: {}",
        backup_dir.display()
    );
    eprintln!("  Revert options: `mirage-proxy --service-uninstall` or restore a backup file.");

    if assume_yes {
        return Ok(InstallDecision::Proceed);
    }

    if !std::io::stdin().is_terminal() {
        eprintln!("  Non-interactive shell detected. Proceeding without prompt (pass `--yes` to silence).");
        return Ok(InstallDecision::Proceed);
    }

    eprint!("  Continue with install? [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let first = answer.trim().to_ascii_lowercase();
    if first == "y" || first == "yes" {
        return Ok(InstallDecision::Proceed);
    }

    eprint!("  Run in dry-run mode instead? [y/N]: ");
    std::io::stderr().flush()?;
    answer.clear();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        return Ok(InstallDecision::ProceedDryRun);
    }

    Ok(InstallDecision::Cancel)
}

fn install_shell(
    port: u16,
    mirage_home: &std::path::Path,
    targets: &[ShellTarget],
) -> Result<Vec<ShellWriteResult>, Box<dyn std::error::Error + Send + Sync>> {
    let _ = port; // port is baked into the shell block constants (8686)
    let backup_dir = mirage_home.join("backups");
    let mut results = Vec::new();

    for target in targets {
        let result = write_shell_block(
            &target.path,
            target.block,
            target.marker_start,
            target.marker_end,
            &backup_dir,
        )?;
        if result.changed {
            eprintln!("  ✓ Shell integration updated in {}", result.path.display());
            if let Some(ref backup) = result.backup_path {
                eprintln!("    backup: {}", backup.display());
            }
        } else {
            eprintln!("  ✓ Shell integration already up-to-date in {}", result.path.display());
        }
        results.push(result);
    }

    Ok(results)
}

fn uninstall_shell() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let home = dirs_next::home_dir().unwrap();

    for name in &[".zshrc", ".bashrc"] {
        let path = home.join(name);
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            if contents.contains(SHELL_MARKER_START) {
                let cleaned = remove_block(&contents, SHELL_MARKER_START, SHELL_MARKER_END);
                std::fs::write(&path, cleaned)?;
                eprintln!("  ✓ Removed from {}", path.display());
            }
        }
    }

    if let Some(ps_profile) = get_powershell_profile() {
        if ps_profile.exists() {
            let contents = std::fs::read_to_string(&ps_profile)?;
            if contents.contains(PS_MARKER_START) {
                let cleaned = remove_block(&contents, PS_MARKER_START, PS_MARKER_END);
                std::fs::write(&ps_profile, cleaned)?;
                eprintln!("  ✓ Removed from {}", ps_profile.display());
            }
        }
    }

    Ok(())
}

fn get_powershell_profile() -> Option<std::path::PathBuf> {
    // Try to get PowerShell profile path
    #[cfg(target_os = "windows")]
    {
        // Windows: Documents\PowerShell\Microsoft.PowerShell_profile.ps1
        // or Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
        if let Some(home) = dirs_next::home_dir() {
            let ps_core = home
                .join("Documents")
                .join("PowerShell")
                .join("Microsoft.PowerShell_profile.ps1");
            let ps_legacy = home
                .join("Documents")
                .join("WindowsPowerShell")
                .join("Microsoft.PowerShell_profile.ps1");
            // Prefer PowerShell Core
            if ps_core.parent().map(|p| p.exists()).unwrap_or(false) {
                return Some(ps_core);
            }
            return Some(ps_legacy);
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        // macOS/Linux: ~/.config/powershell/Microsoft.PowerShell_profile.ps1
        // Only install if pwsh is available
        if std::process::Command::new("pwsh")
            .arg("--version")
            .output()
            .is_ok()
        {
            dirs_next::home_dir().map(|h| {
                h.join(".config")
                    .join("powershell")
                    .join("Microsoft.PowerShell_profile.ps1")
            })
        } else {
            None
        }
    }
}

fn write_shell_block(
    path: &std::path::Path,
    block: &str,
    marker_start: &str,
    marker_end: &str,
    backup_dir: &std::path::Path,
) -> Result<ShellWriteResult, Box<dyn std::error::Error + Send + Sync>> {
    let existed_before = path.exists();
    let contents = std::fs::read_to_string(path).unwrap_or_default();
    let cleaned = remove_block(&contents, marker_start, marker_end);

    let new_contents = format!(
        "{}\n{}\n{}\n{}\n",
        cleaned.trim_end(),
        marker_start,
        block.trim(),
        marker_end,
    );

    let changed = contents != new_contents;
    let mut backup_path = None;

    if changed {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if existed_before {
            backup_path = Some(backup_file(path, backup_dir)?);
        }
        std::fs::write(path, new_contents)?;
    }

    Ok(ShellWriteResult {
        path: path.to_path_buf(),
        changed,
        backup_path,
    })
}

fn backup_file(
    path: &std::path::Path,
    backup_dir: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(backup_dir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("profile");
    let backup_path = backup_dir.join(format!("{}.{}.bak", name, ts));
    std::fs::copy(path, &backup_path)?;
    Ok(backup_path)
}

fn remove_block(contents: &str, marker_start: &str, marker_end: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    for line in contents.lines() {
        if line.trim() == marker_start {
            in_block = true;
            continue;
        }
        if line.trim() == marker_end {
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

// ─── Live log tail (first-time experience) ────────────────────────────

fn tail_log(mirage_home: &std::path::Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let log_path = mirage_home.join("mirage-proxy.log");

    // Wait for log file to appear
    for _ in 0..10 {
        if log_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    if !log_path.exists() {
        eprintln!("  (log file not yet created — daemon may still be starting)");
        return Ok(());
    }

    // Tail the log, showing only detection lines
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    let file = std::fs::File::open(&log_path)?;
    let mut reader = BufReader::new(file);
    // Seek to end
    reader.seek(SeekFrom::End(0))?;

    // Set up Ctrl+C handler
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    })
    .ok();

    let mut line = String::new();
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data, sleep briefly
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Ok(_) => {
                let trimmed = line.trim();
                // Show detection lines and session lines
                if trimmed.contains("🛡️")
                    || trimmed.contains("⚠️")
                    || trimmed.contains("📎")
                    || trimmed.contains("📊")
                {
                    eprint!("{}", line);
                }
            }
            Err(_) => break,
        }
    }

    eprintln!();
    eprintln!("  Daemon continues running in background.");
    Ok(())
}
