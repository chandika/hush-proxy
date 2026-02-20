use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, Clone)]
pub struct Tool {
    pub name: &'static str,
    pub display: &'static str,
    pub detected: bool,
    pub configured: bool,
}

/// Detect installed LLM tools and configure them to use mirage
pub fn run_setup(port: u16, uninstall: bool) {
    let base_url = format!("http://localhost:{}", port);
    let mirage_url = base_url.clone(); // legacy compat
    let anthropic_url = format!("{}/anthropic", base_url);
    let openai_url = base_url.clone(); // OpenAI auto-routes /v1/* and /responses

    println!();
    println!("  mirage-proxy setup");
    println!("  ==================");
    println!();

    if uninstall {
        println!("  Removing mirage-proxy configuration...");
        println!();
        uninstall_all();
        return;
    }

    println!("  Scanning for LLM tools...");
    println!();

    let home = dirs_next::home_dir().expect("Cannot determine home directory");
    let mut tools_found = 0;
    let mut tools_configured = 0;

    // Claude Code
    if let Some(configured) = setup_claude_code(&home, &anthropic_url) {
        tools_found += 1;
        if configured { tools_configured += 1; }
    }

    // Cursor
    if let Some(configured) = setup_cursor(&home, &openai_url) {
        tools_found += 1;
        if configured { tools_configured += 1; }
    }

    // Codex / OpenAI CLI
    if let Some(configured) = setup_openai_env(&home, &openai_url) {
        tools_found += 1;
        if configured { tools_configured += 1; }
    }

    // Aider
    if let Some(configured) = setup_aider(&home, &anthropic_url) {
        tools_found += 1;
        if configured { tools_configured += 1; }
    }

    // Shell profile (catch-all)
    setup_shell_profile(&home, &mirage_url, port);

    println!();
    println!("  ─────────────────────────────────────");
    println!("  Found {} tools, configured {}", tools_found, tools_configured);
    println!();
    println!("  Next steps:");
    println!("  1. Start mirage:  mirage-proxy --target https://api.anthropic.com");
    println!("  2. Restart your LLM tools");
    println!("  3. Check mirage logs to verify traffic is flowing through");
    println!();
    println!("  To undo:  mirage-proxy setup --uninstall");
    println!();
}

/// Claude Code: ~/.claude/settings.json
fn setup_claude_code(home: &Path, mirage_url: &str) -> Option<bool> {
    let settings_path = home.join(".claude").join("settings.json");
    let claude_dir = home.join(".claude");

    // Check if Claude Code is installed
    let installed = claude_dir.exists() || which_exists("claude");
    if !installed {
        println!("  [ ] Claude Code — not found");
        return None;
    }

    println!("  [✓] Claude Code — found");

    // Read or create settings.json
    let mut settings: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or(json!({}))
    } else {
        json!({})
    };

    // Set env.ANTHROPIC_BASE_URL
    if settings.get("env").is_none() {
        settings["env"] = json!({});
    }
    settings["env"]["ANTHROPIC_BASE_URL"] = json!(mirage_url);

    // Write
    fs::create_dir_all(&claude_dir).ok();
    let formatted = serde_json::to_string_pretty(&settings).unwrap();
    fs::write(&settings_path, formatted).ok();

    println!("      → Set ANTHROPIC_BASE_URL={} in ~/.claude/settings.json", mirage_url);
    Some(true)
}

/// Cursor: Settings → Models → Override OpenAI Base URL
/// Cursor stores settings in its own SQLite/JSON config, but also respects env vars
fn setup_cursor(home: &Path, mirage_url: &str) -> Option<bool> {
    // Check common Cursor paths
    let cursor_paths = vec![
        home.join(".cursor"),
        home.join("Library/Application Support/Cursor"),
        home.join(".config/Cursor"),
    ];

    let installed = cursor_paths.iter().any(|p| p.exists()) || which_exists("cursor");
    if !installed {
        println!("  [ ] Cursor — not found");
        return None;
    }

    println!("  [✓] Cursor — found");
    println!("      → Manual step: Settings → Cursor Settings → Models");
    println!("        Enable 'Override OpenAI Base URL' → {}", mirage_url);
    println!("        (Cursor doesn't support file-based proxy config yet)");
    Some(false) // detected but needs manual config
}

/// OpenAI tools (Codex, etc): OPENAI_BASE_URL
fn setup_openai_env(home: &Path, mirage_url: &str) -> Option<bool> {
    let installed = which_exists("codex") || which_exists("openai");
    if !installed {
        println!("  [ ] Codex/OpenAI CLI — not found");
        return None;
    }

    println!("  [✓] Codex/OpenAI CLI — found");
    println!("      → Will be configured via shell profile (OPENAI_BASE_URL)");
    Some(true)
}

/// Aider: --openai-api-base or OPENAI_API_BASE env var
fn setup_aider(home: &Path, mirage_url: &str) -> Option<bool> {
    let installed = which_exists("aider");
    if !installed {
        println!("  [ ] Aider — not found");
        return None;
    }

    println!("  [✓] Aider — found");

    // Aider config file
    let aider_conf = home.join(".aider.conf.yml");
    if aider_conf.exists() {
        println!("      → Will be configured via shell profile (OPENAI_API_BASE)");
    } else {
        println!("      → Will be configured via shell profile (OPENAI_API_BASE)");
    }
    Some(true)
}

/// Add env vars to shell profile
fn setup_shell_profile(home: &Path, _mirage_url: &str, port: u16) {
    let base = format!("http://localhost:{}", port);
    let anthropic = format!("{}/anthropic", base);
    let openai = base.clone(); // auto-routes /v1/* and /responses

    let block = format!(
        r#"
# mirage-proxy — invisible sensitive data filter for LLM APIs
# Remove this block or run `mirage-proxy setup --uninstall` to undo
export ANTHROPIC_BASE_URL="{}"
export OPENAI_BASE_URL="{}"
export OPENAI_API_BASE="{}"
# mirage-proxy-end"#,
        anthropic, openai, openai
    );

    // Detect shell
    let shell = std::env::var("SHELL").unwrap_or_default();
    let profile_path = if shell.contains("zsh") {
        home.join(".zshrc")
    } else if shell.contains("fish") {
        println!("  [!] Fish shell detected — add manually:");
        println!("      set -gx ANTHROPIC_BASE_URL {}", anthropic);
        println!("      set -gx OPENAI_BASE_URL {}", openai);
        return;
    } else {
        home.join(".bashrc")
    };

    // Check if already configured
    if let Ok(content) = fs::read_to_string(&profile_path) {
        if content.contains("# mirage-proxy") {
            println!("  [✓] Shell profile — already configured ({})", profile_path.display());
            return;
        }
    }

    // Append
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&profile_path)
        .expect("Cannot write to shell profile");

    use std::io::Write;
    writeln!(file, "{}", block).ok();

    println!("  [✓] Shell profile — configured ({})", profile_path.display());
    println!("      → Added ANTHROPIC_BASE_URL, OPENAI_BASE_URL, OPENAI_API_BASE");
    println!("      → Run: source {} (or restart terminal)", profile_path.display());
}

/// Remove mirage config from all locations
fn uninstall_all() {
    let home = dirs_next::home_dir().expect("Cannot determine home directory");

    // Remove from Claude Code settings
    let settings_path = home.join(".claude").join("settings.json");
    if settings_path.exists() {
        if let Ok(content) = fs::read_to_string(&settings_path) {
            if let Ok(mut settings) = serde_json::from_str::<Value>(&content) {
                if let Some(env) = settings.get_mut("env").and_then(|e| e.as_object_mut()) {
                    env.remove("ANTHROPIC_BASE_URL");
                    let formatted = serde_json::to_string_pretty(&settings).unwrap();
                    fs::write(&settings_path, formatted).ok();
                    println!("  [✓] Claude Code — removed ANTHROPIC_BASE_URL");
                }
            }
        }
    }

    // Remove from shell profiles
    for profile_name in &[".zshrc", ".bashrc", ".bash_profile"] {
        let profile_path = home.join(profile_name);
        if let Ok(content) = fs::read_to_string(&profile_path) {
            if content.contains("# mirage-proxy") {
                let cleaned: String = content
                    .lines()
                    .filter(|line| {
                        let in_block = line.contains("mirage-proxy");
                        let is_env = line.starts_with("export ANTHROPIC_BASE_URL=")
                            || line.starts_with("export OPENAI_BASE_URL=")
                            || line.starts_with("export OPENAI_API_BASE=");
                        !(in_block || is_env)
                    })
                    .collect::<Vec<&str>>()
                    .join("\n");
                fs::write(&profile_path, cleaned).ok();
                println!("  [✓] {} — removed mirage config", profile_name);
            }
        }
    }

    println!();
    println!("  Done. Restart your terminal and LLM tools.");
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
