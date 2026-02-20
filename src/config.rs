use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub rules: Rules,
    #[serde(default)]
    #[allow(dead_code)]
    pub code_block_passthrough: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub update_check: UpdateCheckConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Paranoid,
}

impl Default for Sensitivity {
    fn default() -> Self {
        Sensitivity::Medium
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    #[serde(default = "default_always_redact")]
    pub always_redact: Vec<String>,
    #[serde(default = "default_mask")]
    pub mask: Vec<String>,
    #[serde(default = "default_warn_only")]
    pub warn_only: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            always_redact: default_always_redact(),
            mask: default_mask(),
            warn_only: default_warn_only(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
    #[serde(default)]
    pub log_values: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_update_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for UpdateCheckConfig {
    fn default() -> Self {
        UpdateCheckConfig {
            enabled: true,
            timeout_ms: default_update_timeout_ms(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            path: default_audit_path(),
            log_values: false,
        }
    }
}

fn default_target() -> String {
    String::new()
}
fn default_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8686
}
fn default_sensitivity() -> Sensitivity {
    Sensitivity::Medium
}
fn default_true() -> bool {
    true
}
fn default_update_timeout_ms() -> u64 {
    1200
}
fn default_audit_path() -> PathBuf {
    PathBuf::from("./mirage-audit.jsonl")
}

fn default_always_redact() -> Vec<String> {
    vec![
        "SSN".into(),
        "CREDIT_CARD".into(),
        "PRIVATE_KEY".into(),
        "AWS_KEY".into(),
        "GITHUB_TOKEN".into(),
        "API_KEY".into(),
        "BEARER_TOKEN".into(),
    ]
}

fn default_mask() -> Vec<String> {
    vec!["EMAIL".into(), "PHONE".into()]
}

fn default_warn_only() -> Vec<String> {
    vec![
        "IP_ADDRESS".into(),
        "CONNECTION_STRING".into(),
        "SECRET".into(),
    ]
}

impl Config {
    pub fn load(path: Option<&str>) -> Self {
        let candidates = match path {
            Some(p) => vec![PathBuf::from(p)],
            None => vec![
                PathBuf::from("mirage.yaml"),
                PathBuf::from("mirage.yml"),
                dirs_next::home_dir()
                    .map(|h| h.join(".config").join("mirage").join("mirage.yaml"))
                    .unwrap_or_default(),
            ],
        };

        for candidate in &candidates {
            if candidate.exists() {
                if let Ok(contents) = std::fs::read_to_string(candidate) {
                    match serde_yaml::from_str(&contents) {
                        Ok(config) => {
                            tracing::info!("Loaded config from {}", candidate.display());
                            return config;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse {}: {}", candidate.display(), e);
                        }
                    }
                }
            }
        }

        tracing::info!("No config file found, using defaults");
        Config {
            target: default_target(),
            bind: default_bind(),
            port: default_port(),
            sensitivity: default_sensitivity(),
            rules: Rules::default(),
            code_block_passthrough: false,
            allowlist: vec![],
            blocklist: vec![],
            audit: AuditConfig::default(),
            dry_run: false,
            update_check: UpdateCheckConfig::default(),
        }
    }

    /// Check if a PII kind should be redacted given current sensitivity
    pub fn should_redact(&self, kind_label: &str) -> RedactAction {
        // Blocklist always wins
        // (blocklist matching is done on values, not kinds — handled elsewhere)

        if self.rules.always_redact.iter().any(|k| k == kind_label) {
            return RedactAction::Redact;
        }

        if self.rules.mask.iter().any(|k| k == kind_label) {
            return match self.sensitivity {
                Sensitivity::Low => RedactAction::Ignore,
                _ => RedactAction::Mask,
            };
        }

        if self.rules.warn_only.iter().any(|k| k == kind_label) {
            return match self.sensitivity {
                Sensitivity::High | Sensitivity::Paranoid => RedactAction::Redact,
                _ => RedactAction::Warn,
            };
        }

        match self.sensitivity {
            Sensitivity::Paranoid => RedactAction::Redact,
            _ => RedactAction::Ignore,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedactAction {
    Redact, // Replace with token [EMAIL_1_abc123]
    Mask,   // Replace with plausible fake
    Warn,   // Log but don't touch
    Ignore, // Do nothing
}
