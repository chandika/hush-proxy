use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;

use crate::config::RedactAction;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub kind: String,
    pub action: String,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    pub context_snippet: String,
}

pub struct AuditLog {
    path: PathBuf,
    log_values: bool,
    file: Mutex<Option<std::fs::File>>,
}

impl AuditLog {
    pub fn new(path: PathBuf, log_values: bool) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();

        AuditLog {
            path,
            log_values,
            file: Mutex::new(file),
        }
    }

    pub fn log(
        &self,
        kind: &str,
        action: &RedactAction,
        original: &str,
        context: &str,
    ) {
        let action_str = match action {
            RedactAction::Redact => "redacted",
            RedactAction::Mask => "masked",
            RedactAction::Warn => "warned",
            RedactAction::Ignore => "ignored",
        };

        // Create a context snippet (30 chars around the value)
        let snippet = if context.len() > 80 {
            format!("{}...", &context[..80])
        } else {
            context.to_string()
        };

        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind: kind.to_string(),
            action: action_str.to_string(),
            confidence: 1.0, // For now, all pattern matches are 1.0
            value_hash: Some(format!("{:x}", md5::compute(original.as_bytes()))),
            original: if self.log_values {
                Some(original.to_string())
            } else {
                None
            },
            context_snippet: snippet,
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            if let Ok(mut guard) = self.file.lock() {
                if let Some(ref mut f) = *guard {
                    let _ = writeln!(f, "{}", json);
                }
            }
        }
    }
}
