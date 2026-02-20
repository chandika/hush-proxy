use serde_json::Value;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::faker::Faker;
use crate::vault::Vault;

/// Manages per-conversation faker instances.
/// Each conversation gets its own consistent mapping.
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Arc<Faker>>>,
    vault: Option<Arc<Vault>>,
}

impl SessionManager {
    pub fn new(vault: Option<Arc<Vault>>) -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
            vault,
        }
    }

    /// Get or create a faker for a given session ID
    /// Get or create a faker for a given session ID.
    /// Returns (is_new, faker) so callers can track new sessions.
    pub fn get_faker(&self, session_id: &str) -> (bool, Arc<Faker>) {
        let mut sessions = self.sessions.lock().unwrap();
        let is_new = !sessions.contains_key(session_id);
        let faker = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| {
                Arc::new(Faker::new(self.vault.clone(), Some(session_id.to_string())))
            })
            .clone();
        (is_new, faker)
    }

    /// Derive session ID from a request body.
    /// Strategy: hash(system_prompt + model + user field)
    /// Falls back to "default" if nothing distinguishing is found.
    pub fn derive_session_id(body: &Value) -> String {
        let mut hasher = Sha256::new();
        let mut has_signal = false;

        // Check for X-Mirage-Session in a custom field (clients can set this)
        if let Some(session) = body.get("mirage_session").and_then(|v| v.as_str()) {
            return session.to_string();
        }

        // Use model name
        if let Some(model) = body.get("model").and_then(|v| v.as_str()) {
            hasher.update(model.as_bytes());
            has_signal = true;
        }

        // Use system prompt for session identity.
        // Only hash the FIRST system block — subsequent blocks often contain volatile
        // tool definitions and cache markers that change every request.
        if let Some(system) = body.get("system") {
            if let Some(s) = system.as_str() {
                // Anthropic Messages API: "system" as a top-level string
                hasher.update(s.as_bytes());
                has_signal = true;
            } else if let Some(arr) = system.as_array() {
                // Anthropic Messages API: "system" as array of content blocks
                // Use only the first text block (core identity), skip tool defs
                if let Some(first) = arr.first() {
                    if let Some(text) = first.get("text").and_then(|t| t.as_str()) {
                        hasher.update(text.as_bytes());
                        has_signal = true;
                    }
                }
            }
        } else if let Some(messages) = body.get("messages").and_then(|v| v.as_array()) {
            // OpenAI format: system message in the messages array
            for msg in messages {
                if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
                    if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                        hasher.update(content.as_bytes());
                        has_signal = true;
                        break;
                    }
                }
            }
        }

        // Use "user" field if present (OpenAI convention)
        if let Some(user) = body.get("user").and_then(|v| v.as_str()) {
            hasher.update(user.as_bytes());
            has_signal = true;
        }

        if has_signal {
            let hash = hasher.finalize();
            format!("{:x}", hash)[..16].to_string()
        } else {
            "default".to_string()
        }
    }

    /// Clean up sessions that haven't been used recently
    pub fn cleanup_stale(&self, max_sessions: usize) {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() > max_sessions {
            // Simple: keep the most recent max_sessions, drop oldest
            // Since we don't track access time in session manager, just trim
            let excess = sessions.len() - max_sessions;
            let keys_to_remove: Vec<String> = sessions.keys().take(excess).cloned().collect();
            for key in keys_to_remove {
                sessions.remove(&key);
            }
        }
    }
}
