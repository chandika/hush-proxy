use serde_json::Value;
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
    ///
    /// Priority:
    /// 1. Explicit `mirage_session` field (client-controlled)
    /// 2. `model` name — one session per model (stable for single-user proxies)
    /// 3. Falls back to "default"
    ///
    /// System prompts are intentionally NOT hashed — they change too frequently
    /// with tool definitions, cache markers, and context injection to be stable.
    pub fn derive_session_id(body: &Value) -> String {
        // Explicit session override
        if let Some(session) = body.get("mirage_session").and_then(|v| v.as_str()) {
            return session.to_string();
        }

        // Model-based session (stable across requests)
        if let Some(model) = body.get("model").and_then(|v| v.as_str()) {
            return model.to_string();
        }

        "default".to_string()
    }

    /// Clean up sessions that haven't been used recently
    #[allow(dead_code)]
    pub fn cleanup_stale(&self, max_sessions: usize) {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() > max_sessions {
            let excess = sessions.len() - max_sessions;
            let keys_to_remove: Vec<String> = sessions.keys().take(excess).cloned().collect();
            for key in keys_to_remove {
                sessions.remove(&key);
            }
        }
    }
}
