use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Encrypted-at-rest mapping vault.
/// User holds the key. Vault file is useless without it.
pub struct Vault {
    path: PathBuf,
    cipher: Aes256Gcm,
    inner: Mutex<VaultInner>,
    flush_threshold: usize,
    auto_flush: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultInner {
    /// session_id -> { original -> entry }
    sessions: HashMap<String, SessionMap>,
    /// Global reverse map: fake -> (session_id, original)
    reverse: HashMap<String, (String, String)>,
    /// Legacy non-session forward map (backward compat)
    #[serde(default)]
    forward: HashMap<String, VaultEntry>,
    /// Total mappings since last flush
    ops_since_flush: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SessionMap {
    entries: HashMap<String, VaultEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultEntry {
    fake: String,
    kind: String,
    created_at: String,
    last_used: String,
    use_count: u64,
}

/// On-disk format: nonce (12 bytes) || ciphertext
/// Ciphertext is AES-256-GCM encrypted JSON

impl Vault {
    /// Create or load a vault.
    /// `key` must be exactly 32 bytes (256-bit). Derived from passphrase via Argon2id.
    /// If loading fails with the primary key, attempts legacy SHA-256 derivation
    /// for backward compatibility, then re-encrypts with the new key.
    #[cfg(test)]
    pub fn new(path: PathBuf, key: &[u8; KEY_LEN], flush_threshold: usize) -> Self {
        Self::new_with_legacy(path, key, None, flush_threshold)
    }

    /// Create or load a vault with optional legacy key fallback.
    pub fn new_with_legacy(path: PathBuf, key: &[u8; KEY_LEN], legacy_key: Option<&[u8; KEY_LEN]>, flush_threshold: usize) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("valid 256-bit key");

        let inner = if path.exists() {
            match Self::load_from_disk(&path, &cipher) {
                Ok(inner) => {
                    info!("Loaded vault with {} session(s) from {}", inner.sessions.len(), path.display());
                    inner
                }
                Err(e) => {
                    // Try legacy key if provided
                    if let Some(lk) = legacy_key {
                        let legacy_cipher = Aes256Gcm::new_from_slice(lk).expect("valid legacy key");
                        match Self::load_from_disk(&path, &legacy_cipher) {
                            Ok(inner) => {
                                info!("Loaded vault using legacy key — will re-encrypt with argon2id on next flush");
                                inner
                            }
                            Err(_) => {
                                warn!("Failed to load vault (wrong key?): {}. Starting fresh.", e);
                                VaultInner::default()
                            }
                        }
                    } else {
                        warn!("Failed to load vault (wrong key?): {}. Starting fresh.", e);
                        VaultInner::default()
                    }
                }
            }
        } else {
            info!("Creating new vault at {}", path.display());
            VaultInner::default()
        };

        Vault {
            path,
            cipher,
            inner: Mutex::new(inner),
            flush_threshold,
            auto_flush: true,
        }
    }

    /// Derive a 256-bit key from a passphrase using Argon2id.
    /// Falls back to SHA-256 only when loading legacy vaults.
    pub fn key_from_passphrase(passphrase: &str) -> [u8; KEY_LEN] {
        // Fixed salt derived from the application name.
        // Per-vault random salts would be better but would require a format change
        // (salt stored in the vault file header). Good enough for passphrase-derived keys
        // where the main threat is offline brute-force.
        const SALT: &[u8] = b"mirage-proxy-vault-v1";
        let params = argon2::Params::new(
            19 * 1024, // 19 MiB memory (m_cost)
            2,         // 2 iterations (t_cost)
            1,         // 1 lane (p_cost)
            Some(KEY_LEN),
        ).expect("valid argon2 params");
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; KEY_LEN];
        argon2.hash_password_into(passphrase.as_bytes(), SALT, &mut key)
            .expect("argon2 hash");
        key
    }

    /// Legacy SHA-256 key derivation for backward compatibility with existing vaults.
    pub fn key_from_passphrase_legacy(passphrase: &str) -> [u8; KEY_LEN] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&result);
        key
    }

    /// Store a session-scoped mapping
    pub fn put_session(&self, session_id: &str, original: &str, fake: &str, kind: &str) {
        let mut inner = self.inner.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        let session = inner.sessions.entry(session_id.to_string()).or_default();

        if let Some(entry) = session.entries.get_mut(original) {
            entry.last_used = now;
            entry.use_count += 1;
        } else {
            session.entries.insert(original.to_string(), VaultEntry {
                fake: fake.to_string(),
                kind: kind.to_string(),
                created_at: now.clone(),
                last_used: now,
                use_count: 1,
            });
            inner.reverse.insert(fake.to_string(), (session_id.to_string(), original.to_string()));
        }

        inner.ops_since_flush += 1;

        if self.auto_flush && inner.ops_since_flush >= self.flush_threshold {
            if let Err(e) = self.persist_inner(&inner) {
                warn!("Auto-flush failed: {}", e);
            } else {
                inner.ops_since_flush = 0;
            }
        }
    }

    /// Get all mappings for a session (for loading into a Faker)
    pub fn get_session_mappings(&self, session_id: &str) -> Vec<(String, String)> {
        let inner = self.inner.lock().unwrap();
        inner.sessions.get(session_id)
            .map(|s| {
                s.entries.iter()
                    .map(|(original, entry)| (original.clone(), entry.fake.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Store a mapping (original -> fake) — legacy global scope
    #[cfg(test)]
    pub fn put(&self, original: &str, fake: &str, kind: &str) {
        let mut inner = self.inner.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        if let Some(entry) = inner.forward.get_mut(original) {
            entry.last_used = now;
            entry.use_count += 1;
        } else {
            inner.forward.insert(original.to_string(), VaultEntry {
                fake: fake.to_string(),
                kind: kind.to_string(),
                created_at: now.clone(),
                last_used: now,
                use_count: 1,
            });
            inner.reverse.insert(fake.to_string(), ("_global".to_string(), original.to_string()));
        }

        inner.ops_since_flush += 1;

        if self.auto_flush && inner.ops_since_flush >= self.flush_threshold {
            if let Err(e) = self.persist_inner(&inner) {
                warn!("Auto-flush failed: {}", e);
            } else {
                inner.ops_since_flush = 0;
            }
        }
    }

    /// Look up existing fake for an original value
    pub fn get_fake(&self, original: &str) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.forward.get(original).map(|e| e.fake.clone())
    }

    /// Look up original for a fake value (for rehydration)
    #[cfg(test)]
    pub fn get_original(&self, fake: &str) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.reverse.get(fake).map(|(_, original)| original.clone())
    }

    /// Get all reverse mappings for rehydration
    #[cfg(test)]
    pub fn reverse_map(&self) -> Vec<(String, String)> {
        let inner = self.inner.lock().unwrap();
        let mut pairs: Vec<_> = inner.reverse.iter()
            .map(|(fake, (_, original))| (fake.clone(), original.clone()))
            .collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        pairs
    }

    /// Flush: persist current state to disk and clear old entries
    #[cfg(test)]
    pub fn flush(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        self.persist_inner(&inner)?;
        inner.ops_since_flush = 0;
        Ok(())
    }

    /// Flush and clear all mappings (periodic reset)
    #[cfg(test)]
    pub fn flush_and_clear(&self) -> Result<usize, String> {
        let mut inner = self.inner.lock().unwrap();
        let count = inner.forward.len();
        self.persist_inner(&inner)?;
        inner.forward.clear();
        inner.reverse.clear();
        inner.ops_since_flush = 0;
        info!("Vault flushed and cleared {} mappings", count);
        Ok(count)
    }

    /// Flush entries older than `max_age` seconds
    #[cfg(test)]
    pub fn flush_stale(&self, max_age_secs: i64) -> Result<usize, String> {
        let mut inner = self.inner.lock().unwrap();
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_secs);
        let cutoff_str = cutoff.to_rfc3339();

        let stale_keys: Vec<String> = inner.forward.iter()
            .filter(|(_, v)| v.last_used < cutoff_str)
            .map(|(k, _)| k.clone())
            .collect();

        let count = stale_keys.len();
        for key in &stale_keys {
            if let Some(entry) = inner.forward.remove(key) {
                inner.reverse.remove(&entry.fake);
            }
        }

        if count > 0 {
            self.persist_inner(&inner)?;
            info!("Flushed {} stale vault entries", count);
        }

        Ok(count)
    }

    /// Stats
    #[cfg(test)]
    pub fn stats(&self) -> VaultStats {
        let inner = self.inner.lock().unwrap();
        VaultStats {
            total_mappings: inner.forward.len(),
            ops_since_flush: inner.ops_since_flush,
        }
    }

    fn persist_inner(&self, inner: &VaultInner) -> Result<(), String> {
        let json = serde_json::to_vec(inner).map_err(|e| format!("serialize: {}", e))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, json.as_ref())
            .map_err(|e| format!("encrypt: {}", e))?;

        let mut data = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        data.extend_from_slice(&nonce_bytes);
        data.extend_from_slice(&ciphertext);

        // Write atomically via temp file
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, &data).map_err(|e| format!("write: {}", e))?;
        fs::rename(&tmp, &self.path).map_err(|e| format!("rename: {}", e))?;

        Ok(())
    }

    fn load_from_disk(path: &Path, cipher: &Aes256Gcm) -> Result<VaultInner, String> {
        let data = fs::read(path).map_err(|e| format!("read: {}", e))?;

        if data.len() < NONCE_LEN {
            return Err("file too short".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "decryption failed (wrong key?)".to_string())?;

        serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize: {}", e))
    }
}

#[derive(Debug)]
#[cfg(test)]
pub struct VaultStats {
    pub total_mappings: usize,
    pub ops_since_flush: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_vault_path() -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("mirage-vault-test-{}.enc", uuid::Uuid::new_v4()));
        p
    }

    #[test]
    fn test_put_and_get() {
        let path = temp_vault_path();
        let key = Vault::key_from_passphrase("test-key-123");
        let vault = Vault::new(path.clone(), &key, 100);

        vault.put("real@email.com", "fake@example.com", "EMAIL");

        assert_eq!(vault.get_fake("real@email.com"), Some("fake@example.com".to_string()));
        assert_eq!(vault.get_original("fake@example.com"), Some("real@email.com".to_string()));
        assert_eq!(vault.get_fake("unknown"), None);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_persist_and_reload() {
        let path = temp_vault_path();
        let key = Vault::key_from_passphrase("persist-test");

        {
            let vault = Vault::new(path.clone(), &key, 100);
            vault.put("secret", "fake-secret", "API_KEY");
            vault.flush().unwrap();
        }

        // Reload
        {
            let vault = Vault::new(path.clone(), &key, 100);
            assert_eq!(vault.get_fake("secret"), Some("fake-secret".to_string()));
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wrong_key_fails() {
        let path = temp_vault_path();
        let key1 = Vault::key_from_passphrase("correct-key");
        let key2 = Vault::key_from_passphrase("wrong-key");

        {
            let vault = Vault::new(path.clone(), &key1, 100);
            vault.put("data", "fake", "TEST");
            vault.flush().unwrap();
        }

        // Reload with wrong key — should start fresh
        {
            let vault = Vault::new(path.clone(), &key2, 100);
            assert_eq!(vault.get_fake("data"), None); // can't decrypt
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_flush_and_clear() {
        let path = temp_vault_path();
        let key = Vault::key_from_passphrase("clear-test");
        let vault = Vault::new(path.clone(), &key, 100);

        vault.put("a", "b", "TEST");
        vault.put("c", "d", "TEST");
        let cleared = vault.flush_and_clear().unwrap();
        assert_eq!(cleared, 2);
        assert_eq!(vault.get_fake("a"), None);

        let _ = fs::remove_file(&path);
    }
}
