use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/chandika/mirage-proxy/releases/latest";
const UPDATE_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub release_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedLatestRelease {
    version: String,
    release_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateCheckCache {
    checked_at_unix_secs: u64,
    latest_release: Option<CachedLatestRelease>,
}

pub async fn check_for_update(timeout_ms: u64) -> Option<UpdateInfo> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let cache_path = cache_path();
    let cached = load_cache(&cache_path);

    if let Some(cache) = cached.as_ref() {
        if is_cache_fresh(cache) {
            return evaluate_cached_release(cache.latest_release.as_ref(), &current);
        }
    }

    match fetch_latest_release(timeout_ms, &current).await {
        Some(latest_release) => {
            save_cache(
                &cache_path,
                &UpdateCheckCache {
                    checked_at_unix_secs: now_unix_secs(),
                    latest_release: Some(latest_release.clone()),
                },
            );
            evaluate_cached_release(Some(&latest_release), &current)
        }
        None => {
            // Network failed: reuse last known cache result (even if stale).
            cached
                .and_then(|cache| evaluate_cached_release(cache.latest_release.as_ref(), &current))
        }
    }
}

fn normalize_version(v: &str) -> Option<String> {
    let stripped = v.trim().trim_start_matches('v');
    if stripped.is_empty() {
        return None;
    }
    Some(stripped.to_string())
}

fn parse_core_numbers(v: &str) -> Option<Vec<u64>> {
    let core = v.split('-').next().unwrap_or(v);
    let mut nums = Vec::new();
    for part in core.split('.') {
        if part.is_empty() {
            return None;
        }
        nums.push(part.parse::<u64>().ok()?);
    }
    Some(nums)
}

fn compare_versions(a: &str, b: &str) -> Ordering {
    let Some(mut va) = parse_core_numbers(a) else {
        return Ordering::Equal;
    };
    let Some(mut vb) = parse_core_numbers(b) else {
        return Ordering::Equal;
    };
    let len = va.len().max(vb.len());
    va.resize(len, 0);
    vb.resize(len, 0);
    va.cmp(&vb)
}

async fn fetch_latest_release(timeout_ms: u64, current: &str) -> Option<CachedLatestRelease> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .ok()?;

    let release = client
        .get(LATEST_RELEASE_API)
        .header(USER_AGENT, format!("mirage-proxy/{}", current))
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json::<GithubRelease>()
        .await
        .ok()?;

    let latest = normalize_version(&release.tag_name)?;
    let release_url = release.html_url.unwrap_or_else(|| {
        format!(
            "https://github.com/chandika/mirage-proxy/releases/tag/v{}",
            latest
        )
    });

    Some(CachedLatestRelease {
        version: latest,
        release_url,
    })
}

fn evaluate_cached_release(
    cached: Option<&CachedLatestRelease>,
    current: &str,
) -> Option<UpdateInfo> {
    let cached = cached?;
    if compare_versions(&cached.version, current) == Ordering::Greater {
        return Some(UpdateInfo {
            current: current.to_string(),
            latest: cached.version.clone(),
            release_url: cached.release_url.clone(),
        });
    }
    None
}

fn cache_path() -> PathBuf {
    let mut base = dirs_next::cache_dir()
        .or_else(|| dirs_next::home_dir().map(|p| p.join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.push("mirage");
    base.push("update-check.json");
    base
}

fn load_cache(path: &Path) -> Option<UpdateCheckCache> {
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str::<UpdateCheckCache>(&contents).ok()
}

fn save_cache(path: &Path, cache: &UpdateCheckCache) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(serialized) = serde_json::to_string(cache) {
        let _ = fs::write(path, serialized);
    }
}

fn is_cache_fresh(cache: &UpdateCheckCache) -> bool {
    now_unix_secs().saturating_sub(cache.checked_at_unix_secs) < UPDATE_CACHE_TTL_SECS
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{compare_versions, is_cache_fresh, normalize_version, UpdateCheckCache};
    use std::cmp::Ordering;

    #[test]
    fn normalizes_v_prefix() {
        assert_eq!(normalize_version("v0.5.15").as_deref(), Some("0.5.15"));
        assert_eq!(normalize_version("0.5.15").as_deref(), Some("0.5.15"));
    }

    #[test]
    fn compares_versions() {
        assert_eq!(compare_versions("0.5.16", "0.5.15"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1"), Ordering::Equal);
        assert_eq!(compare_versions("0.6.0", "0.6.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.6.0", "0.6.1"), Ordering::Less);
    }

    #[test]
    fn treats_recent_cache_as_fresh() {
        let now = super::now_unix_secs();
        let cache = UpdateCheckCache {
            checked_at_unix_secs: now.saturating_sub(60),
            latest_release: None,
        };
        assert!(is_cache_fresh(&cache));
    }
}
