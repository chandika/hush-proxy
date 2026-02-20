use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response, StatusCode};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::audit::AuditLog;
use crate::config::{Config, RedactAction};
use crate::faker::Faker;
use crate::redactor::detect;
use crate::session::SessionManager;
use crate::stats::Stats;
use crate::vault::Vault;

pub struct ProxyState {
    pub target_url: String,
    pub client: Client,
    pub sessions: SessionManager,
    pub config: Config,
    pub audit_log: Option<Arc<AuditLog>>,
    pub stats: Arc<Stats>,
    /// Global set of PII values already seen (by hash) — dedup across all sessions
    pub seen_pii: Mutex<HashSet<String>>,
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: Bytes) -> BoxBody {
    Full::new(data)
        .map_err(|never| match never {})
        .boxed()
}

fn error_response(status: StatusCode, msg: &str) -> Response<BoxBody> {
    let body = serde_json::json!({ "error": { "message": msg, "type": "mirage_proxy_error" } });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// Handle an incoming request: redact PII, forward to target, rehydrate response
pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
    let headers = req.headers().clone();

    debug!("{} {}", method, path);
    for (name, value) in req.headers().iter() {
        let n = name.as_str();
        let v = value.to_str().unwrap_or("<binary>");
        // Mask auth values in debug but show the header name and first/last chars
        if n == "authorization" || n == "x-api-key" || n == "openai-organization" {
            let masked = if v.len() > 12 {
                format!("{}...{}", &v[..8], &v[v.len()-4..])
            } else {
                "***".to_string()
            };
            debug!("  → {}: {}", n, masked);
        } else {
            debug!("  → {}: {}", n, v);
        }
    }

    // Collect request body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            return Ok(error_response(StatusCode::BAD_REQUEST, "Failed to read request body"));
        }
    };

    state.stats.add_request(body_bytes.len() as u64);

    // Parse JSON to derive session ID, then redact with session-scoped faker
    let (redacted_body, session_faker) = if !body_bytes.is_empty() {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(mut json) => {
                let session_id = SessionManager::derive_session_id(&json);
                let (is_new, faker) = state.sessions.get_faker(&session_id);
                if is_new {
                    state.stats.add_session();
                }
                if is_new {
                    eprint!("\r\x1b[2K  📎 session: {}\n", session_id);
                }
                redact_json_value(&mut json, &state, &faker);
                (serde_json::to_vec(&json).unwrap_or_else(|_| body_bytes.to_vec()), faker)
            }
            Err(_) => {
                let (_, faker) = state.sessions.get_faker("default");
                let text = String::from_utf8_lossy(&body_bytes);
                let redacted = smart_redact(&text, &state, &faker);
                (redacted.into_bytes(), faker)
            }
        }
    } else {
        (body_bytes.to_vec(), state.sessions.get_faker("default").1)
    };

    // In dry-run mode, forward the original body
    let forward_body = if state.config.dry_run {
        body_bytes.to_vec()
    } else {
        redacted_body
    };

    // Resolve target: check provider routing first, then fall back to --target
    let (target_url, forward_path) = if let Some((upstream, remaining)) = crate::providers::resolve_provider(&path) {
        (format!("{}{}", upstream.trim_end_matches('/'), remaining), remaining)
    } else if !state.target_url.is_empty() {
        (format!("{}{}", state.target_url.trim_end_matches('/'), &path), path.clone())
    } else {
        warn!("No provider matched for path: {}", path);
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("No provider configured for path: {}. Use a provider prefix (e.g. /anthropic, /openai) or set --target.", path),
        ));
    };
    let _ = forward_path; // used for clarity, target_url has the full URL
    let mut forward = state.client.request(method.clone(), &target_url);

    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        match name_str.as_str() {
            "host" | "connection" | "transfer-encoding" | "content-length" => continue,
            _ => {
                if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                        forward = forward.header(n, v);
                    }
                }
            }
        }
    }

    forward = forward.body(forward_body);

    let response = match forward.send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Upstream request failed: {}", e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream request failed: {}", e),
            ));
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let ct = resp_headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("none");
    debug!("← {} {} ({})", status.as_u16(), status.canonical_reason().unwrap_or(""), ct);

    let is_stream = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        handle_streaming_response(status, resp_headers, response, state, session_faker).await
    } else {
        handle_regular_response(status, resp_headers, response, state, session_faker).await
    }
}

async fn handle_regular_response(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    response: reqwest::Response,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let body_bytes = response.bytes().await.unwrap_or_default();

    state.stats.add_response(body_bytes.len() as u64);

    // Rehydrate: replace fakes back to originals in the response
    // Use string replacement on raw bytes to avoid JSON re-serialization artifacts
    let rehydrated_body = if !body_bytes.is_empty() && !state.config.dry_run {
        let text = String::from_utf8_lossy(&body_bytes);
        let rehydrated = faker.rehydrate(&text);
        rehydrated.into_bytes()
    } else {
        body_bytes.to_vec()
    };

    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "content-length" || name_str == "transfer-encoding" {
            continue;
        }
        if let Ok(n) = hyper::header::HeaderName::from_bytes(name.as_ref()) {
            if let Ok(v) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(n, v);
            }
        }
    }

    Ok(builder
        .body(full_body(Bytes::from(rehydrated_body)))
        .unwrap())
}

async fn handle_streaming_response(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    response: reqwest::Response,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);

    let stats_clone = state.stats.clone();
    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    stats_clone.add_response(bytes.len() as u64);
                    let text = String::from_utf8_lossy(&bytes);
                    let rehydrated = if state.config.dry_run {
                        text.to_string()
                    } else {
                        faker.rehydrate(&text)
                    };
                    let frame = Frame::data(Bytes::from(rehydrated));
                    if tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Stream chunk error: {}", e);
                    break;
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = StreamBody::new(stream);
    let boxed: BoxBody = BodyExt::boxed(body);

    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "content-length" || name_str == "transfer-encoding" {
            continue;
        }
        if let Ok(n) = hyper::header::HeaderName::from_bytes(name.as_ref()) {
            if let Ok(v) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(n, v);
            }
        }
    }

    Ok(builder.body(boxed).unwrap())
}

/// Smart redaction: uses config to decide action per PII kind.
/// Only counts and logs *new* detections — values already seen in this session are silently handled.
fn smart_redact(text: &str, state: &ProxyState, faker: &Faker) -> String {
    let entities = detect(text);
    let mut result = text.to_string();
    let mut new_redaction_count: u64 = 0;

    for entity in &entities {
        let label = entity.kind.label();
        let action = state.config.should_redact(label);

        // Global dedup: check if we've ever seen this exact value
        let is_new = {
            let mut seen = state.seen_pii.lock().unwrap();
            seen.insert(entity.original.clone())  // returns true if newly inserted
        };

        // Only audit-log and count genuinely new detections
        if is_new {
            if let Some(ref audit) = state.audit_log {
                audit.log(label, &action, &entity.original, text);
            }
        }

        match action {
            RedactAction::Redact | RedactAction::Mask => {
                let fake = faker.fake(&entity.original, &entity.kind);
                result = result.replace(&entity.original, &fake);
                if is_new {
                    // Print above status bar: clear line, print, newline
                    let preview = truncate_preview(&entity.original, 40);
                    eprint!("\r\x1b[2K  🛡️  {} → {}\n", label, preview);
                    new_redaction_count += 1;
                }
            }
            RedactAction::Warn => {
                if is_new {
                    let preview = truncate_preview(&entity.original, 40);
                    eprint!("\r\x1b[2K  ⚠️  {} (warn) → {}\n", label, preview);
                }
            }
            RedactAction::Ignore => {}
        }
    }

    if new_redaction_count > 0 {
        state.stats.add_redactions(new_redaction_count);
    }

    result
}

/// Truncate a string for display, masking the middle
fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        // Mask middle: show first 4 and last 4 chars
        if s.len() > 10 {
            let start = &s[..4];
            let end = &s[s.len()-4..];
            format!("{}•••{}", start, end)
        } else {
            format!("{}•••", &s[..s.len().min(3)])
        }
    } else {
        let start = &s[..4];
        format!("{}••• [{} chars]", start, s.len())
    }
}

/// Recursively redact PII in JSON values
/// JSON keys that should NEVER be redacted.
/// Auth, config, IDs, metadata — anything that isn't user content.
const SKIP_REDACT_KEYS: &[&str] = &[
    // Auth
    "api_key", "apikey", "api-key", "api_secret",
    "authorization", "auth", "token", "bearer",
    "x-api-key", "x_api_key",
    "secret_key", "secret", "credentials",
    "access_token", "refresh_token",
    "session_token", "session_key", "session_id",
    // Model/provider config
    "model", "stream", "max_tokens", "temperature",
    "top_p", "top_k", "stop", "seed",
    "anthropic-version", "anthropic_version",
    "openai-organization", "openai_organization",
    // IDs and references (can look like high-entropy secrets)
    "id", "object", "type", "role", "name",
    "previous_response_id", "response_id",
    "message_id", "conversation_id", "thread_id",
    "run_id", "assistant_id", "file_id", "batch_id",
    "tool_call_id", "tool_use_id",
    // Request structure
    "tool_choice", "response_format", "format",
    "encoding_format", "modalities",
    "truncation", "store", "metadata",
    "service_tier", "user",
    // mirage internal
    "mirage_session",
];

/// Keys whose VALUES are user content and SHOULD be redacted.
/// Everything else in the object is skipped — we only recurse into these.
const CONTENT_KEYS: &[&str] = &[
    "content", "text", "messages", "system", "input",
    "instructions", "description", "prompt",
    "tools", "tool_results", "tool_result",
];

fn should_skip_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    // If it's a known content key, always recurse into it
    if CONTENT_KEYS.iter().any(|&k| lower == k) {
        return false;
    }
    // If it's a known skip key, skip it
    if SKIP_REDACT_KEYS.iter().any(|&k| lower == k) {
        return true;
    }
    // For unknown keys: skip if the key name suggests it's an ID or config
    lower.ends_with("_id") || lower.ends_with("_key") || lower.ends_with("_token")
        || lower.ends_with("_secret") || lower.ends_with("_url") || lower.ends_with("_uri")
        || lower.starts_with("x-") || lower.starts_with("x_")
}

fn redact_json_value(value: &mut Value, state: &ProxyState, faker: &Faker) {
    match value {
        Value::String(s) => {
            *s = smart_redact(s, state, faker);
        }
        Value::Array(arr) => {
            for item in arr {
                redact_json_value(item, state, faker);
            }
        }
        Value::Object(obj) => {
            for (key, v) in obj.iter_mut() {
                if should_skip_key(key) {
                    continue; // Never redact auth/config fields
                }
                redact_json_value(v, state, faker);
            }
        }
        _ => {}
    }
}

/// Recursively rehydrate PII fakes in JSON values
fn rehydrate_json_value(value: &mut Value, faker: &Faker) {
    match value {
        Value::String(s) => {
            *s = faker.rehydrate(s);
        }
        Value::Array(arr) => {
            for item in arr {
                rehydrate_json_value(item, faker);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                rehydrate_json_value(v, faker);
            }
        }
        _ => {}
    }
}
