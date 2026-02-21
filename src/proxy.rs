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

/// Decompress a body based on content-encoding
fn decompress_body(data: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    match encoding {
        "zstd" => {
            zstd::decode_all(std::io::Cursor::new(data))
                .map_err(|e| format!("zstd decode error: {}", e))
        }
        "gzip" => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(data));
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf).map_err(|e| format!("gzip decode error: {}", e))?;
            Ok(buf)
        }
        other => Err(format!("unsupported encoding: {}", other)),
    }
}

/// Compress a body back to the specified encoding
fn compress_body(data: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    match encoding {
        "zstd" => {
            zstd::encode_all(std::io::Cursor::new(data), 3)
                .map_err(|e| format!("zstd encode error: {}", e))
        }
        "gzip" => {
            use std::io::Write;
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).map_err(|e| format!("gzip encode error: {}", e))?;
            encoder.finish().map_err(|e| format!("gzip finish error: {}", e))
        }
        other => Err(format!("unsupported encoding: {}", other)),
    }
}

pub struct ProxyState {
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

fn health_response(state: &ProxyState) -> Response<BoxBody> {
    use std::sync::atomic::Ordering;

    let body = serde_json::json!({
        "status": "ok",
        "service": "mirage-proxy",
        "requests": state.stats.requests.load(Ordering::Relaxed),
        "redactions": state.stats.redactions.load(Ordering::Relaxed),
        "sessions": state.stats.sessions.load(Ordering::Relaxed),
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// Fast-path: forward request without inspection (when decompression fails)
async fn forward_request(
    method: hyper::Method,
    path: &str,
    headers: &hyper::HeaderMap,
    body: Vec<u8>,
    state: Arc<ProxyState>,
    faker: Arc<Faker>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let is_chatgpt = headers.contains_key("chatgpt-account-id");
    let (target_url, _) = if let Some((upstream, remaining)) = crate::providers::resolve_provider(path, is_chatgpt) {
        (format!("{}{}", upstream.trim_end_matches('/'), remaining), remaining)
    } else {
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("No provider matched for path: {}. Use a provider prefix (e.g. /anthropic, /openai).", path),
        ));
    };

    debug!("▶ fast-forward {} {} → {} ({} bytes, no inspection)", method, path, target_url, body.len());

    let mut forward = state.client.request(method.clone(), &target_url);
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        match name_str.as_str() {
            "host" | "connection" | "transfer-encoding" | "content-length" | "accept-encoding" => continue,
            _ => {
                if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                        forward = forward.header(n, v);
                    }
                }
            }
        }
    }
    // Force identity encoding so response rehydration can operate safely on plain text/JSON.
    forward = forward.header("accept-encoding", "identity");
    forward = forward.body(body);

    let response = match forward.send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Upstream request failed: {}", e);
            return Ok(error_response(StatusCode::BAD_GATEWAY, &format!("Upstream error: {}", e)));
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let ct = resp_headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("none");
    debug!("← {} {} ({})", status.as_u16(), status.canonical_reason().unwrap_or(""), ct);

    let is_stream = resp_headers.get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        handle_streaming_response(status, resp_headers, response, state, faker).await
    } else {
        handle_regular_response(status, resp_headers, response, state, faker).await
    }
}

/// Handle an incoming request: redact PII, forward to target, rehydrate response
pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
    let headers = req.headers().clone();

    if path == "/healthz" {
        return Ok(health_response(&state));
    }

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

    // Check if this provider is bypassed (no redaction/rehydration)
    let is_chatgpt_early = headers.contains_key("chatgpt-account-id");
    let resolved_upstream = crate::providers::resolve_provider(&path, is_chatgpt_early)
        .map(|(upstream, _)| upstream.to_string())
        .unwrap_or_default();
    if state.config.is_bypassed(&resolved_upstream) {
        debug!("⏩ bypassing {} (matched bypass list)", resolved_upstream);
        let (_, faker) = state.sessions.get_faker("default");
        return forward_request(method, &path, &headers, body_bytes.to_vec(), state, faker).await;
    }

    // Check for compressed body (zstd, gzip, etc.) — decompress for inspection, forward original
    let content_encoding = headers.get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

    let inspect_bytes = if is_compressed {
        debug!("body is compressed ({}), {} bytes — decompressing for inspection", content_encoding, body_bytes.len());
        match decompress_body(&body_bytes, &content_encoding) {
            Ok(decompressed) => {
                debug!("decompressed: {} bytes → {} bytes", body_bytes.len(), decompressed.len());
                decompressed
            }
            Err(e) => {
                warn!("failed to decompress {} body: {} — forwarding as-is without inspection", content_encoding, e);
                // Can't inspect, just forward original
                let (_, faker) = state.sessions.get_faker("default");
                // Skip to forwarding
                return forward_request(method, &path, &headers, body_bytes.to_vec(), state, faker).await;
            }
        }
    } else {
        body_bytes.to_vec()
    };

    // Parse JSON to derive session ID, then redact with session-scoped faker
    let (redacted_body, session_faker) = if !inspect_bytes.is_empty() {
        match serde_json::from_slice::<Value>(&inspect_bytes) {
            Ok(mut json) => {
                debug!("parsed JSON body OK ({} bytes)", inspect_bytes.len());
                let session_id = SessionManager::derive_session_id(&json);
                let (is_new, faker) = state.sessions.get_faker(&session_id);
                if is_new {
                    state.stats.add_session();
                }
                if is_new {
                    eprint!("\r\x1b[2K  📎 session: {}\n", session_id);
                }
                redact_json_value(&mut json, &state, &faker);
                if is_compressed {
                    // Re-compress redacted JSON back to original encoding
                    let redacted_json = serde_json::to_vec(&json).unwrap_or_else(|_| inspect_bytes.clone());
                    debug!("re-compressing redacted body ({} bytes) with {}", redacted_json.len(), content_encoding);
                    match compress_body(&redacted_json, &content_encoding) {
                        Ok(compressed) => {
                            debug!("re-compressed: {} bytes → {} bytes", redacted_json.len(), compressed.len());
                            (compressed, faker)
                        }
                        Err(e) => {
                            warn!("failed to re-compress body: {} — forwarding original", e);
                            (body_bytes.to_vec(), faker)
                        }
                    }
                } else {
                    (serde_json::to_vec(&json).unwrap_or_else(|_| body_bytes.to_vec()), faker)
                }
            }
            Err(e) => {
                debug!("body is not valid JSON: {} — treating as text ({} bytes)", e, inspect_bytes.len());
                let (_, faker) = state.sessions.get_faker("default");
                let text = String::from_utf8_lossy(&inspect_bytes);
                let redacted = smart_redact(&text, &state, &faker);
                if is_compressed {
                    match compress_body(redacted.as_bytes(), &content_encoding) {
                        Ok(compressed) => (compressed, faker),
                        Err(_) => (body_bytes.to_vec(), faker),
                    }
                } else {
                    (redacted.into_bytes(), faker)
                }
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

    // Resolve provider
    let is_chatgpt = headers.contains_key("chatgpt-account-id");
    let (target_url, forward_path) = if let Some((upstream, remaining)) = crate::providers::resolve_provider(&path, is_chatgpt) {
        (format!("{}{}", upstream.trim_end_matches('/'), remaining), remaining)
    } else {
        warn!("No provider matched for path: {}", path);
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("No provider matched for path: {}. Use a provider prefix (e.g. /anthropic, /openai).", path),
        ));
    };
    let _ = forward_path; // used for clarity, target_url has the full URL

    debug!("▶ forwarding {} {} → {}", method, path, target_url);
    debug!("  forward body: {} bytes (compressed: {})", forward_body.len(), is_compressed);

    let mut forward = state.client.request(method.clone(), &target_url);

    let mut forwarded_headers = Vec::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        match name_str.as_str() {
            "host" | "connection" | "transfer-encoding" | "content-length" | "accept-encoding" => {
                debug!("  ⊘ skipping header: {}", name_str);
                continue;
            }
            _ => {
                if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_ref()) {
                        forwarded_headers.push(format!("{}: {}", name_str,
                            if name_str == "authorization" || name_str == "x-api-key" {
                                let val = value.to_str().unwrap_or("***");
                                if val.len() > 12 { format!("{}...{}", &val[..8], &val[val.len()-4..]) } else { "***".to_string() }
                            } else {
                                value.to_str().unwrap_or("<binary>").to_string()
                            }
                        ));
                        forward = forward.header(n, v);
                    }
                }
            }
        }
    }
    for h in &forwarded_headers {
        debug!("  → {}", h);
    }

    // Force identity encoding so response rehydration can operate safely on plain text/JSON.
    forward = forward.header("accept-encoding", "identity");

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

    // Log full response body on error for diagnosis
    if status.as_u16() >= 400 {
        debug!("  ← response headers:");
        for (name, value) in resp_headers.iter() {
            debug!("    {}: {}", name.as_str(), value.to_str().unwrap_or("<binary>"));
        }
    }

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

fn header_content_encoding(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn has_anthropic_thinking_signature(text: &str) -> bool {
    // Anthropic extended thinking blocks are signed.
    // Any mutation inside those blocks invalidates the signature.
    (text.contains("\"type\":\"thinking\"") || text.contains("\"type\": \"thinking\""))
        && (text.contains("\"signature\":\"") || text.contains("\"signature\": \""))
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

    // Log error response bodies for debugging
    if status.as_u16() >= 400 {
        let body_preview = String::from_utf8_lossy(&body_bytes);
        let preview = if body_preview.len() > 2000 { &body_preview[..2000] } else { &body_preview };
        debug!("  ← error body: {}", preview);
    }

    // Rehydrate: replace fakes back to originals in the response.
    // Safety guards:
    // - Never mutate signed thinking payloads (signature would break)
    // - For compressed responses: decompress -> rehydrate -> recompress
    let content_encoding = header_content_encoding(&resp_headers);
    let is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

    let rehydrated_body = if !body_bytes.is_empty() && !state.config.dry_run {
        if is_compressed {
            match decompress_body(&body_bytes, &content_encoding) {
                Ok(decoded) => {
                    let text = String::from_utf8_lossy(&decoded);
                    if has_anthropic_thinking_signature(&text) {
                        debug!("skipping rehydration for signed thinking response (compressed)");
                        body_bytes.to_vec()
                    } else {
                        let rehydrated = faker.rehydrate(&text);
                        match compress_body(rehydrated.as_bytes(), &content_encoding) {
                            Ok(encoded) => encoded,
                            Err(e) => {
                                warn!("failed to re-compress rehydrated response: {}", e);
                                body_bytes.to_vec()
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("failed to decompress response body (content-encoding={}): {}", content_encoding, e);
                    body_bytes.to_vec()
                }
            }
        } else {
            let text = String::from_utf8_lossy(&body_bytes);
            if has_anthropic_thinking_signature(&text) {
                debug!("skipping rehydration for signed thinking response");
                body_bytes.to_vec()
            } else {
                faker.rehydrate(&text).into_bytes()
            }
        }
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

    let content_encoding = header_content_encoding(&resp_headers);
    let stream_is_compressed = !content_encoding.is_empty() && content_encoding != "identity";

    let stats_clone = state.stats.clone();
    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        // Buffer to handle fake values split across chunk boundaries.
        const BOUNDARY_BUF_SIZE: usize = 128;
        let mut leftover = String::new();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    stats_clone.add_response(bytes.len() as u64);

                    let bypass_rehydrate = state.config.dry_run || stream_is_compressed;
                    let out = if bypass_rehydrate {
                        if leftover.is_empty() {
                            bytes.to_vec()
                        } else {
                            let mut s = std::mem::take(&mut leftover);
                            s.push_str(&String::from_utf8_lossy(&bytes));
                            s.into_bytes()
                        }
                    } else {
                        let text = String::from_utf8_lossy(&bytes);

                        // Prepend any leftover from previous chunk
                        let combined = if leftover.is_empty() {
                            text.to_string()
                        } else {
                            let mut s = std::mem::take(&mut leftover);
                            s.push_str(&text);
                            s
                        };

                        // Do not touch signed thinking payloads (Anthropic validates signatures)
                        if has_anthropic_thinking_signature(&combined) {
                            debug!("detected signed thinking chunk in SSE stream — passing through unchanged");
                            combined.into_bytes()
                        } else {
                            // Hold back tail as overlap to catch boundary-split fake values
                            let (to_process, new_leftover) = if combined.len() > BOUNDARY_BUF_SIZE {
                                let split_at = combined.len() - BOUNDARY_BUF_SIZE;
                                let safe_split = combined[split_at..]
                                    .find('\n')
                                    .map(|pos| split_at + pos + 1)
                                    .unwrap_or(split_at);
                                (&combined[..safe_split], &combined[safe_split..])
                            } else {
                                leftover = combined;
                                continue;
                            };

                            leftover = new_leftover.to_string();
                            faker.rehydrate(to_process).into_bytes()
                        }
                    };

                    let frame = Frame::data(Bytes::from(out));
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

        if !leftover.is_empty() {
            let flushed = if state.config.dry_run || stream_is_compressed {
                leftover.into_bytes()
            } else if has_anthropic_thinking_signature(&leftover) {
                leftover.into_bytes()
            } else {
                faker.rehydrate(&leftover).into_bytes()
            };
            let frame = Frame::data(Bytes::from(flushed));
            let _ = tx.send(Ok(frame)).await;
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
                    let detail = if let Some(ref name) = entity.pattern_name {
                        format!("{} ({})", label, name)
                    } else {
                        label.to_string()
                    };
                    let char_count = entity.original.len();
                    eprint!("\r\x1b[2K  🛡️  {} [{} chars] → {}\n", detail, char_count, preview);
                    new_redaction_count += 1;
                }
            }
            RedactAction::Warn => {
                if is_new {
                    let preview = truncate_preview(&entity.original, 40);
                    let detail = if let Some(ref name) = entity.pattern_name {
                        format!("{} ({})", label, name)
                    } else {
                        label.to_string()
                    };
                    let char_count = entity.original.len();
                    eprint!("\r\x1b[2K  ⚠️  {} (warn) [{} chars] → {}\n", detail, char_count, preview);
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
    // Cryptographic / signed envelopes (must remain byte-exact)
    "signature", "encrypted_content", "encrypted_input", "ciphertext",
    "proof", "attestation", "nonce", "iv", "tag", "mac",
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
            // Anthropic signed thinking blocks must never be modified.
            // Shape example:
            // {"type":"thinking","thinking":"...","signature":"base64..."}
            let is_signed_thinking = obj
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t == "thinking")
                .unwrap_or(false)
                && obj.get("signature").is_some();

            if is_signed_thinking {
                return;
            }

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
