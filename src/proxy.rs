use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response, StatusCode};
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

use crate::audit::AuditLog;
use crate::config::{Config, RedactAction};
use crate::faker::Faker;
use crate::redactor::detect;

pub struct ProxyState {
    pub target_url: String,
    pub client: Client,
    pub faker: Faker,
    pub config: Config,
    pub audit_log: Option<Arc<AuditLog>>,
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: Bytes) -> BoxBody {
    Full::new(data)
        .map_err(|never| match never {})
        .boxed()
}

fn error_response(status: StatusCode, msg: &str) -> Response<BoxBody> {
    let body = serde_json::json!({ "error": { "message": msg, "type": "hush_proxy_error" } });
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

    info!("{} {}", method, path);

    // Collect request body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            return Ok(error_response(StatusCode::BAD_REQUEST, "Failed to read request body"));
        }
    };

    // Redact PII in request body (JSON)
    let redacted_body = if !body_bytes.is_empty() {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(mut json) => {
                redact_json_value(&mut json, &state);
                debug!("Redacted request body");
                serde_json::to_vec(&json).unwrap_or_else(|_| body_bytes.to_vec())
            }
            Err(_) => {
                let text = String::from_utf8_lossy(&body_bytes);
                let redacted = smart_redact(&text, &state);
                redacted.into_bytes()
            }
        }
    } else {
        body_bytes.to_vec()
    };

    // In dry-run mode, forward the original body
    let forward_body = if state.config.dry_run {
        body_bytes.to_vec()
    } else {
        redacted_body
    };

    // Build forwarding request
    let target_url = format!("{}{}", state.target_url.trim_end_matches('/'), path);
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
    let is_stream = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        handle_streaming_response(status, resp_headers, response, state).await
    } else {
        handle_regular_response(status, resp_headers, response, state).await
    }
}

async fn handle_regular_response(
    status: reqwest::StatusCode,
    resp_headers: reqwest::header::HeaderMap,
    response: reqwest::Response,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let body_bytes = response.bytes().await.unwrap_or_default();

    let rehydrated_body = if !body_bytes.is_empty() && !state.config.dry_run {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(mut json) => {
                rehydrate_json_value(&mut json, &state);
                serde_json::to_vec(&json).unwrap_or_else(|_| body_bytes.to_vec())
            }
            Err(_) => {
                let text = String::from_utf8_lossy(&body_bytes);
                let rehydrated = rehydrate_all(&text, &state);
                rehydrated.into_bytes()
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
) -> Result<Response<BoxBody>, hyper::Error> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);

    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let rehydrated = if state.config.dry_run {
                        text.to_string()
                    } else {
                        rehydrate_all(&text, &state)
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

/// Smart redaction: uses config to decide action per PII kind
fn smart_redact(text: &str, state: &ProxyState) -> String {
    let entities = detect(text);
    let mut result = text.to_string();

    for entity in &entities {
        let label = entity.kind.label();
        let action = state.config.should_redact(label);

        // Audit log
        if let Some(ref audit) = state.audit_log {
            audit.log(label, &action, &entity.original, text);
        }

        match action {
            RedactAction::Redact | RedactAction::Mask => {
                let fake = state.faker.fake(&entity.original, &entity.kind);
                result = result.replace(&entity.original, &fake);
            }
            RedactAction::Warn => {
                // Logged above, don't modify
            }
            RedactAction::Ignore => {}
        }
    }

    result
}

/// Rehydrate: restore fakes back to originals
fn rehydrate_all(text: &str, state: &ProxyState) -> String {
    state.faker.rehydrate(text)
}

/// Recursively redact PII in JSON values
fn redact_json_value(value: &mut Value, state: &ProxyState) {
    match value {
        Value::String(s) => {
            *s = smart_redact(s, state);
        }
        Value::Array(arr) => {
            for item in arr {
                redact_json_value(item, state);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                redact_json_value(v, state);
            }
        }
        _ => {}
    }
}

/// Recursively rehydrate PII tokens in JSON values
fn rehydrate_json_value(value: &mut Value, state: &ProxyState) {
    match value {
        Value::String(s) => {
            *s = rehydrate_all(s, state);
        }
        Value::Array(arr) => {
            for item in arr {
                rehydrate_json_value(item, state);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                rehydrate_json_value(v, state);
            }
        }
        _ => {}
    }
}
