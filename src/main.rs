mod proxy;
mod redactor;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

use proxy::{handle_request, ProxyState};
use redactor::TokenMap;

#[derive(Parser, Debug)]
#[command(
    name = "hush-proxy",
    version,
    about = "🤫 A fast PII redaction proxy for LLM APIs",
    long_about = "Hush sits between your LLM client and provider, automatically redacting \
    PII and secrets from requests and rehydrating them in responses. \
    Sub-millisecond overhead. Zero config. Works with any OpenAI-compatible client."
)]
struct Args {
    /// Target LLM API base URL (e.g. https://api.openai.com)
    #[arg(short, long)]
    target: String,

    /// Port to listen on
    #[arg(short, long, default_value = "8686")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Disable rehydration (one-way redaction only)
    #[arg(long, default_value = "false")]
    no_rehydrate: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

    let state = Arc::new(ProxyState {
        target_url: args.target.clone(),
        client: Client::new(),
        token_map: TokenMap::new(),
    });

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    info!("🤫 hush-proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("   Listening on http://{}", addr);
    info!("   Forwarding to {}", args.target);
    info!("   Rehydration: {}", if args.no_rehydrate { "off" } else { "on" });

    loop {
        let (stream, remote) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                if !err.to_string().contains("connection closed") {
                    error!("Connection error from {}: {}", remote, err);
                }
            }
        });
    }
}
