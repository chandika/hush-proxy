# 🤫 hush-proxy

A fast, lightweight PII redaction proxy for LLM APIs. Written in Rust. Sub-millisecond overhead.

Hush sits between your LLM client (Claude Code, Codex, Cursor, OpenCode, Aider — anything) and the provider, automatically stripping sensitive data from requests and restoring it in responses.

## Why

Every message you send to an LLM provider includes your full conversation context. That context often contains API keys, connection strings, email addresses, phone numbers, and other secrets — especially when coding agents read your files and environment.

Hush makes sure none of that reaches the provider.

## Install

```bash
cargo install hush-proxy
```

Or build from source:

```bash
git clone https://github.com/chandika/hush-proxy
cd hush-proxy
cargo build --release
# Binary at ./target/release/hush-proxy
```

## Usage

```bash
# Point hush at your LLM provider
hush-proxy --target https://api.openai.com

# Now point your client at hush (default: localhost:8686)
export OPENAI_API_BASE=http://localhost:8686
```

### With Claude Code

```bash
hush-proxy --target https://api.anthropic.com
# Set base URL in Claude Code config to http://localhost:8686
```

### With Codex

```bash
hush-proxy --target https://api.openai.com
export OPENAI_API_BASE=http://localhost:8686
```

### Custom port

```bash
hush-proxy --target https://api.openai.com --port 9090
```

## What it catches

### Layer 1: Pattern matching (< 1ms)
- **Emails** — `user@example.com`
- **Phone numbers** — `(555) 123-4567`, `+1-555-123-4567`
- **Credit cards** — Visa, Mastercard, Amex, Discover
- **SSNs** — `123-45-6789`
- **IP addresses** — `192.168.1.1`
- **AWS keys** — `AKIA...`
- **GitHub tokens** — `ghp_...`, `ghs_...`
- **OpenAI/API keys** — `sk-...`, `sk-proj-...`
- **Bearer tokens** — `Bearer eyJ...`
- **Connection strings** — `postgres://user:pass@host/db`
- **Private keys** — PEM-encoded RSA/EC/DSA keys

### Layer 2: Entropy detection (< 1ms)
- Catches unknown secret formats by detecting high-entropy strings (Shannon entropy > 4.5, length ≥ 32)

## How it works

1. **Intercept** — Client sends request to Hush
2. **Detect** — Pattern matching + entropy analysis finds PII/secrets
3. **Redact** — Sensitive values replaced with consistent tokens (`[EMAIL_1_a3b2c1d4]`)
4. **Forward** — Clean request sent to the real provider
5. **Rehydrate** — Provider response tokens replaced back with original values
6. **Return** — Client gets a natural response with real data intact

The token map is consistent within a session — the same email always maps to the same token, so the LLM can maintain context across turns.

## Streaming

Full SSE streaming support. Hush processes `text/event-stream` responses chunk-by-chunk with minimal buffering.

## Options

```
Options:
  -t, --target <URL>       Target LLM API base URL (required)
  -p, --port <PORT>        Port to listen on [default: 8686]
  -b, --bind <ADDR>        Bind address [default: 127.0.0.1]
      --log-level <LEVEL>  Log level [default: info]
      --no-rehydrate       Disable rehydration (one-way redaction)
  -h, --help               Print help
  -V, --version            Print version
```

## Roadmap

- [ ] v1.0 — Pattern + entropy detection, rehydration, streaming (current)
- [ ] v1.1 — Custom pattern config (YAML), allowlists
- [ ] v2.0 — Optional ONNX NER model for name/org/location detection
- [ ] v2.1 — Plausible fake substitution (names → fake names, not tokens)
- [ ] v3.0 — Multi-provider support (Anthropic native API format)

## License

MIT
