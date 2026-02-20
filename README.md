# mirage-proxy

**Invisible sensitive data filter for LLM APIs.** Single Rust binary, sub-millisecond overhead.

Your coding agent reads your `.env`, your codebase, your credentials — and sends all of it to the cloud. Mirage sits between your client and the provider, silently replacing sensitive data with plausible fakes. The LLM never knows. Your secrets never leave.

```
You:     "Deploy key is AKIAOV29GNU18FMT07EL, email quinn.martin78@aol.com"
         ↓
Mirage:  "Deploy key is AKIAELSZ6DKRY5CJQX4B, email riley.walker@outlook.com"
         ↓
Provider: (sees only fake data, responds normally)
         ↓
Mirage:  (swaps fakes back to originals in the response)
         ↓
You:     "Done! I've drafted the deploy script for quinn.martin78@aol.com"
```

No `[REDACTED]`. No `[[PERSON_1]]`. The provider sees a completely normal request with completely fake data. Responses are rehydrated transparently.

---

## Table of Contents

- [Why this matters](#why-this-matters)
- [Install](#install)
  - [OpenClaw](#openclaw)
  - [Claude Code](#claude-code)
  - [Codex / OpenAI](#codex--openai)
  - [Cursor, Aider, Continue, OpenCode](#cursor-aider-continue-opencode)
  - [All tools — manual setup](#all-tools--manual-setup)
- [Multi-provider mode](#multi-provider-mode)
- [Live output](#live-output)
- [What it detects](#what-it-detects)
- [Configuration](#configuration)
- [Sessions](#sessions)
- [Encrypted vault](#encrypted-vault)
- [Dry run](#dry-run)
- [Audit log](#audit-log)
- [Streaming](#streaming)
- [CLI reference](#cli-reference)
- [How it compares](#how-it-compares)
- [Architecture](#architecture)
- [Building from source](#building-from-source)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why this matters

On Feb 14, 2026, a critical vulnerability ([CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)) was disclosed where Claude Code could be tricked into exfiltrating API keys via prompt injection. The same week, a [Reddit post](https://www.reddit.com/r/ClaudeAI/comments/1r186gl/my_agent_stole_my_api_keys/) hit 1.7K upvotes: "My agent stole my API keys." And Anthropic's own [safety report](https://www-cdn.anthropic.com/f21d93f21602ead5cdbecb8c8e1c765759d9e232.pdf) for Opus 4.6 found the model "aggressively acquired authentication tokens" and "sent unauthorized emails without human permission" during testing.

Every LLM coding tool — Claude Code, Codex, Cursor, Aider, Continue — sends your full codebase to the cloud. If there's a secret in your repo, it's in someone's training data. Mirage fixes this at the network layer, no code changes required.

---

## Install

### OpenClaw

Mirage is a **first-class OpenClaw provider**. The [ClawdHub](https://clawdhub.com) skill handles everything: downloads and verifies the binary, creates the auto-restart wrapper, starts the proxy, and registers `mirage-anthropic` as a provider with ready-to-use model aliases.

```bash
clawdhub install mirage-proxy
bash ~/.openclaw/workspace/skills/mirage-proxy/setup.sh
```

After setup, ask your agent to patch the config, or do it manually:

```json
{
  "models": {
    "mode": "merge",
    "providers": {
      "mirage-anthropic": {
        "baseUrl": "http://127.0.0.1:8686/anthropic",
        "api": "anthropic-messages",
        "apiKey": "${ANTHROPIC_API_KEY}",
        "models": [
          { "id": "claude-opus-4-6",   "name": "Claude Opus 4.6 (mirage)",   "api": "anthropic-messages", "reasoning": true,  "contextWindow": 200000, "maxTokens": 32000 },
          { "id": "claude-sonnet-4-6", "name": "Claude Sonnet 4.6 (mirage)", "api": "anthropic-messages", "reasoning": true,  "contextWindow": 200000, "maxTokens": 16000 },
          { "id": "claude-haiku-3-6",  "name": "Claude Haiku 3.6 (mirage)",  "api": "anthropic-messages", "reasoning": false, "contextWindow": 200000, "maxTokens": 8192  }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "models": {
        "mirage-anthropic/claude-opus-4-6":   { "alias": "mirage-opus" },
        "mirage-anthropic/claude-sonnet-4-6": { "alias": "mirage-sonnet" },
        "mirage-anthropic/claude-haiku-3-6":  { "alias": "mirage-haiku" }
      }
    }
  }
}
```

Then switch with `/model mirage-sonnet` — or set `mirage-anthropic/claude-sonnet-4-6` as your default model.

**Persistence across restarts** — mirage dies when the OpenClaw container restarts. Two fixes:

```yaml
# docker-compose.yml (recommended)
command: sh -c "nohup /home/node/.openclaw/workspace/start-mirage.sh > /dev/null 2>&1 & exec openclaw start"
```

Or add a heartbeat check to `HEARTBEAT.md`:
```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8686/
# 502 or 404 = running. 000 = restart via start-mirage.sh
```

> **Why this matters for OpenClaw users:** OpenClaw agents read your entire workspace — MEMORY.md, config files, daily notes, project repos. That's a significant amount of sensitive surface area hitting cloud APIs on every heartbeat. Mirage closes that gap without changing how your agent works.

---

### Claude Code

```bash
# 1. Install
brew install chandika/tap/mirage-proxy   # macOS/Linux
# or: cargo install --git https://github.com/chandika/mirage-proxy

# 2. Auto-configure (recommended)
mirage-proxy --setup
```

`--setup` detects Claude Code and writes the correct config automatically. To verify it worked:

```bash
cat ~/.claude/settings.json | grep ANTHROPIC_BASE_URL
# Should show: "ANTHROPIC_BASE_URL": "http://localhost:8686"
```

Manual config if you prefer:

```json
// ~/.claude/settings.json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:8686"
  }
}
```

Then start mirage in a separate terminal (or background it):

```bash
mirage-proxy --target https://api.anthropic.com
```

Claude Code routes through mirage transparently. No changes to your workflow.

---

### Codex / OpenAI

```bash
# 1. Install
brew install chandika/tap/mirage-proxy
# or: cargo install --git https://github.com/chandika/mirage-proxy

# 2. Start in multi-provider mode (handles both API key and ChatGPT auth)
mirage-proxy

# 3. Point Codex at mirage
export OPENAI_BASE_URL=http://localhost:8686
```

Or via `--setup`:

```bash
mirage-proxy --setup
```

**ChatGPT Plus/Pro/Team (subscription auth):** Mirage detects the `chatgpt-account-id` header and automatically routes to `chatgpt.com/backend-api/codex/*` — the backend Codex CLI actually uses when you're authenticated via ChatGPT subscription (not api.openai.com). No extra config needed.

**Codex in OpenClaw:** For OAuth-based providers where no API key env var exists, override the built-in `baseUrl` instead of creating a custom provider:

```json
{
  "models": {
    "mode": "merge",
    "providers": {
      "openai-codex": {
        "baseUrl": "http://127.0.0.1:8686"
      }
    }
  }
}
```

> ⚠️ Do **not** add `"apiKey": "${OPENAI_API_KEY}"` to custom providers unless that env var exists in your container — it will crash OpenClaw on startup.

---

### Cursor, Aider, Continue, OpenCode

All of these tools support custom provider base URLs. Point them at `http://localhost:8686` and start mirage in multi-provider mode.

**Cursor:**

```json
// Settings → AI → Base URL
// Or in .cursor/settings.json:
{
  "anthropic.apiBaseUrl": "http://localhost:8686/anthropic",
  "openai.apiBaseUrl": "http://localhost:8686"
}
```

**Aider:**

```bash
mirage-proxy  # start first, no --target needed

# Anthropic models:
ANTHROPIC_BASE_URL=http://localhost:8686 aider --model claude-sonnet-4-6

# OpenAI models:
OPENAI_BASE_URL=http://localhost:8686 aider --model gpt-4o
```

**Continue:**

```json
// ~/.continue/config.json
{
  "models": [{
    "provider": "anthropic",
    "apiBase": "http://localhost:8686/anthropic",
    "model": "claude-sonnet-4-6"
  }]
}
```

**OpenCode / any OpenAI-compatible tool:**

```bash
export OPENAI_BASE_URL=http://localhost:8686
```

---

### All tools — manual setup

```bash
# Install
brew install chandika/tap/mirage-proxy        # Homebrew (macOS & Linux)
scoop bucket add chandika https://github.com/chandika/scoop-bucket
scoop install mirage-proxy                    # Scoop (Windows)
cargo install --git https://github.com/chandika/mirage-proxy  # From source

# Pre-built binaries → https://github.com/chandika/mirage-proxy/releases

# Start pointing at a specific provider
mirage-proxy --target https://api.anthropic.com

# Or in multi-provider mode (routes automatically based on path/header)
mirage-proxy

# Auto-configure all detected tools in one shot
mirage-proxy --setup

# Undo
mirage-proxy --uninstall
```

Release details: [`docs/releasing.md`](docs/releasing.md)

---

## Multi-provider mode

Without `--target`, Mirage acts as a multi-provider proxy. Route to any provider using path prefixes:

```bash
mirage-proxy  # no --target

# Requests auto-route based on path or header:
# /anthropic/*  → api.anthropic.com
# /openai/*     → api.openai.com
# /v1/*         → api.openai.com
# /responses    → api.openai.com (or chatgpt.com for ChatGPT auth)
# /google/*     → generativelanguage.googleapis.com
# /deepseek/*   → api.deepseek.com
# ... and 24 more (mirage-proxy --list-providers)
```

## Live output

Mirage shows a clean live display — no log spam, just what matters:

```
  mirage-proxy v0.5.15
  ─────────────────────────────────────
  listen:  http://127.0.0.1:8686
  target:  https://api.anthropic.com
  mode:    medium
  audit:   ./mirage-audit.jsonl
  ─────────────────────────────────────

  📎 session: claude-sonnet-4-20250514
  🛡️  EMAIL → ops@•••e.com
  🛡️  AWS_KEY → AKIA•••MPLE
  ⚠️  SECRET (warn) → EtUC••• [128 chars]
  📊 1h 2m 3s │ 42 reqs │ 3 masked │ 1 sessions │ ↑2.1MB ↓890KB
```

- **New detections** print once and scroll up
- **Stats bar** updates in-place at the bottom
- Each unique PII value is only counted **once** — conversation history resends don't inflate numbers
- `--log-level debug` for verbose per-request logging

## What it detects

### Secrets & credentials (always redacted)

| Type | Example | Detection |
|---|---|---|
| AWS Access Keys | `AKIAOV29GNU18FMT07EL` | Prefix `AKIA`, `ASIA`, `ABIA`, `ACCA` |
| GitHub Tokens | `ghp_xxxxxxxxxxxx` | Prefix `ghp_`, `ghs_`, `gho_`, `ghu_`, `ghr_` |
| OpenAI API Keys | `sk-proj-abc123...` | Prefix `sk-proj-`, `sk-ant-` |
| Google API Keys | `AIzaSyA...` | Prefix `AIza` |
| GitLab Tokens | `glpat-xxxx` | Prefix `glpat-` |
| Slack Tokens | `xoxb-xxx`, `xoxp-xxx` | Prefix `xoxb-`, `xoxp-`, `xoxs-` |
| Stripe Keys | `sk_live_xxx`, `pk_live_xxx` | Prefix `sk_live_`, `sk_test_`, `rk_live_` |
| Bearer Tokens | `Authorization: Bearer xxx` | Pattern match |
| PEM Private Keys | `-----BEGIN RSA PRIVATE KEY-----` | Structural |
| Connection Strings | `postgres://user:pass@host/db` | URI scheme + credentials |
| High-entropy strings | Unknown format secrets | Shannon entropy > threshold |

### Personal data (masked with plausible fakes)

| Type | Original | Fake |
|---|---|---|
| Email | `kim.anderson@mailbox.org` | `riley.walker@outlook.com` |
| Phone (intl) | `+1-288-472-2704` | `+1-251-419-2633` |
| Phone (US) | `(214) 366-2562` | `(977) 313-2491` |
| SSN | `840-80-2420` | `803-27-2349` |
| Credit Card | `4567 8901 2345 6789` | `4234 5678 9012 3456` |
| IP Address | `10.0.1.42` | `172.18.3.97` |

### How fakes work

Every fake **matches the format and length** of the original:
- An email becomes a different plausible email with a matching-length domain
- An AWS key becomes a different valid-format AWS key
- A phone number keeps its country code and formatting
- A credit card keeps its issuer prefix and passes Luhn validation

**Session consistency:** Within a conversation, `kim.anderson@mailbox.org` always maps to the same fake. The LLM's context stays coherent. Different conversations get different fakes.

## Configuration

Works with zero config. For fine-tuning, create `mirage.yaml`:

```yaml
target: "https://api.anthropic.com"
port: 8686
bind: "127.0.0.1"
sensitivity: medium   # low | medium | high | paranoid

rules:
  always_redact:
    - SSN
    - CREDIT_CARD
    - PRIVATE_KEY
    - AWS_KEY
    - GITHUB_TOKEN
    - API_KEY
    - BEARER_TOKEN
  mask:
    - EMAIL
    - PHONE
  warn_only:
    - IP_ADDRESS
    - CONNECTION_STRING
    - SECRET

allowlist:
  - "192.168.1.*"
  - "sk-test-*"
  - "localhost"

audit:
  enabled: true
  path: "./mirage-audit.jsonl"
  log_values: false

dry_run: false

update_check:
  enabled: true
  timeout_ms: 1200
```

### Sensitivity levels

| Level | What gets filtered |
|---|---|
| `low` | Only `always_redact` (secrets, keys, credentials) |
| `medium` | Secrets + PII masking (email, phone) — **default** |
| `high` | Everything including `warn_only` categories |
| `paranoid` | All detected PII regardless of category rules |

## Sessions

Mirage groups requests into **sessions** by model name. Claude Code typically creates 1-2 sessions (e.g., `claude-sonnet-4-20250514` + `claude-haiku-3.5`).

Within a session:
- Same PII → same fake (conversation stays coherent)
- Dedup: PII in conversation history isn't re-counted
- Audit log only records first occurrence

For explicit session control, add `"mirage_session": "my-session-id"` to request bodies.

## Encrypted vault

Persist mappings across restarts so conversations stay consistent:

```bash
mirage-proxy --target https://api.anthropic.com --vault-key "my-passphrase"
# or:
MIRAGE_VAULT_KEY="my-passphrase" mirage-proxy --target https://api.anthropic.com
```

The vault file (`mirage-vault.enc`) uses AES-256-GCM encryption. Without the passphrase, it's random bytes. Mappings are scoped per session.

Without `--vault-key`, mappings live in memory only and reset on restart.

## Dry run

See what would be caught without modifying traffic:

```bash
mirage-proxy --target https://api.anthropic.com --dry-run
```

Requests pass through unmodified. Detections are still logged to the audit file and shown in the live display.

## Audit log

Every **new** detection is logged to `mirage-audit.jsonl`:

```json
{
  "timestamp": "2026-02-20T02:00:17Z",
  "kind": "EMAIL",
  "action": "masked",
  "confidence": 1.0,
  "value_hash": "d8a94b5c...",
  "context_snippet": "can you email chan@..."
}
```

- Values are hashed (MD5) by default — original values never stored unless `audit.log_values: true`
- Only first occurrence per proxy lifetime is logged (no duplicates from conversation history)
- Use `value_hash` to correlate detections across sessions

## Streaming

SSE streaming support for providers that return `text/event-stream` (Claude, OpenAI, etc.). Fakes are rehydrated in real-time as chunks arrive.

**Known issue:** rehydration is chunk-by-chunk. If a fake value is split across two SSE chunks, it won't be caught. This can cause repeated or garbled lines in the client UI (observed in Claude Code during extended thinking). A cross-boundary buffer is planned.

## CLI reference

```
mirage-proxy [OPTIONS]

Options:
  -t, --target <URL>              Target LLM API base URL
  -p, --port <PORT>               Listen port [default: 8686]
  -b, --bind <ADDR>               Bind address [default: 127.0.0.1]
  -c, --config <PATH>             Config file path
      --sensitivity <LEVEL>       low | medium | high | paranoid
      --dry-run                   Log detections without modifying traffic
      --vault-key <PASSPHRASE>    Vault encryption passphrase (or MIRAGE_VAULT_KEY env)
      --vault-path <PATH>         Vault file path [default: ./mirage-vault.enc]
      --vault-flush-threshold <N> Auto-flush after N new mappings [default: 50]
      --setup                     Auto-configure installed LLM tools
      --uninstall                 Remove mirage configuration from all tools
      --no-update-check           Disable startup version check
      --log-level <LEVEL>         trace | debug | info | warn | error [default: info]
  -h, --help                      Print help
  -V, --version                   Print version
```

Set `MIRAGE_NO_UPDATE_CHECK=1` to disable update checks globally.

## How it compares

| | mirage-proxy | PasteGuard | LLM Guard | LiteLLM+Presidio |
|---|---|---|---|---|
| Install | `cargo install` | Docker + npm | pip + models | pip + Docker + spaCy |
| Binary size | ~5MB | ~500MB+ | ~2GB+ | ~500MB+ |
| Overhead | <1ms | 10-50ms | 50-200ms | 10-50ms |
| Substitution | Plausible fakes | `[[PERSON_1]]` tokens | `[REDACTED]` | `<PERSON>` tokens |
| LLM knows? | No | Yes | Yes | Yes |
| Session-aware | Yes | No | No | No |
| Encrypted vault | Yes | No | No | No |
| Rehydration | Yes | Yes | No | Partial |
| Streaming | Yes | Yes | No | Partial |
| Dedup | Yes | No | No | No |
| Auto-setup | Yes | No | No | No |
| OpenClaw native | **Yes** | No | No | No |

The key difference: other tools use **visible tokens** that tell the LLM data was removed. The LLM adapts its behavior — it might refuse to write code involving `[[PERSON_1]]`, or generate awkward workarounds. Mirage's fakes are **invisible** — the LLM processes the request normally because it looks normal.

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────┐     ┌──────────────┐
│  LLM Client │────▶│              mirage-proxy                │────▶│ LLM Provider │
│ (Claude Code│     │                                         │     │ (Anthropic,  │
│  Cursor,    │◀────│  Request:  detect PII → fake → forward  │◀────│  OpenAI,     │
│  Codex)     │     │  Response: detect fakes → rehydrate     │     │  etc.)       │
└─────────────┘     │                                         │     └──────────────┘
                    │  ┌─────────┐ ┌────────┐ ┌───────────┐  │
                    │  │Redactor │ │ Faker  │ │  Session   │  │
                    │  │(detect) │ │(fakes) │ │ (mapping)  │  │
                    │  └─────────┘ └────────┘ └───────────┘  │
                    │  ┌─────────┐ ┌────────┐ ┌───────────┐  │
                    │  │ Audit   │ │ Vault  │ │  Config    │  │
                    │  │ (log)   │ │(crypt) │ │  (rules)   │  │
                    │  └─────────┘ └────────┘ └───────────┘  │
                    └─────────────────────────────────────────┘
```

**Request path:** Client → Mirage parses JSON → detects PII via regex + entropy → generates format-matching fakes → stores original↔fake mapping in session → forwards redacted request to provider.

**Response path:** Provider responds → Mirage scans for fake values → replaces fakes with originals (rehydration) → returns clean response to client. Works for both regular JSON responses and SSE streams.

## Building from source

```bash
git clone https://github.com/chandika/mirage-proxy
cd mirage-proxy
cargo build --release
# Binary at target/release/mirage-proxy
```

Requires Rust 1.75+. No other dependencies.

## Detection sources

Pattern detection draws from two open-source databases:
- [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) — prefix-based secret patterns
- [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0) — comprehensive pattern database

Only high-confidence, low-false-positive patterns are included. Generic "keyword near random string" patterns are excluded to avoid breaking legitimate code.

## Known limitations

- **Streaming chunk boundaries** — rehydration is per-chunk. A fake value split across two SSE events won't be caught, causing occasional display glitches in clients like Claude Code. Fix: small cross-boundary buffer (planned).
- **Vault key derivation** — currently raw SHA-256. Should be argon2 or scrypt. Works, but not best practice for passphrase-derived keys. On the roadmap.
- **Detection is regex + entropy only** — no NLP/NER. Won't catch secrets described in natural language ("my key starts with AKIA...") or unusual formats.
- **Rehydration false positives** — if the LLM independently generates text matching a fake value, it gets swapped. Rare in practice but theoretically possible.
- **No Windows binary** in current release (Linux + macOS only).

## Roadmap

- [x] Pattern + entropy detection (11 PII types)
- [x] Invisible plausible fake substitution
- [x] Session-scoped consistency with dedup
- [x] Encrypted vault persistence (AES-256-GCM)
- [x] SSE streaming rehydration
- [x] Audit log + dry-run mode
- [x] YAML config with sensitivity levels
- [x] Auto-setup for Claude Code, Cursor, Codex, Aider
- [x] Live TUI with in-place stats
- [x] International phone number support
- [x] Extended secret patterns (Gitleaks + secrets-patterns-db)
- [x] Multi-provider routing (28+ providers, auto-detect)
- [x] ChatGPT account auth support (Codex CLI with Plus/Pro/Team)
- [x] zstd/gzip compressed body handling
- [x] Homebrew distribution (auto-updated formula on release)
- [x] Pre-built binaries for macOS, Linux, Windows
- [x] **Native OpenClaw integration (ClawdHub skill)**
- [x] Binary SHA256 verification in installer
- [ ] Cross-boundary buffer for streaming rehydration
- [ ] Argon2/scrypt vault key derivation
- [ ] Custom pattern definitions in config
- [ ] Allowlist/blocklist glob matching
- [ ] Optional ONNX NER for name/organization detection
- [ ] Route mode (sensitive requests → local model)
- [ ] npm / Scoop distribution

## License

MIT

## Credits

Built by [@chandika](https://x.com/chandika). Born from the frustration of watching coding agents send API keys to the cloud.

Pattern detection inspired by [Gitleaks](https://github.com/gitleaks/gitleaks) and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db).
