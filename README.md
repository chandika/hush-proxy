# mirage-proxy

**Invisible sensitive data filter for LLM APIs.** Single Rust binary, sub-millisecond overhead.

**Now a native [OpenClaw](https://openclaw.ai) provider — install the skill in one command. [↓ Jump to OpenClaw](#openclaw-integration)**

Your coding agent reads your `.env`, your codebase, your credentials — and sends all of it to the cloud. Mirage sits between your client and the provider, silently replacing sensitive data with plausible fakes. The LLM never knows. Your secrets never leave.

```
You:     "Deploy key is AKIAHOV29GNU18FMT07E, email chris.harris@gmail.com"
         ↓
Mirage:  "Deploy key is AKIA7ELSZ6DKRY5CJQX4, email robin.thomas1234@aol.com"
         ↓
Provider: (sees only fake data, responds normally)
         ↓
Mirage:  (swaps fakes back to originals in the response)
         ↓
You:     "Done! I've drafted the deploy script for chris.harris@gmail.com"
```

No `[REDACTED]`. No `[[PERSON_1]]`. The provider sees a completely normal request with completely fake data. Responses are rehydrated transparently.

## OpenClaw integration

Mirage is a **first-class OpenClaw provider**. If you're running [OpenClaw](https://openclaw.ai), install the skill from [ClawdHub](https://clawdhub.com) and every message your agent sends to Anthropic, OpenAI, or any other provider passes through Mirage first — automatically, with no extra configuration.

```bash
# Install the mirage-proxy skill from ClawdHub
clawdhub install mirage-proxy
```

The skill handles everything:

- **Auto-start** — Mirage launches on container boot as a sidecar process
- **Provider registration** — Registers `mirage-anthropic` as a custom provider routing through `localhost:8686`, with ready-to-use model aliases (`mirage-sonnet`, `mirage-haiku`, `mirage-opus`)
- **Health monitoring** — Heartbeat checks restart Mirage if it dies on session compaction or restart
- **Zero config** — Your existing OpenClaw sessions route through Mirage without touching a settings file

Your agent's full context — codebase, memory files, tool outputs — gets filtered on every turn before it hits the provider. Secrets that were already in your `.env` or workspace files never leave clean.

To use a miraged model in OpenClaw:

```bash
# In any session: switch to a filtered provider
/model mirage-sonnet
# or set it as default in your gateway config:
# default_model: mirage-anthropic/claude-sonnet-4-6
```

The `mirage-anthropic/*` aliases behave identically to the direct Anthropic models — same capabilities, same latency profile, invisible filtering layer in between.

> **Why this matters for OpenClaw users:** OpenClaw agents read your entire workspace — MEMORY.md, config files, daily notes, project repos. That's a lot of sensitive surface area hitting cloud APIs on every heartbeat. Mirage closes that gap without changing how your agent works.

---

## Why this matters

On Feb 14, 2026, a critical vulnerability ([CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)) was disclosed where Claude Code could be tricked into exfiltrating API keys via prompt injection. The same week, a [Reddit post](https://www.reddit.com/r/ClaudeAI/comments/1r186gl/my_agent_stole_my_api_keys/) hit 1.7K upvotes: "My agent stole my API keys." And Anthropic's own [safety report](https://www-cdn.anthropic.com/f21d93f21602ead5cdbecb8c8e1c765759d9e232.pdf) for Opus 4.6 found the model "aggressively acquired authentication tokens" and "sent unauthorized emails without human permission" during testing.

Every LLM coding tool — Claude Code, Codex, Cursor, Aider, Continue — sends your full codebase to the cloud. If there's a secret in your repo, it's in someone's training data. Mirage fixes this at the network layer, no code changes required.

## Install

```bash
# Homebrew (macOS & Linux)
brew install chandika/tap/mirage-proxy
# If a new tag was just released:
brew update && brew upgrade mirage-proxy

# Scoop (Windows)
scoop bucket add chandika https://github.com/chandika/scoop-bucket
scoop install mirage-proxy

# Pre-built binaries (macOS, Linux, Windows)
# → https://github.com/chandika/mirage-proxy/releases

# Build from source
cargo install --git https://github.com/chandika/mirage-proxy
```

Release details: [`docs/releasing.md`](docs/releasing.md)

## Quick start

### Auto-setup (recommended)

```bash
mirage-proxy --setup
```

Scans for installed LLM tools (Claude Code, Cursor, Codex, Aider) and configures them to route through Mirage automatically. Edits config files, sets environment variables, done.

To undo: `mirage-proxy --uninstall`

### Manual setup

```bash
# 1. Start mirage, pointing at your provider
mirage-proxy --target https://api.anthropic.com

# 2. Point your tool at mirage (localhost:8686)
export ANTHROPIC_BASE_URL=http://localhost:8686
```

### Per-tool examples

**Claude Code:**
```bash
mirage-proxy --target https://api.anthropic.com
# Auto-configured by --setup, or manually:
# ~/.claude/settings.json → { "env": { "ANTHROPIC_BASE_URL": "http://localhost:8686" } }
```

**Codex / OpenAI:**
```bash
# Multi-provider mode (no --target needed):
mirage-proxy
export OPENAI_BASE_URL=http://localhost:8686

# Or single-provider mode:
mirage-proxy --target https://api.openai.com
export OPENAI_BASE_URL=http://localhost:8686
```

> **Codex CLI with ChatGPT Plus/Pro/Team:** Mirage automatically detects ChatGPT account auth and routes to the correct backend (`chatgpt.com/backend-api/codex/*`). Works with both API key and ChatGPT subscription auth — no extra config needed.

**Cursor / Continue / Aider / OpenCode:**
Point the provider base URL to `http://localhost:8686`. Everything else works as before.

### Multi-provider mode

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
  mirage-proxy v0.3.0
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
| AWS Access Keys | `AKIAHOV29GNU18FMT07E` | Prefix `AKIA`, `ASIA`, `ABIA`, `ACCA` |
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
| Email | `taylor.hall@gmail.com` | `robin.thomas1234@aol.com` |
| Phone (intl) | `+1-570-630-1710` | `+1-533-577-1639` |
| Phone (US) | `(496) 524-1568` | `(459) 471-1497` |
| SSN | `322-58-1426` | `285-95-1355` |
| Credit Card | `4345 6789 0123 4567` | `4012 3456 7890 1234` |
| IP Address | `10.0.1.42` | `172.18.3.97` |

### How fakes work

Every fake **matches the format and length** of the original:
- An email becomes a different plausible email with a matching-length domain
- An AWS key becomes a different valid-format AWS key
- A phone number keeps its country code and formatting
- A credit card keeps its issuer prefix and passes Luhn validation

**Session consistency:** Within a conversation, `taylor.hall@gmail.com` always maps to the same fake. The LLM's context stays coherent. Different conversations get different fakes.

## Configuration

Works with zero config. For fine-tuning, create `mirage.yaml`:

```yaml
target: "https://api.anthropic.com"
port: 8686
bind: "127.0.0.1"
sensitivity: medium   # low | medium | high | paranoid

rules:
  # Always redact — LLM never needs the real value
  always_redact:
    - SSN
    - CREDIT_CARD
    - PRIVATE_KEY
    - AWS_KEY
    - GITHUB_TOKEN
    - API_KEY
    - BEARER_TOKEN

  # Replace with plausible fakes
  mask:
    - EMAIL
    - PHONE

  # Log but don't modify (too context-dependent)
  warn_only:
    - IP_ADDRESS
    - CONNECTION_STRING
    - SECRET

# Never redact these patterns
allowlist:
  - "192.168.1.*"
  - "sk-test-*"
  - "localhost"

audit:
  enabled: true
  path: "./mirage-audit.jsonl"
  log_values: false     # true = log original values (for debugging only!)

dry_run: false

update_check:
  enabled: true
  timeout_ms: 1200      # network timeout (check runs in background)
```

Update results are cached for 24h to avoid checking on every startup.

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
# With passphrase
mirage-proxy --target https://api.anthropic.com --vault-key "my-passphrase"

# Via environment variable
MIRAGE_VAULT_KEY="my-passphrase" mirage-proxy --target https://api.anthropic.com
```

The vault file (`mirage-vault.enc`) uses AES-256-GCM encryption. Without the passphrase, it's random bytes. Mappings are scoped per session.

Without `--vault-key`, mappings live in memory only and reset on restart.

## Dry run

See what would be caught without modifying traffic:

```bash
mirage-proxy --target https://api.anthropic.com --dry-run
```

Requests pass through unmodified. Detections are still logged to the audit file and shown in the live display. Use this to verify detection accuracy before going live.

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

Full SSE streaming support. Mirage handles `text/event-stream` responses from providers (Claude, OpenAI, etc.), rehydrating fakes in real-time as chunks arrive. No buffering delays.

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
- [ ] Custom pattern definitions in config
- [ ] Allowlist/blocklist glob matching
- [ ] Optional ONNX NER for name/organization detection
- [ ] Route mode (sensitive requests → local model)
- [ ] npm / scoop distribution

## License

MIT

## Credits

Built by [@chandika](https://x.com/chandika). Born from the frustration of watching coding agents send API keys to the cloud.

Pattern detection inspired by [Gitleaks](https://github.com/gitleaks/gitleaks) and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db).
