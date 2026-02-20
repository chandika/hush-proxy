# mirage-proxy

A fast, invisible sensitive data filter for LLM APIs. Written in Rust.

Your coding agent reads your `.env`, your codebase, your credentials — and sends all of it to the cloud. Mirage sits between your client and the provider, silently replacing sensitive data with plausible fakes. The LLM never knows. Your secrets never leave.

## How it works

```
You:     "Email sam@acme.com, key is AKIAIOSFODNN7EXAMPLE"
         ↓
Mirage:    "Email jordan.walker3@proton.me, key is AKIAHQ7RN2XK5M3B9Y1T"
         ↓
Provider: (sees only fake data, responds normally)
         ↓
Mirage:    (swaps fakes back to originals)
         ↓
You:     "Done! I've drafted the email to sam@acme.com"
```

No `[REDACTED]`. No `[[PERSON_1]]`. No brackets. The provider sees a completely normal request with completely fake data. Responses are rehydrated transparently.

## Install

```bash
cargo install mirage-proxy
```

Or build from source:

```bash
git clone https://github.com/chandika/mirage-proxy
cd mirage-proxy
cargo build --release
```

## Quick start

```bash
# Point mirage at your LLM provider
mirage-proxy --target https://api.openai.com

# Your client talks to localhost:8686 instead
export OPENAI_BASE_URL=http://localhost:8686
```

### Claude Code

```bash
mirage-proxy --target https://api.anthropic.com
# Set ANTHROPIC_BASE_URL=http://localhost:8686 in your environment
```

### Codex / GPT

```bash
mirage-proxy --target https://api.openai.com
export OPENAI_BASE_URL=http://localhost:8686
```

### Cursor / Continue / Aider / OpenCode

Point the provider base URL to `http://localhost:8686`. Everything else works as before.

## What makes this different

**Invisible substitution.** Most PII tools replace sensitive data with ugly tokens like `[EMAIL_1]` or `<REDACTED>`. The LLM sees these, knows data was removed, and produces worse output. Mirage replaces PII with plausible fakes that match the format and length of the original. The LLM has no idea redaction happened.

**Session-aware consistency.** Within a conversation, the same email always maps to the same fake. Across conversations, the same email maps to different fakes. History messages stay consistent — if `sam@acme.com` became `jordan.walker3@proton.me` in message 1, it stays that way through message 50.

**Encrypted vault.** Mappings persist across restarts in an AES-256-GCM encrypted file. You hold the key. The vault file is useless without it.

**Sub-millisecond overhead.** Pure Rust, pattern-based detection. No ML models, no Docker, no Python, no 500MB spaCy download. A single static binary under 5MB.

## What it catches

### Secrets & credentials
- AWS keys (`AKIA...`)
- GitHub tokens (`ghp_...`, `ghs_...`)
- OpenAI / API keys (`sk-...`, `sk-proj-...`)
- Slack tokens (`xoxb-...`, `xoxp-...`)
- Google API keys (`AIza...`)
- Bearer tokens
- Connection strings (Postgres, MySQL, MongoDB, Redis)
- PEM private keys (RSA, EC, DSA, OpenSSH)
- High-entropy strings (Shannon entropy scanner catches unknown secret formats)

### Personal data
- Email addresses
- Phone numbers (US/international, all common formats)
- Social Security Numbers
- Credit card numbers (Visa, MC, Amex, Discover)
- IP addresses

Every detected value is replaced with a format-matching fake:

| Original | Fake |
|---|---|
| `sam@acme.com` | `jordan.walker3@proton.me` |
| `(555) 123-4567` | `(237) 153-1071` |
| `AKIAIOSFODNN7EXAMPLE` | `AKIAHQ7RN2XK5M3B9Y1T` |
| `sk-proj-abc123def456...` | `sk-proj-hR4kM9nQ2wX7...` |
| `postgres://user:pass@host/db` | `postgres://alex:kR4m9Q2w@db37.internal:5432/app_12` |
| `123-45-6789` | `537-28-4071` |

## Configuration

Mirage works with zero config. For fine-tuning, create a `mirage.yaml`:

```yaml
target: "https://api.openai.com"
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

  # Log but don't touch (too context-dependent)
  warn_only:
    - IP_ADDRESS
    - CONNECTION_STRING
    - SECRET

# Never redact these values
allowlist:
  - "192.168.1.*"
  - "sk-test-*"

audit:
  enabled: true
  path: "./mirage-audit.jsonl"

dry_run: false
```

### Sensitivity levels

| Level | Behavior |
|---|---|
| `low` | Only `always_redact` categories |
| `medium` | `always_redact` + `mask` (default) |
| `high` | Everything including `warn_only` |
| `paranoid` | Redact all detected PII regardless of category |

## Encrypted vault

Mappings persist across restarts so your conversations stay consistent:

```bash
# With vault (encrypted persistence)
mirage-proxy --target https://api.openai.com --vault-key "my-passphrase"

# Or via environment variable
MIRAGE_VAULT_KEY="my-passphrase" mirage-proxy --target https://api.openai.com
```

The vault file (`mirage-vault.enc`) is AES-256-GCM encrypted. Without the passphrase, it's random bytes. Mappings are scoped per conversation session.

Without `--vault-key`, mappings live in memory only and reset on restart.

## Dry run

See what would be redacted without actually changing anything:

```bash
mirage-proxy --target https://api.openai.com --dry-run
```

Requests pass through unmodified. Detections are logged to the audit file. Use this to tune your config before going live.

## Audit log

Every detection is logged to `mirage-audit.jsonl`:

```json
{"timestamp":"2026-02-19T14:30:00Z","kind":"EMAIL","action":"masked","confidence":1.0,"value_hash":"a3b2c1...","context_snippet":"Email sam@... about the deal"}
```

Original values are never logged by default. Enable `audit.log_values: true` only for debugging.

## Streaming

Full SSE streaming support. Mirage handles `text/event-stream` responses from providers, rehydrating fakes in real-time as chunks arrive.

## CLI reference

```
mirage-proxy [OPTIONS]

Options:
  -t, --target <URL>              Target LLM API base URL (required)
  -p, --port <PORT>               Listen port [default: 8686]
  -b, --bind <ADDR>               Bind address [default: 127.0.0.1]
  -c, --config <PATH>             Config file path
      --vault-key <PASSPHRASE>    Vault encryption passphrase (or MIRAGE_VAULT_KEY env)
      --vault-path <PATH>         Vault file path [default: ./mirage-vault.enc]
      --vault-flush-threshold <N> Auto-flush after N new mappings [default: 50]
      --dry-run                   Log detections without redacting
      --sensitivity <LEVEL>       low | medium | high | paranoid
      --log-level <LEVEL>         trace | debug | info | warn | error [default: info]
  -h, --help                      Print help
  -V, --version                   Print version
```

## Why not PasteGuard / LLM Guard / Presidio?

| | mirage-proxy | PasteGuard | LLM Guard | LiteLLM+Presidio |
|---|---|---|---|---|
| Install | `cargo install` | Docker | pip + models | pip + Docker + spaCy |
| Binary size | ~5MB | ~500MB+ | ~2GB+ | ~500MB+ |
| Overhead | <1ms | 10-50ms | 50-200ms | 10-50ms |
| Substitution | Plausible fakes | `[[PERSON_1]]` tokens | `[REDACTED]` | `<PERSON>` tokens |
| LLM knows? | No | Yes | Yes | Yes |
| Session-aware | Yes | No | No | No |
| Encrypted vault | Yes | No | No | No |
| Rehydration | Yes | Yes | No | No |
| Streaming | Yes | Yes | No | Partial |
| Dependencies | None | Node + Presidio | Python + ML models | Python + spaCy + Docker |

## Roadmap

- [x] Pattern + entropy detection
- [x] Invisible plausible fake substitution
- [x] Session-scoped consistency
- [x] Encrypted vault persistence
- [x] Streaming rehydration
- [x] Audit log + dry-run
- [x] YAML config with sensitivity levels
- [ ] Custom pattern definitions
- [ ] Allowlist/blocklist glob matching
- [ ] Optional ONNX NER for name/org detection
- [ ] Multi-provider native format support (Anthropic Messages API)
- [ ] Route mode (sensitive requests → local Ollama)
- [ ] npm/brew/scoop distribution
- [ ] Pre-built binaries for all platforms

## License

MIT
