# mirage-proxy

**Your LLM agent sees fake secrets. Your real ones never leave your machine.**

![Mirage Proxy demo](assets/mirage-proxy-preview.gif)

```
You:    AKIAQX4BIPW3AHOV29GN       →  Agent sees:  AKIADKRY5CJQX4BIPW3A
You:    lee.taylor56789@aol.com     →  Agent sees:  chris.hall456@gmail.com
You:    ghp_abc123secrettoken       →  Agent sees:  ghp_xyz789differentkey
```

Single binary. Sub-millisecond. No config needed.

---

## Why

Coding agents send your entire working context to cloud APIs — open files, git history, env vars, shell output. If a secret is anywhere in that context, it transits upstream.

Mirage sits between your tool and the provider. It replaces sensitive data with **plausible fakes** before the request leaves your machine, then rehydrates the originals in the response. The model processes fake data and never knows. Your real secrets stay local.

Other tools use visible tokens like `[REDACTED]` or `[[PERSON_1]]`. The model knows data was removed and adapts — refusing to help, asking for the missing values, generating broken code. Mirage's fakes are invisible. The model behaves normally because the request looks normal.

---

## How it works

```
Your tool → mirage-proxy (detect → replace with fakes) → Provider API
Provider API → mirage-proxy (detect fakes → restore originals) → Your tool
```

One binary. Runs as a background service. Wrappers control which tools route through it.

---

## Install

```bash
brew install chandika/tap/mirage-proxy    # macOS / Linux
```

```bash
scoop bucket add chandika https://github.com/chandika/scoop-bucket
scoop install mirage-proxy               # Windows
```

```bash
cargo install --locked --git https://github.com/chandika/mirage-proxy  # from source
```

---

## Setup

One command installs the background daemon and wrapper scripts for your tools:

```bash
mirage-proxy --setup
```

This scans your PATH for supported tools, installs per-tool wrappers in `~/.mirage/bin/`, and starts the daemon as a background service (launchd on macOS, systemd on Linux, Task Scheduler on Windows).

Then add the wrapper directory to your PATH once:

```bash
export PATH="$HOME/.mirage/bin:$PATH"
# Add to ~/.zshrc or ~/.bashrc to persist
```

That's it. The daemon runs silently in the background. Wrappers decide which tools route through it.

```bash
codex          # → filtered through mirage
codex-direct   # → bypasses mirage (original binary)
```

No global env mutation. Other apps are unaffected. The daemon auto-starts on boot.

To remove everything:

```bash
mirage-proxy --uninstall
```

---

## Supported tools

| Tool | Wrapper installed |
|---|---|
| **codex** | `~/.mirage/bin/codex` |
| **claude** | `~/.mirage/bin/claude` |
| **cursor** | `~/.mirage/bin/cursor` |
| **aider** | `~/.mirage/bin/aider` |
| **opencode** | `~/.mirage/bin/opencode` |

Each wrapper is a small shell script that sets only the env vars needed for that tool, finds the real binary, and execs it. Nothing else changes.

---

## OpenClaw

Native integration. Install the skill:

```bash
clawdhub install mirage-proxy
```

Registers `mirage-anthropic` as a provider. Switch to a miraged model with `/model mirage-sonnet` (or `mirage-haiku`, `mirage-opus`). All traffic through that session is filtered — no wrapper needed.

---

## Verification

```bash
mirage status   # daemon running? filter active?
mirage logs     # live tail of redactions
```

---

## What it catches

### Secrets & credentials

| Type | Detection method |
|---|---|
| AWS keys (`AKIA...`) | Prefix match |
| GitHub tokens (`ghp_`, `ghs_`, `github_pat_`) | Prefix match |
| OpenAI keys (`sk-proj-...`) | Prefix match |
| Google API keys (`AIzaSy...`) | Prefix match |
| GitLab, Slack, Stripe, 50+ others | 129 patterns from Gitleaks + secrets-patterns-db |
| Bearer tokens | Header pattern |
| Private keys (`-----BEGIN RSA...`) | Structural |
| Connection strings (`postgres://user:pass@host`) | URI + credentials |
| Unknown high-entropy strings | Shannon entropy threshold |

### Personal data

| Type | Original → Fake |
|---|---|
| Email | `lee.taylor@aol.com` → `chris.hall@gmail.com` |
| Phone | `+1-501-369-6183` → `+1-464-316-6112` |
| SSN | `927-83-6041` → `890-30-5970` |
| Credit card | `4890 1234 5678 9012` → `4789 0123 4567 8901` |
| IP address | `10.0.1.42` → `172.18.3.97` |

Every fake matches the **format and length** of the original. An AWS key becomes a different valid-format AWS key. A credit card keeps its issuer prefix and passes Luhn. Within a session, the same value always maps to the same fake (session consistency).

---

## Trust & privacy

- **No telemetry.** No external reporting pipeline. No analytics.
- **Local only.** Mirage proxies only to your configured upstream provider endpoints.
- **Auditable.** Audit logging writes to a local file. `log_values: false` by default.
- **Dry-run mode.** Log what would be filtered without modifying traffic: `mirage-proxy --dry-run`
- **Encrypted vault.** Persist fake↔original mappings across restarts with AES-256-GCM + Argon2id key derivation: `MIRAGE_VAULT_KEY="passphrase" mirage-proxy --setup`

---

## Comparison

| | mirage-proxy | PasteGuard | LLM Guard | LiteLLM+Presidio |
|---|---|---|---|---|
| **Install** | `brew install` | Docker + npm | pip + models | pip + Docker + spaCy |
| **Size** | ~5MB | ~500MB+ | ~2GB+ | ~500MB+ |
| **Overhead** | <1ms | 10–50ms | 50–200ms | 10–50ms |
| **Replacement method** | Plausible fakes | `[[PERSON_1]]` | `[REDACTED]` | `<PERSON>` |
| **LLM knows data was removed?** | No | Yes | Yes | Yes |
| **Session-consistent fakes** | ✓ | ✗ | ✗ | ✗ |
| **Streaming (SSE)** | ✓ | ✓ | ✗ | Partial |
| **Encrypted vault** | ✓ | ✗ | ✗ | ✗ |

---

## Configuration

Zero config needed. For fine-tuning, create `~/.config/mirage/mirage.yaml`:

```yaml
sensitivity: medium   # low | medium | high | paranoid

bypass:
  - "generativelanguage.googleapis.com"  # skip Google (TLS fingerprint issues)

rules:
  always_redact: [SSN, CREDIT_CARD, PRIVATE_KEY, AWS_KEY, GITHUB_TOKEN]
  mask: [EMAIL, PHONE]
  warn_only: [IP_ADDRESS]

audit:
  enabled: true
  path: "./mirage-audit.jsonl"
  log_values: false
```

| Sensitivity | What gets filtered |
|---|---|
| `low` | Secrets & credentials only |
| `medium` | Secrets + PII (email, phone) — **default** |
| `high` | Everything including warn-only |
| `paranoid` | All detected patterns |

---

## Known limitations

- **Regex + entropy only** — no NLP/NER. Won't catch secrets described in natural language ("my API key is abc123").
- **Streaming edge case** — 128-byte boundary buffer handles most splits, but a fake value landing exactly at a chunk boundary can slip through.
- **Signed thinking blocks** — Anthropic validates signatures on extended thinking payloads. Mirage intentionally skips modifying these.
- **Google TLS fingerprinting** — Google's APIs can detect Mirage's `reqwest`/`rustls` fingerprint. Use `bypass: ["generativelanguage.googleapis.com"]` in config.

---

## CLI reference

```
mirage-proxy [OPTIONS]

  --setup                     Install wrappers + daemon (recommended)
  --uninstall                 Remove everything: wrappers + daemon
  --wrapper-install           Install wrappers only
  --wrapper-uninstall         Remove wrappers only
  --service-install           Install daemon only + shell integration
  --service-uninstall         Remove daemon + shell integration
  --service-status            Show daemon status
  -p, --port <PORT>           Listen port [default: 8686]
  -b, --bind <ADDR>           Bind address [default: 127.0.0.1]
  -c, --config <PATH>         Config file path
      --sensitivity <LEVEL>   low | medium | high | paranoid
      --dry-run               Log detections without modifying traffic
      --vault-key <PHRASE>    Vault passphrase (or MIRAGE_VAULT_KEY env)
      --list-providers        Show all 28+ built-in provider routes
      --yes                   Skip interactive confirmation prompts
      --no-update-check       Skip version check on startup
  -h, --help
  -V, --version
```

Day-to-day shell commands (available after `--service-install`):

```bash
mirage status   # daemon running? filter on?
mirage logs     # live tail of detections
mirage on       # route this terminal through mirage
mirage off      # this terminal goes direct (daemon keeps running)
```

---

## Roadmap

- [x] 129 secret patterns (Gitleaks + secrets-patterns-db)
- [x] Plausible fake substitution with session consistency
- [x] Encrypted vault (AES-256-GCM, Argon2id)
- [x] SSE streaming with cross-chunk boundary buffer
- [x] Multi-provider routing (28+ providers)
- [x] macOS (launchd), Linux (systemd), Windows (Task Scheduler)
- [x] Native OpenClaw integration (ClawdHub skill)
- [x] Provider bypass list
- [x] `--setup`: unified installer (wrappers + daemon in one step)
- [ ] Signed release artifacts + provenance attestation
- [ ] Custom pattern definitions in config
- [ ] Optional ONNX NER for name/organization detection
- [ ] Route mode: send sensitive requests to a local model instead

---

## License

MIT

Built by [@chandika](https://x.com/chandika). Born from watching coding agents send API keys to the cloud.

Detection patterns from [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0).
