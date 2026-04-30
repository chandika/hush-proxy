# mirage-proxy

**Your local AI coding agent sees fake secrets. Your real ones never leave your machine.**

![Mirage Proxy demo](assets/mirage-proxy-preview.gif)

```
You:    AKIAQX4BIPW3AHOV29GN       →  Agent sees:  AKIADKRY5CJQX4BIPW3A
You:    lee.taylor56789@aol.com     →  Agent sees:  chris.hall456@gmail.com
You:    ghp_abc123secrettoken       →  Agent sees:  ghp_xyz789differentkey
```

Single binary. Sub-millisecond. No config needed. Works with Claude Code, Cursor, Cline, Aider, Codex CLI, Continue.dev, and any other tool that reads your filesystem and routes through a configurable base URL.

---

## Why now

In April 2026 alone:

- **"Comment and Control"** — a single GitHub-comment prompt injection hijacked Claude Code, Gemini CLI, and Copilot Agent **simultaneously** and exfiltrated their API keys plus `GITHUB_TOKEN`. Anthropic rated it CVSS 9.4. Combined bug bounty paid: $1,937. No CVE filed. ([SecurityWeek](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/), [The Register](https://www.theregister.com/2026/04/15/claude_gemini_copilot_agents_hijacked/))
- **MCP "by-design" RCE** — OX Security disclosed an STDIO transport flaw in 200K MCP servers, 150M downloads. Anthropic declined to patch and called it "expected behavior." ([TheHackerNews](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html))
- **GitGuardian State of Secrets Sprawl 2026** — 24,008 secrets found in public MCP config files; 2,117 confirmed live. AI-credential leaks up 81% YoY. ([GitGuardian](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/))

Every adjacent fix — Cursor 2.5 sandboxing, Codex's egress allowlist, GitGuardian's scanners — treats the agent process as the trust boundary. **None of them stop secrets reaching the model in the first place.**

Mirage is data-layer defense. It sits between your local tool and the cloud LLM, substitutes plausible fakes for real secrets *before* egress, and rehydrates the originals in the response. If a Comment-and-Control payload runs against an agent behind Mirage, the attacker walks away with a key that doesn't open anything.

---

## What this does and does not protect

Mirage is a **localhost proxy**. It only sees traffic that passes through `127.0.0.1:8686`.

| Surface | Protected? |
|---|---|
| Claude Code CLI, Cursor, Cline, Codex CLI, Aider, Continue.dev, OpenClaw, any SDK with a configurable base URL | ✅ Yes |
| GitHub Action runners running Claude Code / Gemini CLI / Codex (with `mirage-action`, planned v0.9) | ⚠️ Roadmap |
| chatgpt.com web, claude.ai web, Claude Desktop, JetBrains AI, Copilot Chat (IDE) | ❌ No — browser/cloud bypasses localhost |
| Claude Cowork (runs in an Apple Virtualization Framework VM with its own network namespace) | ❌ No — VM egress doesn't traverse host loopback |
| Pasting code into a web UI by hand | ❌ No — different threat model; consider `mirage-clipboard` (planned) |

If your team uses local agentic CLIs and you want a layer the protocol owner cannot revoke, this is the tool. If your team uses hosted UIs, the threat model is different and so is the answer.

Why fakes, not `[REDACTED]`? Other tools use visible tokens like `[REDACTED]` or `[[PERSON_1]]`. The model knows data was removed and adapts — refusing to help, asking for the missing values, generating broken code. Mirage's fakes are invisible. The model behaves normally because the request looks normal.

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

```bash
curl -s http://127.0.0.1:8686/healthz   # liveness check
```

### Shadow mode (recommended for the first 24 hours)

Want to see what mirage catches before it changes a single byte?

```bash
mirage-proxy --setup --shadow
```

Traffic passes through unmodified. Detections are logged with a `SHADOW` banner so you can spot false positives, vet the substitutions on real workloads, and only enforce when you trust it. `--shadow` is an alias for `--dry-run`.

```
  mirage-proxy v0.8.2
  ─────────────────────────────────────
  listen:  http://127.0.0.1:8686
  target:  multi-provider (auto-route)
  mode:    SHADOW (medium sensitivity) — detections logged, traffic not modified
```

To switch to enforcement once you trust it:

```bash
mirage-proxy --uninstall
mirage-proxy --setup
```

### When mirage substitutes the wrong thing

Two commands handle false positives. Both talk to the running daemon — no restart needed.

**`mirage-proxy --why <decoy>`** — explain a substitution. Useful when something downstream broke and you want to know what mirage did:

```
$ mirage-proxy --why chris.hall456@gmail.com

  mirage why chris.hall456@gmail.com
  ─────────────────────────────────────
  session:  claude-sonnet-4-6
  length:   24 chars
  md5:      a8f3...

  to forgive this substitution, run:
    mirage-proxy --flag 'chris.hall456@gmail.com'
```

**`mirage-proxy --flag <decoy>`** — tell mirage to stop substituting the underlying value. Persists to `~/.mirage/flags.jsonl`. Session-scoped: re-applied flags take effect after a daemon restart in v0.8.x.

```
$ mirage-proxy --flag chris.hall456@gmail.com

  mirage flag chris.hall456@gmail.com
  ─────────────────────────────────────
  ✓ flagged. mirage will pass this value through unchanged.
  scope: this daemon process; persisted to ~/.mirage/flags.jsonl
```

### What mirage refuses to substitute (false-positive guards, v0.8.2)

Three content shapes that cost the most time in earlier versions are now hard-skipped:

- **JWTs** (`header.payload.signature`) — substituting any segment breaks signature verification
- **Hex digests** (sha256, sha512) — break lockfile installs and CI hashes
- **SRI integrity values** (`sha256-...`, `sha512-...`) — break npm/pnpm package-lock installs

Anthropic-signed thinking blocks, Codex `encrypted_content` envelopes, and binary/multipart request payloads are also skipped (existing behavior, retained).
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

| Sensitivity | What gets substituted | Low-confidence detections (IPs, generic entropy) |
|---|---|---|
| `low` | High-confidence vendor-prefixed secrets only (AWS, GitHub, etc.) | Warn-only |
| `medium` (default) | High + medium-confidence (emails, phones, generic `sk-`/`AIza` keys) | Warn-only |
| `high` | Everything including warn-only categories | Substituted |
| `paranoid` | All detected patterns regardless of rules | Substituted |

**Confidence grading (v0.8.2)**: every detection carries a confidence score. Vendor-prefixed and structural matches (AWS keys, GitHub tokens, SSNs, BEGIN PRIVATE KEY, RFC connection strings) are `high`. Emails, phones, and generic API keys are `medium`. IPs and unbounded high-entropy strings are `low` — these used to silently substitute at default sensitivity and were a frequent false-positive source. They now warn instead. Bump to `high` or `paranoid` if you want the old aggressive behavior.

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

  --setup                         Install wrappers + daemon (recommended)
  --uninstall                     Remove everything: wrappers + daemon
  --wrapper-install               Install wrappers only
  --wrapper-uninstall             Remove wrappers only
  --service-install               Install daemon only + shell integration
  --service-uninstall             Remove daemon + shell integration
  --service-status                Show daemon status
  -p, --port <PORT>               Listen port [default: 8686]
  -b, --bind <ADDR>               Bind address [default: 127.0.0.1]
  -c, --config <PATH>             Config file path
      --sensitivity <LEVEL>       low | medium | high | paranoid
      --shadow                    Pass traffic through unchanged; log substitutions
                                  that would have happened (alias of --dry-run)
      --dry-run                   Same as --shadow
      --why <DECOY>               Ask the running daemon to explain a substitution
      --flag <DECOY>              Ask the running daemon to stop substituting the
                                  original behind a decoy (persists to
                                  ~/.mirage/flags.jsonl)
      --vault-key <PASSPHRASE>    Vault passphrase (or MIRAGE_VAULT_KEY env)
      --list-providers            Show all 28+ built-in provider routes
      --yes                       Skip interactive confirmation prompts
      --no-update-check           Skip version check on startup
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

### HTTP endpoints (on the running daemon)

| Endpoint | Method | Purpose |
|---|---|---|
| `/healthz` | GET | Status + counters |
| `/why?decoy=<value>` | GET | Look up the kind, session, and md5 of the original behind a decoy |
| `/flag?decoy=<value>` | POST | Add the original behind a decoy to the session pass-through list |

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
- [x] **v0.8.2**: shadow mode banner, `--why` / `--flag`, JWT/digest/SRI false-positive guards, confidence grading (high/medium/low) with low-confidence demoted to warn-only at low/medium sensitivity
- [ ] **v0.9**: `mirage-action` GitHub Action wrapper for agentic CI
- [ ] **v0.9**: `mirage scan-mcp-configs` — find leaked secrets in `~/.cursor/mcp.json`, `~/.claude.json`, etc.
- [ ] **v0.10**: Comment-and-Control regression test fixture (replay payload, assert decoy exfil)
- [ ] Signed release artifacts + provenance attestation
- [ ] Custom pattern definitions in config
- [ ] Optional ONNX NER for name/organization detection
- [ ] Route mode: send sensitive requests to a local model instead

---

## License

MIT

Built by [@chandika](https://x.com/chandika). Born from watching coding agents send API keys to the cloud.

Detection patterns from [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0).
