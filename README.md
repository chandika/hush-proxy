# mirage-proxy

**Your LLM agent sees fake secrets & keys. Your real ones never leave your machine.**

![Mirage Proxy demo](assets/mirage-proxy-preview.gif)

```
You:       AKIAQX4BIPW3AHOV29GN     →  Mirage:    AKIADKRY5CJQX4BIPW3A
You:       lee.taylor56789@aol.com   →  Mirage:    chris.hall456@gmail.com
You:       +1-501-369-6183           →  Mirage:    +1-464-316-6112
```

Single binary. Sub-millisecond. Works with every major LLM tool.

If this saves you from one leaked key, **star/watch the repo**.

---

## Why

Anthropic's own [Transparency Hub](https://www.anthropic.com/transparency) (Sonnet 4.6, Feb 2026):

> *"...using credentials to bypass user authentication without permission..."*
> *"We found that Sonnet 4.6 was substantially more likely to engage in over-eager behavior than previous models."*

Agent tools can send sensitive repo context to cloud APIs unless you explicitly block it. If there's a secret in working context, it can transit upstream. Sandboxing doesn't help once it's in context.

Mirage fixes this at the network layer. It sits between your tool and the provider, replaces sensitive data with plausible fakes, and rehydrates the originals in the response. The LLM processes fake data. Your real secrets never transit.

---

## Install (source-first)

If you do not trust prebuilt binaries from an unfamiliar maintainer, use source build.

### Option 1 (recommended): Build from source

```bash
cargo install --locked --git https://github.com/chandika/mirage-proxy
mirage-proxy --service-install
```

Requires Rust 1.75+.

### Option 2: Homebrew / Scoop (convenience)

```bash
brew install chandika/tap/mirage-proxy    # macOS / Linux
mirage-proxy --service-install
```

Windows:

```bash
scoop bucket add chandika https://github.com/chandika/scoop-bucket
scoop install mirage-proxy
mirage-proxy --service-install
```

### Trust & verification

- Source-first: default to `cargo install --locked --git ...` if you do not know the maintainer.
- Install scope: `--service-install` only adds one marked shell block, installs a user-level daemon, and writes backups for changed shell files.
- Rollback: `mirage-proxy --service-uninstall` removes daemon + marked shell block.
- Optional confidence check: run `mirage-proxy --service-install --dry-run` first.

### What it writes to your shell config

`mirage-proxy --service-install` adds one managed block to each target shell file.
On bash/zsh, that block:
- exports provider base URL env vars to `http://127.0.0.1:8686/...`
- defines a `mirage` shell function (`on`, `off`, `status`, `logs`)
- shows a startup status line when the daemon is reachable

It does not rewrite unrelated parts of your `.zshrc`/`.bashrc`.
On reinstall, Mirage removes only its previous marked block and rewrites that block.

Example (bash/zsh block shape):

```bash
# >>> mirage-proxy >>>
export ANTHROPIC_BASE_URL="http://127.0.0.1:8686/anthropic"
export OPENAI_BASE_URL="http://127.0.0.1:8686"
# ...other provider base URLs...
mirage() {
  # on | off | status | logs
}
# <<< mirage-proxy <<<
```

### Why this is safe and easy to undo

- Managed scope only: edits are limited to lines between `# >>> mirage-proxy >>>` and `# <<< mirage-proxy <<<`
- Backup-first for existing files: each changed profile gets a timestamped backup in `~/.mirage/backups/`
- Reversible in one command: `mirage-proxy --service-uninstall` removes daemon + Mirage shell blocks
- Reversible manually: delete only the marked block (or restore a backup file)

### Turn it off

- For current shell only: `mirage off`
- Turn it back on in current shell: `mirage on`
- Fully remove auto-start + shell integration: `mirage-proxy --service-uninstall`

For automation/non-interactive installs:

```bash
mirage-proxy --service-install --yes
```

Done. Mirage runs as a background service and is ON by default for new terminals.

```
🛡️ mirage active (vX.Y.Z)
```

<details>
<summary><b>OpenClaw</b></summary>

Native provider. Install the skill from ClawdHub:

```bash
clawdhub install mirage-proxy
```

Registers `mirage-anthropic` as a provider with aliases: `mirage-sonnet`, `mirage-haiku`, `mirage-opus`. Switch with `/model mirage-sonnet`.

</details>

---

## How it works with your tool

Mirage runs as a background daemon on port 8686. It auto-routes to 28+ providers based on the request path. No per-tool configuration needed — the `--service-install` command sets the right environment variables globally.

| Tool | What gets set | You do |
|---|---|---|
| **Claude Code** | `ANTHROPIC_BASE_URL` | Nothing — just open Claude |
| **Codex** | `OPENAI_BASE_URL` | Nothing — just run Codex |
| **Cursor** | `OPENAI_BASE_URL` | Nothing — just open Cursor |
| **Aider** | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` | Nothing |
| **OpenCode** | `OPENAI_BASE_URL` | Nothing |
| **Continue** | `OPENAI_BASE_URL` | Nothing |
| **Any OpenAI-compatible tool** | `OPENAI_BASE_URL` | Nothing |

### Day-to-day commands

```bash
mirage on       # route this terminal through mirage
mirage off      # this terminal goes direct (daemon stays running)
mirage status   # daemon/filter status + binary/daemon versions
mirage logs     # live tail of redactions and session events
```

### 30-second verification

```bash
mirage status
curl -s http://127.0.0.1:8686/ >/dev/null || true
mirage logs
```

Expected: daemon is running and logs show request/session activity (or unmatched `/` health checks).

### Service model (important)

- `mirage-proxy --service-install` installs a daemon (launchd/systemd/Task Scheduler)
- Daemon files are standard user-level service files:
  - macOS: `~/Library/LaunchAgents/com.mirage-proxy.plist`
  - Linux: `~/.config/systemd/user/mirage-proxy.service`
  - Windows: Task Scheduler job `mirage-proxy`
- Shell integration exports provider base URLs in new terminals
- Shell edits are scoped to a marked block and are reversible
- `mirage on/off` only toggles env vars for the current shell
- `mirage logs` is the easiest way to watch what is being redacted after install

### Dry run

Want to see what mirage catches before committing?

```bash
mirage-proxy --service-install --dry-run
```

Traffic passes through unmodified. Detections are logged. You see exactly what would be filtered.

---

## What it catches

### Secrets & credentials

| Type | Example | How |
|---|---|---|
| AWS keys | `AKIA...` | Prefix match |
| GitHub tokens | `ghp_...`, `ghs_...` | Prefix match |
| OpenAI keys | `sk-proj-...` | Prefix match |
| Google API keys | `AIzaSy...` | Prefix match |
| GitLab, Slack, Stripe | Various prefixes | 129 patterns from Gitleaks + secrets-patterns-db |
| Bearer tokens | `Authorization: Bearer ...` | Header pattern |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` | Structural |
| Connection strings | `postgres://user:pass@host` | URI + credentials |
| Unknown secrets | High-entropy strings | Shannon entropy threshold |

### Personal data

| Type | Original → Fake |
|---|---|
| Email | `lee.taylor56789@aol.com` → `drew.wilson@outlook.com` |
| Phone | `+1-501-369-6183` → `+1-464-316-6112` |
| SSN | `927-83-6041` → `890-30-5970` |
| Credit card | `4890 1234 5678 9012` → `4789 0123 4567 8901` |
| IP address | `10.0.1.42` → `172.18.3.97` |

Every fake matches the **format and length** of the original. An AWS key becomes a different valid-format AWS key. A credit card keeps its issuer prefix and passes Luhn. Within a conversation, the same value always maps to the same fake (session consistency).

---

## How it actually works

### Request path
```
Your tool → mirage-proxy → Provider API
```
1. Tool sends request to `localhost:8686/anthropic/v1/messages`
2. Mirage parses the JSON body
3. Detects secrets via 129 regex patterns + entropy analysis
4. Generates format-matching fakes
5. Stores original↔fake mapping in session
6. Forwards redacted request to `api.anthropic.com`

### Response path
```
Provider API → mirage-proxy → Your tool
```
1. Provider responds (JSON or SSE stream)
2. Mirage scans for fake values
3. Replaces fakes with originals (rehydration)
4. Returns clean response to your tool

### Why fakes, not [REDACTED]?

Other tools use visible tokens: `[REDACTED]`, `[[PERSON_1]]`, `<PHONE_NUMBER>`. The model **knows** data was removed. It adapts — refusing to write code, generating workarounds, asking for the missing data.

Mirage's fakes are **invisible**. The model processes the request normally because it looks normal. This is an architectural difference, not a feature toggle.

### Architecture

```
┌─────────────┐     ┌───────────────────────────────┐     ┌──────────────┐
│  Your tool   │────▶│         mirage-proxy          │────▶│   Provider   │
│             │◀────│                               │◀────│              │
└─────────────┘     │  detect → fake → forward      │     └──────────────┘
                    │  detect fakes → rehydrate     │
                    │                               │
                    │  Sessions · Vault · Audit log  │
                    └───────────────────────────────┘
```

---

## Configuration

Works with zero config. For fine-tuning, create `~/.config/mirage/mirage.yaml`:

```yaml
sensitivity: medium   # low | medium | high | paranoid
dry_run: false

# Skip filtering for specific providers (e.g. TLS fingerprint issues)
bypass:
  - "generativelanguage.googleapis.com"

rules:
  always_redact: [SSN, CREDIT_CARD, PRIVATE_KEY, AWS_KEY, GITHUB_TOKEN, API_KEY, BEARER_TOKEN]
  mask: [EMAIL, PHONE]
  warn_only: [IP_ADDRESS]

audit:
  enabled: true
  path: "./mirage-audit.jsonl"
  log_values: false   # true = log originals (debugging only)
```

| Sensitivity | What gets filtered |
|---|---|
| `low` | Secrets & credentials only |
| `medium` | Secrets + PII (email, phone) — **default** |
| `high` | Everything including warn-only categories |
| `paranoid` | All detected patterns regardless of rules |

### Encrypted vault

Persist fake↔original mappings across restarts:

```bash
MIRAGE_VAULT_KEY="my-passphrase" mirage-proxy --service-install
```

AES-256-GCM encryption. Argon2id key derivation. Without the passphrase, the vault file is random bytes.

---

## Privacy & trust boundaries

- No external telemetry pipeline in mirage-proxy itself.
- Runs locally and proxies only to your configured upstream provider endpoints.
- Audit logging is local-file only and configurable (`log_values: false` by default).
- `--dry-run` shows detections without modifying traffic.

## Comparison

| | mirage-proxy | PasteGuard | LLM Guard | LiteLLM+Presidio |
|---|---|---|---|---|
| **Install** | `brew install` | Docker + npm | pip + models | pip + Docker + spaCy |
| **Size** | ~5MB | ~500MB+ | ~2GB+ | ~500MB+ |
| **Overhead** | <1ms | 10-50ms | 50-200ms | 10-50ms |
| **Method** | Plausible fakes | `[[PERSON_1]]` | `[REDACTED]` | `<PERSON>` |
| **LLM knows?** | No | Yes | Yes | Yes |
| **Session-aware** | ✓ | ✗ | ✗ | ✗ |
| **Streaming** | ✓ | ✓ | ✗ | Partial |
| **Encrypted vault** | ✓ | ✗ | ✗ | ✗ |
| **Auto-setup** | ✓ | ✗ | ✗ | ✗ |

---

## Known limitations

- **Regex + entropy only** — no NLP/NER. Won't catch secrets described in natural language.
- **Streaming boundaries** — 128-byte overlap buffer handles most cases, but very long fake values split exactly at a chunk boundary can slip through.
- **Signed thinking blocks are immutable** — Anthropic validates signatures on extended thinking payloads. Mirage intentionally skips modifying signed thinking blocks.
- **Compressed responses are handled safely** — Mirage now decompresses → rehydrates → recompresses. If decompression/recompression fails, it passes through original bytes to avoid corrupting streams.
- **Google bot detection** — Google's APIs use TLS fingerprinting. Mirage's `reqwest`/`rustls` fingerprint can trigger bot checks. Use the `bypass` config for Google providers.

---

## Troubleshooting

### `Invalid signature in thinking block` (Claude Code)

Use latest mirage version. Mirage skips signed Anthropic thinking blocks now. If you still see this:

```bash
mirage-proxy --service-uninstall
mirage-proxy --service-install
mirage status
```

### `Decompression error: ZlibError`

Use latest mirage version. Responses are now decompressed/rehydrated/recompressed safely. If it persists, collect raw logs:

```bash
mirage logs
# or full logs:
tail -f ~/.mirage/mirage-proxy.log
```

### Lots of `No provider matched for path: /`

Those are health checks. Harmless.

## CLI reference

```
mirage-proxy [OPTIONS]

  -p, --port <PORT>               Listen port [default: 8686]
  -b, --bind <ADDR>               Bind address [default: 127.0.0.1]
  -c, --config <PATH>             Config file path
      --sensitivity <LEVEL>       low | medium | high | paranoid
      --dry-run                   Log detections without modifying traffic
      --vault-key <PASSPHRASE>    Vault passphrase (or MIRAGE_VAULT_KEY env)
      --service-install           Install background service + shell integration
      --yes                       Skip interactive confirmation prompts
      --service-uninstall         Remove service + shell integration
      --service-status            Show daemon and filter status
      --list-providers            Show all 28+ built-in provider routes
      --no-update-check           Skip version check on startup
  -h, --help
  -V, --version
```

---

## Roadmap

- [x] 129 secret patterns (Gitleaks + secrets-patterns-db)
- [x] Plausible fake substitution with session consistency
- [x] Encrypted vault (AES-256-GCM, Argon2id)
- [x] SSE streaming with cross-chunk boundary buffer
- [x] Multi-provider routing (28+ providers)
- [x] `mirage on/off` — background service + shell toggle
- [x] macOS (launchd), Linux (systemd), Windows (Task Scheduler + PowerShell)
- [x] Native OpenClaw integration (ClawdHub skill)
- [x] Provider bypass list
- [ ] Signed release artifacts + provenance attestation
- [ ] Custom pattern definitions in config
- [ ] Optional ONNX NER for name/organization detection
- [ ] Route mode (sensitive requests → local model)

## License

MIT

## Credits

Built by [@chandika](https://x.com/chandika). Born from watching coding agents send API keys to the cloud.

Detection patterns from [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) (Apache 2.0).
