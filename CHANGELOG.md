# Changelog

## v0.8.2 — 2026-04-30

**Theme: false-positive escape hatches, confidence grading, and an honest scope statement.**

> Built on top of v0.8.1's unified `--setup` installer and the binary/base64 payload-mutation fix.

### Added

- **Shadow mode banner.** `--shadow` is a friendlier alias for `--dry-run`, and the startup banner now prints `mode: SHADOW` in yellow when traffic is not being modified. Recommended for the first 24 hours after install so users can spot false positives before enforcement bites.
- **`mirage-proxy --why <decoy>`** — explain a substitution. Talks to the running daemon's new `/why?decoy=...` endpoint and prints the kind, session id, original length, and md5 fingerprint of the underlying value. The original itself never crosses the wire.
- **`mirage-proxy --flag <decoy>`** — tell the daemon to stop substituting the original behind a decoy. Adds the original to a session-scoped pass-through list and persists a record to `~/.mirage/flags.jsonl`. Backed by the new `/flag?decoy=...` endpoint.
- **JWT / hex-digest / SRI integrity guards** in the entropy pass: values shaped like `header.payload.signature`, sha256/sha512 hex digests, or `sha256-<base64>` / `sha512-<base64>` SRI strings now bypass substitution. Substituting any of these silently broke signature verification, lockfile installs, and CI hashes in v0.7.x.
- **`Confidence` enum (high / medium / low)** on every detection. Vendor-prefixed and structural matches (AWS keys, GitHub tokens, SSN, credit cards, BEGIN PRIVATE KEY, RFC connection strings) are `high`. Useful but ambiguous matches (emails, phones, bearer tokens, generic `sk-...`/`AIza...` keys) are `medium`. Shape-only heuristics (IP addresses, generic high-entropy strings) are `low`.
- **Sensitivity-gated confidence demotion.** At `low` and `medium` sensitivity, `low`-confidence detections demote `Redact`/`Mask` to `Warn` — they are logged but no longer substituted. `high` and `paranoid` sensitivity retain pre-v0.8.2 aggressive behavior. Single biggest false-positive reduction since v0.7.x.
- **Audit log gains a real `confidence` value** (was hardcoded `1.0`). Downstream tooling can now distinguish high-confidence detections from heuristic matches.

### Changed

- README leads with the April 2026 incident landscape (Comment and Control, MCP "by-design" RCE, GitGuardian Sprawl 2026) instead of the older Sonnet 4.6 transparency citation.
- README states explicit scope: localhost-routing tools are protected; `chatgpt.com`, `claude.ai` web, hosted CI agents, and **Claude Cowork** (Apple Virtualization Framework VM) are not. Honest scope replaces ambiguous claims of broad coverage.
- `audit::log` now takes a `confidence: f64` parameter (call sites updated).
- IP addresses no longer substitute at `low`/`medium` sensitivity; they now log a one-line warning. Set `sensitivity: high` or `paranoid` to restore aggressive substitution.
- Roadmap updated: `mirage-action` GitHub Action wrapper (v0.9), `mirage scan-mcp-configs` (v0.9), Comment-and-Control regression fixture (v0.10).

### Internal

- `Faker::lookup_original` and `SessionManager::lookup_decoy` expose decoy → original lookups for the `/why` endpoint.
- `Vault::get_original` and new `Vault::lookup_fake` are no longer test-only.
- `ProxyState` gained a `flagged_originals: Mutex<HashSet<String>>` honored by `smart_redact`.

### Tests

- New unit tests assert JWTs, sha256 digests, and SRI integrity values pass through `detect()` unchanged.
- New unit tests for confidence grading: AWS=High, Email=Medium, HighEntropy=Low.
- 34 tests passing.
