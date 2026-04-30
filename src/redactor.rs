use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Arc, Mutex};
#[cfg(test)]
use uuid::Uuid;

/// Confidence that a detection is a real secret rather than a false positive.
///
/// - `High`: vendor-prefixed and structurally unambiguous (AWS keys, GitHub tokens,
///   SSNs, credit cards, BEGIN PRIVATE KEY blocks, RFC connection strings).
///   These almost never false-positive — substitute aggressively.
/// - `Medium`: useful PII but ambiguous in arbitrary text (emails, phone numbers,
///   bearer tokens, generic `sk-...`/`AIza...` keys). Substitute by default; can
///   be demoted at low sensitivity.
/// - `Low`: shape-only heuristics (IPs, high-entropy strings). Most likely to
///   false-positive on UUIDs, build hashes, or content fingerprints. At `low`
///   and `medium` sensitivity these now demote to a one-line warning instead
///   of silently substituting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }

    /// Numeric value for the audit log's `confidence` field.
    pub fn score(&self) -> f64 {
        match self {
            Confidence::High => 1.0,
            Confidence::Medium => 0.7,
            Confidence::Low => 0.4,
        }
    }
}

/// A detected PII entity
#[derive(Debug, Clone)]
pub struct PiiEntity {
    pub kind: PiiKind,
    pub pattern_name: Option<String>,
    pub start: usize,
    pub end: usize,
    pub original: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PiiKind {
    Email,
    Phone,
    CreditCard,
    Ssn,
    IpAddress,
    AwsKey,
    GithubToken,
    GenericApiKey,
    BearerToken,
    ConnectionString,
    PrivateKey,
    HighEntropy,
}

impl PiiKind {
    pub fn label(&self) -> &'static str {
        match self {
            PiiKind::Email => "EMAIL",
            PiiKind::Phone => "PHONE",
            PiiKind::CreditCard => "CREDIT_CARD",
            PiiKind::Ssn => "SSN",
            PiiKind::IpAddress => "IP_ADDRESS",
            PiiKind::AwsKey => "AWS_KEY",
            PiiKind::GithubToken => "GITHUB_TOKEN",
            PiiKind::GenericApiKey => "API_KEY",
            PiiKind::BearerToken => "BEARER_TOKEN",
            PiiKind::ConnectionString => "CONNECTION_STRING",
            PiiKind::PrivateKey => "PRIVATE_KEY",
            PiiKind::HighEntropy => "SECRET",
        }
    }

    /// Default confidence for this kind. Used when `detect()` builds a `PiiEntity`.
    pub fn confidence(&self) -> Confidence {
        match self {
            // Vendor-prefixed and structural matches — almost always real.
            PiiKind::AwsKey
            | PiiKind::GithubToken
            | PiiKind::Ssn
            | PiiKind::CreditCard
            | PiiKind::PrivateKey
            | PiiKind::ConnectionString => Confidence::High,
            // Useful but more prone to false-positive in arbitrary text.
            PiiKind::GenericApiKey
            | PiiKind::BearerToken
            | PiiKind::Email
            | PiiKind::Phone => Confidence::Medium,
            // Shape-only heuristics.
            PiiKind::IpAddress | PiiKind::HighEntropy => Confidence::Low,
        }
    }
}

struct PatternDef {
    kind: PiiKind,
    pattern: &'static str,
}

static PATTERN_DEFS: &[PatternDef] = &[
    PatternDef { kind: PiiKind::Email, pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" },
    PatternDef { kind: PiiKind::Phone, pattern: r"\+\d{1,3}[-.\s]?\d[\d\-.\s]{6,14}\d" },
    // US format: require separators, parens, or +1 prefix to avoid matching bare digit strings (timestamps, IDs)
    PatternDef { kind: PiiKind::Phone, pattern: r"(?:\+1[-.\s]?)\d{3}[-.\s]?\d{3}[-.\s]?\d{4}" },
    PatternDef { kind: PiiKind::Phone, pattern: r"\(?\d{3}\)[-.\s]\d{3}[-.\s]?\d{4}" },
    PatternDef { kind: PiiKind::CreditCard, pattern: r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b" },
    PatternDef { kind: PiiKind::Ssn, pattern: r"\b\d{3}-\d{2}-\d{4}\b" },
    PatternDef { kind: PiiKind::IpAddress, pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b" },
    PatternDef { kind: PiiKind::AwsKey, pattern: r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b" },
    PatternDef { kind: PiiKind::GithubToken, pattern: r"\b(?:ghp|ghs|gho|ghu|ghr)_[a-zA-Z0-9]{36,}\b" },
    PatternDef { kind: PiiKind::GenericApiKey, pattern: r"\b(?:sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|xox[boaprs]-[a-zA-Z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b" },
    PatternDef { kind: PiiKind::BearerToken, pattern: r"(?i)Bearer\s+[a-zA-Z0-9._~+/=-]{20,}" },
    PatternDef { kind: PiiKind::ConnectionString, pattern: r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://\S+" },
    PatternDef { kind: PiiKind::PrivateKey, pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----" },
];

static COMPILED_PATTERNS: Lazy<Vec<(PiiKind, Option<&'static str>, Regex)>> = Lazy::new(|| {
    let mut patterns: Vec<(PiiKind, Option<&'static str>, Regex)> = PATTERN_DEFS
        .iter()
        .map(|p| (p.kind.clone(), None, Regex::new(p.pattern).unwrap()))
        .collect();

    // Add extended patterns from Gitleaks + secrets-patterns-db
    for sp in crate::patterns::SECRET_PATTERNS {
        match Regex::new(sp.regex) {
            Ok(re) => patterns.push((sp.kind.clone(), Some(sp.name), re)),
            Err(e) => {
                eprintln!("  ⚠ skipping pattern '{}': {}", sp.name, e);
            }
        }
    }

    patterns
});

/// Shannon entropy of a string
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in s.as_bytes() {
        *freq.entry(b).or_insert(0) += 1;
    }
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

static HIGH_ENTROPY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-zA-Z0-9+/=_-]{32,}").unwrap());

// Shapes that look high-entropy but must never be substituted.
// Substituting any of these breaks downstream verification or hashing.
//
// JWT: three base64url segments separated by dots; the third is a signature.
static JWT_SHAPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$").unwrap()
});
// SHA-256 / SHA-512 hex digests (commonly appear in lockfiles, integrity fields, content hashes).
static HEX_DIGEST_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$").unwrap());
// "sha256-<base64>" / "sha512-<base64>" SRI integrity values.
static SRI_INTEGRITY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^sha(?:256|384|512)-[A-Za-z0-9+/=]{40,}$").unwrap());

/// Returns true if `s` has the shape of a value we must never substitute
/// (JWTs, content hashes, SRI integrity tags). These are the false-positive
/// classes that produced the most user pain in v0.7.x — substituting them
/// silently breaks signature verification, lockfile installs, and CI hashes.
fn is_protected_shape(s: &str) -> bool {
    JWT_SHAPE_RE.is_match(s) || HEX_DIGEST_RE.is_match(s) || SRI_INTEGRITY_RE.is_match(s)
}

/// Session-scoped token map for consistent redaction and rehydration
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TokenMap {
    // original -> (label, index)
    inner: Arc<Mutex<TokenMapInner>>,
}

#[cfg(test)]
#[derive(Debug)]
struct TokenMapInner {
    forward: HashMap<String, String>,  // original -> token
    reverse: HashMap<String, String>,  // token -> original
    counters: HashMap<String, usize>,  // kind_label -> next index
}

#[cfg(test)]
impl TokenMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenMapInner {
                forward: HashMap::new(),
                reverse: HashMap::new(),
                counters: HashMap::new(),
            })),
        }
    }

    /// Get or create a replacement token for an original value
    pub fn get_or_insert(&self, original: &str, kind: &PiiKind) -> String {
        let mut map = self.inner.lock().unwrap();
        if let Some(token) = map.forward.get(original) {
            return token.clone();
        }
        let label = kind.label();
        let counter = map.counters.entry(label.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("[{}_{}_{}]", label, counter, &Uuid::new_v4().to_string()[..8]);
        map.forward.insert(original.to_string(), token.clone());
        map.reverse.insert(token.clone(), original.to_string());
        token
    }

    /// Rehydrate a response by replacing tokens back with originals
    pub fn rehydrate(&self, text: &str) -> String {
        let map = self.inner.lock().unwrap();
        let mut result = text.to_string();
        for (token, original) in &map.reverse {
            result = result.replace(token, original);
        }
        result
    }
}

/// Detect all PII entities in text
pub fn detect(text: &str) -> Vec<PiiEntity> {
    let mut entities = Vec::new();

    // Pattern-based detection
    for (kind, pattern_name, regex) in COMPILED_PATTERNS.iter() {
        for m in regex.find_iter(text) {
            entities.push(PiiEntity {
                kind: kind.clone(),
                pattern_name: pattern_name.map(|s| s.to_string()),
                start: m.start(),
                end: m.end(),
                original: m.as_str().to_string(),
                confidence: kind.confidence(),
            });
        }
    }

    // High-entropy detection (catch unknown secret formats)
    for m in HIGH_ENTROPY_RE.find_iter(text) {
        let s = m.as_str();
        // Skip if already matched by a pattern above
        let already_matched = entities.iter().any(|e| {
            (m.start() >= e.start && m.start() < e.end)
                || (e.start >= m.start() && e.start < m.end())
        });
        if already_matched {
            continue;
        }
        // Protected shapes (JWT, content hashes, SRI integrity) must pass through unmodified.
        // Their high entropy is a feature of their function — substituting breaks verification.
        if is_protected_shape(s) {
            continue;
        }
        if shannon_entropy(s) > 4.5 && s.len() >= 32 {
            entities.push(PiiEntity {
                kind: PiiKind::HighEntropy,
                pattern_name: Some("High-Entropy String".to_string()),
                start: m.start(),
                end: m.end(),
                original: s.to_string(),
                confidence: PiiKind::HighEntropy.confidence(),
            });
        }
    }

    // Strip JWT-shaped vendor matches too: an `sk-...` style match that on closer
    // inspection has the JWT three-segment shape is almost certainly a session
    // token bound to a signature, not a raw API key.
    entities.retain(|e| !is_protected_shape(&e.original));

    // Deduplicate overlapping entities — keep the first (more specific) match
    entities.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut deduped: Vec<PiiEntity> = Vec::new();
    for entity in entities {
        let overlaps = deduped.iter().any(|e| {
            entity.start < e.end && entity.end > e.start
        });
        if !overlaps {
            deduped.push(entity);
        }
    }

    // Sort by start position descending for safe replacement
    deduped.sort_by(|a, b| b.start.cmp(&a.start));
    deduped
}

/// Redact all PII from text using a token map for consistency
#[cfg(test)]
pub fn redact(text: &str, token_map: &TokenMap) -> String {
    let entities = detect(text);
    let mut result = text.to_string();
    for entity in &entities {
        let replacement = token_map.get_or_insert(&entity.original, &entity.kind);
        result.replace_range(entity.start..entity.end, &replacement);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let input = ["Contact john", "@", "example.com for details"].join("");
        let entities = detect(&input);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::Email);
    }

    #[test]
    fn test_phone_detection() {
        let entities = detect("Call me at (555) 123-4567");
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::Phone);
    }

    #[test]
    fn test_ssn_detection() {
        let entities = detect("SSN: 123-45-6789");
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::Ssn);
    }

    #[test]
    fn test_aws_key_detection() {
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
        let input = format!("key: {}", key);
        let entities = detect(&input);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::AwsKey);
    }

    #[test]
    fn test_github_token_detection() {
        let token = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join("");
        let input = format!("token: {}", token);
        let entities = detect(&input);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::GithubToken);
    }

    #[test]
    fn test_openai_key_detection() {
        let key = ["sk-proj-", "abc123def456ghi789jkl012mno"].join("");
        let input = format!("OPENAI_API_KEY={}", key);
        let entities = detect(&input);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::GenericApiKey);
    }

    #[test]
    fn test_connection_string() {
        let conn = ["postgres://", "user:pass", "@", "host:5432/db"].join("");
        let input = format!("DATABASE_URL={}", conn);
        let entities = detect(&input);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, PiiKind::ConnectionString);
    }

    #[test]
    fn test_redact_and_rehydrate() {
        let map = TokenMap::new();
        let email = ["john", "@", "example.com"].join("");
        let input = format!("Email {} and call (555) 123-4567", email);
        let redacted = redact(&input, &map);
        assert!(!redacted.contains(&email));
        assert!(!redacted.contains("(555) 123-4567"));
        let rehydrated = map.rehydrate(&redacted);
        assert_eq!(rehydrated, input);
    }

    #[test]
    fn test_consistent_redaction() {
        let map = TokenMap::new();
        let email = ["john", "@", "example.com"].join("");
        let r1 = redact(&email, &map);
        let r2 = redact(&email, &map);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_high_entropy() {
        let secret = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hI6kL9";
        let entities = detect(secret);
        assert!(entities.iter().any(|e| e.kind == PiiKind::HighEntropy));
    }

    #[test]
    fn jwt_shape_is_not_substituted() {
        // Real-shape JWT (header.payload.signature) — substituting any segment
        // breaks signature verification. Must pass through unchanged.
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let entities = detect(jwt);
        assert!(entities.is_empty(), "JWT shape leaked through: {:?}", entities);
    }

    #[test]
    fn sha256_digest_is_not_substituted() {
        // 64-char hex sha256 — common in lockfiles, integrity fields, container digests.
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let entities = detect(digest);
        assert!(entities.is_empty(), "sha256 leaked through: {:?}", entities);
    }

    #[test]
    fn sri_integrity_is_not_substituted() {
        // npm/pnpm package-lock.json integrity values must remain byte-exact.
        let sri = "sha512-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==";
        let entities = detect(sri);
        assert!(entities.is_empty(), "SRI integrity leaked through: {:?}", entities);
    }

    #[test]
    fn aws_key_is_high_confidence() {
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
        let entities = detect(&key);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].confidence, Confidence::High);
    }

    #[test]
    fn email_is_medium_confidence() {
        let email = ["alice", "@", "example.com"].join("");
        let entities = detect(&email);
        assert!(entities.iter().any(|e| e.kind == PiiKind::Email
            && e.confidence == Confidence::Medium));
    }

    #[test]
    fn high_entropy_is_low_confidence() {
        let s = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hI6kL9";
        let entities = detect(s);
        assert!(entities
            .iter()
            .any(|e| e.kind == PiiKind::HighEntropy && e.confidence == Confidence::Low));
    }
}
