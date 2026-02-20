use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// A detected PII entity
#[derive(Debug, Clone)]
pub struct PiiEntity {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    pub original: String,
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
}

struct PatternDef {
    kind: PiiKind,
    pattern: &'static str,
}

static PATTERN_DEFS: &[PatternDef] = &[
    PatternDef { kind: PiiKind::Email, pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" },
    PatternDef { kind: PiiKind::Phone, pattern: r"\+\d{1,3}[-.\s]?\d[\d\-.\s]{6,14}\d" },
    // US format as separate pattern
    PatternDef { kind: PiiKind::Phone, pattern: r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}" },
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

static COMPILED_PATTERNS: Lazy<Vec<(PiiKind, Regex)>> = Lazy::new(|| {
    let mut patterns: Vec<(PiiKind, Regex)> = PATTERN_DEFS
        .iter()
        .map(|p| (p.kind.clone(), Regex::new(p.pattern).unwrap()))
        .collect();

    // Add extended patterns from Gitleaks + secrets-patterns-db
    for sp in crate::patterns::SECRET_PATTERNS {
        match Regex::new(sp.regex) {
            Ok(re) => patterns.push((sp.kind.clone(), re)),
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

/// Session-scoped token map for consistent redaction and rehydration
#[derive(Debug, Clone)]
pub struct TokenMap {
    // original -> (label, index)
    inner: Arc<Mutex<TokenMapInner>>,
}

#[derive(Debug)]
struct TokenMapInner {
    forward: HashMap<String, String>,  // original -> token
    reverse: HashMap<String, String>,  // token -> original
    counters: HashMap<String, usize>,  // kind_label -> next index
}

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
    for (kind, regex) in COMPILED_PATTERNS.iter() {
        for m in regex.find_iter(text) {
            entities.push(PiiEntity {
                kind: kind.clone(),
                start: m.start(),
                end: m.end(),
                original: m.as_str().to_string(),
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
        if shannon_entropy(s) > 4.5 && s.len() >= 32 {
            entities.push(PiiEntity {
                kind: PiiKind::HighEntropy,
                start: m.start(),
                end: m.end(),
                original: s.to_string(),
            });
        }
    }

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
}
