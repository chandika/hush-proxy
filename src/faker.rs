use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::redactor::PiiKind;
use crate::vault::Vault;

/// Generates plausible fake values that match the original's length and format.
/// The LLM never knows redaction happened — invisible substitution.
/// Consistent within a session — same input always gets same fake.
/// If a vault is provided, mappings persist encrypted at rest.
pub struct Faker {
    maps: Mutex<FakerMaps>,
    vault: Option<Arc<Vault>>,
    session_id: Option<String>,
}

struct FakerMaps {
    forward: HashMap<String, String>,  // original -> fake
    reverse: HashMap<String, String>,  // fake -> original
    counter: usize,
}

impl FakerMaps {
    fn new() -> Self {
        FakerMaps {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            counter: 0,
        }
    }

    fn get_or_insert(&mut self, original: &str, generator: impl Fn(usize, &str) -> String) -> String {
        if let Some(fake) = self.forward.get(original) {
            return fake.clone();
        }
        self.counter += 1;
        let fake = generator(self.counter, original);
        self.forward.insert(original.to_string(), fake.clone());
        self.reverse.insert(fake.clone(), original.to_string());
        fake
    }

    fn contains(&self, original: &str) -> bool {
        self.forward.contains_key(original)
    }

    fn rehydrate(&self, text: &str) -> String {
        let mut result = text.to_string();
        // Sort by length descending to avoid partial replacements
        let mut pairs: Vec<_> = self.reverse.iter().collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (fake, original) in pairs {
            if !should_allow_rehydrate_mapping(fake) {
                continue;
            }

            // For simple token-like strings, only replace at token boundaries.
            // This prevents accidental mid-word rewrites (e.g. "pattern" -> "p<secret>tern").
            if fake.chars().all(is_token_char) {
                result = replace_token_bounded(&result, fake, original);
            } else {
                result = result.replace(fake, original);
            }
        }
        result
    }

}

fn should_allow_rehydrate_mapping(fake: &str) -> bool {
    // Never rehydrate empty/tiny mappings; these are too collision-prone.
    // Real secrets/fakes are substantially longer.
    fake.len() >= 6
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn replace_token_bounded(input: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() || input.is_empty() || !input.contains(needle) {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;

    for (start, _) in input.match_indices(needle) {
        let end = start + needle.len();

        let prev = input[..start].chars().next_back();
        let next = input[end..].chars().next();
        let left_ok = prev.map(|c| !is_token_char(c)).unwrap_or(true);
        let right_ok = next.map(|c| !is_token_char(c)).unwrap_or(true);

        if left_ok && right_ok {
            out.push_str(&input[last..start]);
            out.push_str(replacement);
            last = end;
        }
    }

    out.push_str(&input[last..]);
    out
}

static FAKE_DOMAINS: &[&str] = &[
    "mailbox.org", "proton.me", "fastmail.com", "outlook.com",
    "yahoo.com", "icloud.com", "gmail.com", "hotmail.com",
    "zoho.com", "aol.com", "mail.com", "yandex.com",
];

static FAKE_NAMES: &[&str] = &[
    "alex", "jordan", "taylor", "morgan", "casey", "riley",
    "avery", "quinn", "blake", "drew", "jamie", "robin",
    "sam", "pat", "chris", "lee", "kim", "dana", "jess", "max",
];

static FAKE_SURNAMES: &[&str] = &[
    "miller", "wilson", "moore", "taylor", "anderson", "thomas",
    "jackson", "white", "harris", "martin", "garcia", "clark",
    "lewis", "walker", "hall", "young", "king", "wright",
];

impl Faker {
    pub fn new(vault: Option<Arc<Vault>>, session_id: Option<String>) -> Self {
        // Load existing mappings from vault for this session
        let mut maps = FakerMaps::new();
        if let (Some(ref vault), Some(ref sid)) = (&vault, &session_id) {
            let pairs = vault.get_session_mappings(sid);
            for (original, fake) in pairs {
                maps.forward.insert(original.clone(), fake.clone());
                maps.reverse.insert(fake, original);
                maps.counter += 1;
            }
        }

        Faker {
            maps: Mutex::new(maps),
            vault,
            session_id,
        }
    }

    /// Check if a value has already been seen/mapped in this session
    pub fn is_known(&self, original: &str) -> bool {
        self.maps.lock().unwrap().contains(original)
    }

    /// Generate a plausible fake for any PII kind, matching format and length
    pub fn fake(&self, original: &str, kind: &PiiKind) -> String {
        // Check vault first for persisted mapping
        if let Some(ref vault) = self.vault {
            if let Some(fake) = vault.get_fake(original) {
                // Also cache in memory
                let mut maps = self.maps.lock().unwrap();
                maps.forward.insert(original.to_string(), fake.clone());
                maps.reverse.insert(fake.clone(), original.to_string());
                // Add component-level reverse mappings for better rehydration robustness.
                if matches!(kind, PiiKind::ConnectionString) {
                    add_connection_component_mappings(&mut maps, original, &fake);
                }
                return fake;
            }
        }

        let mut maps = self.maps.lock().unwrap();
        let fake = maps.get_or_insert(original, |n, orig| {
            match kind {
                PiiKind::Email => fake_email(n, orig),
                PiiKind::Phone => fake_phone(n, orig),
                PiiKind::CreditCard => fake_credit_card(n, orig),
                PiiKind::Ssn => fake_ssn(n),
                PiiKind::IpAddress => fake_ip(n),
                PiiKind::AwsKey => fake_aws_key(n),
                PiiKind::GithubToken => fake_prefixed_token(n, orig),
                PiiKind::GenericApiKey => fake_prefixed_token(n, orig),
                PiiKind::BearerToken => fake_bearer(n, orig),
                PiiKind::ConnectionString => fake_connection_string(n, orig),
                PiiKind::PrivateKey => fake_private_key(orig),
                PiiKind::HighEntropy => fake_high_entropy(n, orig),
            }
        });

        if matches!(kind, PiiKind::ConnectionString) {
            add_connection_component_mappings(&mut maps, original, &fake);
        }

        // Persist to vault with session scope
        if let Some(ref vault) = self.vault {
            let sid = self.session_id.as_deref().unwrap_or("default");
            vault.put_session(sid, original, &fake, kind.label());
        }

        fake
    }

    /// Rehydrate: restore fakes back to originals
    pub fn rehydrate(&self, text: &str) -> String {
        self.maps.lock().unwrap().rehydrate(text)
    }
}

/// Deterministic pseudo-random char from a seed
fn seeded_char(seed: usize, charset: &[u8]) -> char {
    charset[seed % charset.len()] as char
}

fn seeded_digit(seed: usize) -> char {
    b"0123456789"[seed % 10] as char
}

fn seeded_alnum(seed: usize) -> char {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    CHARS[seed % CHARS.len()] as char
}

/// Generate fake string matching length with alphanumeric chars
fn fake_alnum_string(n: usize, len: usize) -> String {
    (0..len).map(|i| seeded_alnum(n * 31 + i * 7)).collect()
}

// --- Per-kind fakers ---

fn fake_email(n: usize, original: &str) -> String {
    let name = FAKE_NAMES[n % FAKE_NAMES.len()];
    let surname = FAKE_SURNAMES[(n * 7) % FAKE_SURNAMES.len()];
    let domain = FAKE_DOMAINS[(n * 3) % FAKE_DOMAINS.len()];

    let fake = format!("{}.{}@{}", name, surname, domain);

    // Try to match original length by adjusting
    if fake.len() < original.len() {
        let diff = original.len() - fake.len();
        let padding: String = (0..diff).map(|i| seeded_digit(n + i)).collect();
        format!("{}.{}{}@{}", name, surname, padding, domain)
    } else {
        fake
    }
}

fn fake_phone(n: usize, original: &str) -> String {
    let area = 200 + (n * 37 % 800);
    let mid = 100 + (n * 53 % 900);
    let last = 1000 + (n * 71 % 9000);

    // Preserve the format of the original
    if original.starts_with('+') {
        let country = if original.starts_with("+1") { "+1" } else { "+1" };
        if original.contains('(') {
            format!("{} ({}) {}-{}", country, area, mid, last)
        } else if original.contains('-') {
            format!("{}-{}-{}-{}", country, area, mid, last)
        } else {
            format!("{}{}{}{}", country, area, mid, last)
        }
    } else if original.contains('(') {
        format!("({}) {}-{}", area, mid, last)
    } else if original.contains('-') {
        format!("{}-{}-{}", area, mid, last)
    } else if original.contains('.') {
        format!("{}.{}.{}", area, mid, last)
    } else if original.contains(' ') {
        format!("{} {} {}", area, mid, last)
    } else {
        format!("{}{}{}", area, mid, last)
    }
}

fn fake_credit_card(n: usize, original: &str) -> String {
    // Preserve prefix type (4=Visa, 5=MC, 3=Amex, 6=Discover)
    let first = original.chars().next().unwrap_or('4');
    let digits: String = std::iter::once(first)
        .chain((1..16).map(|i| seeded_digit(n * 13 + i)))
        .collect();

    // Preserve separator format
    if original.contains('-') {
        format!("{}-{}-{}-{}", &digits[0..4], &digits[4..8], &digits[8..12], &digits[12..16])
    } else if original.contains(' ') {
        format!("{} {} {} {}", &digits[0..4], &digits[4..8], &digits[8..12], &digits[12..16])
    } else {
        digits
    }
}

fn fake_ssn(n: usize) -> String {
    let a = 100 + (n * 37 % 900);
    let b = 10 + (n * 53 % 90);
    let c = 1000 + (n * 71 % 9000);
    format!("{}-{}-{}", a, b, c)
}

fn fake_ip(n: usize) -> String {
    let a = 10 + (n * 37 % 246);
    let b = (n * 53) % 256;
    let c = (n * 71) % 256;
    let d = 1 + (n * 97 % 254);
    format!("{}.{}.{}.{}", a, b, c, d)
}

fn fake_aws_key(n: usize) -> String {
    // AKIA + 16 uppercase alphanumeric
    let suffix: String = (0..16).map(|i| {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        CHARS[(n * 31 + i * 7) % CHARS.len()] as char
    }).collect();
    format!("AKIA{}", suffix)
}

fn fake_prefixed_token(n: usize, original: &str) -> String {
    // Preserve prefix (ghp_, sk-, sk-proj-, xox, AIza, etc.)
    let prefixes = ["sk-proj-", "sk-", "ghp_", "ghs_", "gho_", "ghu_", "ghr_",
                     "xoxb-", "xoxp-", "xoxa-", "xoxo-", "xoxr-", "xoxs-", "AIza"];

    let mut prefix = "";
    for p in &prefixes {
        if original.starts_with(p) {
            prefix = p;
            break;
        }
    }

    let suffix_len = original.len() - prefix.len();
    let suffix = fake_alnum_string(n, suffix_len);
    format!("{}{}", prefix, suffix)
}

fn fake_bearer(n: usize, original: &str) -> String {
    // "Bearer " + token
    let token_part = if original.len() > 7 { &original[7..] } else { original };
    let fake_token = fake_alnum_string(n, token_part.len());
    format!("Bearer {}", fake_token)
}

fn fake_connection_string(n: usize, original: &str) -> String {
    // Preserve protocol, fake the credentials and host
    let protocol = if original.starts_with("postgresql://") {
        "postgresql://"
    } else if original.starts_with("postgres://") {
        "postgres://"
    } else if original.starts_with("mysql://") {
        "mysql://"
    } else if original.starts_with("mongodb+srv://") {
        "mongodb+srv://"
    } else if original.starts_with("mongodb://") {
        "mongodb://"
    } else if original.starts_with("redis://") {
        "redis://"
    } else {
        "postgres://"
    };

    let user = FAKE_NAMES[n % FAKE_NAMES.len()];
    let pass = fake_alnum_string(n * 3, 12);
    let host = format!("db{}.internal", n % 100);
    let port = match protocol {
        p if p.contains("postgres") => 5432,
        p if p.contains("mysql") => 3306,
        p if p.contains("mongo") => 27017,
        p if p.contains("redis") => 6379,
        _ => 5432,
    };
    let db = format!("app_{}", n % 50);

    format!("{}{}:{}@{}:{}/{}", protocol, user, pass, host, port, db)
}

#[derive(Debug)]
struct ConnParts {
    user: Option<String>,
    pass: Option<String>,
    host: Option<String>,
    db: Option<String>,
}

fn parse_connection_parts(s: &str) -> Option<ConnParts> {
    let (_scheme, rest) = s.split_once("://")?;

    let (auth_host, path_part) = match rest.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };

    let (auth_part, host_part) = match auth_host.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, auth_host),
    };

    let (user, pass) = match auth_part {
        Some(a) => match a.split_once(':') {
            Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
            None => (Some(a.to_string()), None),
        },
        None => (None, None),
    };

    let host = if host_part.is_empty() {
        None
    } else {
        // Strip optional :port
        Some(host_part.split(':').next().unwrap_or(host_part).to_string())
    };

    let db = path_part.and_then(|p| {
        let first = p.split('?').next().unwrap_or(p).split('/').next().unwrap_or("");
        if first.is_empty() { None } else { Some(first.to_string()) }
    });

    Some(ConnParts { user, pass, host, db })
}

fn add_connection_component_mappings(maps: &mut FakerMaps, original: &str, fake: &str) {
    let (Some(orig), Some(fk)) = (parse_connection_parts(original), parse_connection_parts(fake)) else {
        return;
    };

    // Add reverse component mappings so rehydration still works when model rewrites the URI
    // but preserves fake subcomponents (user/pass/host/db).
    let pairs = [
        (fk.user, orig.user),
        (fk.pass, orig.pass),
        (fk.host, orig.host),
        (fk.db, orig.db),
    ];

    for (f, o) in pairs {
        if let (Some(fake_comp), Some(orig_comp)) = (f, o) {
            if fake_comp.len() >= 6 && fake_comp != orig_comp {
                maps.reverse.entry(fake_comp).or_insert(orig_comp);
            }
        }
    }
}

fn fake_private_key(original: &str) -> String {
    // Preserve BEGIN/END markers, fake the content with matching length
    let header = if original.contains("RSA") {
        ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
    } else if original.contains("EC") {
        ("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----")
    } else {
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
    };

    // Count content length between markers
    let content_len = original.len().saturating_sub(header.0.len() + header.1.len() + 2);
    let fake_content: String = (0..content_len)
        .map(|i| {
            if i % 65 == 64 { '\n' }
            else {
                const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                B64[i % B64.len()] as char
            }
        })
        .collect();

    format!("{}\n{}\n{}", header.0, fake_content, header.1)
}

fn fake_high_entropy(n: usize, original: &str) -> String {
    // Match exact length with similar character set
    let has_upper = original.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = original.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = original.chars().any(|c| c.is_ascii_digit());
    let has_special = original.contains('+') || original.contains('/') || original.contains('=') || original.contains('_') || original.contains('-');

    let mut charset: Vec<u8> = Vec::new();
    if has_lower { charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz"); }
    if has_upper { charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if has_digit { charset.extend_from_slice(b"0123456789"); }
    if has_special { charset.extend_from_slice(b"+/=_-"); }
    if charset.is_empty() { charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz0123456789"); }

    (0..original.len())
        .map(|i| seeded_char(n * 31 + i * 7, &charset))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_fake() {
        let faker = Faker::new(None, None);
        let email = "real@company.com";
        let fake1 = faker.fake(email, &PiiKind::Email);
        let fake2 = faker.fake(email, &PiiKind::Email);
        assert_eq!(fake1, fake2);
        assert_ne!(fake1, email);
        assert!(fake1.contains('@'));
    }

    #[test]
    fn test_phone_format_preserved() {
        let faker = Faker::new(None, None);
        let phone = "(555) 123-4567";
        let fake = faker.fake(phone, &PiiKind::Phone);
        assert!(fake.contains('('));
        assert!(fake.contains(')'));
        assert!(fake.contains('-'));
    }

    #[test]
    fn test_aws_key_format() {
        let faker = Faker::new(None, None);
        let key = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
        let fake = faker.fake(&key, &PiiKind::AwsKey);
        assert!(fake.starts_with("AKIA"));
        assert_eq!(fake.len(), key.len());
    }

    #[test]
    fn test_high_entropy_length_match() {
        let faker = Faker::new(None, None);
        let secret = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hI6kL9";
        let fake = faker.fake(secret, &PiiKind::HighEntropy);
        assert_eq!(fake.len(), secret.len());
        assert_ne!(fake, secret);
    }

    #[test]
    fn test_rehydrate() {
        let faker = Faker::new(None, None);
        let email = "real@company.com";
        let fake = faker.fake(email, &PiiKind::Email);
        let text = format!("Contact {}", fake);
        let rehydrated = faker.rehydrate(&text);
        assert_eq!(rehydrated, format!("Contact {}", email));
    }

    #[test]
    fn test_ssn_format() {
        let faker = Faker::new(None, None);
        let ssn = "123-45-6789";
        let fake = faker.fake(ssn, &PiiKind::Ssn);
        assert_ne!(fake, ssn);
        // Should match XXX-XX-XXXX format
        let parts: Vec<&str> = fake.split('-').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_ip_format() {
        let faker = Faker::new(None, None);
        let ip = "192.168.1.100";
        let fake = faker.fake(ip, &PiiKind::IpAddress);
        assert_ne!(fake, ip);
        let parts: Vec<&str> = fake.split('.').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_connection_string_protocol_preserved() {
        let faker = Faker::new(None, None);
        let conn = "mongodb+srv://admin:secret@cluster0.abc.mongodb.net/mydb";
        let fake = faker.fake(conn, &PiiKind::ConnectionString);
        assert!(fake.starts_with("mongodb+srv://"));
    }

    #[test]
    fn test_connection_string_component_rehydrate() {
        let faker = Faker::new(None, None);
        let original = "postgresql://chandika:realSecretPass@db.prod.internal:5432/app_prod";
        let fake = faker.fake(original, &PiiKind::ConnectionString);

        // Simulate model rewriting around fake components
        let fake_parts = parse_connection_parts(&fake).unwrap();
        let rewritten = format!(
            "psql \"postgresql://{}:{}@{}:5432/{}\"",
            fake_parts.user.unwrap_or_default(),
            fake_parts.pass.unwrap_or_default(),
            fake_parts.host.unwrap_or_default(),
            fake_parts.db.unwrap_or_default(),
        );

        let rehydrated = faker.rehydrate(&rewritten);
        assert!(rehydrated.contains("chandika"));
        assert!(rehydrated.contains("realSecretPass"));
        assert!(rehydrated.contains("db.prod.internal"));
        assert!(rehydrated.contains("app_prod"));
    }

    #[test]
    fn test_rehydrate_does_not_replace_inside_identifiers() {
        let mut maps = FakerMaps::new();
        maps.reverse.insert("at".to_string(), "pscale_api_real".to_string());
        maps.reverse.insert("pscale_api_fake.abc123".to_string(), "pscale_api_real.abc123".to_string());

        let input = "pattern file_path pscale_api_fake.abc123";
        let out = maps.rehydrate(input);

        // short/tiny mappings are ignored completely
        assert!(out.contains("pattern"));
        assert!(out.contains("file_path"));
        // real fake key still rehydrates
        assert!(out.contains("pscale_api_real.abc123"));
    }

}
