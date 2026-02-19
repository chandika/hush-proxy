use std::collections::HashMap;
use std::sync::Mutex;

/// Generates plausible fake values for masked PII categories.
/// Consistent within a session — same input always gets same fake.
pub struct Faker {
    email_map: Mutex<FakerMap>,
    phone_map: Mutex<FakerMap>,
}

struct FakerMap {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
    counter: usize,
}

impl FakerMap {
    fn new() -> Self {
        FakerMap {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            counter: 0,
        }
    }

    fn get_or_insert(&mut self, original: &str, generator: impl Fn(usize) -> String) -> String {
        if let Some(fake) = self.forward.get(original) {
            return fake.clone();
        }
        self.counter += 1;
        let fake = generator(self.counter);
        self.forward.insert(original.to_string(), fake.clone());
        self.reverse.insert(fake.clone(), original.to_string());
        fake
    }

    fn rehydrate(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (fake, original) in &self.reverse {
            result = result.replace(fake, original);
        }
        result
    }
}

static FAKE_DOMAINS: &[&str] = &[
    "example.com", "example.org", "example.net", "test.com",
    "sample.org", "demo.net", "placeholder.com",
];

static FAKE_FIRST_NAMES: &[&str] = &[
    "alex", "jordan", "taylor", "morgan", "casey",
    "riley", "avery", "quinn", "blake", "drew",
];

impl Faker {
    pub fn new() -> Self {
        Faker {
            email_map: Mutex::new(FakerMap::new()),
            phone_map: Mutex::new(FakerMap::new()),
        }
    }

    pub fn fake_email(&self, original: &str) -> String {
        let mut map = self.email_map.lock().unwrap();
        map.get_or_insert(original, |n| {
            let name = FAKE_FIRST_NAMES[n % FAKE_FIRST_NAMES.len()];
            let domain = FAKE_DOMAINS[n % FAKE_DOMAINS.len()];
            format!("{}{}@{}", name, n, domain)
        })
    }

    pub fn fake_phone(&self, original: &str) -> String {
        let mut map = self.phone_map.lock().unwrap();
        map.get_or_insert(original, |n| {
            // Generate a fake phone in similar format
            let area = 200 + (n % 800);
            let mid = 100 + (n * 7 % 900);
            let last = 1000 + (n * 13 % 9000);
            // Try to preserve the original format
            if original.contains('(') {
                format!("({}) {}-{}", area, mid, last)
            } else if original.contains('-') {
                format!("{}-{}-{}", area, mid, last)
            } else if original.contains('.') {
                format!("{}.{}.{}", area, mid, last)
            } else {
                format!("{}{}{}", area, mid, last)
            }
        })
    }

    pub fn rehydrate(&self, text: &str) -> String {
        let result = self.email_map.lock().unwrap().rehydrate(text);
        self.phone_map.lock().unwrap().rehydrate(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_fake_email() {
        let faker = Faker::new();
        let email = "real@company.com";
        let fake1 = faker.fake_email(email);
        let fake2 = faker.fake_email(email);
        assert_eq!(fake1, fake2);
        assert_ne!(fake1, email);
        assert!(fake1.contains('@'));
    }

    #[test]
    fn test_consistent_fake_phone() {
        let faker = Faker::new();
        let phone = "(555) 123-4567";
        let fake1 = faker.fake_phone(phone);
        let fake2 = faker.fake_phone(phone);
        assert_eq!(fake1, fake2);
        assert_ne!(fake1, phone);
        assert!(fake1.contains('('));
    }

    #[test]
    fn test_rehydrate() {
        let faker = Faker::new();
        let email = "real@company.com";
        let fake = faker.fake_email(email);
        let text = format!("Contact {}", fake);
        let rehydrated = faker.rehydrate(&text);
        assert_eq!(rehydrated, format!("Contact {}", email));
    }
}
