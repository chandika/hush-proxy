use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub struct Stats {
    pub start_time: Instant,
    pub requests: AtomicU64,
    pub redactions: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub sessions: AtomicU64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Stats {
            start_time: Instant::now(),
            requests: AtomicU64::new(0),
            redactions: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            sessions: AtomicU64::new(0),
        })
    }

    pub fn add_request(&self, bytes: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_response(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_redactions(&self, count: u64) {
        self.redactions.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_session(&self) {
        self.sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn display(&self) -> String {
        let uptime = self.start_time.elapsed();
        let hours = uptime.as_secs() / 3600;
        let mins = (uptime.as_secs() % 3600) / 60;
        let secs = uptime.as_secs() % 60;

        let reqs = self.requests.load(Ordering::Relaxed);
        let redactions = self.redactions.load(Ordering::Relaxed);
        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);
        let sessions = self.sessions.load(Ordering::Relaxed);

        format!(
            "{}h {}m {}s │ {} reqs │ {} redacted │ {} sessions │ ↑{} ↓{}",
            hours, mins, secs,
            reqs,
            redactions,
            sessions,
            human_bytes(bytes_in),
            human_bytes(bytes_out),
        )
    }
}

fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
