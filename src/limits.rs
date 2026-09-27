//! Rate limiting and the limits that protect relay and nodes from abuse.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Time allowed for a public client to finish TLS and send a full request head.
pub const PUBLIC_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Public connections with no traffic in either direction for this long are closed.
pub const PUBLIC_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum size of a request head on the public side.
pub const MAX_REQUEST_HEAD: usize = 32 * 1024;
/// Maximum size of a response head coming back from a node.
pub const MAX_RESPONSE_HEAD: usize = 64 * 1024;
/// Maximum number of headers in one request.
pub const MAX_HEADERS: usize = 128;
/// Failed enrollment attempts allowed per IP per window.
pub const JOIN_FAILURES_PER_WINDOW: usize = 5;
/// Window for counting failed enrollment attempts.
pub const JOIN_FAILURE_WINDOW: Duration = Duration::from_secs(600);
/// Lifetime of an enrollment code.
pub const INVITE_TTL: Duration = Duration::from_secs(600);
/// Time allowed for a node to complete the WebSocket upgrade and authentication.
pub const NODE_AUTH_TIMEOUT: Duration = Duration::from_secs(15);
/// A link whose outbound queue exceeds this many bytes is considered stuck and closed.
pub const MAX_LINK_QUEUE: usize = 64 * 1024 * 1024;
/// Maximum concurrent client connections on a relay (nodes and public).
pub const MAX_CONNECTIONS: usize = 16384;
/// Maximum concurrent connections from one client IP.
pub const MAX_CONNECTIONS_PER_IP: usize = 256;

/// Classic token bucket.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u32, capacity: u32) -> TokenBucket {
        TokenBucket {
            capacity: capacity as f64,
            tokens: capacity as f64,
            rate: rate_per_sec as f64,
            last: Instant::now(),
        }
    }

    pub fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    pub fn try_take_at(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Sliding-window failure counter keyed by IP.
#[derive(Debug, Default)]
pub struct FailureLimiter {
    failures: HashMap<IpAddr, VecDeque<Instant>>,
    max: usize,
    window: Duration,
}

impl FailureLimiter {
    pub fn new(max: usize, window: Duration) -> FailureLimiter {
        FailureLimiter {
            failures: HashMap::new(),
            max,
            window,
        }
    }

    fn prune(&mut self, ip: IpAddr, now: Instant) {
        if let Some(q) = self.failures.get_mut(&ip) {
            while q
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= self.window)
            {
                q.pop_front();
            }
            if q.is_empty() {
                self.failures.remove(&ip);
            }
        }
    }

    /// True if `ip` has used up its failures for the current window.
    pub fn blocked_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.prune(ip, now);
        self.failures.get(&ip).map_or(0, |q| q.len()) >= self.max
    }

    pub fn blocked(&mut self, ip: IpAddr) -> bool {
        self.blocked_at(ip, Instant::now())
    }

    pub fn record_at(&mut self, ip: IpAddr, now: Instant) {
        self.prune(ip, now);
        self.failures.entry(ip).or_default().push_back(now);
        // Bound memory: forget the oldest IPs if the table grows huge.
        if self.failures.len() > 100_000 {
            let cutoff = self.window;
            self.failures.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < cutoff)
            });
        }
    }

    pub fn record(&mut self, ip: IpAddr) {
        self.record_at(ip, Instant::now())
    }

    /// Start an attempt: counts as a failure until [`FailureLimiter::forgive`]
    /// is called, so concurrent attempts cannot exceed the limit. Returns
    /// false (and records nothing) if `ip` is already blocked.
    pub fn begin(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.blocked_at(ip, now) {
            return false;
        }
        self.record_at(ip, now);
        true
    }

    /// Undo the provisional failure of a successful attempt.
    pub fn forgive(&mut self, ip: IpAddr) {
        if let Some(q) = self.failures.get_mut(&ip) {
            q.pop_back();
            if q.is_empty() {
                self.failures.remove(&ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(64, 64);
        b.last = t0;
        let ok = (0..100).filter(|_| b.try_take_at(t0)).count();
        assert_eq!(ok, 64);
        assert!(!b.try_take_at(t0));
        assert!(b.try_take_at(t0 + Duration::from_millis(20)));
        let later = t0 + Duration::from_secs(5);
        let ok = (0..100).filter(|_| b.try_take_at(later)).count();
        assert_eq!(ok, 64);
    }

    #[test]
    fn failure_limiter_window() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let t0 = Instant::now();
        let mut l = FailureLimiter::new(5, Duration::from_secs(600));
        for _ in 0..4 {
            l.record_at(ip, t0);
        }
        assert!(!l.blocked_at(ip, t0));
        l.record_at(ip, t0);
        assert!(l.blocked_at(ip, t0));
        assert!(!l.blocked_at(other, t0));
        assert!(l.blocked_at(ip, t0 + Duration::from_secs(599)));
        assert!(!l.blocked_at(ip, t0 + Duration::from_secs(600)));
    }

    #[test]
    fn provisional_attempts_count() {
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let mut l = FailureLimiter::new(5, Duration::from_secs(600));
        // Five concurrent attempts are admitted, the sixth is not.
        for _ in 0..5 {
            assert!(l.begin(ip));
        }
        assert!(!l.begin(ip));
        // A successful attempt gives its slot back.
        l.forgive(ip);
        assert!(l.begin(ip));
        assert!(!l.begin(ip));
    }

    #[test]
    fn defaults_match_documentation() {
        assert_eq!(PUBLIC_HEADER_TIMEOUT, Duration::from_secs(10));
        assert_eq!(PUBLIC_IDLE_TIMEOUT, Duration::from_secs(300));
        assert_eq!(MAX_REQUEST_HEAD, 32 * 1024);
        assert_eq!(JOIN_FAILURES_PER_WINDOW, 5);
        assert_eq!(JOIN_FAILURE_WINDOW, Duration::from_secs(600));
        assert_eq!(INVITE_TTL, Duration::from_secs(600));
        assert_eq!(crate::proto::STREAM_WINDOW, 256 * 1024);
        assert_eq!(crate::proto::MAX_STREAMS_PER_NODE, 1024);
        assert_eq!(crate::proto::MAX_OPENS_PER_SEC, 64);
    }
}
