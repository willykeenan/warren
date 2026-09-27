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
/// Frames that are not flow-controlled (PING/PONG, WINDOW, CTRL, OPEN,
/// OPEN_OK/OPEN_ERR, CLOSE) queued on one link beyond this many bytes mean the
/// peer stopped reading while provoking replies: the link is closed.
/// Flow-controlled DATA has its own budget (see [`NODE_LINK_DATA_BUDGET`] and
/// [`RELAY_LINK_DATA_BUDGET`]) and makes senders wait instead.
pub const MAX_LINK_QUEUE: usize = 64 * 1024 * 1024;
/// DATA bytes a node queues toward the relay before its senders wait. Covers
/// every stream sending a full window at once (1024 x 256 KiB plus frame
/// headers), so senders that respect the windows never wait; only a peer that
/// grants more credit than it consumes makes them wait.
pub const NODE_LINK_DATA_BUDGET: usize =
    crate::proto::MAX_STREAMS_PER_NODE * (crate::proto::STREAM_WINDOW as usize + 1024);
/// DATA bytes the relay queues toward one node (forwarded private streams and
/// public streams) before the senders feeding it wait. This bounds relay
/// memory per node regardless of how much credit nodes grant.
pub const RELAY_LINK_DATA_BUDGET: usize = 32 * 1024 * 1024;
/// A destination link on the relay whose DATA queue makes no room for this
/// long is considered stuck and closed (the sources feeding it are paused
/// meanwhile, so this must stay well below the nodes' keepalive timeout).
pub const LINK_STUCK_TIMEOUT: Duration = Duration::from_secs(20);
/// Stream opens a node paces itself to (a little below the relay's limit of
/// [`crate::proto::MAX_OPENS_PER_SEC`], so network jitter never trips it).
pub const NODE_OPENS_PER_SEC: u32 = 60;
/// Burst of stream opens a node allows itself.
pub const NODE_OPEN_BURST: u32 = 60;
/// Maximum concurrent client connections on a relay (nodes and public).
pub const MAX_CONNECTIONS: usize = 16384;
/// Maximum concurrent connections from one client IP.
pub const MAX_CONNECTIONS_PER_IP: usize = 256;
/// Open files the relay and the node daemon ask for at startup (see
/// [`raise_open_files_limit`]): room for [`MAX_CONNECTIONS`] and more.
pub const WANTED_OPEN_FILES: u64 = 65536;

/// Raise this process's soft limit on open files towards `want`, never above
/// the hard limit, and return the soft limit now in effect. Never lowers it.
///
/// Processes often start with a soft limit of 256 (macOS) or 1024 (Linux),
/// far below what a busy relay needs, while the hard limit is much higher.
pub fn raise_open_files_limit(want: u64) -> u64 {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    let cur = getrlimit(Resource::Nofile);
    let soft = cur.current.unwrap_or(u64::MAX);
    let mut target = want.min(cur.maximum.unwrap_or(u64::MAX));
    while target > soft {
        let new = Rlimit {
            current: Some(target),
            maximum: cur.maximum,
        };
        if setrlimit(Resource::Nofile, new).is_ok() {
            return target;
        }
        // macOS refuses values above kern.maxfilesperproc: try smaller ones.
        target = (target / 2).max(soft);
    }
    soft
}

// Checked at compile time: the budgets admit everything flow control allows
// (every stream sending its whole window in maximal frames), and nodes pace
// themselves under the relay's open rate.
const _: () = {
    use crate::proto::{
        HEADER_LEN, MAX_OPENS_PER_SEC, MAX_PAYLOAD, MAX_STREAMS_PER_NODE, MAX_WS_MESSAGE,
        STREAM_WINDOW,
    };
    let frames_per_window = (STREAM_WINDOW as usize).div_ceil(MAX_PAYLOAD);
    let per_stream = STREAM_WINDOW as usize + frames_per_window * HEADER_LEN;
    assert!(NODE_LINK_DATA_BUDGET >= MAX_STREAMS_PER_NODE * per_stream);
    assert!(RELAY_LINK_DATA_BUDGET >= 64 * MAX_WS_MESSAGE);
    assert!(NODE_OPENS_PER_SEC <= MAX_OPENS_PER_SEC);
    assert!(NODE_OPEN_BURST <= MAX_OPENS_PER_SEC);
};

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
        self.take_or_wait_at(now).is_ok()
    }

    /// Take a token, or say how long until one is available.
    pub fn take_or_wait(&mut self) -> Result<(), Duration> {
        self.take_or_wait_at(Instant::now())
    }

    pub fn take_or_wait_at(&mut self, now: Instant) -> Result<(), Duration> {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else if self.rate > 0.0 {
            Err(Duration::from_secs_f64((1.0 - self.tokens) / self.rate)
                .max(Duration::from_millis(1)))
        } else {
            Err(Duration::from_secs(1))
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
    fn bucket_reports_wait() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(50, 2);
        b.last = t0;
        assert!(b.take_or_wait_at(t0).is_ok());
        assert!(b.take_or_wait_at(t0).is_ok());
        let w = b.take_or_wait_at(t0).unwrap_err();
        assert!(
            w > Duration::from_millis(15) && w <= Duration::from_millis(20),
            "{w:?}"
        );
        assert!(b.take_or_wait_at(t0 + w).is_ok());
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
    fn open_files_limit_is_raised_not_lowered() {
        use rustix::process::{getrlimit, Resource};
        let hard = getrlimit(Resource::Nofile).maximum.unwrap_or(u64::MAX);
        let want = 2048.min(hard);
        let got = raise_open_files_limit(2048);
        assert!(got >= want, "{got} < {want}");
        let soft = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
        assert!(soft >= want);
        assert_eq!(raise_open_files_limit(16), soft, "never lowered");
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
