//! Pure, fail-closed address policy for opt-in LAN gateway connections.
//!
//! This module performs neither DNS nor I/O. The caller must freshly resolve
//! both target and relay for each connection, then connect only to the numeric
//! sockets returned by `validate_resolved`, without another name lookup.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAX_DNS_ANSWERS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayTarget {
    /// Canonical IP (without brackets), or lowercase, absolute `.local.` name.
    pub host: String,
    pub port: u16,
}

impl GatewayTarget {
    /// Parse a bare `HOST:PORT`; IPv6 literals require `[HOST]:PORT`.
    ///
    /// Numeric and named IPv6 zones are deliberately unsupported. Rejecting
    /// them, rather than dropping them, prevents a change in interface scope.
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.is_empty()
            || !input.is_ascii()
            || input
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(
                "gateway target must be nonempty ASCII without whitespace or controls".into(),
            );
        }
        if input.contains('%') {
            return Err("scoped IPv6 gateway targets are not supported".into());
        }

        let (host, port_text, bracketed) = if let Some(rest) = input.strip_prefix('[') {
            let (host, tail) = rest
                .split_once(']')
                .ok_or("IPv6 gateway target requires a closing bracket")?;
            let port = tail
                .strip_prefix(':')
                .ok_or("gateway target requires an explicit port")?;
            (host, port, true)
        } else {
            let (host, port) = input
                .split_once(':')
                .ok_or("gateway target requires HOST:PORT")?;
            if port.contains(':') {
                return Err("IPv6 gateway targets require brackets".into());
            }
            (host, port, false)
        };
        if port_text.is_empty() || !port_text.bytes().all(|b| b.is_ascii_digit()) {
            return Err("gateway port must contain only decimal digits".into());
        }
        let port: u16 = port_text
            .parse()
            .map_err(|_| "gateway port exceeds 65535")?;
        if port == 0 {
            return Err("gateway port must be nonzero".into());
        }

        let host = if bracketed {
            let ip: Ipv6Addr = host
                .parse()
                .map_err(|_| "brackets require an IPv6 literal")?;
            if !is_lan_ip(IpAddr::V6(ip)) {
                return Err("gateway IP is outside the permitted LAN ranges".into());
            }
            ip.to_string()
        } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if !is_lan_ip(IpAddr::V4(ip)) {
                return Err("gateway IP is outside the permitted LAN ranges".into());
            }
            ip.to_string()
        } else {
            normalize_local_name(host)?
        };
        Ok(Self { host, port })
    }
}

fn normalize_local_name(host: &str) -> Result<String, String> {
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if name.len() > 253 || !name.ends_with(".local") {
        return Err("gateway names must be ASCII hostnames below .local".into());
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || label.starts_with("xn--")
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("gateway name contains an invalid or ambiguous label".into());
        }
    }
    // An absolute name also avoids a resolver search-domain suffix changing it.
    Ok(format!("{name}."))
}

/// Only private/link-local unicast LAN ranges are permitted. IPv4-mapped IPv6
/// follows the IPv4 policy; other IPv4 embedding/transition ranges are denied.
pub fn is_lan_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            // Conservative rejection of common directed-broadcast candidates;
            // arbitrary subnet broadcasts need the caller's interface masks.
            if d == 255 || [a, b, c, d] == [169, 254, 169, 254] {
                return false;
            }
            a == 10
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 169 && b == 254)
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

/// Validate an entire fresh answer set before allowing any connection.
///
/// A single unsafe answer poisons the whole set. Relay answers must be freshly
/// resolved by the caller, nonempty, and include every relay endpoint in use.
/// Returned addresses preserve the first numeric socket for each IP/port pair,
/// treating mapped IPv4 and native IPv4 as the same destination.
pub fn validate_resolved(
    target: &GatewayTarget,
    addresses: &[SocketAddr],
    relay_addresses: &[IpAddr],
) -> Result<Vec<SocketAddr>, String> {
    // The fields are public for integration. Revalidate even manually built or
    // later-mutated structs rather than relying solely on use of `parse`.
    let endpoint = match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{}]:{}", target.host, target.port),
        _ => format!("{}:{}", target.host, target.port),
    };
    let target = GatewayTarget::parse(&endpoint)?;
    // Determine literal identity from the canonical result. Public fields may
    // contain bracketed IPv6, which is not itself parseable as `IpAddr` before
    // normalization and must never be treated as an unpinned hostname.
    let literal = target.host.parse::<IpAddr>().ok();
    if relay_addresses.is_empty() {
        return Err("relay addresses are required for gateway validation".into());
    }
    if addresses.is_empty() || addresses.len() > MAX_DNS_ANSWERS {
        return Err("gateway resolution must return between 1 and 32 addresses".into());
    }

    let relays: HashSet<IpAddr> = relay_addresses.iter().copied().map(canonical_ip).collect();
    let mut seen = HashSet::new();
    let mut validated = Vec::new();
    for &address in addresses {
        if let SocketAddr::V6(v6) = address {
            if v6.scope_id() != 0 {
                return Err("scoped IPv6 gateway addresses are not supported".into());
            }
        }
        let ip = canonical_ip(address.ip());
        if address.port() != target.port {
            return Err("resolved gateway port differs from the requested port".into());
        }
        if !is_lan_ip(ip) {
            return Err("gateway resolution contains a disallowed IP".into());
        }
        if literal.is_some_and(|expected| canonical_ip(expected) != ip) {
            return Err("resolved gateway IP differs from the requested literal".into());
        }
        if relays.contains(&ip) {
            return Err("gateway target aliases a relay address".into());
        }
        if seen.insert((ip, address.port())) {
            validated.push(address);
        }
    }
    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
    fn socket(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }
    fn target() -> GatewayTarget {
        GatewayTarget::parse("Device.LOCAL:8080").unwrap()
    }
    fn relays() -> Vec<IpAddr> {
        vec![ip("203.0.113.4"), ip("2001:db8::4")]
    }

    #[test]
    fn canonical_names_and_literals() {
        for input in ["PrInTeR.LoCaL:443", "printer.local.:443"] {
            assert_eq!(
                GatewayTarget::parse(input).unwrap(),
                GatewayTarget {
                    host: "printer.local.".into(),
                    port: 443
                }
            );
        }
        for (input, host, port) in [
            ("10.0.0.1:1", "10.0.0.1", 1),
            ("172.16.0.1:65535", "172.16.0.1", 65535),
            ("169.254.1.1:80", "169.254.1.1", 80),
            ("[FD01:0000::1]:80", "fd01::1", 80),
            ("[fe80::1]:22", "fe80::1", 22),
            ("[::ffff:192.168.1.2]:80", "::ffff:192.168.1.2", 80),
            ("a-1.room.local:00080", "a-1.room.local.", 80),
        ] {
            assert_eq!(
                GatewayTarget::parse(input).unwrap(),
                GatewayTarget {
                    host: host.into(),
                    port
                }
            );
        }
    }

    #[test]
    fn malformed_and_ambiguous_inputs() {
        for input in [
            "",
            "local:80",
            ".local:80",
            "localhost:80",
            "foo.local",
            "foo.local:",
            "foo.local:0",
            "foo.local:+80",
            "foo.local:-1",
            "foo.local:65536",
            "foo.local:999999999999999999999999999999999999999",
            "foo.local:0x50",
            "foo.local:80/",
            "http://foo.local:80",
            "foo.local:80?x",
            "foo.local:80#x",
            "user@foo.local:80",
            "*.local:80",
            "foo..local:80",
            "foo.local..:80",
            "-foo.local:80",
            "foo-.local:80",
            "_ssh._tcp.local:80",
            "xn--bcher-kva.local:80",
            "fóo.local:80",
            "foo．local:80",
            "foo.local:８０",
            "foo.local\0:80",
            "foo.local:\n80",
            " foo.local:80",
            "foo.local:80 ",
            "foo\t.local:80",
            "[foo.local]:80",
            "[10.0.0.1]:80",
            "[fd00::1]80",
            "[fd00::1]:80:90",
            "[fd00::1]:80]",
            "[[fd00::1]]:80",
            "fd00::1:80",
            "[fd00::1:80",
            "[fe80::1%1]:80",
            "[fe80::1%en0]:80",
            "[fe80::1%251]:80",
            "10.0.0.01:80",
            "010.0.0.1:80",
            "0xa000001:80",
            "167772161:80",
            "127.1:80",
            "foo.local.evil:80",
            "foo.local\\evil:80",
        ] {
            assert!(GatewayTarget::parse(input).is_err(), "accepted {input:?}");
        }
        assert!(GatewayTarget::parse(&format!("{}.local:80", "a".repeat(64))).is_err());
        assert!(
            GatewayTarget::parse(&format!("{}.local:80", vec!["a".repeat(63); 4].join(".")))
                .is_err()
        );
    }

    #[test]
    fn parser_control_and_delimiter_mutations_never_panic_or_pass() {
        for byte in 0..=127u8 {
            if byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || b"/@?#%\\[]:*".contains(&byte)
            {
                for position in 0..=16 {
                    let mut text = "device.local:443".to_string();
                    text.insert(position.min(text.len()), char::from(byte));
                    assert!(GatewayTarget::parse(&text).is_err(), "accepted {text:?}");
                }
            }
        }
    }

    #[test]
    fn lan_range_edges_and_transition_addresses() {
        for allowed in [
            "10.0.0.0",
            "10.255.255.254",
            "172.16.0.0",
            "172.31.255.254",
            "192.168.0.0",
            "192.168.255.254",
            "169.254.0.1",
            "169.254.255.254",
            "fc00::1",
            "fdff:ffff::1",
            "fe80::1",
            "febf:ffff::1",
            "::ffff:10.1.2.3",
        ] {
            assert!(is_lan_ip(ip(allowed)), "denied {allowed}");
        }
        for denied in [
            "0.0.0.0",
            "127.0.0.1",
            "127.9.9.9",
            "8.8.8.8",
            "9.255.255.254",
            "11.0.0.0",
            "172.15.255.254",
            "172.32.0.0",
            "192.167.255.254",
            "192.169.0.0",
            "169.253.1.1",
            "169.255.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.168.1.255",
            "10.255.255.255",
            "172.31.255.255",
            "::",
            "::1",
            "::10.1.2.3",
            "::192.168.1.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:8.8.8.8",
            "::ffff:192.168.1.255",
            "2001:db8::1",
            "2002:0a00:0001::1",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::a00:1",
            "fe7f::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(!is_lan_ip(ip(denied)), "allowed {denied}");
        }
    }

    #[test]
    fn literals_are_checked_during_parse() {
        for denied in [
            "127.0.0.1:80",
            "0.0.0.0:80",
            "169.254.169.254:80",
            "192.168.1.255:80",
            "8.8.8.8:80",
            "255.255.255.255:80",
            "[::]:80",
            "[::1]:80",
            "[ff02::1]:80",
            "[::ffff:127.0.0.1]:80",
            "[2002:0a00:0001::1]:80",
            "[64:ff9b::10.0.0.1]:80",
        ] {
            assert!(GatewayTarget::parse(denied).is_err(), "accepted {denied}");
        }
    }

    #[test]
    fn mixed_answer_sets_fail_closed_regardless_of_order() {
        let good = socket("192.168.1.5:8080");
        for bad in [
            "8.8.8.8:8080",
            "127.0.0.1:8080",
            "169.254.169.254:8080",
            "[::ffff:8.8.8.8]:8080",
            "[ff02::1]:8080",
            "[64:ff9b::10.0.0.1]:8080",
            "192.168.1.5:8081",
        ] {
            for addresses in [[good, socket(bad)], [socket(bad), good]] {
                assert!(validate_resolved(&target(), &addresses, &relays()).is_err());
            }
        }
    }

    #[test]
    fn relay_aliases_match_across_address_families_and_ports() {
        for (address, relay) in [
            ("192.168.1.5:8080", "192.168.1.5"),
            ("[::ffff:192.168.1.5]:8080", "192.168.1.5"),
            ("192.168.1.5:8080", "::ffff:192.168.1.5"),
            ("[fd00::5]:8080", "fd00::5"),
        ] {
            assert!(validate_resolved(&target(), &[socket(address)], &[ip(relay)]).is_err());
        }
    }

    #[test]
    fn exact_sockets_and_first_seen_order_are_preserved_with_deduplication() {
        let addresses = [
            socket("[::ffff:192.168.1.5]:8080"),
            socket("192.168.1.5:8080"),
            socket("[fd00::5]:8080"),
            socket("[fd00::5]:8080"),
            socket("10.0.0.2:8080"),
        ];
        assert_eq!(
            validate_resolved(&target(), &addresses, &relays()).unwrap(),
            vec![addresses[0], addresses[2], addresses[4]]
        );
    }

    #[test]
    fn empty_and_excess_answers_fail_before_deduplication() {
        let address = socket("10.0.0.1:8080");
        assert!(validate_resolved(&target(), &[], &relays()).is_err());
        assert!(validate_resolved(&target(), &[address], &[]).is_err());
        assert_eq!(
            validate_resolved(&target(), &[address; 32], &relays()).unwrap(),
            vec![address]
        );
        assert!(validate_resolved(&target(), &[address; 33], &relays()).is_err());
    }

    #[test]
    fn each_connection_revalidates_new_target_and_relay_results() {
        let good = socket("10.0.0.1:8080");
        assert!(validate_resolved(&target(), &[good], &relays()).is_ok());
        assert!(validate_resolved(&target(), &[socket("8.8.8.8:8080")], &relays()).is_err());
        assert!(validate_resolved(&target(), &[good], &[ip("10.0.0.1")]).is_err());
        assert!(validate_resolved(&target(), &[good], &relays()).is_ok());
    }

    #[test]
    fn manually_constructed_targets_and_literal_substitution_are_rejected() {
        for (host, port) in [
            ("evil.com", 8080),
            ("localhost", 8080),
            ("8.8.8.8", 8080),
            ("device.local", 0),
            ("fe80::1%1", 8080),
        ] {
            let forged = GatewayTarget {
                host: host.into(),
                port,
            };
            assert!(validate_resolved(&forged, &[socket("10.0.0.1:8080")], &relays()).is_err());
        }
        let literal = GatewayTarget::parse("10.0.0.1:8080").unwrap();
        assert!(validate_resolved(&literal, &[socket("10.0.0.2:8080")], &relays()).is_err());
        assert!(
            validate_resolved(&literal, &[socket("[::ffff:10.0.0.1]:8080")], &relays()).is_ok()
        );
    }

    #[test]
    fn numeric_scopes_in_resolver_results_are_not_silently_discarded() {
        let scoped = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 8080, 0, 3));
        assert!(validate_resolved(&target(), &[scoped], &relays()).is_err());
    }

    #[test]
    fn manually_constructed_bracketed_literals_remain_pinned_after_normalization() {
        for (host, matching, substituted) in [
            ("[fd00::10]", "[fd00::10]:80", "[fd00::20]:80"),
            ("[FD00:0000::10]", "[fd00::10]:80", "[fd00::20]:80"),
            ("[::ffff:10.0.0.10]", "10.0.0.10:80", "10.0.0.20:80"),
            (
                "[::ffff:10.0.0.10]",
                "[::ffff:10.0.0.10]:80",
                "[::ffff:10.0.0.20]:80",
            ),
            ("[::FFFF:0a00:000a]", "10.0.0.10:80", "10.0.0.20:80"),
            ("fd00::10", "[fd00::10]:80", "[fd00::20]:80"),
            ("::ffff:10.0.0.10", "10.0.0.10:80", "10.0.0.20:80"),
        ] {
            let target = GatewayTarget {
                host: host.into(),
                port: 80,
            };
            assert!(
                validate_resolved(&target, &[socket(matching)], &relays()).is_ok(),
                "rejected matching literal {host}"
            );
            assert!(
                validate_resolved(&target, &[socket(substituted)], &relays()).is_err(),
                "accepted substituted literal {host}"
            );
            assert!(
                validate_resolved(&target, &[socket(matching), socket(substituted)], &relays())
                    .is_err(),
                "accepted mixed literal answers {host}"
            );
        }
    }
}
