# Gateway address policy

`src/gateway_policy.rs` is a pure address-policy module using only Rust's standard
library. It does not discover devices, perform DNS, open sockets, establish a
gateway, or change routing. Passing this policy alone is not a working gateway.

## Supported input

`GatewayTarget::parse` accepts an explicit `HOST:PORT` with a nonzero decimal
`u16` port. Leading zeroes in the decimal port are accepted. IPv4 must use Rust's
strict four-component dotted-decimal representation. IPv6 must be bracketed in
the input (`[fd00::1]:443`), and is stored canonically without brackets.

Names must be ASCII hostnames below `.local`, with labels of 1–63 letters,
digits, or internal hyphens and a total length of at most 253 characters without
the root dot. Names are lowercased and stored with exactly one final dot, so
`Printer.LOCAL:443` and `printer.local.:443` both store `printer.local.`.
The trailing dot makes the name absolute and avoids resolver search suffixes.

URLs, userinfo, paths, queries, fragments, wildcards, service-record underscores,
empty labels, edge hyphens, bare `local`, all non-`.local` names, Unicode, punycode
`xn--` labels, whitespace, controls and nondecimal ports are rejected. Numeric
and named IPv6 scopes (including escaped `%25` syntax) are explicitly rejected;
the module never strips a scope. IPv6 link-local connectivity that needs an
interface scope remains unsupported by this version.

## IP boundaries

The allowlist is RFC1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`), IPv4
link-local (`169.254/16`), IPv6 ULA (`fc00::/7`) and IPv6 link-local (`fe80::/10`).
IPv4-mapped IPv6 uses the embedded IPv4 policy. The metadata destination
`169.254.169.254` is explicitly denied, including its mapped representation.

Unspecified, loopback, multicast, public, shared carrier-grade NAT, deprecated
site-local, IPv4-compatible IPv6, well-known NAT64 and 6to4 addresses are denied.
Limited broadcast is denied. IPv4 addresses ending in `.255` are conservatively
denied, including mapped forms and range-wide directed-broadcast addresses.
This can reject legitimate hosts on larger subnets. An IP-only module cannot
identify every directed broadcast under an arbitrary interface netmask; the
caller must enforce its actual subnet boundaries where that is required.
Likewise it cannot detect custom translation prefixes, routing configuration,
or metadata/services placed at other otherwise-allowed private IPs.
There is no allow-public flag or override.

## Required per-connection integration

1. Parse the configured target.
2. Resolve the target and every relay endpoint freshly for each new connection.
   A literal target needs no DNS; construct its numeric socket directly.
3. Pass the complete target answer set and complete relay IP set to
   `validate_resolved`. Do not prefilter unsafe DNS answers into a safe subset.
4. Connect only to exact numeric sockets returned by that call. Do not perform
   another DNS lookup, reconnect with cached validation, or fall back to the
   original hostname. Retries that create a new connection repeat this process.

Validation rejects an empty target set, over 32 target answers (before
deduplication), an empty relay set, any non-LAN address, any wrong target port,
any nonzero IPv6 scope, or any relay alias. Relay comparison treats native and
IPv4-mapped addresses as equivalent regardless of port. Numeric literal targets
are also pinned to their requested IP. Because `GatewayTarget` fields are public,
validation rechecks target syntax and policy even for manually constructed or
mutated instances. Literal identity is taken from that canonical parse result,
so manually supplied bracketed IPv6 and mapped IPv4 literals remain pinned to
the exact requested address.

The whole answer set must pass before any sockets are returned. Duplicate
destination IP/port pairs are removed in input order, with native/mapped IPv4
equivalence; each retained value is the exact original numeric `SocketAddr`.
The function cannot prove DNS freshness, completeness, or that the caller really
connects to the returned socket. The caller owns those integration requirements,
as well as authentication, authorization, deadlines, firewall and route policy.

## Verification

Run `python3 tools/check_gateway_policy.py`. It compiles this file directly with
`rustc --edition=2021 --test` and executes its unit tests. Tests cover malformed
input mutations, range boundaries, mixed private/public DNS answers, transition
address families, mapped relay aliases, ports, duplicates, answer limits,
revalidation after target/relay changes, forged structs and scoped addresses.
