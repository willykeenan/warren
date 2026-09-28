# Private device attachment service — candidate

This is a local connector component, not a shipped Add device screen. It selects
devices discovered on one of the gateway's own interfaces and asks Warren to
create or revoke an exact named gateway share. It does not proxy a web UI, decode
RTSP, mount SMB, install the phone app, or enroll machines.

## Local operation

Run `python3 -m gateway_connector.device_service --state PRIVATE_SSD_DIRECTORY
--warren /absolute/path/to/warren --warren-home PRIVATE_WARREN_HOME --port PORT`.
The supplied Warren binary must include the gateway-share implementation. No
external packages are required. The service binds **127.0.0.1 only**. A retained
file lock prevents two service instances from writing the same registry. State
directories must be owned by the current user and mode 0700; files must be 0600.
The configured directory and its ancestors must remain under the user's custody.
POSIX is currently qualified. Windows ACL qualification is still required; the
service refuses to start there rather than treating mode bits as an ACL.

The native client reaches this loopback endpoint through an explicitly
key-restricted ordinary Warren share and uses the private bearer from
`auth.json`. Secure enrollment must deliver that token directly to the native
client over Warren; there is **no token delivery or enrollment implementation in
this module**. Do not put the token in the hub, URLs, logs, QR analytics, agent
messages, browser storage or public shares. Device login credentials never pass
through this API. The user enters those only in the device's own prompt.

Requests require one `Authorization: Bearer TOKEN` header. The Host is a
loopback name/address, or `warren-gateway` for a native forwarded request. POST
bodies use `application/json` and are limited to 8192 bytes. Browser Origin,
transfer encoding, duplicate authorization/content-length/JSON keys, and unknown
schema fields are rejected. There is no CORS or request logging. Responses are
no-store. The process has eight request slots and socket timeouts; the private
Warren transport is required and this is not an Internet-facing HTTP server.

## Contract for the phone/desktop owner

All endpoints except `/v1/summary` are gateway-local private data. Do not forward
their records to the hub or widget telemetry.

`GET /v1/interfaces` requires the same bearer, Host and Origin guards as every
other endpoint. It reads only local OS metadata; listing sends no packets, opens
no network socket and performs no DNS lookup. Example (documentation addresses):

```json
{"interfaces":[{"name":"en0","address":"192.168.1.10","prefix_length":24,"cidr":"192.168.1.10/24","family":"ipv4"}],"discovery_limits":{"deadline_seconds":5,"max_hosts":256}}
```

Only these five interface fields are returned. Names are unmodified OS labels
restricted to 1–64 ASCII letters, digits, `_`, `.`, `:`, or `-`; render as plain
text. The service never infers a Wi-Fi/Ethernet role or substitutes a /24. No MAC,
SSID, route, bearer, credential, device name or other OS metadata is returned.
At most 64 records are returned in deterministic label/address order after all
ambiguity checks. Eligible records are active private host addresses with their
actual prefixes, excluding loopback, public/metadata/boundary addresses, scoped
or link-local IPv6, tentative/failed addresses and duplicate IP selections even
when the duplicates have different names or prefixes. IPv6 ULA is supported.
An empty eligible list is a successful `interfaces:[]`; the native client should
explain that no supported active interface is available, without starting a scan.

Enumeration has a two-second local-command/parse budget and a one-MiB output
read cap. macOS uses `/sbin/ifconfig -a`; Linux uses `ip -j address show up`.
Malformed output, command failure or timeout returns 503 `interfaces_unavailable`.
Windows/other unsupported enumeration returns 503 `platform_not_qualified`;
Windows private-state ACL qualification also remains a service startup boundary.
Neither error includes raw OS output. Process termination/OS scheduling cleanup
can extend the wall-clock return beyond the enumeration budget; this is not a
hard real-time guarantee.

Listing and discovery serialize on one request lock; overlapping operations
return 409 `discovery_already_running`. A successful list replaces a process-local
map of at most 64 CIDRs to OS names. This map only detects a renamed/moved issued
selection; it is not authorization or a substitute for fresh OS metadata. It is
lost on restart, and a later successful list replaces it. There is no durable
interface identity or per-client selection token. Discovery without a preceding
list still requires a fresh unique exact host/prefix match. Missing, changed-prefix,
duplicate or known moved selections return 409 `interface_changed` **before any
discovery socket opens**; the client must refresh and explicitly reselect. Malformed
or unsupported host CIDRs return 400 `invalid_interface`. The server never silently
selects another name or scans all interfaces. Changes after validation remain an
OS/network race; this is not a lease on the interface configuration.

`POST /v1/discover` takes `{"interface":"192.168.1.10/24"}`
where the CIDR exactly matches an active **host address and prefix** on the
gateway. The discovery module verifies that interface independently, uses bounded
mDNS/SSDP/WS-Discovery and common-port probes, and does not follow advertised URLs.
The API gives discovery five seconds and a 256-host maximum. Discovered addresses
must remain inside that interface's private network. Public, metadata, subnet
boundary, malformed and mapped/scoped IPv6 addresses are not offered by this API.
Known service protocols may use any explicitly advertised integer port from
1 to 65535; the scan itself still probes only common ports. Discovery transport
details are in GATEWAY-DISCOVERY.md.

The response contains `scan_id`, `expires_in:120`, and `devices`. Each device has
an opaque `id`, a local `name` and `address`, `kind`, `services` (protocol/port
pairs), and `sensitive`. ONVIF/RTSP observations and discovery camera classifications
retain their sensitive label. IPPS is preserved. An ONVIF-only device remains
visible but cannot be attached as a working viewer: the service returns
`device_protocol_not_supported`, because it lacks a resolved viewer/transport
contract. Only four unexpired
discovery snapshots are retained in memory.

`POST /v1/attach` takes `scan_id`, `device_id`, `protocol`, integer `port`, and
optionally a nonempty `peers` list of pinned Warren names. It cannot take an
arbitrary address, URL, password, token or username. It must match an unexpired
discovery selection and advertised service. Omitted peers use Warren's snapshot
of currently pinned peers; no pinned peers means Warren refuses the grant. The
generated name is `device-` plus 16 random hexadecimal characters.
The exact discovered network prefix is persisted privately with each attachment,
so restarting the gateway never substitutes an invented /24 or /64 boundary.

Successful response: `{"device":{...,"share":"device-...","state":"attached"}}`.
The API runs argv, never a shell:

```
warren --json share --target NUMERIC_ADDRESS:PORT --name device-ID [--to peer1,peer2]
```

It accepts only a successful CLI exit and `{name:exact_name,gateway:true}`.
An intent is durably saved before calling Warren. A timeout, malformed reply,
refusal or failed final save remains pending/uncertain; retry never silently
replays that grant. The user must explicitly revoke it before attaching again.
Concurrent duplicate selections yield a single grant. Changing peers on an
existing attachment requires revoke first.

`GET /v1/devices` returns the private registry reconciled with live Warren
`status` (`daemon.running:true`, `gateways:[{name:...}]`). A missing live grant is
shown as `missing`; a stopped or unreachable daemon returns 503, never a made-up
attached count. `GET /v1/summary` returns **only**
`{"attached_device_count":N}` for confirmed live managed grants and is the only
projection suitable for the hub. It does not currently synchronize to the hub.

`POST /v1/revoke` takes only `{"share":"device-..."}`. It records revoking intent
and calls `warren --json unshare --name ...`; only `{name:exact_name,removed:true}`
with exit zero confirms the acknowledgement. Warren owns immediate cancellation
of pending and active streams. A CLI timeout or failed cleanup returns an error,
never success. Unknown names cannot revoke other owners' shares. A manually
removed grant can require local reconciliation if Warren returns removed:false;
the API preserves the uncertain record and does not replay a grant.

## Evidence and remaining integration

`python3 -m unittest discover -s tests -p test_device_service.py -v` exercises
real loopback HTTP, state permissions and single-writer locking, concurrent
attach, strict selection and credentials rejection, saved-state restart,
uncertain results, failed persistence, manual removal, daemon failure, CLI
acknowledgement parsing, authenticated interface listing, private response fields,
serialized selection and stale-interface rejection before traffic. Warren and discovery calls are controlled test doubles;
these tests are not evidence of live-device attachment or phone delivery.

Required next integration: secure native enrollment/token custody, active
native interface-selection UI, the three Add device paths, phone/desktop screens and
viewers, sensitive camera controls and local stream conversion, gateway status
plumbing, two-node end-to-end tests, native Windows qualification, and the real
LAN-device/simulated-iPhone acceptance. No installation or release occurs here.
