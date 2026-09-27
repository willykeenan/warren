# Gateway-local device discovery

This isolated standard-library Python module performs one explicit, bounded discovery pass on one selected local interface. It is a backend candidate; it is not installed hub functionality, a camera viewer, or permission to run a LAN scan. All verification supplied with this candidate uses offline packet fixtures and fake sockets.

## Integration API

```python
from gateway_connector.discovery import DiscoveryError, discover, build_public_summary

# Supply the selected interface's actual host address AND actual prefix.
# Invoke only in the gateway process after the user's discovery action.
# devices = discover("192.168.50.10/24", deadline_seconds=5.0, max_hosts=256,
#                    cancel=threading.Event())
# public_status = build_public_summary(devices)
```

`discover(interface_cidr: str, *, deadline_seconds=5.0, max_hosts=256, cancel=None) -> list[dict]` validates the selected CIDR before opening any socket. The address and prefix must match exactly one active OS interface. A network-only CIDR, fabricated address, wider prefix, ambiguous duplicate interface address, public subnet, loopback, CGNAT, or `/0` fails closed with `DiscoveryError`. Supported address ranges are RFC1918, IPv4 link-local, IPv6 ULA and IPv6 link-local; the entire selected subnet must fit inside one of those ranges.

The macOS adapter reads `/sbin/ifconfig -a`, requiring UP/RUNNING and rejecting inactive interfaces. The Linux adapter reads `ip -j address show up`, requiring UP and an UP/UNKNOWN operational state while rejecting tentative/DAD-failed addresses. The Linux `ip` utility must be installed. These fixed-argument subprocesses use `shell=False`, a timeout of at most two seconds within the overall deadline, and a one-MiB parsed-output cap. Windows deliberately raises `DiscoveryError` until its active-interface adapter exists. A CIDR supplied by the UI is never accepted as proof of locality.

`cancel` accepts a `threading.Event`-compatible object or a zero-argument boolean callback. A cancellation or deadline returns observations collected so far, with all sockets closed. A callback must return promptly. Limits outside `0 < deadline_seconds <= 30` and integer `1 <= max_hosts <= 256` are rejected. The deadline includes interface enumeration; normal event-loop cancellation latency is at most its 50 ms selector wait, plus bounded parsing and local OS-call time. This is not a hard real-time guarantee.

Each device has exactly these keys:

```json
{
  "id": "ip:192.168.50.20",
  "name": "office printer",
  "kind": "printer",
  "address": "192.168.50.20",
  "services": [{"protocol": "ipp", "port": 631}],
  "sensitive": false
}
```

Identity is the observed source IP, not a durable hardware identifier. DNS-SD instance names are untrusted display text, normalized to lowercase; render them as text, never markup. Unknown names remain empty and conflicting names are omitted. The gateway merges services per IP and sorts devices numerically and services lexically. Classification priority is camera (`rtsp` or ONVIF video-transmitter reply), printer (`ipp`/`ipps`), NAS (`smb`), then web device (`http`/`https`). Camera observations set `sensitive=true`. An open common TCP port supplies a tentative protocol classification, not verified device capabilities or authenticated identity.

The standalone packet APIs are `parse_mdns_packet(data: bytes, source_ip: str)`, `parse_ssdp_reply(data: bytes, source_ip: str)`, and `parse_onvif_reply(data: bytes, source_ip: str)`, each returning normalized device dictionaries or an empty list. They validate the sender against allowed address classes, and require any retained service endpoint to refer to that literal sender. `discover` adds actual selected-subnet, host-address and self-address rejection. Do not use a standalone parser as an authorization decision.

## Traffic and resource bounds

- One pass probes at most `max_hosts` addresses from the chosen subnet's ascending host sequence, excluding the gateway address, on TCP ports 80, 443, 554, 445 and 631. It stops at the overall deadline. Large networks are intentionally incomplete.
- At most 16 sockets are open at once, including three multicast listeners; normally at most 13 TCP connections are pending. Each pending TCP attempt expires after at most 350 ms. Sockets bind the selected local IP and use a one-hop TTL/hop limit. There are no retries or background jobs.
- IPv4 sends one small query each for mDNS (`224.0.0.251:5353`), SSDP (`239.255.255.250:1900`) and ONVIF WS-Discovery (`239.255.255.250:3702`). Each socket sets `IP_MULTICAST_IF` and TTL 1. mDNS requests unicast replies using the QU bit from an ephemeral source port; no multicast group joins or privileged ports are needed.
- IPv6 performs the same capped TCP sequence only; IPv6 multicast discovery is not implemented. Link-local sockets use the chosen interface's scope ID. Scanning the first 256 addresses of a typical `/64` is not effective address enumeration; the UI must describe this coverage honestly.
- Replies from outside the selected subnet, IPv4 broadcast/network addresses and the gateway itself are ignored. At most 256 datagrams, 16 KiB per datagram, and `max_hosts` output devices are processed/retained. DNS is additionally capped at 32 questions and 128 records with bounded label expansion and backward-pointer/loop checks; malformed or conflicting address/SRV records are ignored.
- SSDP requires a literal same-sender HTTP(S) Location and drops that URL after extracting the scheme and port. ONVIF accepts a bounded UTF-8 SOAP ProbeMatch for NetworkVideoTransmitter, rejects DTD/entity declarations and other-sender endpoints, and discards XAddrs, scopes and UUIDs. Neither parser fetches anything.

No HTTP request is sent to a device. TCP probes only establish/close a socket. The explicit multicast SSDP M-SEARCH is the discovery query required by SSDP; it does not fetch Location. No DNS resolver, password, credential, remote URL fetch, shell command, write command, camera stream, transcoding or device-control operation is used. UDP discovery and TCP connection attempts are still observable network activity, so the caller must retain user initiation and cancellation.

## Privacy and limitations

`build_public_summary(devices)` returns exactly `{"attached_device_count": len(devices)}`. Only pass that summary across the public status boundary. Device addresses, names and service details must remain on the gateway; the module itself does not persist, log, upload or authenticate anything. The helper intentionally does not inspect or serialize device fields.

Discovery protocols are unauthenticated and devices can misreport names or services. Same-source/subnet checks prevent following advertised remote targets, but do not authenticate a LAN sender. Filtering, firewalls, sleeping devices, short deadlines, large subnets and devices that omit DNS-SD address records can all yield incomplete results. mDNS only recognizes HTTP, HTTPS, RTSP, SMB, IPP and IPPS DNS-SD records; service capabilities are not invented for unknown records. SSDP with hostname-based Location is deliberately ignored without resolving it. No actual LAN behavior, Windows support, viewer integration or installed application behavior has been proven by this candidate.

## Offline verification and test seams

Run `python3 tools/check_gateway_discovery.py`. The tests replace `_active_interfaces`, `socket.socket`, `selectors.DefaultSelector` and `time.monotonic`. The `_run_interface_command` seam permits OS-output fixtures. Every discovery test uses fake sockets; parser tests also prohibit DNS resolution. Tests cover schemas/privacy, compressed and malformed DNS, XML entities, spoofed addresses and endpoints, platform parsing, exact interface membership, caps, cancellation, deadlines, deterministic sorting and cleanup. No live LAN scan is part of the verifier.
