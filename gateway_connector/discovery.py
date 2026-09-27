"""Bounded gateway-local discovery. Device details must never enter public telemetry.

Interface enumeration and sockets are module seams for offline tests. No import
performs I/O; callers explicitly invoke discover with an active interface CIDR.
"""
from __future__ import annotations

import errno
import ipaddress
import io
import itertools
import json
import math
import platform
import re
import selectors
import socket
import struct
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

MAX_PACKET = 16_384
MAX_DEVICES = 256
MAX_SOCKETS = 16
MAX_PACKETS = 256
PORTS = {80: "http", 443: "https", 554: "rtsp", 445: "smb", 631: "ipp"}
SERVICE_TYPES = {
    "_http._tcp.local": "http", "_https._tcp.local": "https",
    "_rtsp._tcp.local": "rtsp", "_smb._tcp.local": "smb",
    "_ipp._tcp.local": "ipp", "_ipps._tcp.local": "ipps",
}
_ALLOWED = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
))
_ONVIF_NS = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
_SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"


class DiscoveryError(ValueError):
    """The selected network cannot safely be established as an active local subnet."""


def _private_ip(value):
    try:
        if not isinstance(value, str) or "%" in value:
            return None
        address = ipaddress.ip_address(value)
        return address if any(address.version == n.version and address in n for n in _ALLOWED) else None
    except ValueError:
        return None


def _name(value):
    # Untrusted names are display text, never HTML or credentials/URL storage.
    if not isinstance(value, str) or len(value) > 253 or not value.strip():
        return ""
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "@" in value or "://" in value:
        return ""
    return value.strip()


def _device(address, name="", services=()):
    address = _private_ip(str(address))
    if address is None:
        return None
    clean = sorted({(p, port) for p, port in services
                    if p in {*PORTS.values(), "ipps", "onvif"}
                    and isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535})
    protocols = {p for p, _ in clean}
    kind = ("camera" if protocols & {"rtsp", "onvif"} else "printer" if protocols & {"ipp", "ipps"}
            else "nas" if "smb" in protocols else "web device" if protocols & {"http", "https"} else "device")
    return {"id": f"ip:{address}", "name": _name(name), "kind": kind, "address": str(address),
            "services": [{"protocol": p, "port": port} for p, port in clean],
            "sensitive": kind == "camera"}


def build_public_summary(devices):
    """Only a count crosses the gateway boundary; never serialize device objects."""
    return {"attached_device_count": len(devices)}


def _dns_name(data, offset):
    labels, visited, end, expanded = [], set(), None, 0
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise ValueError("invalid DNS compression")
        visited.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("short DNS pointer")
            pointer = ((size & 0x3F) << 8) | data[offset + 1]
            # RFC compression points backward; prohibit forward/cyclic expansion.
            if pointer >= offset:
                raise ValueError("forward DNS pointer")
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if size & 0xC0 or size > 63 or offset + size + 1 > len(data):
            raise ValueError("invalid DNS label")
        offset += 1
        if size == 0:
            return ".".join(labels), end if end is not None else offset
        label = data[offset:offset + size].decode("utf-8", "strict")
        if "." in label or any(ord(c) < 32 or ord(c) == 127 for c in label):
            raise ValueError("unsafe DNS label")
        labels.append(label)
        expanded += size + 1
        if expanded > 254:
            raise ValueError("oversized DNS name")
        offset += size
    raise ValueError("too much DNS compression")


def parse_mdns_packet(data: bytes, source_ip: str) -> list[dict]:
    """Accept only known DNS-SD services whose SRV target resolves to the sender.

    TXT records, aliases, remote targets and contradictory RRs are not retained.
    DNS-SD replies are observations, not authenticated device identity.
    """
    source = _private_ip(source_ip)
    if source is None or not isinstance(data, bytes) or not 12 <= len(data) <= MAX_PACKET:
        return []
    try:
        _, flags, questions, answers, authority, additional = struct.unpack_from("!6H", data)
        if not flags & 0x8000 or flags & 0x7A0F or questions > 32 or answers + authority + additional > 128:
            return []
        offset, records = 12, {}
        for _ in range(questions):
            _, offset = _dns_name(data, offset)
            if offset + 4 > len(data):
                return []
            offset += 4
        for _ in range(answers + authority + additional):
            owner, offset = _dns_name(data, offset)
            record_type, record_class, ttl, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            end = offset + length
            if end > len(data):
                return []
            value = None
            if record_class & 0x7FFF == 1 and ttl:
                if record_type in (1, 28):
                    if length != (4 if record_type == 1 else 16):
                        return []
                    value = str(ipaddress.ip_address(data[offset:end]))
                elif record_type == 12:
                    target, consumed = _dns_name(data, offset)
                    if consumed != end:
                        return []
                    value = target.lower()
                elif record_type == 33:
                    if length < 7:
                        return []
                    _, _, port = struct.unpack_from("!HHH", data, offset)
                    target, consumed = _dns_name(data, offset + 6)
                    if consumed != end or not port:
                        return []
                    value = (port, target.lower())
                if value is not None:
                    records.setdefault((owner.lower(), record_type), set()).add(value)
            offset = end
        if offset != len(data):
            return []
        devices = []
        for (owner, record_type), values in sorted(records.items()):
            if record_type != 33 or len(values) != 1:
                continue
            service = next((s for s in SERVICE_TYPES if owner.endswith("." + s)), None)
            if not service:
                continue
            port, target = next(iter(values))
            if not target.endswith(".local"):
                continue
            addresses = records.get((target, 1 if source.version == 4 else 28), set())
            if addresses != {str(source)}:
                continue
            # PTR is optional in direct service responses; a conflicting PTR is ignored.
            ptrs = records.get((service, 12))
            if ptrs is not None and owner not in ptrs:
                continue
            display = owner[:-(len(service) + 1)]
            devices.append(_device(source, display, [(SERVICE_TYPES[service], port)]))
        return [d for d in devices if d]
    except (ValueError, UnicodeError, struct.error):
        return []


def _safe_endpoint(value, source):
    """Validate a literal same-sender endpoint, without resolving or fetching it."""
    try:
        if not value or len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value):
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or parsed.username is not None or parsed.password is not None:
            return None
        if parsed.fragment or _private_ip(parsed.hostname) != source:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme, port) if 1 <= port <= 65535 else None
    except (ValueError, TypeError):
        return None


def parse_ssdp_reply(data: bytes, source_ip: str) -> list[dict]:
    source = _private_ip(source_ip)
    if source is None or not isinstance(data, bytes) or not data or len(data) > MAX_PACKET:
        return []
    try:
        text = data.decode("ascii", "strict")
        if "\r\n\r\n" not in text:
            return []
        lines = text.split("\r\n")
        if len(lines) > 64 or not re.fullmatch(r"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", lines[0]):
            return []
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if line[0].isspace() or ":" not in line or any(ord(c) < 32 or ord(c) == 127 for c in line):
                return []
            key, value = line.split(":", 1)
            key, value = key.lower(), value.strip()
            if not re.fullmatch(r"[a-z0-9-]+", key) or key in headers:
                return []
            headers[key] = value
        if not headers.get("st") or not headers.get("usn"):
            return []
        endpoint = _safe_endpoint(headers.get("location", ""), source)
        if endpoint is None:
            return []
        # SERVER/USN/LOCATION are not trustworthy names and may contain identifiers.
        return [_device(source, services=[endpoint])]
    except (ValueError, UnicodeError):
        return []


def parse_onvif_reply(data: bytes, source_ip: str) -> list[dict]:
    source = _private_ip(source_ip)
    if source is None or not isinstance(data, bytes) or not data or len(data) > MAX_PACKET:
        return []
    # UTF-8 only prevents UTF-16 encodings from hiding entity declarations.
    try:
        text = data.decode("utf-8", "strict")
        if "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            return []
        namespaces, depth, nodes = {}, 0, 0
        parsed = ET.iterparse(io.StringIO(text), events=("start-ns", "start", "end"))
        for event, value in parsed:
            if event == "start-ns":
                prefix, uri = value
                if prefix in namespaces and namespaces[prefix] != uri:
                    return []
                namespaces[prefix] = uri
            elif event == "start":
                depth += 1
                nodes += 1
                if depth > 16 or nodes > 128:
                    return []
            else:
                depth -= 1
        root = parsed.root
        if root.tag != f"{{{_SOAP_NS}}}Envelope":
            return []
        devices = []
        for match in root.findall(f"./{{{_SOAP_NS}}}Body/{{{_ONVIF_NS}}}ProbeMatches/{{{_ONVIF_NS}}}ProbeMatch"):
            types = match.find(f"{{{_ONVIF_NS}}}Types")
            if types is None:
                continue
            camera_type = False
            for token in (types.text or "").split():
                prefix, _, local_name = token.rpartition(":")
                if local_name == "NetworkVideoTransmitter" and namespaces.get(prefix) == "http://www.onvif.org/ver10/network/wsdl":
                    camera_type = True
            if not camera_type:
                continue
            endpoints = match.findall(f"{{{_ONVIF_NS}}}XAddrs")
            if len(endpoints) != 1:
                continue
            urls = (endpoints[0].text or "").split()
            if not 1 <= len(urls) <= 8:
                continue
            services = [_safe_endpoint(url, source) for url in urls]
            if any(s is None for s in services):
                continue
            # Do not retain XAddrs paths, scopes, device UUIDs or credential data.
            devices.append(_device(source, services=[("onvif", port) for _, port in services]))
        return devices
    except (ValueError, UnicodeError, ET.ParseError):
        return []


def _run_interface_command(argv, timeout):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True, shell=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError("Cannot inspect active local interfaces") from exc
    if len(result.stdout) > 1_048_576:
        raise DiscoveryError("Interface listing exceeded limit")
    return result.stdout


def _active_interfaces(timeout):
    """Return (interface name, ip_interface) pairs from local OS metadata only."""
    system = platform.system()
    found = []
    try:
        if system == "Linux":
            raw = _run_interface_command(["ip", "-j", "address", "show", "up"], timeout)
            rows = json.loads(raw)
            if not isinstance(rows, list) or len(rows) > 512:
                raise ValueError("invalid interface listing")
            for row in rows:
                if "UP" not in row.get("flags", []) or "LOOPBACK" in row.get("flags", []):
                    continue
                if row.get("operstate") not in ("UP", "UNKNOWN"):
                    continue
                for addr in row.get("addr_info", []):
                    if addr.get("family") not in ("inet", "inet6") or any(addr.get(f) for f in ("tentative", "dadfailed")) or set(addr.get("flags", [])) & {"tentative", "dadfailed"}:
                        continue
                    found.append((row["ifname"], ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}")))
        elif system == "Darwin":
            raw = _run_interface_command(["/sbin/ifconfig", "-a"], timeout)
            for block in re.split(r"(?m)(?=^[^\s:]+: flags=)", raw):
                header = re.match(r"([^\s:]+): flags=\d+<([^>]+)>", block)
                if not header or not {"UP", "RUNNING"}.issubset(set(header[2].split(","))):
                    continue
                if "LOOPBACK" in header[2].split(",") or re.search(r"status:\s*inactive", block):
                    continue
                for address, mask in re.findall(r"(?m)^\s+inet ([\d.]+) netmask (0x[\da-fA-F]+|[\d.]+)", block):
                    if mask.startswith("0x"):
                        mask = str(ipaddress.IPv4Address(int(mask, 16)))
                    found.append((header[1], ipaddress.ip_interface(f"{address}/{mask}")))
                for address, prefix in re.findall(r"(?m)^\s+inet6 ([\da-fA-F:%\w.]+) prefixlen (\d+)", block):
                    found.append((header[1], ipaddress.ip_interface(f"{address.split('%')[0]}/{prefix}")))
        else:
            raise DiscoveryError("Local subnet validation supports macOS and Linux; Windows is not supported yet")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, DiscoveryError):
            raise
        raise DiscoveryError("Invalid local interface metadata") from exc
    return found


def _select_interface(cidr, timeout):
    try:
        if not isinstance(cidr, str) or "/" not in cidr or "%" in cidr:
            raise ValueError("host CIDR required")
        requested = ipaddress.ip_interface(cidr)
        if not any(requested.version == n.version and requested.network.subnet_of(n) for n in _ALLOWED):
            raise ValueError("not a private or link-local subnet")
        if _private_ip(str(requested.ip)) is None:
            raise ValueError("not a local address")
        matches = [(name, address) for name, address in _active_interfaces(timeout) if address == requested]
        if len(matches) != 1:
            raise ValueError("CIDR must match one active local interface address and prefix exactly")
        return matches[0]
    except ValueError as exc:
        raise DiscoveryError(str(exc)) from exc


def _cancelled(cancel):
    if cancel is None:
        return False
    return bool(cancel() if callable(cancel) else cancel.is_set())


def _query_name(value):
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in value.split(".")) + b"\0"


def _queries():
    mdns = struct.pack("!6H", 0, 0, len(SERVICE_TYPES), 0, 0, 0)
    mdns += b"".join(_query_name(s) + struct.pack("!HH", 12, 0x8001) for s in SERVICE_TYPES)
    ssdp = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    onvif = (f'<s:Envelope xmlns:s="{_SOAP_NS}" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
             f'xmlns:d="{_ONVIF_NS}" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
             f'<s:Header><a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>'
             '<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
             f'<a:Action>{_ONVIF_NS}/Probe</a:Action></s:Header>'
             '<s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>').encode()
    return [("224.0.0.251", 5353, mdns, parse_mdns_packet),
            ("239.255.255.250", 1900, ssdp, parse_ssdp_reply),
            ("239.255.255.250", 3702, onvif, parse_onvif_reply)]


def _in_subnet(value, network):
    address = _private_ip(value)
    if address is None or address.version != network.version or address not in network:
        return False
    return not (address.version == 4 and network.prefixlen < 31 and address in (network.network_address, network.broadcast_address))


def discover(interface_cidr: str, *, deadline_seconds=5.0, max_hosts=256, cancel=None) -> list[dict]:
    """One bounded discovery pass on one verified local interface.

    Raises DiscoveryError/ValueError before traffic for unsupported or invalid
    selections. Cancellation or the deadline returns observations collected so
    far; all sockets are closed before return. No HTTP/device-control payloads.
    """
    if isinstance(deadline_seconds, bool) or not isinstance(deadline_seconds, (int, float)) or not math.isfinite(deadline_seconds) or not 0 < deadline_seconds <= 30:
        raise ValueError("deadline_seconds must be finite and between 0 and 30")
    if isinstance(max_hosts, bool) or not isinstance(max_hosts, int) or not 1 <= max_hosts <= MAX_DEVICES:
        raise ValueError("max_hosts must be an integer from 1 to 256")
    started = time.monotonic()
    deadline = started + deadline_seconds
    if _cancelled(cancel):
        return []
    interface_name, interface = _select_interface(interface_cidr, min(2.0, deadline_seconds))
    if _cancelled(cancel) or time.monotonic() >= deadline:
        return []
    family = socket.AF_INET if interface.version == 4 else socket.AF_INET6
    scope = socket.if_nametoindex(interface_name) if interface.version == 6 and interface.ip.is_link_local else 0
    local = (str(interface.ip), 0) if family == socket.AF_INET else (str(interface.ip), 0, 0, scope)
    hosts = itertools.islice((h for h in interface.network.hosts() if h != interface.ip), max_hosts)
    targets = iter((str(h), port) for h in hosts for port in PORTS)
    devices, names, active, packets = {}, {}, {}, 0
    exhausted = False

    def add(row):
        if not isinstance(row, dict) or not _in_subnet(row.get("address"), interface.network) or row["address"] == str(interface.ip):
            return
        address = str(ipaddress.ip_address(row["address"]))
        if address not in devices and len(devices) >= max_hosts:
            return
        valid_services = []
        for service in row.get("services", []):
            if isinstance(service, dict):
                valid_services.append((service.get("protocol"), service.get("port")))
        current = devices.get(address)
        if current:
            valid_services.extend((s["protocol"], s["port"]) for s in current["services"])
        display = _name(row.get("name"))
        if display:
            names.setdefault(address, set()).add(display)
        # Conflicting advertised names are omitted; identity is the observed IP.
        candidates = names.get(address, set())
        devices[address] = _device(address, next(iter(candidates)) if len(candidates) == 1 else "", valid_services)

    with selectors.DefaultSelector() as selector:
        def close(sock):
            active.pop(sock, None)
            try:
                selector.unregister(sock)
            except (KeyError, ValueError):
                pass
            sock.close()

        try:
            if family == socket.AF_INET:
                for group, port, payload, parser in _queries():
                    if _cancelled(cancel) or time.monotonic() >= deadline:
                        break
                    sock = None
                    try:
                        sock = socket.socket(family, socket.SOCK_DGRAM)
                        sock.setblocking(False)
                        sock.bind(local)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(str(interface.ip)))
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                        sock.sendto(payload, (group, port))
                        selector.register(sock, selectors.EVENT_READ)
                        active[sock] = ("udp", parser, None)
                    except OSError:
                        if sock is not None:
                            close(sock)
            while not _cancelled(cancel) and time.monotonic() < deadline:
                now = time.monotonic()
                for sock, (mode, value, expires) in list(active.items()):
                    if mode == "tcp" and now >= expires:
                        close(sock)
                while not exhausted and len(active) < MAX_SOCKETS and not _cancelled(cancel) and time.monotonic() < deadline:
                    target = next(targets, None)
                    if target is None:
                        exhausted = True
                        break
                    address, port = target
                    sock = None
                    try:
                        sock = socket.socket(family, socket.SOCK_STREAM)
                        sock.setblocking(False)
                        sock.bind(local)
                        if family == socket.AF_INET:
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
                        else:
                            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1)
                        endpoint = (address, port) if family == socket.AF_INET else (address, port, 0, scope)
                        error = sock.connect_ex(endpoint)
                        if error == 0:
                            add(_device(address, services=[(PORTS[port], port)]))
                            close(sock)
                        elif error in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR):
                            selector.register(sock, selectors.EVENT_WRITE)
                            active[sock] = ("tcp", (address, port), min(deadline, time.monotonic() + 0.35))
                        else:
                            close(sock)
                    except OSError:
                        if sock is not None:
                            close(sock)
                if not active:
                    break
                timeout = min(0.05, max(0, deadline - time.monotonic()))
                for key, _ in selector.select(timeout):
                    if _cancelled(cancel) or time.monotonic() >= deadline:
                        break
                    sock = key.fileobj
                    if sock not in active:
                        continue
                    mode, value, _ = active[sock]
                    try:
                        if mode == "tcp":
                            address, port = value
                            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                                add(_device(address, services=[(PORTS[port], port)]))
                            close(sock)
                        else:
                            data, sender = sock.recvfrom(MAX_PACKET + 1)
                            packets += 1
                            if len(data) <= MAX_PACKET and _in_subnet(sender[0], interface.network):
                                for row in value(data, sender[0]):
                                    if row.get("address") == sender[0]:
                                        add(row)
                            if packets >= MAX_PACKETS:
                                for udp, (kind, _, _) in list(active.items()):
                                    if kind == "udp":
                                        close(udp)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        close(sock)
        finally:
            for sock in list(active):
                close(sock)
    return [devices[a] for a in sorted(devices, key=lambda a: int(ipaddress.ip_address(a)))]
