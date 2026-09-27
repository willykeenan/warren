"""Offline discovery checks. Every discovery test replaces sockets and interfaces."""
import errno
import ipaddress
import json
import selectors
import socket
import struct
import subprocess
import threading
import types
import unittest
from unittest import mock

from gateway_connector import discovery as d

SOURCE = "192.168.50.20"
LOCAL = ipaddress.ip_interface("192.168.50.10/24")


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def rr(name, kind, value, ttl=120):
    return dns_name(name) + struct.pack("!HHIH", kind, 1, ttl, len(value)) + value


def mdns(ip=SOURCE, port=631, duplicate=None):
    service, instance, target = "_ipp._tcp.local", "Office Printer._ipp._tcp.local", "printer.local"
    records = [rr(service, 12, dns_name(instance)),
               rr(instance, 33, struct.pack("!HHH", 0, 0, port) + dns_name(target)),
               rr(target, 1, ipaddress.ip_address(ip).packed)]
    if duplicate is not None:
        records.append(rr(instance, 33, struct.pack("!HHH", 0, 0, duplicate) + dns_name(target)))
    return struct.pack("!6H", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def ssdp(location=None):
    location = location or f"http://{SOURCE}:8080/private/device.xml?token=secret"
    return f"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:private-id\r\nLOCATION: {location}\r\nSERVER: private-model\r\n\r\n".encode()


def onvif(location=None, kinds="dn:NetworkVideoTransmitter"):
    location = location or f"http://{SOURCE}:8000/onvif/device_service"
    return (f'<s:Envelope xmlns:s="{d._SOAP_NS}" xmlns:d="{d._ONVIF_NS}" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            f'<s:Body><d:ProbeMatches><d:ProbeMatch><d:Types>{kinds}</d:Types>'
            f'<d:XAddrs>{location}</d:XAddrs><d:Scopes>private-location</d:Scopes>'
            '</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>').encode()


class PacketTests(unittest.TestCase):
    def test_public_summary_has_only_count(self):
        private = [{"name": "SECRET", "address": SOURCE, "password": "SECRET"}]
        self.assertEqual(d.build_public_summary(private), {"attached_device_count": 1})
        self.assertEqual(d.build_public_summary([]), {"attached_device_count": 0})

    def test_mdns_schema(self):
        rows = d.parse_mdns_packet(mdns(), SOURCE)
        self.assertEqual(rows, [{"id": f"ip:{SOURCE}", "name": "office printer", "address": SOURCE,
                                 "kind": "printer", "sensitive": False,
                                 "services": [{"protocol": "ipp", "port": 631}]}])

    def test_mdns_compressed_record_owner(self):
        # An A owner compressed to its earlier SRV target is accepted.
        instance = "Cam._rtsp._tcp.local"
        prefix = struct.pack("!6H", 0, 0x8400, 0, 2, 0, 0)
        srv = rr(instance, 33, struct.pack("!HHH", 0, 0, 554) + dns_name("cam.local"))
        target_offset = 12 + len(dns_name(instance)) + 10 + 6
        address = struct.pack("!HHHIH", 0xC000 | target_offset, 1, 1, 120, 4) + ipaddress.ip_address(SOURCE).packed
        rows = d.parse_mdns_packet(prefix + srv + address, SOURCE)
        self.assertEqual(rows[0]["kind"], "camera")
        self.assertTrue(rows[0]["sensitive"])

    def test_mdns_ipv6_fixture(self):
        source = "fd12::20"
        records = rr("NAS._smb._tcp.local", 33, struct.pack("!HHH", 0, 0, 445) + dns_name("nas.local"))
        records += rr("nas.local", 28, ipaddress.ip_address(source).packed)
        rows = d.parse_mdns_packet(struct.pack("!6H", 0, 0x8400, 0, 2, 0, 0) + records, source)
        self.assertEqual(rows[0]["kind"], "nas")

    def test_mdns_rejects_spoofed_target_and_conflicting_srv(self):
        self.assertEqual(d.parse_mdns_packet(mdns("192.168.50.30"), SOURCE), [])
        self.assertEqual(d.parse_mdns_packet(mdns(duplicate=123), SOURCE), [])
        self.assertEqual(d.parse_mdns_packet(mdns(), "8.8.8.8"), [])

    def test_mdns_bad_compression_and_bounds(self):
        header = struct.pack("!6H", 0, 0x8400, 0, 1, 0, 0)
        packets = [b"", b"\0" * 11, b"x" * (d.MAX_PACKET + 1), header + b"\xc0\x0c",
                   header + b"\xc0\xff", header + b"\xff", mdns()[:-1], mdns() + b"garbage",
                   struct.pack("!6H", 0, 0x8400, 0, 129, 0, 0),
                   struct.pack("!6H", 0, 0x8600, 0, 0, 0, 0)]
        for packet in packets:
            with self.subTest(packet=packet[:20]):
                self.assertEqual(d.parse_mdns_packet(packet, SOURCE), [])

    def test_ssdp_keeps_only_source_and_service(self):
        row = d.parse_ssdp_reply(ssdp(), SOURCE)[0]
        self.assertEqual(row["services"], [{"protocol": "http", "port": 8080}])
        self.assertEqual(row["name"], "")
        for secret in ("secret", "private-id", "private-model", "device.xml"):
            self.assertNotIn(secret, json.dumps(row))

    def test_ssdp_invalid_location_never_resolves_or_fetches(self):
        for location in ("https://example.com/device", "http://8.8.8.8/x", "http://192.168.50.21/x",
                         f"http://user:password@{SOURCE}/x", f"file://{SOURCE}/x", f"http://{SOURCE}:0/x",
                         f"http://{SOURCE}:99999/x", f"http://{SOURCE}/x#fragment"):
            with self.subTest(location=location), mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                self.assertEqual(d.parse_ssdp_reply(ssdp(location), SOURCE), [])

    def test_ssdp_malformed_and_duplicates(self):
        for packet in (ssdp().replace(b"200 OK", b"404 Nope"), ssdp().replace(b"ST:", b" ST:"),
                       ssdp().replace(b"SERVER:", b"LOCATION:"), b"x" * (d.MAX_PACKET + 1), b"\xff"):
            self.assertEqual(d.parse_ssdp_reply(packet, SOURCE), [])

    def test_onvif_minimal_observation(self):
        row = d.parse_onvif_reply(onvif(), SOURCE)[0]
        self.assertEqual(row["kind"], "camera")
        self.assertTrue(row["sensitive"])
        self.assertEqual(row["services"], [{"protocol": "onvif", "port": 8000}])
        self.assertNotIn("onvif/device", json.dumps(row))
        self.assertNotIn("private-location", json.dumps(row))

    def test_onvif_rejects_entities_xml_and_remote_targets(self):
        packets = [b'<!DOCTYPE x [<!ENTITY x "bad">]>' + onvif(), b"<!ENTITY x SYSTEM 'file:///tmp/x'>",
                   onvif().decode().encode("utf-16"), b"<broken", b"x" * (d.MAX_PACKET + 1),
                   onvif("http://8.8.8.8/onvif"), onvif(f"http://admin:secret@{SOURCE}/onvif"),
                   onvif(f"http://{SOURCE}/onvif http://192.168.50.21/onvif"), onvif(kinds="dn:Printer"), onvif(kinds="fake:NetworkVideoTransmitter"),
                   onvif().replace(b"http://www.onvif.org/ver10/network/wsdl", b"http://example.invalid/pretend")]
        for packet in packets:
            with self.subTest(packet=packet[:40]):
                self.assertEqual(d.parse_onvif_reply(packet, SOURCE), [])

    def test_parsers_bounded_random_and_truncated_data(self):
        # Deterministic offline fuzz controls, including every truncation boundary.
        for parser, valid in ((d.parse_mdns_packet, mdns()), (d.parse_ssdp_reply, ssdp()), (d.parse_onvif_reply, onvif())):
            for index in range(len(valid)):
                rows = parser(valid[:index], SOURCE)
                self.assertIsInstance(rows, list)
            for size in range(0, 1024, 17):
                self.assertEqual(parser(bytes((i * 73 + size) % 256 for i in range(size)), SOURCE), [])


class InterfaceTests(unittest.TestCase):
    def test_exact_active_cidr_is_required(self):
        with mock.patch.object(d, "_active_interfaces", return_value=[("en0", LOCAL)]):
            self.assertEqual(d._select_interface(str(LOCAL), 1), ("en0", LOCAL))
            for value in ("192.168.50.0/24", "192.168.50.10/16", "192.168.99.1/24", "192.168.50.10"):
                with self.subTest(value=value), self.assertRaises(d.DiscoveryError):
                    d._select_interface(value, 1)

    def test_rejects_public_loopback_supernets_and_ambiguous_interfaces(self):
        with mock.patch.object(d, "_active_interfaces", return_value=[("en0", LOCAL), ("en1", LOCAL)]):
            for value in ("8.8.8.8/24", "127.0.0.1/8", "0.0.0.0/0", "192.168.1.1/0", "100.64.1.1/24",
                          "::1/128", "2001:db8::1/64", "fc00::1/0", str(LOCAL)):
                with self.subTest(value=value), self.assertRaises(d.DiscoveryError):
                    d._select_interface(value, 1)

    def test_local_ranges(self):
        for cidr in ("10.1.2.3/24", "172.16.1.2/24", "169.254.1.2/24", "fd00::1/120", "fe80::1/64"):
            interface = ipaddress.ip_interface(cidr)
            with mock.patch.object(d, "_active_interfaces", return_value=[("en0", interface)]):
                self.assertEqual(d._select_interface(cidr, 1)[1], interface)

    def test_linux_interface_listing(self):
        listing = [{"ifname": "eth0", "flags": ["UP", "BROADCAST"], "operstate": "UP",
                    "addr_info": [{"family": "inet", "local": str(LOCAL.ip), "prefixlen": 24}]},
                   {"ifname": "eth1", "flags": ["UP"], "operstate": "DOWN", "addr_info": []}]
        with mock.patch.object(d.platform, "system", return_value="Linux"), mock.patch.object(d, "_run_interface_command", return_value=json.dumps(listing)) as run:
            self.assertEqual(d._active_interfaces(0.7), [("eth0", LOCAL)])
            run.assert_called_once_with(["ip", "-j", "address", "show", "up"], 0.7)

    def test_macos_active_only(self):
        listing = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.50.10 netmask 0xffffff00 broadcast 192.168.50.255
\tinet6 fe80::123%en0 prefixlen 64 secured scopeid 0x4
\tstatus: active
en1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
\tinet 192.168.22.1 netmask 0xffffff00
\tstatus: inactive
"""
        with mock.patch.object(d.platform, "system", return_value="Darwin"), mock.patch.object(d, "_run_interface_command", return_value=listing):
            self.assertEqual(d._active_interfaces(1), [("en0", LOCAL), ("en0", ipaddress.ip_interface("fe80::123/64"))])

    def test_interface_commands_bounded_argv_no_shell(self):
        with mock.patch.object(d.subprocess, "run", return_value=types.SimpleNamespace(stdout="ok")) as run:
            self.assertEqual(d._run_interface_command(["/sbin/ifconfig", "-a"], 0.3), "ok")
            self.assertEqual(run.call_args.kwargs["timeout"], 0.3)
            self.assertFalse(run.call_args.kwargs["shell"])
        with mock.patch.object(d.subprocess, "run", side_effect=subprocess.TimeoutExpired(["ip"], 0.3)), self.assertRaises(d.DiscoveryError):
            d._run_interface_command(["ip"], 0.3)

    def test_windows_and_invalid_metadata_fail_closed(self):
        with mock.patch.object(d.platform, "system", return_value="Windows"), self.assertRaises(d.DiscoveryError):
            d._active_interfaces(1)
        with mock.patch.object(d.platform, "system", return_value="Linux"), mock.patch.object(d, "_run_interface_command", return_value="{}"), self.assertRaises(d.DiscoveryError):
            d._active_interfaces(1)


class FakeClock:
    now = 0.0

    def monotonic(self):
        return self.now


class FakeNetwork:
    def __init__(self, clock, replies=None, connect_error=errno.EINPROGRESS, ready=True, connection_result=0):
        self.clock, self.replies, self.connect_error = clock, replies or {}, connect_error
        self.ready, self.connection_result = ready, connection_result
        self.created, self.connects, self.sent = [], [], []
        self.open_count, self.peak = 0, 0
        self.cancel_after = None

    def socket(self, family, kind):
        network = self

        class Sock:
            def __init__(self):
                self.family, self.kind, self.closed = family, kind, False
                self.options, self.queue = [], []
                network.open_count += 1
                network.peak = max(network.peak, network.open_count)
                network.created.append(self)

            def setblocking(self, value):
                assert value is False

            def bind(self, value):
                self.bound = value

            def setsockopt(self, *value):
                self.options.append(value)

            def sendto(self, payload, endpoint):
                network.sent.append((self, payload, endpoint))
                self.queue.extend(network.replies.get(endpoint[1], []))
                return len(payload)

            def connect_ex(self, endpoint):
                self.endpoint = endpoint
                network.connects.append(endpoint)
                if network.cancel_after and len(network.connects) >= network.cancel_after[0]:
                    network.cancel_after[1].set()
                return network.connect_error

            def getsockopt(self, *args):
                return network.connection_result

            def recvfrom(self, size):
                if not self.queue:
                    raise BlockingIOError()
                return self.queue.pop(0)

            def close(self):
                if not self.closed:
                    network.open_count -= 1
                    self.closed = True
        return Sock()

    def selector(self):
        network = self

        class Selector:
            def __init__(self):
                self.sockets = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def register(self, sock, event):
                self.sockets[sock] = event

            def unregister(self, sock):
                del self.sockets[sock]

            def select(self, timeout):
                network.clock.now += timeout
                return [(types.SimpleNamespace(fileobj=sock), event) for sock, event in self.sockets.items()
                        if sock.queue or (sock.kind == socket.SOCK_STREAM and network.ready)]
        return Selector()


class ScanTests(unittest.TestCase):
    def run_scan(self, network, cidr=str(LOCAL), interfaces=None, **kwargs):
        with mock.patch.object(d, "_active_interfaces", return_value=interfaces or [("en0", LOCAL)]), \
                mock.patch.object(d.socket, "socket", side_effect=network.socket), \
                mock.patch.object(d.selectors, "DefaultSelector", side_effect=network.selector), \
                mock.patch.object(d.time, "monotonic", side_effect=network.clock.monotonic), \
                mock.patch.object(d.socket, "getaddrinfo", side_effect=AssertionError("No DNS resolution")):
            return d.discover(cidr, **kwargs)

    def test_scan_caps_bindings_protocols_privacy_and_dedup(self):
        network = FakeNetwork(FakeClock(), replies={5353: [(mdns(), (SOURCE, 5353))],
                              1900: [(ssdp(), (SOURCE, 1900))], 3702: [(onvif(), (SOURCE, 3702))]})
        rows = self.run_scan(network, max_hosts=25, deadline_seconds=2)
        self.assertLessEqual(len(rows), 25)
        self.assertLessEqual(network.peak, 16)
        self.assertEqual(network.open_count, 0)
        self.assertEqual(len(network.sent), 3)
        self.assertLessEqual(len(network.connects), 25 * 5)
        self.assertEqual({x[1] for x in network.connects}, set(d.PORTS))
        self.assertTrue(all(sock.bound == (str(LOCAL.ip), 0) for sock in network.created))
        self.assertTrue(all(endpoint[0] in {str(h) for h in LOCAL.network.hosts()} for endpoint in network.connects))
        self.assertTrue(all((socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) in sock.options for sock, _, _ in network.sent))
        self.assertTrue(all((socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(str(LOCAL.ip))) in sock.options for sock, _, _ in network.sent))
        self.assertEqual(len({r["id"] for r in rows}), len(rows))
        row = next(r for r in rows if r["address"] == SOURCE)
        self.assertTrue(row["sensitive"])
        self.assertIn({"protocol": "onvif", "port": 8000}, row["services"])
        self.assertEqual(d.build_public_summary(rows), {"attached_device_count": len(rows)})
        self.assertNotIn("private", json.dumps(rows))
        self.assertEqual(rows, sorted(rows, key=lambda r: int(ipaddress.ip_address(r["address"]))))

    def test_spoofed_outside_subnet_and_broadcast_replies_ignored(self):
        replies = [(ssdp(), ("192.168.51.20", 1900)), (ssdp(), ("8.8.8.8", 1900)),
                   (ssdp(), ("192.168.50.255", 1900)), (ssdp(), ("192.168.50.0", 1900)),
                   (ssdp(), ("192.168.50.21", 1900))]
        network = FakeNetwork(FakeClock(), replies={1900: replies}, connect_error=errno.ECONNREFUSED)
        self.assertEqual(self.run_scan(network, max_hosts=1, deadline_seconds=1), [])
        self.assertEqual(network.open_count, 0)

    def test_cancel_before_any_interface_or_socket_work(self):
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(d, "_active_interfaces", side_effect=AssertionError("No interfaces")), \
                mock.patch.object(d.socket, "socket", side_effect=AssertionError("No sockets")):
            self.assertEqual(d.discover(str(LOCAL), cancel=cancelled), [])

    def test_cancel_during_connect_closes_every_socket(self):
        event = threading.Event()
        network = FakeNetwork(FakeClock())
        network.cancel_after = (4, event)
        self.assertEqual(self.run_scan(network, cancel=event), [])
        self.assertEqual(len(network.connects), 4)
        self.assertEqual(network.open_count, 0)

    def test_timeout_bound_and_inflight_cap(self):
        clock = FakeClock()
        network = FakeNetwork(clock, ready=False)
        self.assertEqual(self.run_scan(network, deadline_seconds=0.2), [])
        self.assertLessEqual(clock.now, 0.200001)
        self.assertLessEqual(network.peak, 16)
        self.assertEqual(len(network.connects), 13)
        self.assertEqual(network.open_count, 0)

    def test_max_hosts_exact_budget_and_tcp_is_only_connect(self):
        network = FakeNetwork(FakeClock(), connect_error=0)
        rows = self.run_scan(network, max_hosts=2, deadline_seconds=0.1)
        self.assertEqual(len(network.connects), 10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(network.open_count, 0)
        # Fake sockets expose no send/sendall; attempts to send HTTP would fail.

    def test_no_sockets_when_validation_fails(self):
        with mock.patch.object(d, "_active_interfaces", return_value=[]), \
                mock.patch.object(d.socket, "socket", side_effect=AssertionError("No traffic before validation")):
            with self.assertRaises(d.DiscoveryError):
                d.discover(str(LOCAL))

    def test_invalid_limits_never_open_sockets(self):
        with mock.patch.object(d.socket, "socket", side_effect=AssertionError("No sockets")):
            for kwargs in ({"max_hosts": 0}, {"max_hosts": 257}, {"max_hosts": True}, {"max_hosts": 1.5},
                           {"deadline_seconds": 0}, {"deadline_seconds": 31}, {"deadline_seconds": float("nan")},
                           {"deadline_seconds": float("inf")}, {"deadline_seconds": True}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    d.discover(str(LOCAL), **kwargs)

    def test_ipv6_own_subnet_probes_with_no_ipv4_multicast(self):
        interface = ipaddress.ip_interface("fd00::2/126")
        network = FakeNetwork(FakeClock(), connect_error=0)
        rows = self.run_scan(network, cidr=str(interface), interfaces=[("en0", interface)], max_hosts=2)
        self.assertEqual(network.sent, [])
        self.assertTrue(rows)
        self.assertEqual(network.open_count, 0)
        self.assertTrue(all(sock.bound == ("fd00::2", 0, 0, 0) for sock in network.created))

    def test_packet_flood_has_hard_receive_budget(self):
        network = FakeNetwork(FakeClock(), replies={1900: [(b"bad", (SOURCE, 1900))] * 300}, connect_error=errno.ECONNREFUSED)
        self.assertEqual(self.run_scan(network, max_hosts=1, deadline_seconds=30), [])
        udp = next(sock for sock, _, (_, port) in network.sent if port == 1900)
        self.assertEqual(len(udp.queue), 300 - d.MAX_PACKETS)
        self.assertEqual(network.open_count, 0)

    def test_deadline_includes_interface_enumeration(self):
        clock = FakeClock()

        def inspect(timeout):
            self.assertLessEqual(timeout, 0.1)
            clock.now += 0.2
            return [("en0", LOCAL)]

        with mock.patch.object(d, "_active_interfaces", side_effect=inspect), \
                mock.patch.object(d.time, "monotonic", side_effect=clock.monotonic), \
                mock.patch.object(d.socket, "socket", side_effect=AssertionError("Expired before traffic")):
            self.assertEqual(d.discover(str(LOCAL), deadline_seconds=0.1), [])

    def test_socket_setup_failure_closes_unregistered_sockets(self):
        network = FakeNetwork(FakeClock())
        create = network.socket

        def broken_socket(family, kind):
            sock = create(family, kind)
            sock.bind = mock.Mock(side_effect=OSError("interface disappeared"))
            return sock

        network.socket = broken_socket
        self.assertEqual(self.run_scan(network, max_hosts=2, deadline_seconds=0.2), [])
        self.assertEqual(network.open_count, 0)
        self.assertEqual(network.connects, [])
        self.assertEqual(network.sent, [])

    def test_oversized_datagram_and_self_response_ignored(self):
        network = FakeNetwork(FakeClock(), connect_error=errno.ECONNREFUSED,
                              replies={1900: [(b"x" * (d.MAX_PACKET + 1), (SOURCE, 1900)),
                                              (ssdp(f"http://{LOCAL.ip}/x"), (str(LOCAL.ip), 1900))]})
        self.assertEqual(self.run_scan(network, max_hosts=1, deadline_seconds=0.2), [])
        self.assertEqual(network.open_count, 0)

    def test_conflicting_names_are_omitted_and_services_merge(self):
        first = mdns()
        second = first.replace(b"Office Printer", b"Office Scanner")
        network = FakeNetwork(FakeClock(), connect_error=errno.ECONNREFUSED,
                              replies={5353: [(first, (SOURCE, 5353)), (second, (SOURCE, 5353))]})
        rows = self.run_scan(network, max_hosts=1, deadline_seconds=0.2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "")
        self.assertEqual(rows[0]["services"], [{"protocol": "ipp", "port": 631}])

    def test_all_immediate_tcp_attempts_exclude_the_gateway(self):
        network = FakeNetwork(FakeClock(), connect_error=errno.ECONNREFUSED)
        self.run_scan(network, max_hosts=15, deadline_seconds=0.1)
        self.assertEqual(len({endpoint[0] for endpoint in network.connects}), 15)
        self.assertNotIn(str(LOCAL.ip), {endpoint[0] for endpoint in network.connects})
        self.assertTrue(all((socket.IPPROTO_IP, socket.IP_TTL, 1) in sock.options
                            for sock in network.created if sock.kind == socket.SOCK_STREAM))

    def test_connection_refused_is_not_a_device(self):
        network = FakeNetwork(FakeClock(), connection_result=errno.ECONNREFUSED)
        self.assertEqual(self.run_scan(network, max_hosts=1, deadline_seconds=0.1), [])


if __name__ == "__main__":
    unittest.main()
