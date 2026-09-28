"""Private local API regression tests. No device discovery or external sockets."""
import concurrent.futures
import http.client
import importlib.util
import json
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("device_service", Path(__file__).parents[1] / "gateway_connector/device_service.py")
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


class FakeWarren:
    def __init__(self):
        self.calls, self.active = [], set()
        self.fail = False

    def __call__(self, args):
        self.calls.append(args)
        if self.fail:
            raise RuntimeError("private password must never escape")
        if args == ["status"]:
            return {"daemon": {"running": True}, "gateways": [{"name": s} for s in self.active]}
        name = args[args.index("--name") + 1]
        if args[0] == "share":
            self.active.add(name)
            return {"name": name, "gateway": True}
        self.active.discard(name)
        return {"name": name, "removed": True}


@unittest.skipUnless(os.name == "posix", "POSIX private API qualification")
class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state"
        self.warren = FakeWarren()
        self.now = 100.
        self.rows = [{"address": "192.168.1.27", "name": "Camera", "services": [
            {"protocol": "rtsp", "port": 554}, {"protocol": "http", "port": 80}]}]
        self.discovery_calls = []

        def discover(*args, **kwargs):
            self.discovery_calls.append((args, kwargs))
            return self.rows
        self.discover = discover
        self.service = api.DeviceService(self.path, self.warren, discover, lambda: self.now)

    def tearDown(self):
        self.service.close()
        self.tmp.cleanup()

    def selection(self):
        scan = self.service.dispatch("POST", "/v1/discover", {"interface": "192.168.1.10/24"})
        return {"scan_id": scan["scan_id"], "device_id": scan["devices"][0]["id"], "protocol": "rtsp", "port": 554}

    def attach(self):
        return self.service.dispatch("POST", "/v1/attach", self.selection())["device"]

    def test_attach_revoke_live_summary_and_restart(self):
        entry = self.attach()
        self.assertTrue(entry["sensitive"])
        self.assertEqual(self.warren.calls[0], ["share", "--target", "192.168.1.27:554", "--name", entry["share"]])
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 1})
        token = self.service.token
        self.service.close()
        self.service = api.DeviceService(self.path, self.warren, self.discover)
        self.assertEqual(self.service.token, token)
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 1})
        self.assertEqual(self.service.dispatch("POST", "/v1/revoke", {"share": entry["share"]}), {"revoked": True})
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 0})

    def test_concurrent_attach_is_idempotent(self):
        body = self.selection()
        body["peers"] = ["phone", "mac", "phone"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.service.dispatch("POST", "/v1/attach", body), range(12)))
        self.assertEqual(len({r["device"]["share"] for r in results}), 1)
        self.assertEqual(len([c for c in self.warren.calls if c[0] == "share"]), 1)
        self.assertEqual(self.warren.calls[0][-2:], ["--to", "mac,phone"])

    def test_rejects_credentials_and_arbitrary_target_without_cli(self):
        body = self.selection()
        for key in ("password", "token", "url", "address", "target", "username"):
            with self.subTest(key=key), self.assertRaisesRegex(api.DeviceError, "invalid_fields"):
                self.service.dispatch("POST", "/v1/attach", {**body, key: "sensitive"})
        self.assertEqual(self.warren.calls, [])
        self.assertNotIn(b"sensitive", (self.path / "auth.json").read_bytes())

    def test_expired_wrong_and_modified_service(self):
        body = self.selection()
        for bad in ({**body, "port": 22}, {**body, "port": True}, {**body, "protocol": "https"}):
            with self.assertRaisesRegex(api.DeviceError, "service_not_discovered"):
                self.service.dispatch("POST", "/v1/attach", bad)
        for bad in ({**body, "scan_id": "forged"}, {**body, "device_id": []}):
            with self.assertRaisesRegex(api.DeviceError, "discovery_selection_expired"):
                self.service.dispatch("POST", "/v1/attach", bad)
        self.now += 121
        with self.assertRaisesRegex(api.DeviceError, "discovery_selection_expired"):
            self.service.dispatch("POST", "/v1/attach", body)
        self.assertEqual(self.warren.calls, [])

    def test_unknown_and_injected_peers_rejected(self):
        body = self.selection()
        for peers in ([], ["phone,evil"], ["--flag"], ["phone\nsecret"], "phone", [None]):
            with self.subTest(peers=peers), self.assertRaisesRegex(api.DeviceError, "invalid_peers"):
                self.service.dispatch("POST", "/v1/attach", {**body, "peers": peers})

    def test_cli_timeout_never_replays_grant(self):
        body = self.selection()
        self.warren.fail = True
        with self.assertRaisesRegex(api.DeviceError, "attachment_uncertain_revoke_before_retry"):
            self.service.dispatch("POST", "/v1/attach", body)
        self.assertEqual(next(iter(self.service.devices.values()))["state"], "uncertain")
        with self.assertRaisesRegex(api.DeviceError, "existing_attachment_requires_revoke"):
            self.service.dispatch("POST", "/v1/attach", body)
        self.assertEqual(len(self.warren.calls), 1)

    def test_failed_intent_persist_never_calls_warren(self):
        body = self.selection()
        with patch.object(self.service.store, "write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.service.dispatch("POST", "/v1/attach", body)
        self.assertEqual(self.service.devices, {})
        self.assertEqual(self.warren.calls, [])

    def test_success_then_persist_failure_is_uncertain_and_not_replayed(self):
        body = self.selection()
        real = self.service.store.write
        def write(name, value):
            if next(iter(value["devices"].values()))["state"] == "attached":
                raise OSError("disk full")
            real(name, value)
        with patch.object(self.service.store, "write", side_effect=write):
            with self.assertRaisesRegex(api.DeviceError, "attachment_uncertain"):
                self.service.dispatch("POST", "/v1/attach", body)
        self.assertEqual(next(iter(self.service.devices.values()))["state"], "uncertain")
        saved = json.loads((self.path / "devices.json").read_text())
        self.assertEqual(next(iter(saved["devices"].values()))["state"], "pending")
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 0})

    def test_revocation_failure_is_not_success(self):
        entry = self.attach()
        self.warren.fail = True
        with self.assertRaisesRegex(api.DeviceError, "revocation_not_confirmed"):
            self.service.dispatch("POST", "/v1/revoke", {"share": entry["share"]})
        self.assertEqual(self.service.devices[entry["share"]]["state"], "uncertain")

    def test_manual_revoke_and_offline_status_never_report_attached(self):
        entry = self.attach()
        self.warren.active.clear()
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 0})
        self.assertEqual(self.service.dispatch("GET", "/v1/devices", {})["devices"][0]["state"], "missing")
        self.warren.fail = True
        with self.assertRaisesRegex(api.DeviceError, "gateway_status_unavailable"):
            self.service.public_summary()

    def test_returned_records_are_not_mutable_state(self):
        entry = self.attach()
        entry["service"]["port"] = 22
        result = self.service.dispatch("GET", "/v1/devices", {})
        result["devices"][0]["services"].clear()
        self.assertEqual(next(iter(self.service.devices.values()))["service"]["port"], 554)
        self.assertEqual(len(next(iter(self.service.devices.values()))["services"]), 2)

    def test_discovery_filters_off_subnet_metadata_public_and_malformed(self):
        base = self.rows[0]
        self.rows += [{**base, "address": a} for a in ["8.8.8.8", "192.168.2.1", "169.254.169.254", "192.168.1.255", "192.168.1.0", "127.0.0.1", "garbage"]]
        self.rows += [{**base, "services": None}, {**base, "services": [{"protocol": [], "port": 80}]}]
        result = self.service.dispatch("POST", "/v1/discover", {"interface": "192.168.1.10/24"})
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(self.discovery_calls[0][1], {"deadline_seconds": 5.0, "max_hosts": 256, "expected_interface_name": None})

    def test_only_one_state_writer(self):
        with self.assertRaisesRegex(api.DeviceError, "device_service_already_running"):
            api.DeviceService(self.path, self.warren, self.discover)

    def test_camera_classification_advertised_ports_and_ipps_survive(self):
        net = api.ipaddress.ip_network("192.168.1.0/24")
        for protocols in ([('onvif', 8000)], [('onvif', 8000), ('http', 80)], [('rtsp', 8554)]):
            row = {"address": "192.168.1.27", "kind": "camera", "sensitive": True,
                   "services": [{"protocol": p, "port": n} for p, n in protocols]}
            clean = api.clean_device(row, net)
            self.assertEqual(clean["kind"], "camera")
            self.assertIs(clean["sensitive"], True)
            self.assertEqual(clean["services"], row["services"])
        for protocol, port in (("http", 8000), ("ipps", 631)):
            row = {"address": "192.168.1.27", "services": [{"protocol": protocol, "port": port}]}
            self.assertEqual(api.clean_device(row, net)["services"], row["services"])

    def test_onvif_only_discovery_is_visible_but_not_a_fake_viewer(self):
        self.rows[0]["services"] = [{"protocol": "onvif", "port": 8000}]
        scan = self.service.dispatch("POST", "/v1/discover", {"interface": "192.168.1.10/24"})
        self.assertTrue(scan["devices"][0]["sensitive"])
        with self.assertRaisesRegex(api.DeviceError, "device_protocol_not_supported"):
            self.service.dispatch("POST", "/v1/attach", {"scan_id": scan["scan_id"],
                "device_id": scan["devices"][0]["id"], "protocol": "onvif", "port": 8000})
        self.assertEqual(self.warren.calls, [])

    def test_saved_actual_subnet_survives_restart(self):
        self.rows[0]["address"] = "192.168.1.0"
        scan = self.service.dispatch("POST", "/v1/discover", {"interface": "192.168.0.10/23"})
        body = {"scan_id": scan["scan_id"], "device_id": scan["devices"][0]["id"],
                "protocol": "rtsp", "port": 554}
        self.service.dispatch("POST", "/v1/attach", body)
        self.service.close()
        self.service = api.DeviceService(self.path, self.warren, self.discover)
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 1})
        self.assertEqual(next(iter(self.service.devices.values()))["network"], "192.168.0.0/23")

    def test_state_permissions_symlink_and_malformed_registry_fail_closed(self):
        entry = self.attach()
        self.service.close()
        registry = self.path / "devices.json"
        os.chmod(registry, 0o644)
        with self.assertRaisesRegex(api.DeviceError, "unsafe_state_file"):
            api.DeviceService(self.path, self.warren, self.discover)
        os.chmod(registry, 0o600)
        saved = json.loads(registry.read_text())
        saved["devices"][entry["share"]]["password"] = "must not be read"
        registry.write_text(json.dumps(saved))
        with self.assertRaisesRegex(api.DeviceError, "invalid_device_registry"):
            api.DeviceService(self.path, self.warren, self.discover)
        registry.unlink()
        registry.symlink_to(self.path / "auth.json")
        with self.assertRaises(OSError):
            api.DeviceService(self.path, self.warren, self.discover)

    def test_list_mapping_is_bounded_replaced_and_discovery_serialized(self):
        d = api.local_interfaces
        local = ipaddress.ip_interface("192.168.1.10/24")
        with patch.object(d, "_active_interfaces", return_value=[("en0", local)]):
            result = self.service.dispatch("GET", "/v1/interfaces", {})
        self.assertEqual(result["discovery_limits"], {"deadline_seconds": 5, "max_hosts": 256})
        self.assertEqual(self.service.interface_selection, {str(local): "en0"})
        with patch.object(d, "_active_interfaces", return_value=[]):
            self.assertEqual(self.service.dispatch("GET", "/v1/interfaces", {})["interfaces"], [])
        self.assertEqual(self.service.interface_selection, {})
        self.service.scanning.acquire()
        try:
            with patch.object(d, "list_interfaces") as listing:
                with self.assertRaisesRegex(api.DeviceError, "discovery_already_running"):
                    self.service.dispatch("GET", "/v1/interfaces", {})
                listing.assert_not_called()
        finally: self.service.scanning.release()

    def test_stale_moved_and_ambiguous_selection_is_409_before_network(self):
        d = api.local_interfaces
        local = ipaddress.ip_interface("192.168.1.10/24")
        self.service.discover = d.discover
        for rows in [[], [("en1", local)], [("en0", ipaddress.ip_interface("192.168.1.10/25"))],
                     [("en0", local), ("en1", local)]]:
            with patch.object(d, "_active_interfaces", return_value=[("en0", local)]):
                self.service.dispatch("GET", "/v1/interfaces", {})
            with patch.object(d, "_active_interfaces", return_value=rows), patch.object(socket, "socket", side_effect=AssertionError("no traffic")):
                with self.assertRaises(api.DeviceError) as failure:
                    self.service.dispatch("POST", "/v1/discover", {"interface": str(local)})
                self.assertEqual((failure.exception.status, failure.exception.code), (409, "interface_changed"))
        self.assertEqual(self.service.scans, {})

    def test_map_never_replaces_fresh_validation_and_invalid_host_rejected(self):
        d = api.local_interfaces
        self.service.discover = d.discover
        for mapping in [{}, {"192.168.1.10/24": "en0"}]:
            self.service.interface_selection = mapping
            with patch.object(d, "_active_interfaces", return_value=[]) as active, patch.object(socket, "socket", side_effect=AssertionError("no traffic")):
                with self.assertRaisesRegex(api.DeviceError, "interface_changed"):
                    self.service.dispatch("POST", "/v1/discover", {"interface": "192.168.1.10/24"})
                active.assert_called_once()
        for value in ["192.168.1.0/24", "192.168.1.10", "fe80::1/64", "169.254.169.254/16"]:
            with self.assertRaisesRegex(api.DeviceError, "invalid_interface"):
                self.service.dispatch("POST", "/v1/discover", {"interface": value})



class WarrenClientTests(unittest.TestCase):
    def test_exact_argv_and_acknowledgement(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "warren"
            binary.touch()
            client = api.WarrenClient(binary, tmp)
            args = ["share", "--target", "192.168.1.27:554", "--name", "device-a"]
            good = subprocess.CompletedProcess([], 0, b'{"name":"device-a","gateway":true}', b"")
            with patch.object(api.subprocess, "run", return_value=good) as run:
                self.assertTrue(client(args)["gateway"])
                self.assertEqual(run.call_args.args[0], [str(binary.resolve()), "--json", *args])
                self.assertEqual(run.call_args.kwargs["env"]["WARREN_HOME"], str(Path(tmp).resolve()))
                self.assertNotIn("shell", run.call_args.kwargs)
            for body in (b'{"ok":true}', b'{"name":"other","gateway":true}', b'null', b'private password'):
                with patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, body, b"")):
                    with self.assertRaisesRegex(api.DeviceError, "warren_result_uncertain"):
                        client(args)
            with patch.object(api.subprocess, "run", side_effect=subprocess.TimeoutExpired("secret", 1)):
                with self.assertRaisesRegex(api.DeviceError, "warren_result_uncertain"):
                    client(args)


@unittest.skipUnless(os.name == "posix", "POSIX private API qualification")
class HttpTests(unittest.TestCase):
    selection = DeviceTests.selection
    attach = DeviceTests.attach

    def setUp(self):
        DeviceTests.setUp(self)
        self.http = api.server(self.service)
        self.thread = threading.Thread(target=self.http.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)
        DeviceTests.tearDown(self)

    def request(self, method="GET", path="/v1/summary", body=None, headers=None):
        conn = http.client.HTTPConnection(*self.http.server_address, timeout=3)
        request_headers = {"Authorization": "Bearer " + self.service.token, "Content-Type": "application/json"}
        request_headers.update(headers or {})
        conn.request(method, path, body, request_headers)
        response = conn.getresponse()
        result = response.status, dict(response.headers), json.loads(response.read())
        conn.close()
        return result

    def test_loopback_authenticated_count_only(self):
        self.attach()
        status, headers, body = self.request()
        self.assertEqual(self.http.server_address[0], "127.0.0.1")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"attached_device_count": 1})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_auth_origin_and_host_guards(self):
        for headers, status in (({"Authorization": "Bearer wrong"}, 401), ({"Origin": "https://evil.example"}, 403),
                                ({"Origin": ""}, 403), ({"Host": "evil.example"}, 403)):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(headers=headers)[0], status)

    def test_body_schema_limits_and_sanitized_failures(self):
        cases = [("{bad", 400), ('{"interface":"192.168.1.10/24","password":"secret"}', 400),
                 ('{"interface":"one","interface":"two"}', 400), ("x" * 8193, 413)]
        for body, status in cases:
            with self.subTest(status=status):
                response = self.request("POST", "/v1/discover", body)
                self.assertEqual(response[0], status)
                self.assertNotIn("secret", json.dumps(response[2]))
        self.warren.fail = True
        self.assertEqual(self.request()[2], {"error": "gateway_status_unavailable"})

    def test_interfaces_authenticated_no_store_and_safe_schema(self):
        d = api.local_interfaces
        with patch.object(d, "_active_interfaces", return_value=[("en0", ipaddress.ip_interface("192.168.1.10/24"))]) as active:
            self.assertEqual(self.request(path="/v1/interfaces", headers={"Authorization": "Bearer wrong"})[0], 401)
            active.assert_not_called()
            status, headers, body = self.request(path="/v1/interfaces")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body, {"interfaces": [{"name": "en0", "address": "192.168.1.10", "prefix_length": 24,
            "cidr": "192.168.1.10/24", "family": "ipv4"}], "discovery_limits": {"deadline_seconds": 5, "max_hosts": 256}})
        self.assertEqual(self.service.public_summary(), {"attached_device_count": 0})

    def test_interfaces_empty_failure_and_platform_errors(self):
        d = api.local_interfaces
        with patch.object(d, "_active_interfaces", return_value=[]):
            self.assertEqual(self.request(path="/v1/interfaces")[2]["interfaces"], [])
        for error, code in [(d.DiscoveryError("private diagnostic"), "interfaces_unavailable"),
                            (d.PlatformNotQualified("Windows"), "platform_not_qualified")]:
            with patch.object(d, "list_interfaces", side_effect=error):
                response = self.request(path="/v1/interfaces")
            self.assertEqual((response[0], response[2]), (503, {"error": code}))

    def test_duplicate_authorization_rejected(self):
        port = self.http.server_address[1]
        payload = (f"GET /v1/summary HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   f"Authorization: Bearer {self.service.token}\r\nAuthorization: Bearer wrong\r\n\r\n").encode()
        with socket.create_connection(self.http.server_address, timeout=3) as connection:
            connection.sendall(payload)
            self.assertIn(b" 401 ", connection.recv(4096))


if __name__ == "__main__":
    unittest.main()
