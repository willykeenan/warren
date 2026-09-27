"""Private device attachment API. Run only behind a key-restricted Warren share.

No hub forwarding, device credentials, proxying, or camera decoding occurs here.
The caller owns Warren enrollment and native viewers; this module owns discovery
selection and acknowledged creation/revocation of exact named gateway shares.
"""
from __future__ import annotations

import argparse
import copy
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
ATTACH_PROTOCOLS = {"http", "https", "rtsp", "smb", "ipp", "ipps"}
DISCOVERY_PROTOCOLS = ATTACH_PROTOCOLS | {"onvif"}


class DeviceError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def private_directory(path):
    """Retain a private directory handle. Unsupported ACL platforms fail closed."""
    if os.name != "posix":
        raise DeviceError("gateway_api_platform_not_qualified", 503)
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(fd)
        raise DeviceError("private_state_permissions_required", 503)
    return fd


class PrivateStore:
    def __init__(self, path):
        self.fd = private_directory(path)
        self.lease = None
        try:
            import fcntl
            self.lease = os.open("writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                                 0o600, dir_fd=self.fd)
            info = os.fstat(self.lease)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise DeviceError("unsafe_state_file", 503)
            try:
                fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DeviceError("device_service_already_running", 409) from None
        except Exception:
            self.close()
            raise

    def close(self):
        if self.lease is not None:
            os.close(self.lease)
            self.lease = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read(self, name, default):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            return default
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 1024 * 1024):
                raise DeviceError("unsafe_state_file", 503)
            return json.load(f)

    def write(self, name, value):
        tmp = "." + name + "." + secrets.token_hex(12)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(value, f, separators=(",", ":"), ensure_ascii=True)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(tmp, dir_fd=self.fd)
            except FileNotFoundError:
                pass


class WarrenClient:
    def __init__(self, executable, home):
        executable = Path(executable)
        if not executable.is_absolute() or not executable.is_file():
            raise DeviceError("absolute_warren_binary_required", 503)
        self.executable = str(executable.resolve(strict=True))
        self.home = str(Path(home).resolve(strict=True))

    def __call__(self, args):
        try:
            result = subprocess.run([self.executable, "--json", *args],
                                    env={**os.environ, "WARREN_HOME": self.home},
                                    capture_output=True, timeout=25, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise DeviceError("warren_result_uncertain", 503) from None
        if result.returncode:
            # Neither stderr nor arbitrary daemon replies are shipped to clients.
            raise DeviceError("warren_refused", 409)
        try:
            reply = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise DeviceError("warren_result_uncertain", 503) from None
        if not isinstance(reply, dict):
            raise DeviceError("warren_result_uncertain", 503)
        if args[0] in {"share", "unshare"}:
            name = args[args.index("--name") + 1]
            acknowledgement = "gateway" if args[0] == "share" else "removed"
            if reply.get("name") != name or reply.get(acknowledgement) is not True:
                raise DeviceError("warren_result_uncertain", 503)
        return reply


def fields(value, required, optional=()):
    if (not isinstance(value, dict) or not set(required) <= value.keys()
            or value.keys() - set(required) - set(optional)):
        # Reject passwords/tokens/URLs/unknown fields instead of recording them.
        raise DeviceError("invalid_fields")


def clean_device(raw, network):
    if not isinstance(raw, dict):
        return None
    try:
        address = ipaddress.ip_address(raw["address"])
    except (KeyError, ValueError, TypeError):
        return None
    allowed = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
               ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("169.254.0.0/16"),
               ipaddress.ip_network("fc00::/7"), ipaddress.ip_network("fe80::/10"))
    if (address not in network or not any(address in n for n in allowed)
            or str(address) == "169.254.169.254" or getattr(address, "scope_id", None)
            or getattr(address, "ipv4_mapped", None)
            or address in {network.network_address, network.broadcast_address}):
        return None
    services = []
    raw_services = raw.get("services")
    if not isinstance(raw_services, list):
        return None
    for item in raw_services[:16]:
        if (isinstance(item, dict) and isinstance(item.get("protocol"), str)
                and item["protocol"] in DISCOVERY_PROTOCOLS
                and type(item.get("port")) is int
                and 1 <= item["port"] <= 65535):
            entry = {"protocol": item["protocol"], "port": item["port"]}
            if entry not in services:
                services.append(entry)
    if not services:
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip() or any(ord(c) < 32 or ord(c) == 127 for c in name):
        name = str(address)
    protocols = {s["protocol"] for s in services}
    camera = bool(protocols & {"rtsp", "onvif"}) or raw.get("kind") == "camera" or raw.get("sensitive") is True
    kind = "camera" if camera else "nas" if "smb" in protocols else "printer" if protocols & {"ipp", "ipps"} else "web"
    return {"id": secrets.token_urlsafe(16), "name": name[:96], "address": str(address),
            "kind": kind, "services": services, "sensitive": kind == "camera"}


class DeviceService:
    def __init__(self, state_dir, warren, discover, clock=time.monotonic):
        self.store, self.warren, self.discover, self.clock = PrivateStore(state_dir), warren, discover, clock
        self.lock = threading.Lock()
        self.scanning = threading.Lock()
        self.scans = {}
        try:
            saved = self.store.read("devices.json", {"version": 1, "devices": {}})
            if (not isinstance(saved, dict) or set(saved) != {"version", "devices"}
                    or saved.get("version") != 1 or not isinstance(saved.get("devices"), dict)
                    or len(saved["devices"]) > 256):
                raise DeviceError("invalid_device_registry", 503)
            self.devices = saved["devices"]
            for share, entry in self.devices.items():
                self.validate_saved(share, entry)
            auth = self.store.read("auth.json", None)
            if auth is None:
                auth = {"token": secrets.token_hex(32)}
                self.store.write("auth.json", auth)
            if (not isinstance(auth, dict) or set(auth) != {"token"}
                    or not isinstance(auth["token"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", auth["token"])):
                raise DeviceError("invalid_api_auth", 503)
            self.token = auth["token"]
        except Exception:
            self.close()
            raise

    @staticmethod
    def validate_saved(share, entry):
        try:
            required = {"id", "name", "address", "kind", "services", "sensitive",
                        "share", "service", "peers", "state", "network"}
            if (not isinstance(entry, dict) or set(entry) != required
                    or not re.fullmatch(r"device-[a-f0-9]{16}", share)
                    or entry["share"] != share
                    or entry["state"] not in {"pending", "attached", "uncertain", "revoking"}
                    or not isinstance(entry["id"], str)
                    or not isinstance(entry["name"], str) or len(entry["name"]) > 96):
                raise ValueError()
            if not isinstance(entry["network"], str):
                raise ValueError()
            cleaned = clean_device(entry, ipaddress.ip_network(entry["network"], strict=True))
            if (not cleaned or cleaned["services"] != entry["services"]
                    or cleaned["kind"] != entry["kind"] or cleaned["sensitive"] is not entry["sensitive"]
                    or entry["service"] not in cleaned["services"]):
                raise ValueError()
            peers = entry["peers"]
            if peers is not None and (not isinstance(peers, list) or not 1 <= len(peers) <= 64
                                      or any(not isinstance(p, str) or not NAME.fullmatch(p) for p in peers)):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise DeviceError("invalid_device_registry", 503) from None

    def close(self):
        self.store.close()

    def save(self):
        self.store.write("devices.json", {"version": 1, "devices": self.devices})

    def set_devices(self, devices):
        self.store.write("devices.json", {"version": 1, "devices": devices})
        self.devices = devices

    def public_summary(self):
        with self.lock:
            active = self.active_names()
            return {"attached_device_count": sum(d["state"] == "attached" and name in active
                                                  for name, d in self.devices.items())}

    def active_names(self):
        try:
            status = self.warren(["status"])
            if (not isinstance(status, dict) or status.get("daemon", {}).get("running") is not True
                    or not isinstance(status.get("gateways"), list)
                    or any(not isinstance(g, dict) or not isinstance(g.get("name"), str)
                           for g in status["gateways"])):
                raise ValueError()
            return {g["name"] for g in status["gateways"]}
        except Exception:
            raise DeviceError("gateway_status_unavailable", 503) from None

    def dispatch(self, method, path, body):
        if method == "GET" and path == "/v1/summary":
            return self.public_summary()
        if method == "GET" and path == "/v1/devices":
            with self.lock:
                active = self.active_names()
                devices = copy.deepcopy(list(self.devices.values()))
                for entry in devices:
                    if entry["state"] == "attached" and entry["share"] not in active:
                        entry["state"] = "missing"
                return {"devices": devices}
        if method == "POST" and path == "/v1/discover":
            fields(body, ["interface"])
            try:
                if not isinstance(body["interface"], str):
                    raise ValueError()
                network = ipaddress.ip_network(body["interface"], strict=False)
            except (ValueError, TypeError):
                raise DeviceError("invalid_interface") from None
            if not self.scanning.acquire(blocking=False):
                raise DeviceError("discovery_already_running", 409)
            try:
                # Discovery independently verifies an actual gateway interface.
                rows = self.discover(body["interface"], deadline_seconds=5.0, max_hosts=256)
                if not isinstance(rows, list):
                    raise DeviceError("invalid_discovery_result", 503)
                clean, addresses = [], set()
                for raw in rows[:256]:
                    entry = clean_device(raw, network)
                    if entry and entry["address"] not in addresses:
                        clean.append(entry)
                        addresses.add(entry["address"])
                scan_id = secrets.token_urlsafe(24)
                with self.lock:
                    now = self.clock()
                    self.scans = {k: v for k, v in self.scans.items() if v["expires"] > now}
                    if len(self.scans) >= 4:
                        self.scans.pop(next(iter(self.scans)))
                    self.scans[scan_id] = {"expires": now + 120, "network": str(network),
                                           "devices": {d["id"]: d for d in clean}}
                return {"scan_id": scan_id, "expires_in": 120, "devices": clean}
            finally:
                self.scanning.release()
        if method == "POST" and path == "/v1/attach":
            fields(body, ["scan_id", "device_id", "protocol", "port"], ["peers"])
            peers = body.get("peers")
            if peers is not None and (not isinstance(peers, list) or not peers or len(peers) > 64
                                      or any(not isinstance(p, str) or not NAME.fullmatch(p) for p in peers)):
                raise DeviceError("invalid_peers")
            if peers is not None:
                peers = sorted(set(peers))
            with self.lock:
                try:
                    scan = self.scans[body["scan_id"]]
                    device = scan["devices"][body["device_id"]]
                except (KeyError, TypeError):
                    raise DeviceError("discovery_selection_expired", 409) from None
                if scan["expires"] <= self.clock():
                    raise DeviceError("discovery_selection_expired", 409)
                service = {"protocol": body["protocol"], "port": body["port"]}
                if type(body["port"]) is not int or service not in device["services"]:
                    raise DeviceError("service_not_discovered")
                if body["protocol"] not in ATTACH_PROTOCOLS:
                    raise DeviceError("device_protocol_not_supported")
                for existing in self.devices.values():
                    if existing["address"] == device["address"] and existing["service"] == service:
                        if existing["state"] == "attached" and existing["peers"] == peers:
                            if existing["share"] not in self.active_names():
                                raise DeviceError("existing_attachment_requires_revoke", 409)
                            return {"device": copy.deepcopy(existing)}
                        raise DeviceError("existing_attachment_requires_revoke", 409)
                if len(self.devices) >= 256:
                    raise DeviceError("attached_device_limit", 409)
                share = "device-" + secrets.token_hex(8)
                entry = {**device, "share": share, "service": service, "peers": peers,
                         "state": "pending", "network": scan["network"]}
                # Persist intent before invoking Warren. An uncertain outcome is never replayed.
                self.set_devices({**self.devices, share: entry})
                host = device["address"]
                target = f"[{host}]:{body['port']}" if ":" in host else f"{host}:{body['port']}"
                args = ["share", "--target", target, "--name", share]
                if peers is not None:
                    args += ["--to", ",".join(peers)]
                try:
                    self.warren(args)
                except Exception:
                    entry["state"] = "uncertain"
                    self.save()
                    raise DeviceError("attachment_uncertain_revoke_before_retry", 503) from None
                entry["state"] = "attached"
                try:
                    self.save()
                except Exception:
                    entry["state"] = "uncertain"
                    raise DeviceError("attachment_uncertain_revoke_before_retry", 503) from None
                return {"device": copy.deepcopy(entry)}
        if method == "POST" and path == "/v1/revoke":
            fields(body, ["share"])
            if not isinstance(body["share"], str) or not NAME.fullmatch(body["share"]):
                raise DeviceError("invalid_share")
            with self.lock:
                share = body["share"]
                if share not in self.devices:
                    raise DeviceError("unknown_attachment", 404)
                replacement = copy.deepcopy(self.devices)
                replacement[share]["state"] = "revoking"
                self.set_devices(replacement)
                try:
                    self.warren(["unshare", "--name", share])
                except Exception:
                    self.devices[share]["state"] = "uncertain"
                    self.save()
                    raise DeviceError("revocation_not_confirmed", 503) from None
                replacement = {key: value for key, value in self.devices.items() if key != share}
                try:
                    self.set_devices(replacement)
                except Exception:
                    self.devices[share]["state"] = "uncertain"
                    raise DeviceError("revocation_cleanup_required", 503) from None
                return {"revoked": True}
        raise DeviceError("not_found", 404)


def server(service, port=0):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass  # No device names, targets, tokens, paths or request payloads in logs.

        def do_GET(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request()

        def handle_request(self):
            self.connection.settimeout(8)
            self.close_connection = True
            try:
                if "Origin" in self.headers or "Transfer-Encoding" in self.headers:
                    raise DeviceError("browser_origin_not_allowed", 403)
                hosts = self.headers.get_all("Host", [])
                if len(hosts) != 1 or not re.fullmatch(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?|warren-gateway", hosts[0]):
                    raise DeviceError("invalid_host", 403)
                auth = self.headers.get_all("Authorization", [])
                if len(auth) != 1 or not hmac.compare_digest(auth[0].encode(), ("Bearer " + service.token).encode()):
                    raise DeviceError("unauthorized", 401)
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) > 1:
                    raise DeviceError("invalid_content_length")
                try:
                    if lengths and not re.fullmatch(r"[0-9]+", lengths[0]):
                        raise ValueError()
                    size = int(lengths[0]) if lengths else 0
                except ValueError:
                    raise DeviceError("invalid_content_length") from None
                if size < 0 or size > 8192:
                    raise DeviceError("request_too_large", 413)
                if self.command == "POST" and self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise DeviceError("json_required", 415)
                if self.command == "GET" and size:
                    raise DeviceError("get_body_not_allowed")
                data = self.rfile.read(size)
                if len(data) != size:
                    raise DeviceError("incomplete_request")
                def unique_object(pairs):
                    obj = {}
                    for key, value in pairs:
                        if key in obj:
                            raise ValueError("duplicate_json_key")
                        obj[key] = value
                    return obj
                body = json.loads(data, object_pairs_hook=unique_object) if data else {}
                result, status = service.dispatch(self.command, self.path, body), 200
            except DeviceError as exc:
                result, status = {"error": exc.code}, exc.status
            except (ValueError, UnicodeError):
                result, status = {"error": "invalid_json"}, 400
            except Exception:
                result, status = {"error": "local_device_operation_failed"}, 503
            encoded = json.dumps(result, ensure_ascii=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

    class BoundedServer(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 8

        def __init__(self, *args):
            self.slots = threading.BoundedSemaphore(8)
            super().__init__(*args)

        def process_request(self, request, client_address):
            request.settimeout(8)
            if not self.slots.acquire(False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self.slots.release()
                raise

        def process_request_thread(self, *args):
            try:
                super().process_request_thread(*args)
            finally:
                self.slots.release()

        def handle_error(self, request, client_address):
            pass  # No request diagnostics or private device data on stderr.

    return BoundedServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description="Private gateway device service; never bind to LAN")
    parser.add_argument("--state", required=True)
    parser.add_argument("--warren", required=True)
    parser.add_argument("--warren-home", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    from .discovery import discover
    service = DeviceService(args.state, WarrenClient(args.warren, args.warren_home), discover)
    http = server(service, args.port)
    try:
        http.serve_forever()
    finally:
        http.server_close()
        service.close()


if __name__ == "__main__":
    main()
