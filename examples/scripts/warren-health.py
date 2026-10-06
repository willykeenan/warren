#!/usr/bin/env python3
"""Check a warren relay and the service published through it; append one JSON line per run.

Run it from a machine other than the relay (for example the machine that
publishes the service), every few minutes, so it measures what clients see
and still reports when the relay host is down. It needs only Python 3.8+.

    warren-health.py --relay https://relay.example.com \\
        --publish-url https://relay.example.com/ --expect-ip 203.0.113.10 \\
        --out ~/.local/state/warren/health.jsonl

    warren-health.py --summary ~/.local/state/warren/health.jsonl

Exit status: 0 healthy, 1 unhealthy, 2 usage error. See
docs/production-relay.md for the line format.
"""

import argparse
import datetime
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

USER_AGENT = "warren-health/1"
BODY_LIMIT = 1 << 20


def probe(url, timeout, expect_text=None, expect_ip=None):
    """GET one https URL without following redirects; time the whole request."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"not an https URL: {url}")
    host, port = parts.hostname, parts.port or 443
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    result = {
        "url": url,
        "http_status": 0,
        "latency_ms": None,
        "tls_verified": False,
        "remote_ip": None,
        "expected_ip": None,
        "content_ok": None,
        "error": None,
    }
    peer_cert = None
    raw = None
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    started = time.monotonic()
    try:
        # Connect by hand so the answering address is known even when TLS fails.
        raw = socket.create_connection((host, port), timeout=timeout)
        result["remote_ip"] = raw.getpeername()[0]
        connection.sock = context.wrap_socket(raw, server_hostname=host)
        result["tls_verified"] = True
        peer_cert = connection.sock.getpeercert()
        connection.request("GET", path, headers={"User-Agent": USER_AGENT, "Connection": "close"})
        response = connection.getresponse()
        body = response.read(BODY_LIMIT)
        result["http_status"] = response.status
        result["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
        if expect_text is not None:
            result["content_ok"] = expect_text.lower().encode() in body.lower()
        result["_body"] = body
    except ssl.SSLCertVerificationError:
        result["error"] = "tls_not_verified"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (OSError, http.client.HTTPException) as error:
        result["error"] = type(error).__name__
    finally:
        connection.close()
        if raw is not None:
            raw.close()  # a no-op once TLS has taken the socket over
    if expect_ip is not None and result["remote_ip"] is not None:
        result["expected_ip"] = result["remote_ip"] == expect_ip
    return result, peer_cert


def certificate(peer_cert, remote_ip):
    if not peer_cert or "notAfter" not in peer_cert:
        return {"verified": False, "endpoint_ip": remote_ip, "expires_at": None, "days_remaining": None}
    expiry = ssl.cert_time_to_seconds(peer_cert["notAfter"])
    return {
        "verified": True,
        "endpoint_ip": remote_ip,
        "expires_at": datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc).isoformat(),
        "days_remaining": round((expiry - time.time()) / 86400, 2),
    }


def node_status(warren, publish_name, timeout):
    """Ask the local node daemon (`warren --json status`); WARREN_HOME is taken from the environment."""
    empty = {"state": "unavailable", "latency_ms": None, "connects": None, "publish_registered": None, "error": None}
    try:
        completed = subprocess.run(
            [warren, "--json", "status"], capture_output=True, text=True, timeout=timeout
        )
        status = json.loads(completed.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return dict(empty, error=type(error).__name__)
    if status.get("ok") is False:  # e.g. not enrolled: {"ok": false, "code": ..., "error": ...}
        return dict(empty, error=status.get("code"))
    connection = status.get("connection") or {}
    registered = None
    if publish_name:
        registered = any(entry.get("name") == publish_name for entry in status.get("publishes") or [])
    return {
        "state": connection.get("state", "unavailable"),
        "latency_ms": connection.get("latency_ms"),
        "connects": connection.get("connects"),
        "publish_registered": registered,
        "error": None,
    }


def judge(name, result, accepted):
    """Problem codes for one probe: name_unreachable, name_tls, name_status, name_content, name_wrong_server."""
    problems = []
    if result["expected_ip"] is False:
        problems.append(f"{name}_wrong_server")
    if result["error"] == "tls_not_verified":
        problems.append(f"{name}_tls")
    elif result["http_status"] == 0:
        problems.append(f"{name}_unreachable")
    elif result["http_status"] not in accepted:
        problems.append(f"{name}_status")
    elif result["content_ok"] is False:
        problems.append(f"{name}_content")
    return problems


def check(args):
    started = time.time()
    clock = time.monotonic()
    problems = []

    relay_url = args.relay.rstrip("/") + "/healthz"
    relay, relay_cert = probe(relay_url, args.timeout, expect_ip=args.expect_ip)
    body = relay.pop("_body", b"")
    relay["content_ok"] = body.strip() == b"ok" if relay["http_status"] else None
    problems += judge("relay", relay, [200])

    cert = certificate(relay_cert, relay["remote_ip"])
    if cert["days_remaining"] is not None and cert["days_remaining"] < args.min_cert_days:
        problems.append("certificate_expiring")

    publish = None
    if args.publish_url:
        publish, _ = probe(args.publish_url, args.timeout, args.expect_text, args.expect_ip)
        publish.pop("_body", None)
        problems += judge("publish", publish, args.publish_status)

    node = None
    if args.node:
        node = node_status(args.warren, args.publish_name, args.timeout)
        if node["state"] != "connected":
            problems.append("node_not_connected")
        elif node["publish_registered"] is False:
            problems.append("node_publish_missing")

    compare = None
    if args.compare_url:
        compare, _ = probe(args.compare_url, args.timeout, args.expect_text)
        compare.pop("_body", None)

    return {
        "timestamp": datetime.datetime.fromtimestamp(started, datetime.timezone.utc).isoformat(),
        "healthy": not problems,
        "problems": problems,
        "relay": relay,
        "certificate": cert,
        "publish": publish,
        "node": node,
        "compare": compare,
        "check_ms": round((time.monotonic() - clock) * 1000, 2),
    }


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(0, min(len(ordered) - 1, round(fraction * (len(ordered) - 1))))
    return ordered[rank]


def summary(path):
    lines = [json.loads(line) for line in Path(path).expanduser().read_text().splitlines() if line.strip()]
    healthy = sum(1 for line in lines if line.get("healthy"))
    report = {
        "samples": len(lines),
        "healthy_samples": healthy,
        "healthy_percent": round(healthy / len(lines) * 100, 2) if lines else None,
        "first": lines[0]["timestamp"] if lines else None,
        "last": lines[-1]["timestamp"] if lines else None,
    }
    for key in ("relay", "publish", "compare"):
        values = [line[key]["latency_ms"] for line in lines if line.get(key) and line[key].get("latency_ms") is not None]
        if values:
            report[f"{key}_latency_ms"] = {
                "p50": percentile(values, 0.50),
                "p95": percentile(values, 0.95),
                "max": max(values),
            }
    print(json.dumps(report, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Health check for a warren relay; one JSON line per run.")
    parser.add_argument("--relay", help="relay base URL, e.g. https://relay.example.com")
    parser.add_argument("--publish-url", help="a page of the published service (redirects are not followed)")
    parser.add_argument("--publish-status", type=int, nargs="+", default=[200], help="accepted status codes (default 200)")
    parser.add_argument("--expect-text", help="text the published page must contain (case-insensitive)")
    parser.add_argument("--expect-ip", help="the relay's public address; any other answering server is a problem")
    parser.add_argument("--min-cert-days", type=float, default=14.0, help="days of certificate validity required (default 14)")
    parser.add_argument("--node", action="store_true", help="also ask the local node daemon (`warren --json status`)")
    parser.add_argument("--warren", default="warren", help="path of the warren binary for --node")
    parser.add_argument("--publish-name", help="with --node: the published name that must be registered")
    parser.add_argument("--compare-url", help="another route to the same service, measured but not judged")
    parser.add_argument("--timeout", type=float, default=15.0, help="seconds per request (default 15)")
    parser.add_argument("--out", default="~/.local/state/warren/health.jsonl", help="JSONL file to append to")
    parser.add_argument("--summary", metavar="FILE", help="print counts and latency percentiles of FILE and exit")
    args = parser.parse_args(argv)

    if args.summary:
        return summary(args.summary)
    if not args.relay:
        parser.print_usage(sys.stderr)
        print("error: --relay is required", file=sys.stderr)
        return 2
    try:
        record = check(args)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    line = json.dumps(record, separators=(",", ":"))
    out = Path(args.out).expanduser()
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(out, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, (line + "\n").encode())
    finally:
        os.close(descriptor)
    print(line)
    return 0 if record["healthy"] else 1


if __name__ == "__main__":
    sys.exit(main())
