#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Local browser controls for the disposable, offline ML-DSA prototype."""

import argparse
from collections import OrderedDict
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import sys
import threading
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import webbrowser


HERE = Path(__file__).resolve().parent
MAX_MONEY = 2100000000000000
ACTIONS = {"start", "stop", "receive", "fund", "send", "mine", "backup", "recover", "lock", "unlock"}
CONSOLE_SCHEMA = "PQBTC-MLDSA44-LOCAL-CONSOLE-1"


class LaunchError(ValueError):
    pass


def console_identity(state_dir, container, prepared):
    return {"schema": CONSOLE_SCHEMA, "state_id": hashlib.sha256(str(state_dir.resolve()).encode()).hexdigest(),
            "container": container, "managed": not prepared}


def runtime_kind(state_dir, descriptor_path):
    state = Path(state_dir)
    if descriptor_path is not None or (state / "runtime.json").exists() or (state / "runtime.json").is_symlink():
        return "source"
    if (state / "session.json").exists() or (state / "session.json").is_symlink():
        return "legacy"
    return "source"


def start_network(controller, server):
    try:
        controller.action("start", {})
        server.startup_error = ""
        return True
    except (ValueError, OSError) as error:
        server.startup_error = str(error)[:800]
        print("Wallet could not resume; open Backup & recovery in the local console. " + server.startup_error, flush=True)
        return False


def read_local(url, *, data=None, token=None):
    headers = {"Origin": url.split("/api/", 1)[0]}
    if data is not None:
        headers.update({"Content-Type": "application/json", "X-Console-Token": token})
    request = Request(url, data=None if data is None else json.dumps(data).encode(), headers=headers)
    try:
        with urlopen(request, timeout=240 if data else 30) as response:
            raw = response.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024 or response.headers.get("X-PQBTC-Console") != "1":
                raise LaunchError("The local port belongs to another application")
            return raw
    except HTTPError as error:
        with error:
            raw = error.read(4096)
        try:
            message = json.loads(raw).get("error", "Console request failed")
        except (ValueError, AttributeError):
            message = "The local port belongs to another application"
        raise LaunchError(str(message)) from error


def reopen_existing(url, identity, autostart=True):
    try:
        found = json.loads(read_local(url + "/api/identity"))
    except URLError as error:
        if isinstance(error.reason, ConnectionRefusedError):
            return False
        raise LaunchError("The existing local console could not be reached") from error
    except (ValueError, UnicodeError) as error:
        if isinstance(error, LaunchError):
            raise
        raise LaunchError("The local port belongs to another application") from error
    if found != identity:
        raise LaunchError("This port is serving another wallet or runtime; use its original launcher or a different port")
    if autostart:
        status = json.loads(read_local(url + "/api/status"))
        if status.get("ok") is not True:
            raise LaunchError("The existing console could not read its wallet status")
        if status["data"]["phase"] != "running":
            html = read_local(url + "/").decode()
            match = re.search(r'name="console-token"\s+content="([A-Za-z0-9_-]+)"', html)
            if match is None:
                raise LaunchError("Refresh the existing console before resuming")
            try:
                result = json.loads(read_local(url + "/api/action", data={"action": "start", "params": {},
                                              "request_id": secrets.token_urlsafe(24)}, token=match[1]))
            except LaunchError as error:
                print("Wallet needs attention; opening its recovery controls. " + str(error), flush=True)
                return True
            if result.get("ok") is not True:
                raise LaunchError("The existing wallet could not resume")
    return True


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate request field")
        result[key] = value
    return result


def integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(label + " must be an integer in the allowed range")


def validate_action(value):
    if type(value) is not dict or set(value) != {"action", "params", "request_id"}:
        raise ValueError("Expected an action, parameters, and request ID")
    action, params, identity = value["action"], value["params"], value["request_id"]
    if type(action) is not str or action not in ACTIONS or type(params) is not dict:
        raise ValueError("Unknown console action")
    if type(identity) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{12,80}", identity):
        raise ValueError("Invalid request ID")
    allowed = {
        "fund": {"amount_sats", "address"}, "send": {"address", "amount_sats", "fee_sats"},
        "mine": {"blocks"}, "recover": {"backup_id"},
    }.get(action, set())
    if set(params) - allowed:
        raise ValueError("Unexpected action parameter")
    if action == "send":
        address = params.get("address")
        if type(address) is not str or not 8 <= len(address) <= 128 or not address.isascii():
            raise ValueError("Enter a local receive address")
        integer(params.get("amount_sats"), 1, MAX_MONEY, "Amount")
        integer(params.get("fee_sats", 1000), 1, 20000, "Fee")
    if action == "fund":
        integer(params.get("amount_sats", 2000000), 1, 100000000, "Test coin amount")
        if "address" in params and (type(params["address"]) is not str or len(params["address"]) > 128):
            raise ValueError("Invalid test receive address")
    if action == "mine":
        integer(params.get("blocks", 1), 1, 101, "Block count")
    if action == "recover":
        identity_value = params.get("backup_id")
        if type(identity_value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", identity_value):
            raise ValueError("Choose a saved backup")
    return action, params, identity


def make_server(controller, host="127.0.0.1", port=8844, token=None, identity=None):
    if host != "127.0.0.1":
        raise ValueError("The console binds only to local loopback")
    launch_token = token or secrets.token_urlsafe(32)
    cache = OrderedDict()
    # Keep small ID tombstones for this launch after large responses expire.
    # A delayed retry must never become a second native operation.
    seen = set()
    operation = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *_):
            pass

        def send_data(self, status, body, content_type="application/json; charset=utf-8"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, default=str).encode("utf8")
            elif isinstance(body, str):
                body = body.encode("utf8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-PQBTC-Console", "1")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                             "frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def error(self, code, message):
            self.send_data(code, {"ok": False, "error": message})

        def local_host(self):
            expected = {"127.0.0.1:" + str(self.server.server_port), "localhost:" + str(self.server.server_port)}
            return self.headers.get("Host") in expected

        def do_GET(self):
            if not self.local_host():
                self.error(403, "Local console requests only")
                return
            if self.path == "/api/identity":
                self.send_data(200, identity or {"schema": CONSOLE_SCHEMA})
                return
            if self.path == "/api/status":
                try:
                    status = controller.status()
                    if self.server.startup_error:
                        status = {**status, "startup_error": self.server.startup_error}
                    self.send_data(200, {"ok": True, "data": status})
                except Exception as error:
                    self.error(503, str(error)[:800])
                return
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8")}
            asset = assets.get(self.path)
            if asset is None:
                self.error(404, "Page not found")
                return
            try:
                contents = (HERE / "web" / asset[0]).read_text(encoding="utf8")
                if asset[0] == "index.html":
                    contents = contents.replace("__CONSOLE_TOKEN__", launch_token)
                self.send_data(200, contents, asset[1])
            except OSError:
                self.error(503, "Console assets are unavailable")

        def do_POST(self):
            if (not self.local_host() or self.headers.get("Origin") != "http://" + self.headers.get("Host", "")
                    or not secrets.compare_digest(self.headers.get("X-Console-Token", ""), launch_token)):
                self.error(403, "Refresh the local console before changing the lab")
                return
            if self.path != "/api/action":
                self.error(404, "Action endpoint not found")
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                self.error(415, "Console actions require JSON")
                return
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                    raise ValueError("A bounded request body is required")
                length = int(lengths[0])
                if not 0 < length <= 16384:
                    raise ValueError("Request is too large or empty")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete request")
                value = json.loads(raw, object_pairs_hook=strict_object)
                action, params, identity = validate_action(value)
            except (ValueError, UnicodeError, RecursionError) as error:
                self.error(400, str(error)[:800])
                return
            fingerprint = json.dumps([action, params], sort_keys=True, separators=(",", ":"))
            if not operation.acquire(blocking=False):
                self.error(409, "Another action is running; wait for it to finish")
                return
            try:
                if identity in cache:
                    old_fingerprint, code, response = cache[identity]
                    if old_fingerprint != fingerprint:
                        self.error(409, "Request ID already belongs to another operation")
                        return
                    self.send_data(code, response)
                    return
                if identity in seen:
                    self.error(409, "Earlier request result expired; refresh status before using a new request")
                    return
                seen.add(identity)
                try:
                    response = {"ok": True, "data": controller.action(action, params)}
                    if response["data"].get("status", {}).get("phase") == "running":
                        self.server.startup_error = ""
                    code = 200
                except Exception as error:
                    response = {"ok": False, "error": str(error)[:800]}
                    if action == "start":
                        self.server.startup_error = response["error"]
                    code = 409
                cache[identity] = (fingerprint, code, response)
                while len(cache) > 128:
                    cache.popitem(last=False)
                self.send_data(code, response)
            finally:
                operation.release()

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.startup_error = ""
    server.timeout = 1
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="pqbtc-mldsa-local")
    parser.add_argument("--source", default="/tmp/mldsa-demo-source")
    parser.add_argument("--build", default="/tmp/mldsa-demo-build")
    parser.add_argument("--state-dir", type=Path,
                        default=Path.home() / "quantum-proof-bitcoin-evidence/local-console")
    parser.add_argument("--port", type=int, default=8844)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--no-autostart", action="store_true", help="open controls without starting the test network")
    parser.add_argument("--prepared-runtime", action="store_true", help="use an explicitly prepared container without durable provisioning")
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc", help="compiler for a new source-built runtime")
    parser.add_argument("--runtime-descriptor", type=Path, help="use an already source-built image descriptor")
    parser.add_argument("--no-build-cache", action="store_true", help="disable Docker build cache for a new source installation")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Choose a local port between 1 and 65535")
    sys.path.insert(0, str(HERE))
    runtime_descriptor = None
    if not args.prepared_runtime:
        if runtime_kind(args.state_dir, args.runtime_descriptor) == "source":
            from source_runtime import SourceManager, load_descriptor
            print("Preparing source-built offline runtime…", flush=True)
            supplied = load_descriptor(args.runtime_descriptor) if args.runtime_descriptor else None
            result = SourceManager(container=args.container).ensure(args.state_dir, repo=HERE.parents[1],
                       compiler=args.compiler, descriptor=supplied, no_cache=args.no_build_cache)
            runtime_descriptor = result["runtime_descriptor"]
        else:
            from durable import RuntimeManager
            print("Resuming the existing durable offline runtime…", flush=True)
            RuntimeManager(container=args.container).ensure(args.state_dir)
    identity = console_identity(args.state_dir, args.container, args.prepared_runtime)
    url = "http://127.0.0.1:" + str(args.port)
    if reopen_existing(url, identity, autostart=not args.no_autostart):
        print("ML-DSA local console already running: " + url, flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        return
    from controller import Controller
    controller = Controller(args.container, args.source, args.build, args.state_dir, HERE, runtime_descriptor=runtime_descriptor)
    try:
        server = make_server(controller, port=args.port, identity=identity)
    except OSError as error:
        if error.errno == errno.EADDRINUSE and reopen_existing(url, identity, autostart=not args.no_autostart):
            if not args.no_browser:
                webbrowser.open(url)
            return
        raise
    try:
        if not args.no_autostart:
            start_network(controller, server)
        print("ML-DSA local console: " + url, flush=True)
        print("Disposable test coins only. Ctrl+C stops the console and lab processes.", flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        controller.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit("Local wallet could not launch: " + str(error)) from error
