#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Launch the dedicated, valueless public-test wallet on local loopback."""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import webbrowser

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import app  # noqa: E402
from public_controller import PublicController, PROFILE, source  # noqa: E402


def validate_action(value):
    if type(value) is not dict or set(value) != {"action", "params", "request_id"}:
        raise ValueError("Expected a public action, parameters and request ID")
    action, params, request_id = value["action"], value["params"], value["request_id"]
    allowed = {"start": set(), "stop": set(), "setup": {"password"}, "unlock": {"password"}, "lock": set(),
               "receive": set(), "send": {"address", "amount_sats", "fee_sats"}, "mine": {"blocks", "address"},
               "fund": {"address"}, "backup": set(), "recover": {"backup_id", "password"}, "peer": {"endpoint"}, "bootstrap": set()}
    if (type(action) is not str or type(params) is not dict or action not in allowed or set(params) - allowed[action] or
            type(request_id) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{12,80}", request_id)):
        raise ValueError("Invalid public action, parameters or request ID")
    if action in ("setup", "unlock", "recover"):
        password = params.get("password")
        if type(password) is not str or not 0 < len(password.encode("utf8")) <= 1024:
            raise ValueError("Enter a wallet password of 1..1024 UTF-8 bytes")
    if action == "recover" and (type(params.get("backup_id")) is not str or not re.fullmatch(r"[0-9a-f]{32}", params["backup_id"])):
        raise ValueError("Choose a saved public backup")
    if action == "send":
        app.integer(params.get("amount_sats"), 1, app.MAX_MONEY, "Amount")
        app.integer(params.get("fee_sats", 5000), 1, 20000, "Fee")
        if type(params.get("address")) is not str or not 8 <= len(params["address"]) <= 128 or not params["address"].isascii():
            raise ValueError("Enter a public-test receive address")
    if action == "mine":
        app.integer(params.get("blocks", 1), 1, 101, "Block count")
    if "address" in params and (type(params["address"]) is not str or not 8 <= len(params["address"]) <= 128):
        raise ValueError("Invalid public-test address")
    if action == "peer":
        endpoint = params.get("endpoint")
        if type(endpoint) is not str or not 3 <= len(endpoint) <= 255 or not endpoint.isascii() or any(c.isspace() for c in endpoint):
            raise ValueError("Enter a P2P host:port endpoint")
    return action, params, request_id


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path.home() / "quantum-proof-bitcoin-evidence/public-console")
    parser.add_argument("--container", default="pqbtc-mldsa-public")
    parser.add_argument("--port", type=int, default=8845)
    parser.add_argument("--p2p-port", type=int, default=23833)
    parser.add_argument("--runtime-descriptor", type=Path)
    parser.add_argument("--bootstrap", action="store_true", help="explicitly mine activation H1 if this dedicated chain is empty")
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--no-autostart", action="store_true")
    parser.add_argument("--docker-sudo", action="store_true", help="use existing passwordless sudo Docker on Linux")
    parser.add_argument("--upgrade-descriptor", type=Path)
    parser.add_argument("--rollback-descriptor", type=Path)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535 or args.upgrade_descriptor and args.rollback_descriptor:
        parser.error("Choose a local port >=1024 and at most one binary replacement")
    identity = {"schema": "PQBTC-MLDSA44-PUBLIC-CONSOLE-1", "profile_sha256": PROFILE,
                "state_id": hashlib.sha256(str(args.state_dir.resolve()).encode()).hexdigest(), "container": args.container}
    url = "http://127.0.0.1:" + str(args.port)
    # Reopening never spawns a second signer or competes for its writer lock.
    if not (args.upgrade_descriptor or args.rollback_descriptor) and app.reopen_existing(
            url, identity, autostart=not args.no_autostart, max_bytes=2 * 1024 * 1024):
        if not args.no_browser:
            webbrowser.open(url)
        print("ML-DSA public-test console: " + url, flush=True)
        return
    docker = ("sudo", "-n", "docker") if args.docker_sudo else ("docker",)
    if not args.docker_sudo:
        source._legacy.RuntimeManager(container=args.container)._daemon(print)
    descriptor = source.load_descriptor(args.runtime_descriptor) if args.runtime_descriptor else None
    if descriptor is None and not (args.state_dir / "public-runtime.json").exists():
        if args.docker_sudo:
            parser.error("Provide an existing source-built descriptor when using sudo Docker")
        builder = source.SourceManager(container=args.container)
        descriptor = builder._build_image(HERE.parents[1], compiler=args.compiler, no_cache=False, progress=print)
    controller = PublicController(args.state_dir, descriptor, container=args.container, p2p_port=args.p2p_port,
                                  bootstrap=args.bootstrap, docker=docker)
    server = None
    try:
        controller.manager.ensure(descriptor)
        replacement = args.upgrade_descriptor or args.rollback_descriptor
        if replacement:
            action = "upgrade" if args.upgrade_descriptor else "rollback"
            controller.action(action, {"descriptor": source.load_descriptor(replacement)})
        server = app.make_server(controller, port=args.port, identity=identity, action_validator=validate_action,
                                 assets_dir=HERE / "web-public")
        if not args.no_autostart:
            app.start_network(controller, server)
        print("ML-DSA public-test console: " + url, flush=True)
        print("Valueless test coins only. RPC and browser controls remain local. Restart requires wallet unlock.", flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.server_close()
        controller.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit("Public-test wallet could not launch: " + str(error)) from error
