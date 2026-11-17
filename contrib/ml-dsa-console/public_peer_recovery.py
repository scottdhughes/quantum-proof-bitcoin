#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Bounded, read-only-policy recovery of one registered public peer."""
import importlib.util
import json
import math
import os
from pathlib import Path
import sys
import time

SOURCE = Path('/opt/pqbtc-runtime/seed/mldsa-demo-source')
HERE = Path(__file__).resolve().parent if '__file__' in globals() else SOURCE / 'contrib/ml-dsa-console'
spec = importlib.util.spec_from_file_location('peer_recovery_runtime', HERE / 'public_runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
require = runtime.require


def read_policy(state):
    path = Path(state) / 'peer-policy.json'
    temporary = Path(state) / 'peer-policy.tmp'
    require(not os.path.lexists(temporary), 'public peer policy temporary file present')
    # Use the worker's guarded reader and duplicate-key decoder without invoking
    # its constructor, which can modify an orphaned policy.
    reader = object.__new__(runtime.PeerPolicy)
    value = reader._decode(reader._read_bytes(path))
    require(not os.path.lexists(temporary), 'public peer policy temporary file present')
    return value


def renew(node, state, endpoint, budget_seconds, *, deadline=None):
    endpoint = runtime.peer_endpoint(endpoint)
    require(type(budget_seconds) in (int, float) and math.isfinite(budget_seconds) and 0 < budget_seconds <= 10,
            'public peer recovery budget refused')
    now = time.monotonic()
    deadline = now + budget_seconds if deadline is None else deadline
    require(type(deadline) in (int, float) and math.isfinite(deadline) and now < deadline <= now + 10,
            'public peer recovery deadline')

    def rpc(method, *args):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'public peer recovery deadline')
        return getattr(node.rpc(timeout=min(.5, remaining)), method)(*args)

    def guard():
        policy = read_policy(state)
        require(policy['network_active'] and endpoint in policy['endpoints'], 'public peer policy refused')
        network = rpc('getnetworkinfo')
        require(type(network) is dict and network.get('networkactive') is True, 'public network inactive')
        added = rpc('getaddednodeinfo', endpoint)
        require(type(added) is list and len(added) == 1 and type(added[0]) is dict and
                added[0].get('addednode') == endpoint and type(added[0].get('connected')) is bool,
                'public peer registration refused')
        addresses = added[0].get('addresses', [])
        require(type(addresses) is list and len(addresses) <= 16, 'public peer addresses refused')
        targets = {endpoint}
        for row in addresses:
            require(type(row) is dict and set(row) == {'address', 'connected'} and
                    row['connected'] in ('inbound', 'outbound'), 'public peer address refused')
            targets.add(runtime.peer_endpoint(row['address']))
        return targets

    def peers(targets):
        values = rpc('getpeerinfo')
        require(type(values) is list and len(values) <= 256, 'public peer inventory refused')
        matches = [p for p in values if type(p) is dict and p.get('addr') in targets]
        require(len(matches) <= 1 and all(type(p.get('id')) is int and p['id'] >= 0 for p in matches),
                'ambiguous public peer')
        return matches

    targets = guard()
    old = peers(targets)
    old_ids = [p['id'] for p in old]
    transport = old[0].get('transport_protocol_type') if old else None
    require(not old or transport in ('v1', 'v2'), 'public peer transport refused')
    if old:
        # Reinspect immediately before mutation. A vanished ID is already being
        # renewed; do not disconnect an unrelated replacement.
        current = peers(guard())
        if current and current[0]['id'] == old_ids[0]:
            try:
                rpc('disconnectnode', '', old_ids[0])
            except Exception:
                # The RPC may have taken effect before a lost response.
                pass
    current = peers(guard())
    if not current:
        try:
            args = (endpoint, 'onetry') if transport is None else (endpoint, 'onetry', transport == 'v2')
            rpc('addnode', *args)
        except Exception:
            # A connection may already be in flight; observe without replay.
            pass
    baseline = None
    while True:
        targets = guard()
        current = peers(targets)
        if current:
            peer = current[0]
            if peer['id'] not in old_ids and peer.get('version', 0) > 0 and peer.get('relaytxes') is True and peer.get('connection_type') in ('manual', 'inbound', 'outbound-full-relay'):
                observed_transport = peer.get('transport_protocol_type')
                require(observed_transport in ('v1', 'v2') and (transport is None or transport == observed_transport),
                        'public peer transport changed')
                sent, received = peer.get('bytessent_per_msg', {}).get('ping', 0), peer.get('bytesrecv_per_msg', {}).get('pong', 0)
                require(type(sent) is int and sent >= 0 and type(received) is int and received >= 0, 'public peer ping counters refused')
                if baseline is None:
                    baseline = (peer['id'], sent, received)
                    rpc('ping')
                elif peer['id'] == baseline[0] and sent > baseline[1] and received > baseline[2] and not peer.get('pingwait', 0):
                    guard()
                    require(time.monotonic() < deadline, 'public peer recovery deadline')
                    return {'endpoint': endpoint, 'renewed': True, 'network_active': True, 'old_peer_ids': old_ids,
                            'new_peer_id': peer['id'], 'transport_protocol_type': observed_transport, 'fresh_pong': True,
                            'ping_sent_before': baseline[1], 'ping_sent_after': sent,
                            'pong_received_before': baseline[2], 'pong_received_after': received}
            elif baseline is not None and peer['id'] != baseline[0]:
                require(False, 'public peer changed during ping')
        require(time.monotonic() < deadline, 'public peer recovery deadline')
        time.sleep(min(.05, max(0, deadline - time.monotonic())))


def main():
    sys.path.insert(0, str(SOURCE / 'test/functional'))
    from test_framework.authproxy import AuthServiceProxy
    node = runtime.PublicNode('/opt/pqbtc-runtime/seed/mldsa-demo-build/bin/pqbtcd', '/var/lib/pqbtc/node/chain', AuthServiceProxy)
    try:
        result = renew(node, '/var/lib/pqbtc/node', sys.argv[1], 10, deadline=globals()['__recovery_deadline__'])
        print(json.dumps(result, separators=(',', ':')))
    except Exception:
        print('public peer recovery refused', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
