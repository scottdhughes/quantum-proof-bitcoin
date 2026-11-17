"""Owned disposable public wallet: real Desktop recovery, not public soak time."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path('/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/candidate-l/source-clean-7223772e')
HEAD = '7223772e76d2d0a0bb7fd1d35e0e16fba61918fd'
TREE = '33b36275b1da7f7fbc27fae00d519206b0f7c16f'
ORIGINAL = 'pqbtc-mldsa-local'
ORIGINAL_IMAGE = 'sha256:767891744587d93faf96d0f9d8ce2c66ebe3a73695b2a7389f82b62735b8ad3a'
ENGINE = '4d2c0ea7-0efe-46b4-9ca7-f8cb3ee300ab'
GCC_IMAGE = 'sha256:fc470f630a0eaa679aa49563d13b1a1e1d183528eb4348877c7cbb60b3c0e6f3'


def require(value, message):
    if not value:
        raise ValueError(message)


def command(argv, timeout=240):
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=True)


def inspect(name):
    template = ('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
                '"running":{{json .State.Running}},"pid":{{json .State.Pid}},"restart":{{json .HostConfig.RestartPolicy}},'
                '"mounts":{{json .Mounts}}}')
    return json.loads(command(['docker', 'container', 'inspect', '--format', template, name]).stdout)


def volume(name):
    template = '{"name":{{json .Name}},"driver":{{json .Driver}},"created":{{json .CreatedAt}},"labels":{{json .Labels}}}'
    return json.loads(command(['docker', 'volume', 'inspect', '--format', template, name]).stdout)


def engine_identity():
    endpoint = json.loads(command(['docker', 'context', 'inspect', 'desktop-linux', '--format', '{{json .Endpoints.docker.Host}}']).stdout)
    require(endpoint == 'unix://' + str(Path.home() / '.docker/run/docker.sock'), 'Local Desktop socket context required')
    identity = json.loads(command(['docker', 'info', '--format', '{{json .ID}}']).stdout)
    require(identity == ENGINE, 'Unexpected Docker engine; Desktop operation refused')
    return identity


def exclusive(name):
    engine_identity()
    running = command(['docker', 'ps', '--format', '{{.Names}}']).stdout.decode().splitlines()
    require(set(running) <= {ORIGINAL, name}, 'Unrelated running containers; Desktop operation refused')


def confirm_owned(owned, expected_image):
    engine_identity()
    current = inspect(owned['id'])
    require(current['id'] == owned['id'] and current['image'] == expected_image
            and current['name'] == owned['name'] and current['mounts'] == owned['mounts'], 'Owned container identity changed')
    return current


def stop_owned(owned, expected_image):
    current = confirm_owned(owned, expected_image)
    if current['running']:
        command(['docker', 'stop', '--time', '30', owned['id']], timeout=60)
    final = confirm_owned(owned, expected_image)
    require(final['running'] is False and type(final['pid']) is int and final['pid'] == 0, 'Owned backend not stopped')
    return {'container_id': final['id'], 'image': final['image'], 'backend_stopped': True, 'pid': 0, 'volume_retained': True}


def confirmed(owned, descriptor, txid, block_hash):
    require(all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in (txid, block_hash)), 'Known transaction/block required')
    confirm_owned(owned, descriptor['image'])
    node_sha = descriptor['manifest']['sha256']['/tmp/mldsa-demo-build/bin/pqbtcd']
    script = r'''import hashlib,json,pathlib,sys
try:
 source='/opt/pqbtc-runtime/seed/mldsa-demo-source'; build='/opt/pqbtc-runtime/seed/mldsa-demo-build'
 assert hashlib.sha256(pathlib.Path(build+'/bin/pqbtcd').read_bytes()).hexdigest()==sys.argv[3]
 sys.path.insert(0,source+'/contrib/ml-dsa-console');sys.path.insert(0,source+'/test/functional')
 from public_runtime import PublicNode
 from test_framework.authproxy import AuthServiceProxy
 rpc=PublicNode(build+'/bin/pqbtcd',pathlib.Path('/var/lib/pqbtc/node/chain'),AuthServiceProxy).rpc(timeout=10)
 header=rpc.getblockheader(sys.argv[2]);block=rpc.getblock(sys.argv[2],1)
 count=header['confirmations']
 print(json.dumps({'txid':sys.argv[1],'block_hash':sys.argv[2],'confirmations':count,
  'confirmed':sys.argv[1] in block['tx'] and type(count) is int and count>=1},sort_keys=True))
except Exception as error:
 sys.stderr.write(type(error).__name__+'\n');sys.exit(1)
'''
    raw = command(['docker', 'exec', '--user', '1001:1001', owned['id'], 'python3', '-I', '-B', '-c', script,
                   txid, block_hash, node_sha], timeout=30).stdout
    require(len(raw) <= 2048, 'Bounded transaction proof required')
    value = json.loads(raw)
    require(set(value) == {'txid', 'block_hash', 'confirmations', 'confirmed'} and value['txid'] == txid
            and value['block_hash'] == block_hash and value['confirmed'] is True
            and type(value['confirmations']) is int and value['confirmations'] >= 1, 'Exact transaction confirmation missing')
    return value


def read(url, path, timeout=30):
    with urlopen(url + path, timeout=timeout) as response:
        raw = response.read(2 * 1024**2 + 1)
    require(len(raw) <= 2 * 1024**2, 'Bounded HTTP response required')
    return json.loads(raw)


def status(url):
    result = read(url, '/api/status')
    require(result.get('ok') is True, 'Public status refused')
    return result['data']


def action(url, name, params=None):
    with urlopen(url, timeout=15) as response:
        html = response.read(2 * 1024**2 + 1).decode()
    token = re.search(r'name="console-token"\s+content="([A-Za-z0-9_-]+)"', html)
    require(token is not None, 'Expected own console token')
    request = Request(url + '/api/action', data=json.dumps({'action': name, 'params': params or {},
                      'request_id': secrets.token_urlsafe(24)}).encode(),
                      headers={'Content-Type': 'application/json', 'Origin': url, 'X-Console-Token': token[1]})
    try:
        with urlopen(request, timeout=300) as response:
            result = json.load(response)
    except HTTPError:
        raise ValueError('Own HTTP action rejected: ' + name) from None
    require(result.get('ok') is True, 'Own HTTP action failed: ' + name)
    return result['data']


def selected(value):
    return {'phase': value['phase'], 'ready': value.get('ready'),
            'backup_ids': sorted(item['id'] for item in value.get('backups', [])),
            'wallet': {k: value.get('wallet', {}).get(k) for k in
                       ('wallet_id', 'next_receive', 'next_change', 'balance_sats', 'confirmed_sats', 'locked')},
            'nodes': [{k: node.get(k) for k in ('height', 'tip', 'utxo_hash', 'utxo_count', 'network_active')}
                      for node in value.get('nodes', [])]}


def wait_ready(url, child, seconds=240):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        require(child.poll() is None, 'Owned app exited')
        try:
            value = status(url)
            if value['phase'] == 'running' and value.get('ready') is True:
                return value
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.25)
    raise ValueError('Owned public wallet did not become ready')


def main():
    require(__debug__, 'Optimized Python refused')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--descriptor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-desktop-restart', action='store_true', required=True)
    args = parser.parse_args()
    # Only this test process and its children receive the explicit local context.
    os.environ.pop('DOCKER_HOST', None)
    os.environ['DOCKER_CONTEXT'] = 'desktop-linux'
    engine_identity()
    require(not os.path.lexists(args.output), 'Fresh output required')
    require(command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).stdout.decode().strip() == HEAD, 'Source HEAD')
    require(command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD^{tree}']).stdout.decode().strip() == TREE, 'Source tree')
    require(not command(['git', '-C', str(ROOT), 'status', '--porcelain=v1', '--untracked-files=all']).stdout.strip(), 'Source dirty')
    descriptor = json.loads(args.descriptor.read_bytes())
    require(descriptor['manifest']['source_head'] == HEAD and descriptor['manifest']['source_tree'] == TREE, 'Descriptor source')
    require(hashlib.sha256(args.descriptor.read_bytes()).hexdigest() == 'c483f14b416eeb25c90d635a98f872faecda00d57259c5f35130816c2bf0eefb'
            and descriptor['image'] == GCC_IMAGE, 'Exact qualified L GCC descriptor required')
    name = 'pqbtc-mldsa-public-l-desktop-20261117-02'
    url = 'http://127.0.0.1:18848'
    old_url = 'http://127.0.0.1:8844'
    exclusive(name)
    for kind, target in [('container', name), ('volume', name + '-data-v1')]:
        result = subprocess.run(['docker', kind, 'inspect', target], capture_output=True, timeout=30)
        require(result.returncode != 0 and b'no such' in result.stderr.lower(), 'Namespace absence unproven')
    try:
        read(url, '/api/identity')
    except URLError as error:
        require(isinstance(error.reason, ConnectionRefusedError), 'Unexpected HTTP port failure')
    else:
        raise ValueError('Test HTTP port already in use')
    original = inspect(ORIGINAL)
    require(original['image'] == ORIGINAL_IMAGE and original['running'], 'Original container identity')
    original_volume = volume(ORIGINAL + '-data-v1')
    original_identity = read(old_url, '/api/identity')
    original_status = selected(status(old_url))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    state = args.output / 'state'
    events = []
    report = {'schema': 'PQBTC-L-ACTUAL-DESKTOP-PUBLIC-RECOVERY-1', 'result': 'FAIL',
              'scope': 'ONE_DISPOSABLE_PUBLIC_TEST_WALLET_HOST_APP_AND_REAL_DESKTOP_NOT_PUBLIC_SOAK',
              'source': {'head': HEAD, 'tree': TREE}, 'image': descriptor['image'],
              'original_before': {'container': original, 'volume': original_volume, 'identity': original_identity,
                                  'status': original_status}, 'public_soak_credit_seconds': 0}
    child = None
    owned = None
    log = (args.output / 'launcher.log').open('xb')
    launcher = [str(ROOT / 'contrib/ml-dsa-console/launch-public.command'), '--container', name,
                '--state-dir', str(state), '--port', '18848', '--p2p-port', '23944',
                '--runtime-descriptor', str(args.descriptor), '--no-browser']

    def event(step, **data):
        events.append({'step': step, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'monotonic_ns': time.monotonic_ns(), **data})

    def reopen():
        result = subprocess.run(launcher, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        require(result.returncode == 0, 'One-click relaunch failed')
        return wait_ready(url, child)

    def retained(expected, initial_container, initial_volume):
        engine_identity()
        value = selected(wait_ready(url, child))
        require(value['wallet']['wallet_id'] == expected['wallet']['wallet_id'], 'Wallet identity changed')
        for field in ('next_receive', 'next_change', 'balance_sats', 'confirmed_sats'):
            require(value['wallet'][field] == expected['wallet'][field], 'Retained wallet changed: ' + field)
        require(value['wallet']['locked'] is True, 'Restart did not lock signer')
        require(value['nodes'] == expected['nodes'], 'Chain or paused networking changed')
        require(set(expected['backup_ids']) <= set(value['backup_ids']), 'Retained backup disappeared')
        current = inspect(name)
        require(current['id'] == initial_container['id'] and current['image'] == descriptor['image']
                and current['mounts'] == initial_container['mounts'], 'Container or mounts replaced')
        require(volume(name + '-data-v1') == initial_volume, 'Volume identity changed')
        return value

    try:
        child = subprocess.Popen(launcher + ['--no-autostart'], stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 90
        while True:
            require(child.poll() is None, 'Fresh public launcher exited')
            try:
                identity = read(url, '/api/identity')
                break
            except URLError:
                require(time.monotonic() < deadline, 'Fresh HTTP server deadline')
                time.sleep(0.25)
        require(identity['container'] == name and identity['state_id'] == hashlib.sha256(str(state.resolve()).encode()).hexdigest(), 'HTTP identity')
        action(url, 'start')
        owned = inspect(name)
        require(owned['image'] == descriptor['image'] and owned['name'] == '/' + name, 'Initial owned image/name')
        action(url, 'bootstrap')
        password = secrets.token_urlsafe(32)
        action(url, 'setup', {'password': password})
        address = action(url, 'receive')['result']
        action(url, 'fund')
        backup = action(url, 'backup')['result']['id']
        action(url, 'unlock', {'password': password})
        later = action(url, 'receive')['result']
        sent = action(url, 'send', {'address': address['address'], 'amount_sats': 100000, 'fee_sats': 5000})['result']
        first_block = action(url, 'mine', {'blocks': 1})['result']['blocks'][0]
        first_confirmation = confirmed(owned, descriptor, sent['txid'], first_block)
        action(url, 'network', {'active': False})
        before = selected(status(url))
        require(before['nodes'][0]['network_active'] is False, 'Pause not observed')
        data_volume = volume(name + '-data-v1')
        event('disposable_wallet_funded_sent_confirmed_and_paused', status=before, txid=sent['txid'],
              confirmation=first_confirmation, app_pid=child.pid, container_id=owned['id'])
        exclusive(name)
        command(['docker', 'desktop', 'restart', '--timeout', '180'])
        reopen()
        event('actual_desktop_restart_existing_app_reopened', status=retained(before, owned, data_volume),
              confirmation=confirmed(owned, descriptor, sent['txid'], first_block))
        exclusive(name)
        command(['docker', 'desktop', 'stop', '--timeout', '120'])
        require(child.poll() is None and read(url, '/api/identity') == identity, 'HTTP app did not survive Desktop stop')
        require(subprocess.run(['docker', 'info', '--format', '{{json .ServerVersion}}'], capture_output=True, timeout=15).returncode != 0,
                'Docker was not actually stopped')
        event('desktop_stopped_existing_http_app_still_alive', app_pid=child.pid)
        reopen()
        event('one_click_started_desktop_and_reused_app', status=retained(before, owned, data_volume), app_pid=child.pid,
              confirmation=confirmed(owned, descriptor, sent['txid'], first_block))
        previous_app_pid = child.pid
        require(child.poll() is None, 'Existing app exited before cold-start drill')
        child.send_signal(signal.SIGINT)
        require(child.wait(timeout=90) == 0, 'Existing app did not close before cold start')
        exclusive(name)
        command(['docker', 'desktop', 'stop', '--timeout', '120'])
        require(subprocess.run(['docker', 'info', '--format', '{{json .ServerVersion}}'], capture_output=True, timeout=15).returncode != 0,
                'Docker was not actually stopped before the new host app')
        child = subprocess.Popen(launcher, stdout=log, stderr=subprocess.STDOUT)
        wait_ready(url, child)
        require(child.pid != previous_app_pid and read(url, '/api/identity') == identity, 'Fresh host app identity')
        event('cold_desktop_and_new_host_app_one_click_resume', status=retained(before, owned, data_volume),
              old_app_pid=previous_app_pid, new_app_pid=child.pid,
              confirmation=confirmed(owned, descriptor, sent['txid'], first_block))
        action(url, 'network', {'active': True})
        action(url, 'unlock', {'password': password})
        newest = action(url, 'receive')['result']
        require(newest['index'] > later['index'], 'Address reused after Desktop recovery')
        action(url, 'recover', {'backup_id': backup, 'password': password})
        require(status(url)['wallet']['locked'] is False, 'Successful recovery did not unlock the wallet')
        recovered = action(url, 'receive')['result']
        require(recovered['index'] > newest['index'], 'Older backup reused an address')
        final_send = action(url, 'send', {'address': recovered['address'], 'amount_sats': 100000, 'fee_sats': 5000})['result']
        final_block = action(url, 'mine', {'blocks': 1})['result']['blocks'][0]
        final_confirmation = confirmed(owned, descriptor, final_send['txid'], final_block)
        final = selected(status(url))
        require(final['wallet']['wallet_id'] == before['wallet']['wallet_id'] and final_send['txid'] != sent['txid'], 'Final recovered spend')
        event('old_backup_recovered_and_new_spend_confirmed', status=final, txid=final_send['txid'], confirmation=final_confirmation)
        report.update(result='PASS', final_status=final, original_app_pid=child.pid,
                      native_reexecution='ACTUAL_L_QUALIFIED_IMAGE', secrets_written_to_artifacts=False,
                      operating_system_reboot_performed=False)
    except Exception as error:
        report.update(error_class=type(error).__name__, failed_step=events[-1]['step'] if events else 'setup')
        raise
    finally:
        # Restore Docker/original availability even if a disposable assertion fails.
        sys.path.insert(0, str(ROOT / 'contrib/ml-dsa-console'))
        from durable import RuntimeManager
        try:
            RuntimeManager(container=ORIGINAL)._daemon(lambda _: None)
            current = inspect(ORIGINAL)
            require(current['id'] == original['id'] and current['image'] == original['image']
                    and current['mounts'] == original['mounts'], 'Original container custody changed')
            if original['running'] and not current['running']:
                command(['docker', 'start', ORIGINAL])
            original_launcher = [str(ROOT / 'contrib/ml-dsa-console/launch.command'), '--container', ORIGINAL,
                                 '--state-dir', str(Path.home() / 'quantum-proof-bitcoin-evidence/local-console'),
                                 '--port', '8844', '--no-browser']
            command(original_launcher, timeout=300)
            require(read(old_url, '/api/identity') == original_identity and volume(ORIGINAL + '-data-v1') == original_volume,
                    'Original identity or volume changed')
            after = selected(status(old_url))
            require(after['wallet']['wallet_id'] == original_status['wallet']['wallet_id'], 'Original wallet identity changed')
            if original_status['ready'] is True:
                require(after['phase'] == 'running' and after['ready'] is True, 'Original console did not resume')
            for field in ('next_receive', 'next_change'):
                previous = original_status['wallet'][field]
                require(type(previous) is int and type(after['wallet'][field]) is int and after['wallet'][field] >= previous,
                        'Original address counter regressed')
            require(set(original_status['backup_ids']) <= set(after['backup_ids']), 'Original backup disappeared')
            report['original_after'] = {'container': inspect(ORIGINAL), 'volume': volume(ORIGINAL + '-data-v1'),
                                        'identity': original_identity, 'status': after}
            report['original_custody_preserved'] = True
        except Exception as error:
            report.update(result='FAIL', original_restore_error_class=type(error).__name__)
        if child is not None:
            try:
                require(child.poll() is None, 'Owned app exited unexpectedly before intentional cleanup')
                child.send_signal(signal.SIGINT)
                require(child.wait(timeout=90) == 0, 'Owned app cleanup failed')
                report['app_cleanup'] = 'INTENTIONAL_SIGINT_EXIT0'
            except Exception as error:
                report.update(result='FAIL', app_cleanup_error_class=type(error).__name__)
        if owned is not None:
            try:
                report['backend_cleanup'] = stop_owned(owned, descriptor['image'])
            except Exception as error:
                report.update(result='FAIL', backend_cleanup_error_class=type(error).__name__)
        else:
            report.update(result='FAIL', backend_cleanup='NO_VERIFIED_OWNED_BACKEND_HANDLE')
        log.close()
        report['events'] = events
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with (args.output / 'report.json').open('x') as target:
            json.dump(report, target, sort_keys=True, indent=2)
            target.write('\n')
        require(report['result'] == 'PASS', 'Actual Desktop recovery failed; preserved report')
    print('PASS_REAL_DESKTOP_RESTART_AND_STOP_WITH_EXISTING_PUBLIC_APP')


if __name__ == '__main__':
    main()
