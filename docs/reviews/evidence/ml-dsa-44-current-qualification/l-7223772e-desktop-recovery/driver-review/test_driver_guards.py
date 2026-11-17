"""Pure mock fixtures. Never contact Docker, Desktop, Research or HTTP."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

DRIVER = Path(__file__).resolve().parent.parent/'run_desktop_recovery_02.py'
spec = importlib.util.spec_from_file_location('desktop_recovery_driver_review', DRIVER)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def complete(stdout=b'', returncode=0, stderr=b''):
    return subprocess.CompletedProcess(['PUBLIC_MOCK_ONLY'], returncode, stdout, stderr)


class Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class PublicDriverGuards(unittest.TestCase):
    def test_unrelated_running_container_refused(self):
        with mock.patch.object(driver, 'engine_identity', return_value=driver.ENGINE), mock.patch.object(driver, 'command', return_value=complete(b'pqbtc-mldsa-local\nPUBLIC_UNRELATED_TASK\n')) as command:
            with self.assertRaisesRegex(ValueError, 'Unrelated running containers'):
                driver.exclusive('pqbtc-mldsa-public-l-desktop-20261117-02')
        self.assertEqual(command.call_count, 1)

    def test_expected_running_names_accepted(self):
        owned = 'pqbtc-mldsa-public-l-desktop-20261117-02'
        with mock.patch.object(driver, 'engine_identity', return_value=driver.ENGINE), mock.patch.object(driver, 'command', return_value=complete((driver.ORIGINAL+'\n'+owned+'\n').encode())):
            driver.exclusive(owned)

    def test_inspect_projection_excludes_environment_and_commandline(self):
        observed = {}
        def command(argv, **kwargs):
            observed['argv'] = argv
            return complete(b'{"id":"PUBLIC_ID","running":false}')
        with mock.patch.object(driver, 'command', command):
            driver.inspect('PUBLIC_EXACT_NAME')
        template = observed['argv'][4]
        self.assertNotIn('.Env', template)
        self.assertNotIn('.Cmd', template)
        self.assertNotIn('.Args', template)

    def test_http_read_bounds_body(self):
        with mock.patch.object(driver, 'urlopen', return_value=Reply(b'X'*(2*1024**2+1))):
            with self.assertRaisesRegex(ValueError, 'Bounded HTTP'):
                driver.read('http://127.0.0.1:18848', '/api/status')

    def test_status_requires_real_bool(self):
        for invalid in (False, 1, 'true', None):
            with self.subTest(invalid=invalid), mock.patch.object(driver, 'read', return_value={'ok': invalid, 'data': {}}):
                with self.assertRaisesRegex(ValueError, 'Public status refused'):
                    driver.status('http://127.0.0.1:18848')

    def test_action_synthetic_password_and_token_only_in_memory(self):
        password = 'PUBLIC_SYNTHETIC_PASSWORD_FIXTURE'
        token = 'PUBLIC_SYNTHETIC_TOKEN_FIXTURE'
        captured = {}
        count = 0
        def urlopen(request, **kwargs):
            nonlocal count
            count += 1
            if count == 1:
                return Reply(('<meta name="console-token" content="'+token+'">').encode())
            captured['request'] = request
            return Reply(b'{"ok":true,"data":{"result":"PUBLIC_OK"}}')
        output = io.StringIO()
        with mock.patch.object(driver, 'urlopen', urlopen), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = driver.action('http://127.0.0.1:18848', 'unlock', {'password': password})
        self.assertEqual(result, {'result': 'PUBLIC_OK'})
        body = json.loads(captured['request'].data)
        self.assertEqual(body['params'], {'password': password})
        self.assertEqual(captured['request'].get_header('X-console-token'), token)
        self.assertNotIn(password, captured['request'].full_url)
        self.assertNotIn(token, captured['request'].full_url)
        self.assertNotIn(password, output.getvalue())
        self.assertNotIn(token, output.getvalue())

    def test_action_rejection_does_not_echo_error_body(self):
        marker = b'PUBLIC_SYNTHETIC_UNSAFE_ERROR_BODY'
        html = Reply(b'<meta name="console-token" content="PUBLIC_TOKEN">')
        error = HTTPError('http://127.0.0.1:18848/api/action', 403, 'PUBLIC_DENIAL', {}, Reply(marker))
        with mock.patch.object(driver, 'urlopen', side_effect=[html, error]):
            with self.assertRaisesRegex(ValueError, '^Own HTTP action rejected: unlock$') as caught:
                driver.action('http://127.0.0.1:18848', 'unlock', {'password': 'PUBLIC_SYNTHETIC'})
        self.assertNotIn(marker.decode(), str(caught.exception))
        error.close()

    def test_dead_owned_app_refuses_before_http(self):
        child = mock.Mock()
        child.poll.return_value = 9
        with mock.patch.object(driver, 'status') as status:
            with self.assertRaisesRegex(ValueError, 'Owned app exited'):
                driver.wait_ready('http://127.0.0.1:18848', child)
        status.assert_not_called()

    def test_wait_ready_transport_retry_has_original_deadline(self):
        child = mock.Mock()
        child.poll.return_value = None
        with mock.patch.object(driver.time, 'monotonic', side_effect=[0, 0, 2]), mock.patch.object(driver.time, 'sleep'), mock.patch.object(driver, 'status', side_effect=URLError('PUBLIC_UNAVAILABLE')):
            with self.assertRaisesRegex(ValueError, 'did not become ready'):
                driver.wait_ready('http://127.0.0.1:18848', child, seconds=1)

    def test_selected_projection_retains_counters_but_no_extra_data(self):
        raw = {'phase': 'stopped', 'ready': False, 'startup_error': 'PUBLIC_EXISTING_FAILURE',
               'wallet': {'wallet_id': 'PUBLIC_WALLET', 'next_receive': 7, 'next_change': 3,
                          'password': 'PUBLIC_SYNTHETIC_NEVER_OUTPUT', 'ciphertext': 'PUBLIC_SYNTHETIC'},
               'nodes': [{'height': 2, 'network_active': False, 'cookie': 'PUBLIC_SYNTHETIC'}]}
        selected = driver.selected(raw)
        self.assertEqual(selected['phase'], 'stopped')
        self.assertIs(selected['ready'], False)
        self.assertEqual(selected['wallet']['next_receive'], 7)
        self.assertEqual(selected['wallet']['next_change'], 3)
        self.assertNotIn('PUBLIC_SYNTHETIC', json.dumps(selected))


class OwnedCleanupAndMembership(unittest.TestCase):
    def setUp(self):
        engine = mock.patch.object(driver, 'engine_identity', return_value=driver.ENGINE)
        engine.start()
        self.addCleanup(engine.stop)
        self.owned = {'id': 'a'*64, 'name': '/pqbtc-mldsa-public-l-desktop-20261117-02',
                      'image': driver.GCC_IMAGE, 'running': True, 'pid': 123,
                      'mounts': [{'Type': 'volume', 'Name': 'PUBLIC_DISPOSABLE_VOLUME', 'Destination': '/var/lib/pqbtc'}]}
        self.descriptor = {'image': driver.GCC_IMAGE, 'manifest': {'sha256': {'/tmp/mldsa-demo-build/bin/pqbtcd': 'e'*64}}}
        self.txid, self.block = 'b'*64, 'c'*64

    def test_foreign_or_replaced_owned_identity_refuses_before_stop(self):
        variants = [{'id': 'd'*64}, {'image': 'sha256:'+'f'*64}, {'name': '/PUBLIC_FOREIGN'}, {'mounts': []}]
        for change in variants:
            with self.subTest(change=change):
                current = {**self.owned, **change}
                with mock.patch.object(driver, 'inspect', return_value=current), mock.patch.object(driver, 'command') as command:
                    with self.assertRaisesRegex(ValueError, 'Owned container identity changed'):
                        driver.stop_owned(self.owned, driver.GCC_IMAGE)
                    command.assert_not_called()

    def test_stop_uses_exact_ID_then_proves_zero_PID(self):
        final = {**self.owned, 'running': False, 'pid': 0}
        with mock.patch.object(driver, 'inspect', side_effect=[self.owned, final]) as inspect, mock.patch.object(driver, 'command', return_value=complete()) as command:
            value = driver.stop_owned(self.owned, driver.GCC_IMAGE)
        self.assertEqual(inspect.call_args_list, [mock.call(self.owned['id']), mock.call(self.owned['id'])])
        command.assert_called_once_with(['docker', 'stop', '--time', '30', self.owned['id']], timeout=60)
        self.assertTrue(value['backend_stopped'])
        self.assertEqual(value['pid'], 0)

    def test_already_stopped_backend_does_not_signal(self):
        final = {**self.owned, 'running': False, 'pid': 0}
        with mock.patch.object(driver, 'inspect', return_value=final), mock.patch.object(driver, 'command') as command:
            driver.stop_owned(self.owned, driver.GCC_IMAGE)
        command.assert_not_called()

    def test_cleanup_uncertain_state_cannot_pass(self):
        for change in [{'running': True, 'pid': 0}, {'running': False, 'pid': 9}, {'running': False, 'pid': False}, {'running': False, 'pid': '0'}]:
            with self.subTest(change=change), mock.patch.object(driver, 'inspect', side_effect=[self.owned, {**self.owned, **change}]), mock.patch.object(driver, 'command', return_value=complete()):
                with self.assertRaisesRegex(ValueError, 'Owned backend not stopped'):
                    driver.stop_owned(self.owned, driver.GCC_IMAGE)

    def proof(self):
        return {'txid': self.txid, 'block_hash': self.block, 'confirmations': 1, 'confirmed': True}

    def test_exact_known_membership_and_cookie_stays_inside(self):
        with mock.patch.object(driver, 'confirm_owned', return_value=self.owned), mock.patch.object(driver, 'command', return_value=complete(json.dumps(self.proof()).encode())) as command:
            self.assertEqual(driver.confirmed(self.owned, self.descriptor, self.txid, self.block), self.proof())
        argv = command.call_args.args[0]
        self.assertEqual(argv[:8], ['docker', 'exec', '--user', '1001:1001', self.owned['id'], 'python3', '-I', '-B'])
        self.assertEqual(argv[-3:], [self.txid, self.block, 'e'*64])
        self.assertIn('PublicNode', argv[-4])
        self.assertIn("'/var/lib/pqbtc/node/chain'", argv[-4])
        self.assertNotIn('__cookie__:', json.dumps(argv))
        self.assertNotIn('http://', json.dumps(argv))
        self.assertIn("type(error).__name__", argv[-4])

    def test_invalid_known_transaction_or_block_refuses_before_exec(self):
        invalid = ['', 'b'*63, 'g'*64, 'B'*64, 7, None]
        for bad in invalid:
            for pair in [(bad, self.block), (self.txid, bad)]:
                with self.subTest(pair=pair), mock.patch.object(driver, 'confirm_owned') as owned, mock.patch.object(driver, 'command') as command:
                    with self.assertRaisesRegex(ValueError, 'Known transaction/block required'):
                        driver.confirmed(self.owned, self.descriptor, *pair)
                    owned.assert_not_called()
                    command.assert_not_called()

    def test_false_missing_or_mismatched_membership_cannot_pass(self):
        variants = [{'confirmed': False}, {'confirmed': 1}, {'confirmations': 0}, {'confirmations': True},
                    {'confirmations': 1.0}, {'txid': 'd'*64}, {'block_hash': 'd'*64}, {'extra': 'PUBLIC_UNUSED'}]
        for change in variants:
            value = {**self.proof(), **change}
            with self.subTest(change=change), mock.patch.object(driver, 'confirm_owned', return_value=self.owned), mock.patch.object(driver, 'command', return_value=complete(json.dumps(value).encode())):
                with self.assertRaisesRegex(ValueError, 'Exact transaction confirmation missing'):
                    driver.confirmed(self.owned, self.descriptor, self.txid, self.block)
        value = self.proof()
        del value['confirmed']
        with mock.patch.object(driver, 'confirm_owned', return_value=self.owned), mock.patch.object(driver, 'command', return_value=complete(json.dumps(value).encode())):
            with self.assertRaisesRegex(ValueError, 'Exact transaction confirmation missing'):
                driver.confirmed(self.owned, self.descriptor, self.txid, self.block)

    def test_confirmation_output_is_bounded(self):
        with mock.patch.object(driver, 'confirm_owned', return_value=self.owned), mock.patch.object(driver, 'command', return_value=complete(b'X'*2049)):
            with self.assertRaisesRegex(ValueError, 'Bounded transaction proof required'):
                driver.confirmed(self.owned, self.descriptor, self.txid, self.block)


class DesktopEngineScope(unittest.TestCase):
    def test_exact_local_context_and_engine_accepted(self):
        replies = [complete(json.dumps('unix://'+str(Path.home()/'.docker/run/docker.sock')).encode()), complete(json.dumps(driver.ENGINE).encode())]
        with mock.patch.object(driver, 'command', side_effect=replies) as command:
            self.assertEqual(driver.engine_identity(), driver.ENGINE)
        self.assertFalse(any('desktop' in args.args[0] for args in command.call_args_list))

    def test_foreign_endpoint_or_engine_refuses_without_desktop_mutation(self):
        local = 'unix://'+str(Path.home()/'.docker/run/docker.sock')
        for replies, message in [([complete(b'"ssh://PUBLIC_FOREIGN"')], 'Local Desktop socket context required'),
                                 ([complete(json.dumps(local).encode()), complete(b'"PUBLIC_FOREIGN_ENGINE"')], 'Unexpected Docker engine')]:
            with self.subTest(message=message), mock.patch.object(driver, 'command', side_effect=replies) as command:
                with self.assertRaisesRegex(ValueError, message):
                    driver.exclusive('pqbtc-mldsa-public-l-desktop-20261117-02')
                self.assertFalse(any('desktop' in args.args[0] for args in command.call_args_list))

    def test_main_pins_only_child_environment_and_rejects_engine_before_any_workload(self):
        environment = {'DOCKER_HOST': 'PUBLIC_SYNTHETIC_REMOTE', 'DOCKER_CONTEXT': 'PUBLIC_OTHER_CONTEXT'}
        argv = ['PUBLIC_DRIVER', '--descriptor', '/PUBLIC_NOT_OPENED', '--output', '/PUBLIC_NOT_CREATED', '--allow-desktop-restart']
        def refuse():
            self.assertNotIn('DOCKER_HOST', environment)
            self.assertEqual(environment['DOCKER_CONTEXT'], 'desktop-linux')
            raise ValueError('PUBLIC_FOREIGN_ENGINE_REFUSED')
        with mock.patch.object(driver.os, 'environ', environment), mock.patch.object(driver.sys, 'argv', argv), mock.patch.object(driver, 'engine_identity', refuse), mock.patch.object(driver, 'command') as command, mock.patch.object(driver.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(ValueError, 'PUBLIC_FOREIGN_ENGINE_REFUSED'):
                driver.main()
        command.assert_not_called()
        popen.assert_not_called()

    def test_actual_driver_control_flow_gates_mutations_and_final_PASS(self):
        source = DRIVER.read_text()
        main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        workload = next(n for n in main.body if isinstance(n, ast.Try) and n.finalbody)
        mutations = []
        for index, node in enumerate(workload.body):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'command':
                argv = node.value.args[0]
                if isinstance(argv, ast.List) and [ast.literal_eval(v) for v in argv.elts[:2]] == ['docker', 'desktop']:
                    mutations.append(node)
                    self.assertEqual(ast.unparse(workload.body[index-1]), 'exclusive(name)')
        self.assertEqual(len(mutations), 3)
        self.assertEqual([ast.literal_eval(node.value.args[0].elts[2]) for node in mutations], ['restart', 'stop', 'stop'])
        cold_index = workload.body.index(mutations[-1])
        down_check = ast.get_source_segment(source, workload.body[cold_index+1])
        self.assertIn("['docker', 'info'", down_check)
        self.assertIn('returncode != 0', down_check)
        cold_start = ast.get_source_segment(source, workload.body[cold_index+2])
        self.assertIn('child = subprocess.Popen(launcher', cold_start)
        self.assertIn("operating_system_reboot_performed=False", source)
        cleanup = '\n'.join(ast.get_source_segment(source, n) for n in workload.finalbody)
        self.assertLess(cleanup.index('child.poll() is None'), cleanup.index('child.send_signal(signal.SIGINT)'))
        self.assertLess(cleanup.index('child.send_signal(signal.SIGINT)'), cleanup.index('child.wait(timeout=90) == 0'))
        self.assertLess(cleanup.index('stop_owned(owned'), cleanup.index("require(report['result'] == 'PASS'"))
        self.assertIn("backend_cleanup='NO_VERIFIED_OWNED_BACKEND_HANDLE'", cleanup)


if __name__ == '__main__':
    unittest.main()
