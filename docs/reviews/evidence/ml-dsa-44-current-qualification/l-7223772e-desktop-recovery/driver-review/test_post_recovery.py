"""Execute only the driver's recovery tail against an in-memory HTTP model."""
import ast
import importlib.util
from pathlib import Path
import unittest

BASE = Path(__file__).parent.parent
NEW = BASE / 'run_desktop_recovery_02.py'
DRIVER = NEW if NEW.is_file() else BASE / 'run_desktop_recovery.py'


def recovery_tail():
    tree = ast.parse(DRIVER.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    body = next(node.body for node in main.body if isinstance(node, ast.Try) and node.finalbody)
    begin = next(i for i, node in enumerate(body) if isinstance(node, ast.Expr) and
                 isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and
                 node.value.func.id == 'action' and len(node.value.args) > 1 and
                 isinstance(node.value.args[1], ast.Constant) and node.value.args[1].value == 'recover')
    end = next(i for i in range(begin, len(body)) if isinstance(body[i], ast.Expr) and
               isinstance(body[i].value, ast.Call) and isinstance(body[i].value.func, ast.Name) and
               body[i].value.func.id == 'event' and body[i].value.args[0].value == 'old_backup_recovered_and_new_spend_confirmed')
    return compile(ast.fix_missing_locations(ast.Module(body=body[begin:end+1], type_ignores=[])), str(DRIVER), 'exec')


def loaded_driver():
    spec = importlib.util.spec_from_file_location('post_recovery_driver', DRIVER)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class RecoverModel:
    def __init__(self, *, reported_locked=False):
        self.locked = True
        self.reported_locked = reported_locked
        self.calls = []
        self.events = []
        self.proofs = []

    def action(self, _url, name, params=None):
        self.calls.append(name)
        if name == 'recover':
            self.locked = False
            return {'result': {'wallet_id': 'a' * 32}}
        if name == 'unlock':
            if not self.locked:
                raise ValueError('Model rejects redundant unlock after successful recovery')
            self.locked = False
            return {'result': {'unlocked': True}}
        if name == 'receive':
            if self.locked:
                raise ValueError('Model wallet is locked')
            return {'result': {'index': 4, 'address': 'PUBLIC_RECOVERED_ADDRESS'}}
        if name == 'send':
            return {'result': {'txid': 'b' * 64}}
        if name == 'mine':
            return {'result': {'blocks': ['c' * 64]}}
        raise AssertionError('Unexpected model action')

    def status(self, _url):
        return {'wallet': {'wallet_id': 'a' * 32, 'locked': self.reported_locked}}

    def confirmed(self, _owned, _descriptor, txid, block):
        self.proofs.append((txid, block))
        return {'txid': txid, 'block_hash': block, 'confirmed': True, 'confirmations': 1}

    def run(self):
        driver = loaded_driver()
        scope = {'action': self.action, 'status': self.status, 'require': driver.require,
                 'confirmed': self.confirmed, 'selected': lambda value: value,
                 'event': lambda name, **value: self.events.append((name, value)),
                 'url': 'http://127.0.0.1:18848', 'password': 'PUBLIC_MODEL_PASSWORD', 'backup': 'PUBLIC_MODEL_BACKUP',
                 'newest': {'index': 3}, 'owned': {'id': 'PUBLIC_OWNED_ID'}, 'descriptor': {'image': 'PUBLIC_IMAGE'},
                 'before': {'wallet': {'wallet_id': 'a' * 32}}, 'sent': {'txid': 'd' * 64}}
        exec(recovery_tail(), scope)
        return scope


class PostRecoveryFlow(unittest.TestCase):
    def test_successful_recovery_continues_without_redundant_unlock(self):
        model = RecoverModel()
        try:
            scope = model.run()
        except ValueError as error:
            self.fail(str(error))
        self.assertEqual(model.calls, ['recover', 'receive', 'send', 'mine'])
        self.assertEqual(model.proofs, [('b' * 64, 'c' * 64)])
        self.assertEqual(scope['recovered']['index'], 4)
        self.assertEqual(model.events[-1][0], 'old_backup_recovered_and_new_spend_confirmed')

    def test_recovery_reported_locked_refuses_before_new_address(self):
        model = RecoverModel(reported_locked=True)
        with self.assertRaisesRegex(ValueError, 'Successful recovery did not unlock the wallet'):
            model.run()
        self.assertEqual(model.calls, ['recover'])
        self.assertEqual(model.proofs, [])


if __name__ == '__main__':
    unittest.main()
