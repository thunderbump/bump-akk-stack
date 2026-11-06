"""Fixed operations through real client/service sockets, with harmless host controls."""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch

import test_maintenance as fixtures
m, client = fixtures.m, fixtures.client


class FixedOperations(unittest.TestCase):
    def setUp(self):
        fixtures.Transaction.setUp(self)
        self.slot = self.root / 'last-integration'
        self.slot.mkdir(mode=0o700)
        self.enterContext(patch.object(m, 'RETAINED', self.slot))
        original_stat = Path.lstat
        def logical_stat(path, *a, **kw):
            info = original_stat(path, *a, **kw)
            if path in (self.root, self.slot):
                values = list(info); values[4:6] = [995, 980]
                return os.stat_result(values)
            return info
        self.enterContext(patch.object(Path, 'lstat', logical_stat))
        original_read = m.read
        def logical_read(path, *a, **kw):
            raw, item = original_read(path, *a, **kw)
            if path.parent == self.slot:
                item.update(uid=995, gid=980)
            return raw, item
        # read's real inode checks must see real stat; logical ownership is only
        # supplied after its file checks, while directory ownership is mapped.
        self.enterContext(patch.object(m, 'read', logical_read))
        self.run = 'a' * 32
        pending = dict(version=1, name=m.ARTIFACT, candidate='b'*40,
                       fixture_sha256='c'*64, run_id=self.run)
        self.receipt = dict(pending, bytes=0, sha256=m.sha(b''), terminal=False,
                            complete=False, client_durable=False, original_transfer='uncertain',
                            error='integration-incomplete', execution=dict(workload_exit_code=None,
                            validator_exit_code=2, native_cleanup='not-run', database_cleanup=True,
                            vm_cleanup=True))
        self.write('pending.json', pending); self.write('receipt.json', self.receipt)
        (self.slot / m.ARTIFACT).write_bytes(b''); (self.slot / m.ARTIFACT).chmod(0o600)

    def write(self, name, value):
        (self.slot / name).write_bytes(m.canonical(value)); (self.slot / name).chmod(0o600)

    def call(self, op, **fields):
        endpoint = self.root / 'request.sock'
        endpoint.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(endpoint)); server.listen()
        errors = []
        def serve():
            try:
                conn, _ = server.accept()
                with conn: m.serve(conn, self.config, self.store)
            except Exception as error: errors.append(error)
            finally: server.close()
        thread = threading.Thread(target=serve); thread.start()
        result = client.exchange(dict(schema=1, id='d'*32, op=op, **fields), str(endpoint), os.getuid())
        thread.join(5); self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        return result

    def test_retire_preserves_every_byte_and_explicit_repeat_refuses(self):
        before = {p.name:p.read_bytes() for p in self.slot.iterdir()}
        self.host.active = True
        result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertTrue(result['ok'], result)
        target = self.state / 'retired-integrations' / self.run
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, before)
        self.assertFalse(self.slot.exists()); self.assertFalse(self.host.active)
        self.assertEqual(self.call('status')['result']['retired_integrations']['runs'], [self.run])
        self.assertEqual(result['result']['execution']['native_cleanup'], 'not-run')
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, before)

    def test_mismatch_vm_cleanup_malformed_success_and_archive_refuse(self):
        self.assertFalse(self.call('retire-failed-integration', expected_run='e'*32)['ok'])
        for cleanup in (False, 'unknown', 'not-run'):
            self.receipt['execution']['vm_cleanup'] = cleanup; self.write('receipt.json', self.receipt)
            self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.receipt['execution']['vm_cleanup'] = True
        self.receipt['execution']['validator_exit_code'] = 0
        self.receipt.update(complete=True, terminal=True, client_durable=True, original_transfer='durable', error='none')
        self.write('receipt.json', self.receipt)
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.receipt['execution']['validator_exit_code'] = 2; self.write('receipt.json', self.receipt)
        archive = self.state/'retired-integrations'; archive.mkdir(mode=0o700)
        (archive/self.run).mkdir()
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertTrue(self.slot.exists()); self.assertEqual(self.host.controls, [])

    def test_malformed_metadata_and_child_symlink_refuse(self):
        receipt = self.slot/'receipt.json'
        receipt.chmod(0o644)
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        receipt.chmod(0o600)
        self.receipt['complete'] = 'false'; self.write('receipt.json', self.receipt)
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        receipt.unlink(); receipt.symlink_to(self.root/'missing')
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertEqual(self.host.controls, [])

    def test_root_symlink_refuses_without_following(self):
        original = self.root/'original'; self.slot.rename(original); self.slot.symlink_to(original)
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertTrue(self.slot.is_symlink()); self.assertTrue(original.exists())
        self.assertEqual(self.host.controls, [])

    def test_socket_controls_status_busy_arguments_and_peer(self):
        self.assertTrue(self.call('socket-start')['ok']); self.assertTrue(self.host.active)
        self.assertTrue(self.call('status')['result']['ordinary_socket_active'])
        self.assertTrue(self.call('socket-stop')['ok']); self.assertFalse(self.host.active)
        for fields in ({'unit':'evil'}, {'options':['--now']}):
            self.assertFalse(self.call('socket-start', **fields)['ok'])
        self.host.busy = True
        self.assertFalse(self.call('socket-start')['ok'])
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.host.busy = False
        self.config['submitter_uid'] += 1
        with self.assertRaisesRegex(m.Refusal, 'response-binding'):
            self.call('socket-start')

    def test_fixed_systemctl_argv_and_failure_timeout(self):
        host = m.Host()
        with patch.object(m.subprocess, 'run') as run, patch.object(host, 'socket_active', return_value=True):
            host.socket(True)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl','start','eqemu-validator.socket'])
            self.assertEqual(run.call_args.kwargs['timeout'], 15)
            self.assertEqual(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
        with patch.object(m.subprocess, 'run') as run, patch.object(host, 'socket_active', return_value=False):
            host.socket(False)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl','stop','eqemu-validator.socket'])
        for failure in (subprocess.TimeoutExpired(['fixture'], 15), subprocess.CalledProcessError(1, ['fixture'])):
            with patch.object(self.host, 'socket', side_effect=failure):
                result = self.call('socket-start')
                self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'command-failed-or-uncertain')
                result = self.call('retire-failed-integration', expected_run=self.run)
                self.assertFalse(result['ok']); self.assertTrue(self.slot.exists())

    def test_post_rename_failure_reports_uncertain_and_never_repeats(self):
        with patch.object(m.os, 'fsync', side_effect=OSError('injected')):
            result = self.call('retire-failed-integration', expected_run=self.run)
            self.assertFalse(result['ok'])
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertTrue((self.state/'retired-integrations'/self.run/'receipt.json').exists())

class UpdatePackage(unittest.TestCase):
    def test_preparer_only_writes_fixed_package_and_review_commands(self):
        import importlib.util
        import tempfile
        spec = importlib.util.spec_from_file_location('prepare_mvp', fixtures.ROOT/'validation/maintenance/prepare_mvp_update.py')
        preparer = importlib.util.module_from_spec(spec); spec.loader.exec_module(preparer)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); installed = root/'installed'; installed.mkdir()
            (installed/'maintenance.py').write_bytes(b'old core')
            baseline = dict(code_sha256={'maintenance.py':m.sha(b'old core'), 'service.py':'unchanged'}, marker='preserve config')
            (installed/'baseline.json').write_bytes(m.canonical(baseline))
            unit = root/'eqemu-validator-maintenance@.service'; unit.write_bytes(b'old unit')
            with patch.object(preparer, 'ROOT', installed), patch.object(preparer, 'UNIT', unit), patch.object(preparer.subprocess, 'check_output', side_effect=[b'', b'f'*40+b'\n']):
                with patch('builtins.print'): preparer.prepare(root/'package')
            package = root/'package'; manifest = json.loads((package/'manifest.json').read_bytes())
            after = json.loads((package/'baseline.json').read_bytes())
            self.assertEqual(after['marker'], baseline['marker'])
            self.assertEqual(after['code_sha256']['service.py'], 'unchanged')
            self.assertEqual(after['code_sha256']['maintenance.py'], m.sha((package/'maintenance.py').read_bytes()))
            self.assertEqual((installed/'maintenance.py').read_bytes(), b'old core')
            self.assertEqual(unit.read_bytes(), b'old unit')
            self.assertEqual(len(manifest['files']), 3)
            for name in ('UPDATE-REVIEW-ONLY.sh', 'RESTORE-REVIEW-ONLY.sh'):
                subprocess.run(['/bin/sh', '-n', str(package/name)], check=True, timeout=5)
                self.assertNotIn('start eqemu-validator.socket', (package/name).read_text())
