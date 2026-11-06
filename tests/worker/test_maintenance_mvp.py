"""Fixed operations through real client/service sockets, with harmless host controls."""
import json
import errno
import os
from pathlib import Path
import socket
import subprocess
import threading
from types import SimpleNamespace
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
                # Preserve actual timestamp precision, including nanoseconds.
                fields = {key:getattr(info, key) for key in dir(info) if key.startswith('st_')}
                fields.update(st_uid=995, st_gid=980)
                return SimpleNamespace(**fields)
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
        try:
            return client.exchange(dict(schema=1, id='d'*32, op=op, **fields), str(endpoint), os.getuid())
        finally:
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_stale_atime_listing_retirement_preserves_original_bytes(self):
        artifact = b'failed fixture evidence\x00\xff' * 64
        (self.slot/m.ARTIFACT).write_bytes(artifact)
        self.receipt.update(bytes=len(artifact), sha256=m.sha(artifact))
        self.write('receipt.json', self.receipt)
        original = {p.name:p.read_bytes() for p in self.slot.iterdir()}
        os.utime(self.slot, ns=(1_000_000_000, 2_000_000_000))
        before = os.stat(self.slot, follow_symlinks=False)
        observed = []
        control = self.host.socket
        def after_listing(active):
            observed.append(os.stat(self.slot, follow_symlinks=False))
            control(active)
        with patch.object(self.host, 'socket', side_effect=after_listing):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertEqual(len(observed), 1)
        fields = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_atime', 'st_mtime', 'st_ctime',
                  'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')
        old = {key:getattr(before, key) for key in fields}
        new = {key:getattr(observed[0], key) for key in fields}
        changed = [key for key in fields if old[key] != new[key]]
        print('STALE-ATIME-FIXTURE '+json.dumps(dict(before=old, after=new, changed_fields=changed,
              result=result, source_present=self.slot.exists()), sort_keys=True), flush=True)
        self.assertEqual(changed, ['st_atime', 'st_atime_ns'])
        self.assertIsNotNone(self.slot.lstat().st_mtime_ns if self.slot.exists() else before.st_mtime_ns)
        if self.slot.exists():
            self.assertEqual({p.name:p.read_bytes() for p in self.slot.iterdir()}, original)
        self.assertTrue(result['ok'], result)
        target = self.state/'retired-integrations'/self.run
        self.assertFalse(self.slot.exists()); self.assertFalse(self.host.active)
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, original)
        self.assertEqual(result['result']['execution'], self.receipt['execution'])

    def test_directory_replacement_refuses(self):
        old = self.root/'original-slot'
        def replace(active):
            self.slot.rename(old); self.slot.mkdir(mode=0o700)
            for entry in old.iterdir():
                (self.slot/entry.name).write_bytes(entry.read_bytes())
                (self.slot/entry.name).chmod(0o600)
        with patch.object(self.host, 'socket', side_effect=replace):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'retention-changed')
        self.assertTrue(old.exists()); self.assertTrue(self.slot.exists())
        self.assertFalse((self.state/'retired-integrations'/self.run).exists())

    def test_directory_ownership_change_refuses(self):
        original_stat = Path.lstat
        changed = False
        def ownership(path, *a, **kw):
            info = original_stat(path, *a, **kw)
            if path == self.slot and changed:
                return SimpleNamespace(**dict(vars(info), st_uid=996))
            return info
        def change(active):
            nonlocal changed
            changed = True
        with patch.object(Path, 'lstat', ownership), patch.object(self.host, 'socket', side_effect=change):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'retention-changed')
        self.assertTrue(self.slot.exists()); self.assertFalse((self.state/'retired-integrations'/self.run).exists())

    def test_directory_mode_change_refuses(self):
        with patch.object(self.host, 'socket', side_effect=lambda active:self.slot.chmod(0o500)):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.slot.chmod(0o700)
        self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'retention-changed')
        self.assertTrue(self.slot.exists()); self.assertFalse((self.state/'retired-integrations'/self.run).exists())

    def test_file_content_change_refuses_without_transfer(self):
        receipt = (self.slot/'receipt.json').read_bytes()
        with patch.object(self.host, 'socket', side_effect=lambda active:(self.slot/m.ARTIFACT).write_bytes(b'changed evidence')):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertFalse(result['ok'])
        self.assertTrue(self.slot.exists()); self.assertFalse((self.state/'retired-integrations'/self.run).exists())
        self.assertEqual((self.slot/m.ARTIFACT).read_bytes(), b'changed evidence')
        self.assertEqual((self.slot/'receipt.json').read_bytes(), receipt)

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
        before = dict(vars(self.host), controls=list(self.host.controls))
        try:
            with self.assertRaises((m.Refusal, BrokenPipeError, ConnectionResetError)) as rejected:
                self.call('socket-start')
            if isinstance(rejected.exception, m.Refusal):
                self.assertEqual(str(rejected.exception), 'response-binding')
        finally:
            self.assertEqual(vars(self.host), before)

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

    def test_exdev_dispatch_uses_fixed_real_mv_and_preserves_complete_bytes(self):
        artifact = b'original failure evidence\x00\xff' * 100
        (self.slot/m.ARTIFACT).write_bytes(artifact)
        self.receipt.update(bytes=len(artifact), sha256=m.sha(artifact))
        self.write('receipt.json', self.receipt)
        before = {p.name:p.read_bytes() for p in self.slot.iterdir()}
        target = self.state/'retired-integrations'/self.run
        self.host.active = True
        real_run = subprocess.run
        with patch.object(m.os, 'rename', side_effect=OSError(errno.EXDEV, 'injected bind-mount boundary')) as rename, patch.object(m.subprocess, 'run', wraps=real_run) as move:
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertTrue(result['ok'], result)
        rename.assert_called_once_with(self.slot, target)
        self.assertEqual(move.call_args.args[0], ['/usr/bin/mv', '--no-clobber', '--no-target-directory', '--', str(self.slot), str(target)])
        self.assertEqual(move.call_args.kwargs, dict(check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15))
        self.assertFalse(self.slot.exists()); self.assertFalse(self.host.active)
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, before)
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, before)

    def test_exdev_move_failure_timeout_and_false_success_never_claim_retirement(self):
        before = {p.name:p.read_bytes() for p in self.slot.iterdir()}
        for failure in (subprocess.TimeoutExpired(['fixture'], 15), subprocess.CalledProcessError(1, ['fixture']), None):
            self.host.active = True
            with patch.object(m.os, 'rename', side_effect=OSError(errno.EXDEV, 'boundary')), patch.object(m.subprocess, 'run', side_effect=failure):
                result = self.call('retire-failed-integration', expected_run=self.run)
            self.assertFalse(result['ok'])
            self.assertFalse(self.host.active)
            self.assertEqual({p.name:p.read_bytes() for p in self.slot.iterdir()}, before)

    def test_exdev_real_mv_no_clobber_when_destination_appears(self):
        target = self.state/'retired-integrations'/self.run
        before = {p.name:p.read_bytes() for p in self.slot.iterdir()}
        real_run = subprocess.run
        def appeared(*args, **kwargs):
            target.mkdir(); (target/'keep').write_bytes(b'untouched evidence')
            return real_run(*args, **kwargs)
        with patch.object(m.os, 'rename', side_effect=OSError(errno.EXDEV, 'boundary')), patch.object(m.subprocess, 'run', side_effect=appeared):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertFalse(result['ok'])
        self.assertEqual({p.name:p.read_bytes() for p in self.slot.iterdir()}, before)
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, {'keep':b'untouched evidence'})
        self.assertFalse(self.host.active)

    def test_exdev_bad_copy_is_uncertain_and_repeat_refuses(self):
        target = self.state/'retired-integrations'/self.run
        real_rename = os.rename
        def bad_copy(*args, **kwargs):
            real_rename(self.slot, target)
            (target/m.ARTIFACT).write_bytes(b'bad copy')
        with patch.object(m.os, 'rename', side_effect=OSError(errno.EXDEV, 'boundary')), patch.object(m.subprocess, 'run', side_effect=bad_copy):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'retirement-copy-unconfirmed')
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertFalse(self.host.active)
        self.assertEqual((target/'receipt.json').read_bytes(), m.canonical(self.receipt))

    def test_exdev_timeout_after_move_reports_uncertain_with_original_archive(self):
        target = self.state/'retired-integrations'/self.run
        before = {p.name:p.read_bytes() for p in self.slot.iterdir()}
        real_rename = os.rename
        def moved_then_timeout(*args, **kwargs):
            real_rename(self.slot, target)
            raise subprocess.TimeoutExpired(args[0], 15)
        with patch.object(m.os, 'rename', side_effect=OSError(errno.EXDEV, 'boundary')), patch.object(m.subprocess, 'run', side_effect=moved_then_timeout):
            result = self.call('retire-failed-integration', expected_run=self.run)
        self.assertFalse(result['ok']); self.assertEqual(result['reason'], 'command-failed-or-uncertain')
        self.assertFalse(self.slot.exists()); self.assertFalse(self.host.active)
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, before)
        self.assertFalse(self.call('retire-failed-integration', expected_run=self.run)['ok'])
        self.assertEqual({p.name:p.read_bytes() for p in target.iterdir()}, before)

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
            with patch.object(preparer, 'ROOT', installed), patch.object(preparer, 'UNIT', unit), patch.object(preparer, 'EXPECTED_BEFORE', {name:m.sha((installed/name).read_bytes()) for name in ('maintenance.py','baseline.json')}), patch.object(preparer, 'EXPECTED_UNIT', m.sha(unit.read_bytes())), patch.object(preparer.subprocess, 'check_output', side_effect=[b'', b'f'*40+b'\n']):
                with patch('builtins.print'): preparer.prepare(root/'package')
            package = root/'package'; manifest = json.loads((package/'manifest.json').read_bytes())
            after = json.loads((package/'baseline.json').read_bytes())
            self.assertEqual(after['marker'], baseline['marker'])
            self.assertEqual(after['code_sha256']['service.py'], 'unchanged')
            self.assertEqual(after['code_sha256']['maintenance.py'], m.sha((package/'maintenance.py').read_bytes()))
            self.assertEqual((installed/'maintenance.py').read_bytes(), b'old core')
            self.assertEqual(unit.read_bytes(), b'old unit')
            self.assertEqual(len(manifest['files']), 2)
            self.assertEqual(manifest['retained_unit'], dict(destination=str(unit), sha256=m.sha(b'old unit')))
            self.assertFalse((package/unit.name).exists())
            self.assertNotIn('/root/eqemu-maintenance-mvp-update\n', (package/'UPDATE-REVIEW-ONLY.sh').read_text())
            self.assertIn('/root/eqemu-maintenance-mvp-atime-update-v4', (package/'UPDATE-REVIEW-ONLY.sh').read_text())
            guards = []
            for name in ('UPDATE-REVIEW-ONLY.sh', 'RESTORE-REVIEW-ONLY.sh'):
                subprocess.run(['/bin/sh', '-n', str(package/name)], check=True, timeout=5)
                self.assertNotIn('start eqemu-validator.socket', (package/name).read_text())
                lines = (package/name).read_text().splitlines()
                index = next(i for i, line in enumerate(lines) if 'list-units' in line)
                guard = lines[index:index+2]
                guards.append(guard)
                self.assertEqual(guard[1], 'test -z "$maintenance_active"')
                self.assertEqual(manifest['scripts_sha256'][name], m.sha((package/name).read_bytes()))
                enumeration = root/'enumerate'
                enumeration.write_text('#!/bin/sh\nprintf "%s" "$FIXTURE_OUTPUT"\nexit "$FIXTURE_EXIT"\n')
                enumeration.chmod(0o700)
                # Execute only the two generated guard lines, substituting the
                # enumeration executable. No root preflight/service action runs.
                seam = '\n'.join(guard).replace('/usr/bin/systemctl', str(enumeration))
                for code, output, allowed in ((7, '', False), (0, 'active-instance', False), (0, '', True)):
                    with self.subTest(recipe=name, exit=code, active=bool(output)):
                        result = subprocess.run(['/bin/sh', '-c', 'set -eu\n'+seam+'\nprintf reached-marker'],
                            env=dict(os.environ, FIXTURE_EXIT=str(code), FIXTURE_OUTPUT=output),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                        self.assertEqual(result.returncode == 0, allowed)
                        self.assertEqual(result.stdout, b'reached-marker' if allowed else b'')
            self.assertEqual(guards[0], guards[1])
            expected = {name:m.sha((installed/name).read_bytes()) for name in ('maintenance.py','baseline.json')}
            for changed in ('maintenance.py', 'baseline.json', 'unit'):
                path = unit if changed == 'unit' else installed/changed
                saved = path.read_bytes(); path.write_bytes(b'unexpected drift')
                try:
                    with patch.object(preparer, 'ROOT', installed), patch.object(preparer, 'UNIT', unit), patch.object(preparer, 'EXPECTED_BEFORE', expected), patch.object(preparer, 'EXPECTED_UNIT', m.sha(b'old unit')), patch.object(preparer.subprocess, 'check_output', side_effect=[b'', b'f'*40+b'\n']):
                        with self.assertRaisesRegex(AssertionError, 'drift'):
                            preparer.prepare(root/'refused-package')
                    self.assertFalse((root/'refused-package').exists())
                finally:
                    path.write_bytes(saved)
