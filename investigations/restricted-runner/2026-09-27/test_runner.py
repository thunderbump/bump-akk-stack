import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('control', ROOT / 'control.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class Requests(unittest.TestCase):
    def test_fixed_profile(self):
        self.assertEqual(C.parse_request(b'{"version":1,"op":"run","profile":"startup-diagnostic"}')['op'], 'run')

    def test_injection_and_unknown_fields(self):
        normal = {'version': 1, 'op': 'run', 'profile': C.PROFILE}
        for key, value in [('path', '/etc/shadow'), ('command', '/bin/sh'), ('uid', 0), ('unit', 'ssh.service'), ('budget', 0)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                C.parse_request(json.dumps(dict(normal, **{key: value})).encode())

    def test_wrong_types_duplicates_and_size(self):
        for data in (b'{', b'[]', b'null', b'{}', b'x' * 4097,
                     b'{"version":true,"op":"run","profile":"startup-diagnostic"}',
                     b'{"version":1,"version":1,"op":"run","profile":"startup-diagnostic"}',
                     b'{"version":1,"op":"publish","run_id":"0123456789"}',
                     b'{"version":1,"op":"run","profile":"/tmp/evil.py"}'):
            with self.subTest(data=data[:50]), self.assertRaises(ValueError):
                C.parse_request(data)

    def test_run_id_cannot_name_host_resources(self):
        for ident in ('../root', '0123456789\n', '/etc/shadow', 'ssh.service', None, 12):
            with self.subTest(ident=ident), self.assertRaises(ValueError):
                C.parse_request(json.dumps({'version': 1, 'op': 'cancel', 'run_id': ident}).encode())

    def test_pipe_reader_real_eof_and_stall(self):
        r, w = os.pipe()
        try:
            os.write(w, b'{"version":1,"op":"status","run_id":"0123456789"}')
            with self.assertRaisesRegex(ValueError, 'deadline'):
                C.read_request(r, seconds=.03)
        finally:
            os.close(r)
            os.close(w)
        r, w = os.pipe()
        os.write(w, b'{"version":1,"op":"status","run_id":"0123456789"}')
        os.close(w)
        try:
            self.assertEqual(C.read_request(r)['op'], 'status')
        finally:
            os.close(r)

    def test_pipe_overflow(self):
        r, w = os.pipe()
        os.write(w, b'x' * 4097)
        os.close(w)
        try:
            with self.assertRaisesRegex(ValueError, 'large'):
                C.read_request(r)
        finally:
            os.close(r)

    def test_other_user_cannot_read_or_cancel(self):
        owner = {'run_id': '0123456789', 'version': str(C.VERSION), 'uid': 1234}
        with patch.object(C, 'safe_path'), patch.object(C, 'read_json', return_value=owner):
            with self.assertRaisesRegex(ValueError, 'another submitter'):
                C.run_root('0123456789', 1235)
            self.assertEqual(C.run_root('0123456789', 1234).name, '0123456789')

    def test_ownership_checked_before_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'request.lock').touch()
            with patch.object(C, 'BASE', root), patch.object(C, 'safe_path'), \
                 patch.object(C, 'run_root', side_effect=ValueError('other owner')), \
                 patch.object(C, 'load_suite') as load:
                with self.assertRaises(ValueError):
                    C.dispatch({'op': 'cancel', 'run_id': '0123456789'}, 123)
                load.assert_not_called()

    def test_writable_host_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.py'
            path.write_text('raise RuntimeError("must never run")')
            with self.assertRaises(ValueError):
                C.safe_path(path)

    def test_replaced_code_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'suite.py').write_text('raise AssertionError("executed untrusted code")')
            owner = {'code': {'suite.py': '0' * 64}}
            with patch.object(C, 'read_json', return_value=owner), patch.object(C, 'safe_path', return_value=types.SimpleNamespace(st_size=100)):
                with self.assertRaisesRegex(ValueError, 'controller changed'):
                    C.load_suite(path)


class Adapter(unittest.TestCase):
    def modules(self, ident):
        code = C.render(ident)
        result = {}
        for name, content in code.items():
            module = types.ModuleType(name)
            module.__file__ = '/var/lib/eqemu-test/runs/' + ident + '/' + name
            exec(compile(content, name, 'exec'), module.__dict__)
            result[name] = module
        return result

    def test_fresh_identity_and_private_code(self):
        first = self.modules('0123456789')
        second = self.modules('abcdef0123')
        for name in first:
            self.assertNotEqual(first[name].ROOT, second[name].ROOT)
            self.assertNotEqual(first[name].UNIT, second[name].UNIT)
        worker = first['consumer-worker.py']
        self.assertLessEqual(len(worker.NAME), 20)
        self.assertEqual(worker.INPUTS, Path('/var/lib/eqemu-test/inputs'))
        self.assertEqual(worker.ARTIFACT_OWNER, Path('/var/lib/eqemu-vm-proof/build-handoff-01'))
        self.assertEqual(first['suite.py'].LOCAL, first['suite.py'].ROOT)
        self.assertNotIn('/home/bump', C.render('0123456789')['consumer-worker.py'])

    def test_real_xml_and_apparmor_static_check(self):
        worker = self.modules('0123456789')['consumer-worker.py']
        state = {'uuid': '00000000-0000-4000-8000-000000000042', 'profile': 'libvirt-00000000-0000-4000-8000-000000000042'}
        worker.schema_check(worker.domain(state))
        worker.run(['/usr/sbin/apparmor_parser', '-Q', '-K', '-j', '1'], data=worker.policy(state))

    def test_nonroot_entrypoint_refuses_without_side_effects(self):
        if os.geteuid() == 0:
            self.skipTest('Requires ordinary user')
        for name in ('control.py', 'install.py', 'remove.py'):
            result = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / name)], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_wrapper_extra_arguments_refused(self):
        # Same wrapper shape as the installation; it must reject before Python is executed.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrapper'
            path.write_text('#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexit 99\n')
            result = subprocess.run(['/bin/sh', str(path), 'publish', '0123456789'])
            self.assertEqual(result.returncode, 2)


class Installation(unittest.TestCase):
    def exercise(self, fail_at=None):
        spec = importlib.util.spec_from_file_location('installer', ROOT / 'install.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        top = Path(temporary.name)
        source = top / 'package'
        source.mkdir()
        import hashlib
        files = {}
        for name in ('control.py', 'client.py', 'preflight.py', 'probe.py'):
            data = (ROOT / name).read_bytes()
            (source / name).write_bytes(data)
            files[name] = hashlib.sha256(data).hexdigest()
        inputs = {}
        for name in ('base.qcow2', 'seed.iso', 'fixture.iso', 'runtime.iso'):
            p = top / name
            p.write_bytes(name.encode())
            inputs[name] = {'source': str(p), 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
        data = json.dumps(inputs).encode()
        (source / 'inputs.json').write_bytes(data)
        files['inputs.json'] = hashlib.sha256(data).hexdigest()
        (source / 'manifest.json').write_text(json.dumps({'version': 1, 'files': files}))
        group_exists = False
        calls = []
        def group(_):
            if not group_exists:
                raise KeyError('not created')
            return types.SimpleNamespace(gr_gid=os.getgid())
        def account(name):
            if name == installer.PROOF_USER:
                raise KeyError('not created')
            return types.SimpleNamespace(pw_uid=os.getuid())
        def command(args):
            nonlocal group_exists
            calls.append(args)
            if args[0].endswith('groupadd'):
                group_exists = True
            if fail_at and any(str(part).endswith(fail_at) for part in args):
                raise RuntimeError('Injected installation failure')
            return types.SimpleNamespace(returncode=0)
        values = {'SOURCE': source, 'BASE': top / 'state', 'LIB': top / 'code',
                  'ENTRY': top / 'entry', 'CLIENT': top / 'client', 'POLICY': top / 'sudoers'}
        with patch.multiple(installer, **values), patch.object(installer, 'parent_safe'), \
             patch.object(installer.os, 'geteuid', return_value=0), patch.object(installer.os, 'chown'), \
             patch.object(installer.grp, 'getgrnam', side_effect=group), \
             patch.object(installer.pwd, 'getpwnam', side_effect=account), \
             patch.object(installer, 'run', side_effect=command), patch('sys.stdout', new=io.StringIO()):
            previous = os.umask(0o077)
            try:
                if fail_at:
                    with self.assertRaisesRegex(RuntimeError, 'Injected'):
                        installer.install()
                else:
                    installer.install()
            finally:
                os.umask(previous)
        return top, calls

    def test_install_order_and_exact_policy(self):
        top, calls = self.exercise()
        self.assertIn('""', (top / 'sudoers').read_text())
        preflight = next(i for i, args in enumerate(calls) if str(args[-1]).endswith('/preflight.py'))
        full_policy = next(i for i, args in enumerate(calls) if args[-1] == '-c')
        proof = next(i for i, args in enumerate(calls) if str(args[-1]).endswith('/probe.py'))
        self.assertLess(preflight, full_policy)
        self.assertLess(full_policy, proof)
        self.assertTrue(json.loads((top / 'state/installation.json').read_text())['enabled'])
        self.assertEqual((top / 'state/reports').stat().st_mode & 0o777, 0o750)

    def test_post_grant_failure_revokes_grant(self):
        top, _ = self.exercise('probe.py')
        self.assertFalse((top / 'sudoers').exists())
        self.assertFalse(json.loads((top / 'state/installation.json').read_text())['enabled'])

    def test_preflight_failure_never_grants_access(self):
        top, _ = self.exercise('preflight.py')
        self.assertFalse((top / 'sudoers').exists())


class LifecycleRegressions(unittest.TestCase):
    def test_revoked_inflight_request_cannot_start(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'request.lock').touch()
            with patch.object(C, 'BASE', base), patch.object(C, 'safe_path'), \
                 patch.object(C, 'read_json', return_value={'enabled': False, 'version': str(C.VERSION)}), \
                 patch.object(C, 'start') as start:
                with self.assertRaisesRegex(RuntimeError, 'disabled'):
                    C.dispatch({'op': 'run', 'profile': C.PROFILE}, 1234)
                start.assert_not_called()

    def test_rejected_admission_does_not_reserve_or_block_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'runs').mkdir()
            with patch.object(C, 'BASE', base), patch.object(C, 'admission_preflight', side_effect=RuntimeError('Low memory')):
                with self.assertRaisesRegex(RuntimeError, 'Low memory'):
                    C.start(1234)
            self.assertFalse((base / 'active.json').exists())
            self.assertEqual(list((base / 'runs').iterdir()), [])
            suite = types.SimpleNamespace(setup=lambda: None)
            with patch.object(C, 'BASE', base), patch.object(C, 'admission_preflight'), \
                 patch.object(C, 'safe_path'), patch.object(C, 'load_suite', return_value=suite):
                result = C.start(1234)
            self.assertTrue(result['started'])

    def test_real_signal_is_deferred_until_ownership_recorded(self):
        import signal
        suite = Adapter().modules('0123456789')['suite.py']
        ledger = {'active': {}, 'released': []}
        worker = types.SimpleNamespace(NAME='eqemu-rt0123456789', admission=lambda: {},
                                      state=lambda: {'uuid': 'id'}, virsh=lambda *args: types.SimpleNamespace(stdout=''))
        def setup():
            os.kill(os.getpid(), signal.SIGTERM)
            # Signal must still be pending while ownership is being established.
            self.assertEqual(ledger['active']['consumer']['state'], 'starting')
        worker.setup = setup
        def interrupted(*_):
            raise RuntimeError('Supervisor interrupted')
        previous = signal.signal(signal.SIGTERM, interrupted)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'admission.lock').touch()
                with patch.object(suite, 'ROOT', root), patch.object(suite, 'module', return_value=worker), \
                     patch.object(suite, 'read', return_value=ledger), patch.object(suite, 'write'):
                    with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                        suite.admit()
                self.assertEqual(ledger['active']['consumer']['state'], 'active')
                self.assertEqual(ledger['active']['consumer']['uuid'], 'id')
        finally:
            signal.signal(signal.SIGTERM, previous)

    def test_failed_unstarted_setup_releases_only_empty_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'runs').mkdir()
            suite = types.SimpleNamespace(setup=lambda: (_ for _ in ()).throw(RuntimeError('Pre-start rejection')),
                                          module=lambda _: object(), quiescent=lambda _: True,
                                          properties=lambda _: {}, UNIT='test', unstarted_absent=lambda _: True,
                                          CTLFILE=base / 'absent.slice')
            with patch.object(C, 'BASE', base), patch.object(C, 'admission_preflight'), \
                 patch.object(C, 'safe_path'), patch.object(C, 'load_suite', return_value=suite):
                with self.assertRaisesRegex(RuntimeError, 'Setup failed'):
                    C.start(1234)
            self.assertFalse((base / 'active.json').exists())
            root = next((base / 'runs').iterdir())
            result = json.loads((root / 'suite-result.json').read_text())
            self.assertFalse(result['suite_passed'])
            self.assertTrue(result['cleanup']['unstarted'])


if __name__ == '__main__':
    unittest.main()
