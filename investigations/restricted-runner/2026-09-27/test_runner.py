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


if __name__ == '__main__':
    unittest.main()
