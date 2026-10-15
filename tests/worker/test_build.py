"""Real local sockets/processes and source packaging; no candidate code or VM execution."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import build_guest
import prepare
import runtime
import test_runtime


class Transfer(unittest.TestCase):
    def test_early_infrastructure_diagnostic_survives_large_read(self):
        # Coalesce real pipe reads to exercise platforms with a larger pipe buffer.
        data = b'failed to select a version for the requirement cxx\n' + b'x' * 20000
        original_read = os.read
        def coalesced(fd, count):
            block = original_read(fd, count)
            if count == 65536 and block:
                os.set_blocking(fd, True)
                try:
                    while len(block) < len(data):
                        extra = original_read(fd, count - len(block))
                        if not extra: break
                        block += extra
                finally:
                    os.set_blocking(fd, False)
            return block
        self.addCleanup(setattr, build_guest, 'DEADLINE', build_guest.DEADLINE)
        build_guest.DEADLINE = time.monotonic() + 10
        with patch.object(build_guest.os, 'read', side_effect=coalesced), self.assertRaises(RuntimeError) as caught:
            build_guest.command('trusted-large-read-fixture',
                                [sys.executable, '-c', 'import os; os.write(1,' + repr(data) + '); raise SystemExit(101)'],
                                candidate=True)
        self.assertIs(type(caught.exception), RuntimeError)

    def test_streaming_hash_and_disconnect(self):
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ('pass', 'changed', 'disconnect'):
                with self.subTest(mode=mode):
                    sender, receiver = socket.socketpair()
                    try:
                        data = b'opaque ISO bytes' * 1000
                        wanted = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        def send():
                            sender.sendall(data if mode != 'changed' else b'x' * len(data))
                            sender.shutdown(socket.SHUT_WR)
                        if mode == 'disconnect':
                            sender.shutdown(socket.SHUT_WR)
                        else:
                            thread = threading.Thread(target=send); thread.start()
                        path = Path(tmp) / mode
                        if mode == 'pass':
                            runtime.receive_payload(receiver, path, wanted, time.monotonic() + 2)
                            self.assertEqual(path.read_bytes(), data)
                        else:
                            with self.assertRaises((ValueError, RuntimeError)):
                                runtime.receive_payload(receiver, path, wanted, time.monotonic() + 2)
                        if mode != 'disconnect': thread.join(2)
                    finally:
                        sender.close(); receiver.close()

    def test_guest_phase_exit_and_resource_failure_classification(self):
        old_deadline = build_guest.DEADLINE
        self.addCleanup(setattr, build_guest, 'DEADLINE', old_deadline)
        build_guest.DEADLINE = time.monotonic() + 10
        for candidate, script, error in (
                (True, 'exit 1', build_guest.CandidateFailure),
                (False, 'exit 1', RuntimeError),
                (True, 'echo "no matching package named dependency"; exit 101', RuntimeError),
                (True, 'echo "Killed signal terminated program cc1plus"; exit 1', RuntimeError),
                (True, 'echo "failed to select a version for the requirement cxx"; exit 101', RuntimeError),
                (True, 'echo "Could NOT find MissingLibrary"; exit 1', RuntimeError),
                (True, 'echo "Could not find a package configuration file provided by MissingLibrary"; exit 1', RuntimeError)):
            with self.subTest(script=script, candidate=candidate):
                with self.assertRaises(error) as caught:
                    build_guest.command('trusted-fixture', ['/bin/sh', '-c', script], candidate=candidate)
                self.assertIs(type(caught.exception), error)


class BuildRuntime(unittest.TestCase):
    def setUp(self):
        test_runtime.Runtime.setUp(self)
        disk = patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=100*1024**3))
        disk.start(); self.addCleanup(disk.stop)
    def build_request(self):
        return dict(version=1, operation='build', candidate='a'*40, tree='b'*40, bytes=3,
                    sha256=hashlib.sha256(b'ISO').hexdigest())

    def test_build_uses_larger_guest_readonly_input_and_same_owned_cleanup(self):
        request = self.build_request(); self.client.sendall(b'ISO')
        guest = dict(version=1, nonce='n', scope='worker-build', exit_code=1, stage='rust-tests', error='assertion failed',
                     selected_checks=list(runtime.BUILD_CHECKS), completed_checks=list(runtime.BUILD_CHECKS[:3]))
        def simulate(*args):
            args[-2](12345); args[-1].update(guest); return 1
        with patch.object(runtime, 'resource_state', return_value={'memory.max': str(6*1024**3)}), \
                patch.object(runtime, 'supervise', side_effect=simulate) as supervisor:
            result = runtime.run_vm(self.value, self.server, build=request)
        self.assertEqual(result['exit_code'], 1, result)
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(result['candidate'], request['candidate'])
        self.assertEqual(result['guest']['stage'], 'rust-tests')
        self.assertEqual(result['completed_checks'], list(runtime.BUILD_CHECKS[:3]))
        self.assertRegex(result['implementation_sha256'], '^[a-f0-9]{64}$')
        argv = supervisor.call_args.args[0]
        self.assertEqual(argv[argv.index('-m') + 1], '4096')
        self.assertEqual(argv[argv.index('-nic') + 1], 'none')
        self.assertIn('payload.iso,media=cdrom,readonly=on,format=raw', ' '.join(argv))
        self.assertFalse((self.state / 'active.json').exists())
        self.assertFalse(any(path.is_dir() for path in self.state.iterdir()))

    def test_changed_payload_and_old_host_budget_start_no_vm_and_return_two(self):
        for memory in (2, 6):
            with self.subTest(memory=memory), \
                    patch.object(runtime, 'resource_state', return_value={'memory.max': str(memory*1024**3)}), \
                    patch.object(runtime, 'supervise') as supervisor:
                if memory == 6: self.client.sendall(b'bad')
                result = runtime.run_vm(self.value, self.server, build=self.build_request())
                self.assertEqual(result['exit_code'], 2)
                self.assertFalse(result['vm_started'])
                self.assertTrue(result['cleanup_complete'])
                supervisor.assert_not_called()

    def test_coalesced_request_header_preserves_binary_payload(self):
        request = self.build_request()
        self.client.sendall(json.dumps(request).encode() + b'\nISO')
        def consume(value, connection, **kwargs):
            self.assertEqual(kwargs['build'], request)
            self.assertEqual(connection.recv(3), b'ISO')
            return {'exit_code': 2}
        with patch.object(runtime, 'run_vm', side_effect=consume):
            self.assertEqual(runtime.request(self.server, self.value), {'exit_code': 2})

    def test_build_completion_preserves_infrastructure_details(self):
        result = dict(version=1, nonce='a'*32, scope='worker-build', exit_code=2,
                      stage='offline-package-install', error='Missing offline input',
                      selected_checks=list(runtime.BUILD_CHECKS), completed_checks=[])
        script = self.root / 'emit.py'
        script.write_text('print(' + repr('EQEMU_WORKER_RESULT ' + json.dumps(result)) + ')\n')
        detail = {}
        code = runtime.supervise([sys.executable, str(script)], self.root, self.root / 'console.log',
                                 self.server, time.monotonic() + 2, 'a'*32, build_result=detail)
        self.assertEqual(code, 2)
        self.assertEqual(detail['error'], result['error'])


class Packaging(unittest.TestCase):
    def test_prepare_actual_git_commit_without_executing_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo = root / 'repo'; repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q'); git('config', 'user.email', 'fixture@example.test'); git('config', 'user.name', 'Fixture')
            (repo / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            (repo / 'build.rs').write_text('panic!("MUST NEVER EXECUTE ON HOST");\n')
            git('add', '.'); git('commit', '-qm', 'opaque fixture')
            commit = git('rev-parse', 'HEAD'); tree = git('rev-parse', 'HEAD^{tree}')
            native = root / 'native.iso'; native.write_bytes(b'fixture native')
            rust = root / 'rust.tar'; rust.write_bytes(b'fixture rust')
            profile = {'sources': {'eqemu': {'gitlinks': {}}, 'websocketpp': {'commit': commit, 'tree': tree}}, 'dependency_blobs': {}}
            with patch.object(prepare.json, 'loads', return_value=profile), \
                    patch.object(prepare, 'NATIVE_SHA', prepare.record(native)['sha256']), \
                    patch.object(prepare, 'RUST_SHA', prepare.record(rust)['sha256']):
                output = root / 'payload.iso'
                request = prepare.prepare(repo, 'HEAD', repo, native, rust, output)
                self.assertEqual(request['candidate'], commit)
                self.assertEqual(request['sha256'], prepare.record(output)['sha256'])
                (repo / 'Cargo.toml').write_text('dirty')
                with self.assertRaisesRegex(ValueError, 'Dirty source'):
                    prepare.prepare(repo, 'HEAD', repo, native, rust, root / 'dirty.iso')


if __name__ == '__main__':
    unittest.main()
