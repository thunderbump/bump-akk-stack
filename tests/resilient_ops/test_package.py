"""Harmless finite package, transport and disabled-service regression tests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'validation/resilient_ops'

def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

package, service, client = map(load, ('package', 'service', 'client'))
DISABLED = {'peers': [{'uid': 1000, 'gid': 1000, 'methods': ['status'], 'targets': [], 'actions': []}], 'targets': {}}


class FakeEngine:
    policy = {'peers': [{'uid': os.getuid(), 'gid': os.getgid()}]}

    def handle(self, request, peer):
        return {'method': request['method'], 'peer': list(peer)}


def fixture():
    """Synthetic target only. No existing validator inventory is inferred."""
    value = copy.deepcopy(DISABLED)
    value['peers'][0].update(methods=['prepare', 'execute', 'status'], targets=['fixture'], actions=['publish', 'revert', 'recover'])
    value['targets']['fixture'] = dict(actions=['publish', 'revert', 'recover'], resources=['fixture-code', 'fixture-data'], root='/var/lib/eqemu-resilient-targets/fixture', units=['fixture-only.service'], service_uid=2000, timeout=30, files=['worker.py', 'data.json'], max_bytes=4096, max_files=2)
    return value


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.host = self.root / 'host'
        self.host.mkdir(mode=0o700)
        # Test-only trust anchor. Check all sandbox descendants while leaving
        # real host ownership and /tmp permissions out of the simulated host.
        def protected(path, uid=0, leaf_file=False):
            path = Path(path)
            if self.host not in path.parents and path != self.host:
                raise ValueError('outside test host')
            for entry in (path, *path.parents):
                st = entry.lstat()
                if entry == self.host.parent:
                    break
                kind = stat.S_ISREG if entry == path and leaf_file else stat.S_ISDIR
                if not kind(st.st_mode) or st.st_mode & 0o022 or st.st_uid != os.getuid():
                    raise ValueError('unprotected test asset')
        self.patch = mock.patch.object(package, 'protected', protected)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.operator = package.Operator(self.host, os.getuid())

    def stage(self, name='stage', changed=False):
        source = self.root / (name + '-source')
        source.mkdir()
        for asset in package.ASSETS:
            data = (SOURCE / asset).read_bytes()
            if changed and asset == 'client.py':
                data += b'\n# second test release\n'
            (source / asset).write_bytes(data)
        output = self.root / name
        info = package.prepare(source, output)
        return output, info['manifest_sha256']

    def test_install_upgrade_guarded_rollback_uninstall_preserves_evidence(self):
        stage, first = self.stage()
        self.operator.apply('install', 'absent', stage, first)
        self.assertEqual(self.operator.active(), first)
        for name in package.ASSETS:
            self.assertEqual((self.operator.code / 'current' / name).read_bytes(), (stage / name).read_bytes())
        with self.assertRaises(ValueError):
            self.operator.apply('uninstall', '0' * 64)
        stage2, second = self.stage('second', True)
        self.operator.apply('upgrade', first, stage2, second)
        self.operator.apply('rollback', second, release=first)
        result = self.operator.apply('uninstall', first)
        self.assertFalse(result['activation_performed'])
        self.assertEqual(self.operator.active(), 'absent')
        self.assertTrue((self.operator.code / 'releases' / second).is_dir())
        self.assertEqual(len(list((self.operator.state / 'package-events').iterdir())), 8)

    def test_unknown_tampered_and_symlink_assets_rejected(self):
        for corruption in ('extra', 'hash', 'link'):
            stage, expected = self.stage(corruption)
            if corruption == 'extra':
                (stage / 'unknown').write_text('x')
            elif corruption == 'hash':
                (stage / 'engine.py').write_text('different')
            else:
                (stage / 'engine.py').unlink()
                (stage / 'engine.py').symlink_to(SOURCE / 'engine.py')
            with self.assertRaises((ValueError, OSError)):
                self.operator.apply('install', 'absent', stage, expected)
        self.assertFalse(self.operator.code.exists())

    def test_release_directory_sync_failure_prevents_selection(self):
        stage, expected = self.stage()
        sync = package.fsync_directory
        def fail_release_sync(path):
            if path == self.operator.code / 'releases' and (path/expected).exists():
                raise OSError('injected directory sync failure')
            sync(path)
        with mock.patch.object(package, 'fsync_directory', side_effect=fail_release_sync):
            with self.assertRaises(OSError):
                self.operator.apply('install', 'absent', stage, expected)
        self.assertEqual(self.operator.active(), 'absent')
        self.assertTrue((self.operator.code / 'releases' / expected).is_dir())
        self.assertEqual(list((self.operator.state / 'package-events').iterdir()), [])
        with mock.patch.object(package, 'fsync_directory', side_effect=fail_release_sync):
            with self.assertRaises(OSError):
                self.operator.apply('install', 'absent', stage, expected)
        self.assertEqual(self.operator.active(), 'absent')
        self.operator.apply('install', 'absent', stage, expected)
        self.assertEqual(self.operator.active(), expected)

    def test_release_sync_precedes_current_selection(self):
        stage, expected = self.stage()
        sync = package.fsync_directory
        calls = []
        def observe(path):
            calls.append(path)
            sync(path)
        select = self.operator.select
        def select_after_sync(release):
            self.assertIn(self.operator.code / 'releases', calls)
            select(release)
        with mock.patch.object(package, 'fsync_directory', side_effect=observe), mock.patch.object(self.operator, 'select', side_effect=select_after_sync):
            self.operator.apply('install', 'absent', stage, expected)

    def test_uninstall_sync_failure_never_records_completion(self):
        for failed_parent in ('units', 'code'):
            with self.subTest(parent=failed_parent):
                # Each fault runs against a separate harmless simulated host.
                self.operator = package.Operator(self.host / failed_parent, os.getuid())
                stage, expected = self.stage(failed_parent)
                self.operator.apply('install', 'absent', stage, expected)
                sync = package.fsync_directory
                def fail_sync(path):
                    events = [package.decode(p.read_bytes())['action'] for p in (self.operator.state/'package-events').glob('*.json')]
                    if path == getattr(self.operator, failed_parent) and 'uninstall-intent' in events:
                        raise OSError('injected unlink sync failure')
                    sync(path)
                with mock.patch.object(package, 'fsync_directory', side_effect=fail_sync):
                    with self.assertRaises(OSError):
                        self.operator.apply('uninstall', expected)
                events = [package.decode(path.read_bytes())['action'] for path in (self.operator.state / 'package-events').iterdir()]
                self.assertIn('uninstall-intent', events)
                self.assertNotIn('uninstall', events)
                self.assertEqual((self.operator.code / 'current').is_symlink(), failed_parent == 'units')

    def test_unknown_installed_unit_and_release_dependency_fail_closed(self):
        stage, expected = self.stage()
        self.operator.apply('install', 'absent', stage, expected)
        (self.operator.units / package.UNITS[0]).write_text('unknown')
        with self.assertRaises(ValueError):
            self.operator.apply('uninstall', expected)
        (self.operator.units / package.UNITS[0]).write_bytes((stage / package.UNITS[0]).read_bytes())
        (self.operator.code / 'current' / 'engine.py').write_text('tampered dependency')
        with self.assertRaises(ValueError):
            self.operator.apply('uninstall', expected)

    def test_enroll_fresh_roots_traversable_and_reject_adoption(self):
        policy = self.root / 'policy.json'
        raw = package.encode(fixture())
        policy.write_bytes(raw)
        self.operator.enroll(policy, package.digest(raw))
        root = self.host / 'var/lib/eqemu-resilient-targets/fixture'
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o711)
        self.assertEqual(stat.S_IMODE(root.parent.stat().st_mode), 0o711)
        self.assertEqual((self.operator.config / 'policy.json').read_bytes(), raw)
        with self.assertRaises(ValueError):
            self.operator.enroll(policy, package.digest(raw))
        (self.operator.config / 'policy.json').unlink()
        with self.assertRaises(ValueError):
            self.operator.enroll(policy, package.digest(raw))

    def test_disabled_policy_and_strict_fixture_schema(self):
        package.validate_policy(DISABLED)
        package.validate_policy(fixture())
        for mutation in ('unknown', 'root', 'uid', 'path', 'bound', 'peer'):
            value = fixture()
            target = value['targets']['fixture']
            if mutation == 'unknown': target['hook'] = 'no'
            if mutation == 'root': target['root'] = '/srv/existing'
            if mutation == 'uid': target['service_uid'] = 0
            if mutation == 'path': target['files'] = ['.']
            if mutation == 'bound': target['timeout'] = 121
            if mutation == 'peer': value['peers'][0]['uid'] = 0
            with self.assertRaises(ValueError, msg=mutation):
                package.validate_policy(value)

    def test_invalid_resource_rejected_by_enrollment_and_service_entry(self):
        # Exercise real enrollment and main startup, substituting only protected
        # fixture ancestry. Neither path can accept a malformed resource gate.
        value = fixture()
        value['targets']['fixture']['resources'] = ['bad/resource']
        raw = package.encode(value)
        policy_path = self.root/'bad-policy.json'
        policy_path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'resource ID'):
            self.operator.enroll(policy_path, package.digest(raw))
        self.assertFalse(self.operator.code.exists())
        with mock.patch.object(service, 'POLICY', policy_path), mock.patch.object(service, 'STORE', self.root), mock.patch.object(service, 'protected'), mock.patch.object(service.socket, 'socket', side_effect=AssertionError('invalid enrollment reached transport')):
            with self.assertRaisesRegex(ValueError, 'resource ID'):
                service.main()

    def test_prepare_prints_pins_and_separate_enrollment_without_activation(self):
        stage, expected = self.stage()
        package.load_package(stage, expected)
        policy = self.root / 'disabled.json'
        policy.write_bytes(package.encode(DISABLED))
        result = package.prepare(stage, self.root / 'prepared', policy)
        self.assertEqual(result['manifest_sha256'], expected)
        self.assertEqual(result['operator_sha256'], package.digest((stage / 'package.py').read_bytes()))
        self.assertIn('enroll', result['enroll_argv'])
        self.assertEqual(result['enroll_argv'][-1], package.digest(policy.read_bytes()))
        self.assertFalse(self.operator.code.exists())
        with self.assertRaises(ValueError):
            package.prepare(stage, self.root / 'uncommitted', expected_assets={name: '0' * 64 for name in package.ASSETS})


class InterfaceTests(unittest.TestCase):
    def test_artifact_regular_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').write_bytes(b'hello')
            self.assertEqual(client.artifact(root), {'a': 'aGVsbG8='})
            (root / 'a').chmod(0o2644)
            with self.assertRaises(ValueError):
                client.artifact(root)
            (root / 'a').chmod(0o644)
            child = root / 'child'
            child.mkdir()
            child.chmod(0o1700)
            with self.assertRaises(ValueError):
                client.artifact(root)
            child.rmdir()
            (root / 'link').symlink_to(root / 'a')
            with self.assertRaises(ValueError):
                client.artifact(root)
            (root / 'link').unlink()
            os.mkfifo(root / 'fifo')
            with self.assertRaises(ValueError):
                client.artifact(root)

    def exchange(self, wire, engine):
        caller, receiver = socket.socketpair()
        with caller, receiver:
            thread = threading.Thread(target=service.serve, args=(receiver, engine))
            thread.start()
            caller.sendall(wire)
            caller.shutdown(socket.SHUT_WR)
            result = json.loads(caller.makefile('rb').readline())
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            return result

    def test_socket_peer_alias_bounds_and_duplicate_keys(self):
        Engine = FakeEngine
        result = self.exchange(b'{"method":"diagnose"}\n', Engine())
        self.assertEqual(result, {'method': 'status', 'peer': [os.getuid(), os.getgid()]})
        self.assertFalse(self.exchange(b'{"method":"status","method":"execute"}\n', Engine())['ok'])
        self.assertFalse(self.exchange(b'{"method":"status"}\n{}\n', Engine())['ok'])
        class Large(FakeEngine):
            def handle(self, request, peer): return {'value': 'x' * service.MAX_RESPONSE}
        self.assertFalse(self.exchange(b'{}\n', Large())['ok'])
        with mock.patch.object(service, 'MAX_REQUEST', 64):
            self.assertFalse(self.exchange(b'x' * 65 + b'\n', Engine())['ok'])

    def test_unauthorized_peer_rejected_before_read(self):
        connection = mock.Mock()
        connection.getsockopt.return_value = service.struct.pack('3i', 42, 99999, 99999)
        service.serve(connection, FakeEngine())
        connection.recv.assert_not_called()
        self.assertEqual(json.loads(connection.sendall.call_args.args[0])['error'], 'request_failed')

    def test_slow_trickle_uses_one_absolute_deadline(self):
        connection = mock.Mock()
        connection.getsockopt.return_value = service.struct.pack('3i', 42, os.getuid(), os.getgid())
        connection.recv.side_effect = [b'{', b'"', b'm']
        with mock.patch.object(service.time, 'monotonic', side_effect=[0, 1, 10, 11, 20, 21, 31]):
            service.serve(connection, FakeEngine())
        self.assertEqual(connection.recv.call_count, 3)
        self.assertEqual([call.args[0] for call in connection.settimeout.call_args_list], [30, 29, 19, 9, 30])
        self.assertEqual(json.loads(connection.sendall.call_args.args[0])['error'], 'request_failed')

    def test_concrete_rejections_preserved_other_errors_hidden(self):
        class Rejected(Exception):
            pass
        class Engine(FakeEngine):
            def handle(self, request, peer):
                raise Rejected('administrative requirement: target not enrolled')
        connection = mock.Mock()
        connection.getsockopt.return_value = service.struct.pack('3i', 42, os.getuid(), os.getgid())
        connection.recv.return_value = b'{}\n'
        service.serve(connection, Engine(), Rejected)
        self.assertEqual(json.loads(connection.sendall.call_args.args[0])['error'], 'administrative requirement: target not enrolled')
        # A name/module lookalike is not the admitted exception class.
        Rejected.__module__ = 'engine'
        service.serve(connection, Engine())
        self.assertEqual(json.loads(connection.sendall.call_args.args[0])['error'], 'request_failed')

    def test_unit_bootstrap_pins_release_before_loading_service(self):
        unit = (SOURCE / 'eqemu-resilient-ops@.service').read_text()
        argv = shlex.split(next(line.removeprefix('ExecStart=') for line in unit.splitlines() if line.startswith('ExecStart=')))
        self.assertEqual(argv[:3], ['/usr/bin/python3', '-I', '-c'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('old', 'new'):
                release = root / name
                release.mkdir()
                (release / 'marker.py').write_text('VALUE=' + repr(name))
                (release / 'service.py').write_text("from pathlib import Path\nimport sys\nsys.path.insert(0,str(Path(__file__).resolve().parent))\nimport marker\nprint(marker.VALUE)\n")
            current = root / 'current'
            current.symlink_to('old')
            bootstrap = argv[3].replace('/usr/lib/eqemu-resilient-ops/current/service.py', str(current / 'service.py'))
            # Upgrade exactly after realpath selection, before source is opened.
            wrapper = "import os,runpy\noriginal=runpy.run_path\ndef swapped(path,**kw):\n os.unlink(" + repr(str(current)) + ")\n os.symlink('new'," + repr(str(current)) + ")\n return original(path,**kw)\nrunpy.run_path=swapped\n"
            result = subprocess.run([sys.executable, '-I', '-c', wrapper + bootstrap], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'old\n')

    def test_real_engine_service_with_fd_zero_under_no_new_privs(self):
        # A real process, inherited connected AF_UNIX fd0, real engine and NNP.
        # Only the fixture ownership boundary is substituted; no manager executes.
        with tempfile.TemporaryDirectory() as directory:
            code = '''import ctypes,importlib.util,os,socket,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import service,engine
assert ctypes.CDLL(None).prctl(38,1,0,0,0)==0
assert 'NoNewPrivs:\\t1' in Path('/proc/self/status').read_text()
engine.protected=lambda path,uid: None
policy={'peers':[{'uid':os.getuid(),'gid':os.getgid(),'methods':['status'],'targets':[],'actions':[]}],'targets':{}}
with socket.socket(fileno=os.dup(0)) as connection:
 service.serve(connection,engine.Engine(policy,Path(sys.argv[2]),trusted_uid=os.getuid()),engine.Rejected)
'''
            caller, receiver = socket.socketpair()
            with caller, receiver:
                process = subprocess.Popen([sys.executable, '-I', '-c', code, str(SOURCE), directory], stdin=receiver, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                caller.sendall(b'{"method":"health"}\n')
                caller.shutdown(socket.SHUT_WR)
                response = json.loads(caller.makefile('rb').readline())
                out, err = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, err)
                self.assertEqual(out, b'')
                self.assertTrue(response['healthy'])
                self.assertEqual(response['targets'], [])


if __name__ == '__main__':
    unittest.main()

class NamespaceDurabilityTests(unittest.TestCase):
    setUp = PackageTests.setUp
    stage = PackageTests.stage

    def required_paths(self, enroll=False):
        leaves=[self.operator.code/'releases',self.operator.units]
        leaves += [self.operator.state/name for name in ('package-events','plans','requests','operations','locks')]
        if enroll:
            leaves += [self.operator.config,self.operator.base/'var/lib/eqemu-resilient-targets/fixture']
        paths=set()
        for leaf in leaves:
            path=leaf
            while path!=self.operator.base:
                paths.add(path)
                path=path.parent
            paths.add(path)
        return paths

    def trace(self, required, failure=None):
        from contextlib import contextmanager
        @contextmanager
        def capture():
            events=[]
            actual_fsync=os.fsync
            actual_replace=os.replace
            def fsync(fd):
                info=os.fstat(fd)
                observed=None
                for path in required:
                    try: candidate=path.stat()
                    except FileNotFoundError: continue
                    if (candidate.st_dev,candidate.st_ino)==(info.st_dev,info.st_ino):
                        observed=path
                        break
                if observed==failure and failure is not None:
                    events.append(('fsync-failed',observed))
                    raise OSError('injected namespace prerequisite fsync failure')
                actual_fsync(fd)
                if observed is not None:
                    events.append(('fsync',observed))
            def replace(source,destination,*args,**kwargs):
                actual_replace(source,destination,*args,**kwargs)
                events.append(('replace',Path(destination)))
            with mock.patch.object(os,'fsync',new=fsync),mock.patch.object(os,'replace',new=replace):
                yield events
        return capture()

    def assert_barriers(self, events, required, publication):
        first=next(i for i,e in enumerate(events) if e[0]=='replace' and e[1] in publication)
        for path in required:
            self.assertIn(('fsync',path),events[:first],str(path))
        return first

    def assert_no_install_publication(self):
        self.assertFalse((self.operator.code/'current').exists())
        self.assertFalse((self.operator.code/'current').is_symlink())
        for name in package.UNITS:
            self.assertFalse((self.operator.units/name).exists())
        for path in (self.operator.state/'package-events').glob('*.json'):
            self.assertNotEqual(package.decode(path.read_bytes())['action'],'install')

    def assert_no_enrollment_publication(self):
        self.assertFalse((self.operator.config/'policy.json').exists())
        for path in (self.operator.state/'package-events').glob('*.json'):
            self.assertNotEqual(package.decode(path.read_bytes())['action'],'enroll')

    def test_actual_fresh_install_persists_all_namespace_paths_before_units(self):
        stage,expected=self.stage()
        required=self.required_paths()
        with self.trace(required) as events:
            result=self.operator.apply('install','absent',stage,expected)
        self.assertEqual(result['selected'],expected)
        self.assert_barriers(events,required,{self.operator.units/name for name in package.UNITS}|{self.operator.code/'current'})

    def test_actual_install_reestablishes_preexisting_namespace_durability(self):
        stage,expected=self.stage()
        required=self.required_paths()
        for path in sorted(required,key=lambda p:len(p.parts)):
            path.mkdir(mode=0o700,exist_ok=True)
            path.chmod(0o700)
        with self.trace(required) as events:
            result=self.operator.apply('install','absent',stage,expected)
        self.assertEqual(result['selected'],expected)
        self.assert_barriers(events,required,{self.operator.units/name for name in package.UNITS}|{self.operator.code/'current'})

    def test_install_namespace_sync_faults_remain_nonpass_and_retry_barriers(self):
        for name,relative in (('code','usr/lib'),('state','var/lib'),('operations','var/lib/eqemu-resilient-ops/operations'),('units','etc/systemd')):
            with self.subTest(namespace=name):
                self.operator=package.Operator(self.host/name,os.getuid())
                stage,expected=self.stage(name)
                required=self.required_paths()
                failed=self.operator.base/relative
                with self.trace(required,failed):
                    with self.assertRaisesRegex(OSError,'namespace prerequisite'):
                        self.operator.apply('install','absent',stage,expected)
                    self.assert_no_install_publication()
                    self.assertTrue(failed.is_dir())
                    # Explicit identical request must hit the barrier AGAIN,
                    # even though its previous directory effect is visible.
                    with self.assertRaisesRegex(OSError,'namespace prerequisite'):
                        self.operator.apply('install','absent',stage,expected)
                    self.assert_no_install_publication()
                with self.trace(required) as events:
                    result=self.operator.apply('install','absent',stage,expected)
                self.assertEqual(result['selected'],expected)
                self.assert_barriers(events,required,{self.operator.units/n for n in package.UNITS}|{self.operator.code/'current'})

    def policy_file(self):
        path=self.root/'selected-policy.json'
        raw=package.encode(fixture())
        path.write_bytes(raw)
        return path,package.digest(raw)

    def test_actual_fresh_enrollment_persists_target_and_state_namespaces(self):
        path,expected=self.policy_file()
        required=self.required_paths(enroll=True)
        with self.trace(required) as events:
            result=self.operator.enroll(path,expected)
        self.assertEqual(result['enrolled'],expected)
        self.assert_barriers(events,required,{self.operator.config/'policy.json'})

    def test_enrollment_namespace_faults_and_exact_intent_retries(self):
        cases=(('config','etc'),('common','var/lib/eqemu-resilient-targets'),
               ('target','var/lib/eqemu-resilient-targets/fixture'),
               ('plans','var/lib/eqemu-resilient-ops/plans'),
               ('operations','var/lib/eqemu-resilient-ops/operations'))
        for name,relative in cases:
            with self.subTest(namespace=name):
                self.operator=package.Operator(self.host/name,os.getuid())
                path,expected=self.policy_file()
                required=self.required_paths(enroll=True)
                failed=self.operator.base/relative
                with self.trace(required,failed):
                    with self.assertRaisesRegex(OSError,'namespace prerequisite'):
                        self.operator.enroll(path,expected)
                    self.assert_no_enrollment_publication()
                    self.assertTrue(failed.is_dir())
                    with self.assertRaisesRegex(OSError,'namespace prerequisite'):
                        self.operator.enroll(path,expected)
                    self.assert_no_enrollment_publication()
                with self.trace(required) as events:
                    result=self.operator.enroll(path,expected)
                self.assertEqual(result['enrolled'],expected)
                self.assert_barriers(events,required,{self.operator.config/'policy.json'})

    def test_interrupted_enrollment_rejects_changed_policy_and_dirty_root(self):
        path,expected=self.policy_file()
        required=self.required_paths(enroll=True)
        root=self.operator.base/'var/lib/eqemu-resilient-targets/fixture'
        with self.trace(required,root):
            with self.assertRaises(OSError):
                self.operator.enroll(path,expected)
        changed=fixture();changed['targets']['fixture']['timeout']=31
        path.write_bytes(package.encode(changed))
        with self.assertRaisesRegex(ValueError,'intent content conflict'):
            self.operator.enroll(path,package.digest(path.read_bytes()))
        path,expected=self.policy_file()
        (root/'unknown').write_bytes(b'not an empty owned retry')
        with self.assertRaisesRegex(ValueError,'unknown state'):
            self.operator.enroll(path,expected)
        self.assert_no_enrollment_publication()
