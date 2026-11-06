"""Nonroot fixed-root fixtures. No host/systemd calls or existing state reads."""
import fcntl
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[2] / 'validation/resilient_ops'
sys.path.insert(0, str(SOURCE))
try:
    spec = importlib.util.spec_from_file_location('fixed_host', SOURCE / 'host.py')
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
finally:
    sys.path.pop(0)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        for name, relative in [('CODE_ROOT', 'managed/code'), ('WORKSPACE_ROOT', 'managed/evidence'),
                               ('BINDING', 'srv/code'), ('WORKSPACE', 'state/last-integration'),
                               ('SHARED_LOCK', 'state/worker.lock'), ('CGROUP_ROOT', 'cgroup')]:
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            patcher = patch.object(h, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        h.CODE_ROOT.mkdir()
        h.WORKSPACE_ROOT.mkdir()
        h.SHARED_LOCK.write_bytes(b'unchanged lock')
        h.SHARED_LOCK.chmod(0o600)
        for directory in self.base.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o755)
        self.addCleanup(patch.stopall)
        patch.object(h, 'TRUSTED_UID', os.getuid()).start()
        # Model a protected simulated host without requiring root or trusting /tmp.
        def protected(path, uid):
            path = Path(path)
            self.assertTrue(path == self.base or self.base in path.parents)
            for part in (path, *path.parents):
                if part == self.base.parent:
                    break
                info = part.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
                    raise h.Rejected('unprotected fixture')
        patch.object(h, 'protected', protected).start()
        patch.object(h.pwd, 'getpwnam', lambda n: types.SimpleNamespace(pw_uid=995 if n == 'eqemu-validator' else 0)).start()
        patch.object(h.grp, 'getgrnam', lambda n: types.SimpleNamespace(gr_gid=980 if n == 'eqemu-validator' else 0)).start()
        self.target = dict(root=str(h.CODE_ROOT), actions=['publish', 'revert', 'recover'],
                           resources=['validator-worker-code'], files=list(h.FILES),
                           units=['eqemu-validator@.service'], service_uid=995,
                           host_contract=h.CONTRACT_SHA, timeout=1)
        self.manager = h.HostManager()
        self.calls = []
        self.instances = {}
        self.sockets = {s: 'inactive' for s in h.SOCKETS}
        patch.object(self.manager, '_run', self.run_systemctl).start()

    def run_systemctl(self, args, timeout):
        self.calls.append(args)
        if args[0] == 'list-units':
            self.assertEqual(args[1:4], ['--all', '--plain', '--no-legend'])
            return ''.join(u + ' loaded active running fixture\n' for u in self.instances).encode()
        if args[0] == 'show':
            unit = args[1]
            values = self.instances.get(unit, dict(ControlGroup='', InvocationID='', User='', Group='',
                                                  ActiveState=self.sockets.get(unit, 'inactive'), KillMode=''))
            return ''.join(k + '=' + v + '\n' for k, v in values.items()).encode()
        if args[0] in ('start', 'stop'):
            unit = args[1]
            if args[0] == 'start':
                self.assertIn(unit, h.SOCKETS)
                self.sockets[unit] = 'active'
            elif unit in self.sockets:
                self.sockets[unit] = 'inactive'
            else:
                self.instances[unit].update(ActiveState='inactive', ControlGroup='', InvocationID='')
            return b''
        self.fail('unexpected systemctl command')

    def instance(self, template, active='active', populated=0):
        unit = template.replace('@.', '@accepted-1.')
        group = '/system.slice/' + unit
        path = h.CGROUP_ROOT / group[1:]
        path.mkdir(parents=True, exist_ok=True)
        (path / 'cgroup.events').write_text('populated ' + str(populated) + '\n')
        root = template == h.PUBLISHER
        self.instances[unit] = dict(ControlGroup=group, InvocationID='a'*32, User='root' if root else 'eqemu-validator',
                                    Group='root' if root else 'eqemu-validator', ActiveState=active, KillMode='control-group')
        return unit

    def release(self, character):
        path = h.CODE_ROOT / 'releases' / (character * 64)
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
        path.parent.chmod(0o755)
        return path

    def test_fixed_enrollment_rejects_generic_paths_and_identity(self):
        h.validate_target(self.target)
        for field, value in [('host_contract', 'bad'), ('root', '/arbitrary'), ('service_uid', 0),
                             ('units', [h.PUBLISHER]), ('files', ['one']), ('resources', ['other'])]:
            target = {**self.target, field: value}
            with self.assertRaises(h.Rejected, msg=field):
                h.validate_target(target)
        workspace = {**self.target, 'root': str(h.WORKSPACE_ROOT), 'actions': ['recover'],
                     'resources': ['validator-integration-evidence', 'validator-ordinary-state'],
                     'files': ['central-cdau-integration-v1.json', 'pending.json', 'receipt.json']}
        self.assertEqual(self.manager.workspace(workspace), h.WORKSPACE)

    def test_nss_identities_and_populated_cgroup(self):
        unit = self.instance(h.TEMPLATES[0], populated=1)
        self.assertTrue(self.manager.observe(self.target)[unit]['populated'])
        self.instances[unit]['Group'] = '0'
        with self.assertRaises(h.Rejected):
            self.manager.observe(self.target)
        self.instances[unit]['Group'] = 'eqemu-validator'
        self.instances[unit]['KillMode'] = 'process'
        with self.assertRaises(h.Rejected):
            self.manager.observe(self.target)

    def test_fence_rejects_active_workload_without_stopping_or_replaying(self):
        unit = self.instance(h.TEMPLATES[0])
        with self.manager.guard(self.target):
            with self.assertRaises(h.Rejected):
                self.manager.stop(self.target)
        effects = [c for c in self.calls if c[0] in ('start', 'stop')]
        self.assertEqual(effects, [['stop', s] for s in h.SOCKETS])
        self.assertEqual(self.instances[unit]['ActiveState'], 'active')

    def test_adoption_stop_before_guard_publisher_stop_only_restore_diagnostics(self):
        publisher = self.instance(h.PUBLISHER)
        self.sockets[h.SOCKETS[1]] = self.sockets[h.SOCKETS[-1]] = 'active'
        before = self.manager.observe(self.target)
        self.manager.stop(self.target)
        with self.manager.guard(self.target):
            self.manager.start(self.target, before)
        effects = [c for c in self.calls if c[0] in ('start', 'stop')]
        self.assertEqual(effects[:6], [['stop', s] for s in h.SOCKETS])
        self.assertIn(['stop', publisher], effects)
        self.assertEqual([c for c in effects if c[0] == 'start'], [['start', h.SOCKETS[1]], ['start', h.SOCKETS[-1]]])
        self.assertEqual(self.sockets[h.ORDINARY_SOCKET], 'inactive')

    def test_lock_preserves_inode_and_bytes_busy_missing_symlink(self):
        inode = h.SHARED_LOCK.stat().st_ino
        with h.SHARED_LOCK.open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(h.Rejected):
                with self.manager.guard(self.target):
                    self.fail('busy lock acquired')
        with self.manager.guard(self.target):
            pass
        self.assertEqual(h.SHARED_LOCK.stat().st_ino, inode)
        self.assertEqual(h.SHARED_LOCK.read_bytes(), b'unchanged lock')
        h.SHARED_LOCK.unlink()
        with self.assertRaises(OSError):
            with self.manager.guard(self.target):
                pass
        h.SHARED_LOCK.symlink_to(self.base / 'missing')
        with self.assertRaises(OSError):
            with self.manager.guard(self.target):
                pass

    def test_binding_requires_adoption_check_fence_and_compensates(self):
        old, new = self.release('a'), self.release('b')
        h.BINDING.mkdir()
        with self.assertRaises(h.Rejected):
            self.manager.check_binding(self.target, old)
        h.BINDING.rmdir()
        h.BINDING.symlink_to(old)
        with self.assertRaises(h.Rejected):
            self.manager.publish_binding(self.target, new)
        with self.manager.guard(self.target):
            self.manager.check_binding(self.target, old)
            self.manager.stop(self.target)
            self.manager.publish_binding(self.target, new)
            self.assertEqual(os.readlink(h.BINDING), str(new))
            self.manager.publish_binding(self.target, old)
            self.assertEqual(os.readlink(h.BINDING), str(old))
            with self.assertRaises(h.Rejected):
                self.manager.publish_binding(self.target, self.base)
        self.assertEqual(list(h.BINDING.parent.glob('.eqemu-binding-*')), [])
        with self.assertRaises(h.Rejected):
            self.manager.check_binding(self.target, new)

    def test_binding_fsync_failure_can_restore_observed_previous_release(self):
        old, new = self.release('a'), self.release('b')
        h.BINDING.symlink_to(old)
        with self.manager.guard(self.target):
            self.manager.check_binding(self.target, old)
            self.manager.stop(self.target)
            with patch.object(h, 'sync_dir', side_effect=OSError('fixture sync failure')):
                with self.assertRaises(OSError):
                    self.manager.publish_binding(self.target, new)
            self.assertEqual(os.readlink(h.BINDING), str(new))
            self.manager.publish_binding(self.target, old)
        self.assertEqual(os.readlink(h.BINDING), str(old))

    def test_missing_active_cgroup_and_changed_invocation_fail_closed(self):
        unit = self.instance(h.TEMPLATES[0])
        events = h.CGROUP_ROOT / self.instances[unit]['ControlGroup'][1:] / 'cgroup.events'
        events.unlink()
        with self.assertRaises(h.Rejected):
            self.manager.observe(self.target)
        self.instances[unit].update(ActiveState='inactive', ControlGroup='')
        with self.manager.guard(self.target):
            self.manager.stop(self.target)
            self.instances[unit]['InvocationID'] = 'b' * 32
            with self.assertRaises(h.Rejected):
                self.manager.start(self.target, {})
        self.assertFalse(any(c[0] == 'start' for c in self.calls))

    def test_binding_replacement_since_check_is_rejected(self):
        old, new = self.release('a'), self.release('b')
        h.BINDING.symlink_to(old)
        with self.manager.guard(self.target):
            self.manager.check_binding(self.target, old)
            self.manager.stop(self.target)
            replacement = h.BINDING.parent / 'replacement'
            replacement.symlink_to(old)
            replacement.replace(h.BINDING)
            with self.assertRaises(h.Rejected):
                self.manager.publish_binding(self.target, new)
        self.assertEqual(os.readlink(h.BINDING), str(old))

    def test_recovery_binding_accepts_only_bounded_sealed_choices(self):
        old, new, other = self.release('a'), self.release('b'), self.release('c')
        h.BINDING.symlink_to(new)
        with self.manager.guard(self.target):
            self.assertEqual(self.manager.recovery_binding(self.target, [old, new]), new)
            with self.assertRaises(h.Rejected):
                self.manager.recovery_binding(self.target, [old])
            with self.assertRaises(h.Rejected):
                self.manager.recovery_binding(self.target, [old, new, other])
            self.manager.stop(self.target)
            self.manager.publish_binding(self.target, old)
        self.assertEqual(os.readlink(h.BINDING), str(old))

    def test_stopped_publisher_gc_verified_empty_new_instance_rejected(self):
        publisher = self.instance(h.PUBLISHER)
        original = self.run_systemctl
        def collected(args, timeout):
            result = original(args, timeout)
            if args == ['stop', publisher]:
                del self.instances[publisher]
            return result
        with patch.object(self.manager, '_run', collected):
            self.manager.stop(self.target)
        self.assertTrue(self.manager._fenced)
        with self.manager.guard(self.target):
            self.instance(h.PUBLISHER, active='inactive')
            with self.assertRaises(h.Rejected):
                self.manager.start(self.target, {})

    def test_bound_discovery_and_unexpected_template(self):
        for raw in (b'evil@one.service loaded active running\n',
                    ('\n'.join('eqemu-validator@a'+str(i)+'.service loaded active running' for i in range(33))).encode(),
                    b'x' * (h.MAX_OUTPUT+1)):
            with patch.object(self.manager, '_run', return_value=raw):
                with self.assertRaises(h.Rejected):
                    self.manager.observe(self.target)

    def test_new_instance_or_population_blocks_publication(self):
        old, new = self.release('a'), self.release('b')
        h.BINDING.symlink_to(old)
        with self.manager.guard(self.target):
            self.manager.check_binding(self.target, old)
            self.manager.stop(self.target)
            self.instance(h.TEMPLATES[1], active='inactive', populated=1)
            with self.assertRaises(h.Rejected):
                self.manager.publish_binding(self.target, new)
        self.assertEqual(os.readlink(h.BINDING), str(old))


if __name__ == '__main__':
    unittest.main()
