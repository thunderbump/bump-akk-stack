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
                               ('BINDING', 'srv/code'), ('WORKSPACE', 'state/ordinary/last-integration'),
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
        if args == ['daemon-reload']:
            return b''
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
        self.sockets[h.SOCKETS[1]] = self.sockets[h.SOCKETS[4]] = 'active'
        before = self.manager.observe(self.target)
        self.manager.stop(self.target)
        with self.manager.guard(self.target):
            self.manager.start(self.target, before)
        effects = [c for c in self.calls if c[0] in ('start', 'stop')]
        self.assertEqual(effects[:6], [['stop', s] for s in h.SOCKETS])
        self.assertIn(['stop', publisher], effects)
        self.assertEqual([c for c in effects if c[0] == 'start'], [['start', h.SOCKETS[1]], ['start', h.SOCKETS[4]]])
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

class HostRecoveryIntegrationTests(unittest.TestCase):
    setUp = HostTests.setUp
    run_systemctl = HostTests.run_systemctl
    def interrupted_allocation(self, boundary):
        import base64
        import contextlib
        import sys
        core=sys.modules['engine']
        class Interrupted(BaseException): pass
        target=dict(self.target,root=str(h.WORKSPACE_ROOT),actions=['recover'],resources=['validator-ordinary-state','validator-integration-evidence'],files=['central-cdau-integration-v1.json','pending.json','receipt.json'],max_bytes=4096,max_files=20)
        code=dict(self.target,max_bytes=4096,max_files=20)
        peer=(os.getuid(),os.getgid())
        policy={'peers':[dict(uid=peer[0],gid=peer[1],methods=['prepare','execute','status'],targets=['workspace','code'],actions=['publish','revert','recover'])],'targets':{'workspace':target,'code':code}}
        store=self.base/'store';store.mkdir()
        self.sockets[h.SOCKETS[1]] = self.sockets[h.SOCKETS[4]] = 'active'
        h.WORKSPACE.mkdir(mode=0o700)
        (h.WORKSPACE/'failure').write_text('old failed evidence')
        with patch.dict(sys.modules,{'host':h}),patch.object(core,'protected',lambda path,uid:None),patch.object(core.os,'chown',lambda *args:None):
            engine=core.Engine(policy,store,self.manager,trusted_uid=os.getuid())
            original=dict(operation_id='original',plan_id='legacy',target='workspace',resources=target['resources'],state='failed',step='retained',recovery_required=True)
            core.atomic(store/'operations/original.json',original)
            def prepare(rid, linked):
                return engine.handle(dict(method='prepare',request_id=rid,target='workspace',action='recover',generation=engine.current(target)['generation'],recovery_of=linked),peer)['plan_id']
            def execute(pid,oid):
                return engine.handle(dict(method='execute',plan_id=pid,operation_id=oid),peer)
            plan=prepare('first','original')
            engine.fault=lambda point: (_ for _ in ()).throw(Interrupted()) if point==boundary else None
            with self.assertRaises(Interrupted): execute(plan,'interrupted')
            engine.fault=lambda _:None
            self.assertEqual(engine.handle(dict(method='status',operation_id='interrupted'),peer)['state'],'uncertain')
            result=execute(prepare('linked','interrupted'),'recovered')
            self.assertEqual(result['state'],'succeeded',result)
            self.assertEqual(core.read(store/'operations/original.json'),original)
            self.assertEqual((h.WORKSPACE_ROOT/'evidence/0/workspace/failure').read_text(),'old failed evidence')
            self.assertTrue(h.WORKSPACE.is_dir())
            self.assertEqual(self.sockets[h.SOCKETS[1]], 'active')
            self.assertEqual(self.sockets[h.SOCKETS[4]], 'active')
            self.assertEqual(self.sockets[h.ORDINARY_SOCKET], 'inactive')
            # A separately approved code publication still works after state recovery.
            published=engine.handle(dict(method='prepare',request_id='code',target='code',action='publish',generation=0,artifact={name:base64.b64encode(b'fixture').decode() for name in h.FILES}),peer)['plan_id']
            h.BINDING.symlink_to(h.CODE_ROOT/'releases'/published)
            core.atomic(h.CODE_ROOT/'current.json',dict(generation=0,workspace_generation=0,release=published),0o644)
            self.assertEqual(execute(published,'next-code')['state'],'succeeded')
            self.assertEqual(self.sockets[h.SOCKETS[1]], 'active')
            self.assertEqual(self.sockets[h.SOCKETS[4]], 'active')

    def test_fixed_workspace_allocation_effect_crash(self): self.interrupted_allocation('allocate-effect')
    def test_fixed_workspace_allocation_observed_crash(self): self.interrupted_allocation('allocate-observed')

    def test_workspace_accepted_crash_restores_ingress(self): self.interrupted_allocation('accepted')
    def test_workspace_stop_effect_crash_restores_ingress(self): self.interrupted_allocation('stop-effect')
    def test_workspace_publish_effect_crash_restores_ingress(self): self.interrupted_allocation('publish-effect')
    def test_workspace_restore_intent_crash(self): self.interrupted_allocation('restore-ingress-intent')
    def test_workspace_restore_effect_crash(self): self.interrupted_allocation('restore-ingress-effect')

    def test_code_acceptance_crash_linked_recovery_and_next_deployment(self):
        import base64
        core = sys.modules['engine']
        import multiprocessing
        import signal
        target = dict(self.target, max_bytes=4096, max_files=20)
        peer = (os.getuid(), os.getgid())
        policy = dict(peers=[dict(uid=peer[0], gid=peer[1], methods=['prepare','execute','status'],
                                 targets=['code'], actions=['publish','revert','recover'])],
                      targets={'code': target})
        store = self.base/'store'
        store.mkdir()
        with patch.dict(sys.modules, {'host': h}), patch.object(core, 'protected', lambda path,uid:None):
            engine = core.Engine(policy, store, self.manager, trusted_uid=os.getuid())
            def prepare(rid, generation, **kw):
                return engine.handle(dict(method='prepare', request_id=rid, target='code',
                                          generation=generation, **kw), peer)['plan_id']
            def publish(rid, generation):
                return prepare(rid, generation, action='publish',
                               artifact={name:base64.b64encode(rid.encode()).decode() for name in h.FILES})
            def execute(pid, oid):
                return engine.handle(dict(method='execute', plan_id=pid, operation_id=oid), peer)
            old = publish('adopted', 0)
            h.BINDING.symlink_to(h.CODE_ROOT/'releases'/old)
            core.atomic(h.CODE_ROOT/'current.json', dict(generation=0,workspace_generation=0,release=old))
            candidate = publish('candidate', 0)
            def killed_executor():
                engine.fault = lambda point: os.kill(os.getpid(), signal.SIGKILL) if point == 'accepted' else None
                execute(candidate, 'interrupted')
            child = multiprocessing.get_context('fork').Process(target=killed_executor)
            child.start()
            child.join(5)
            if child.is_alive():
                child.kill()
                child.join(5)
                self.fail('fixture executor did not reach acceptance')
            self.assertEqual(child.exitcode, -signal.SIGKILL)
            original = (store/'operations/interrupted.json').read_bytes()
            engine = core.Engine(policy, store, self.manager, trusted_uid=os.getuid())
            self.assertEqual(engine.status(dict(operation_id='interrupted'))['state'], 'uncertain')
            recovered = execute(prepare('recover', 0, action='recover', recovery_of='interrupted'), 'recovery')
            self.assertEqual(recovered['state'], 'succeeded', recovered)
            self.assertEqual(os.readlink(h.BINDING), str(h.CODE_ROOT/'releases'/old))
            self.assertEqual((store/'operations/interrupted.json').read_bytes(), original)
            self.assertEqual(execute(publish('next', 1), 'subsequent')['state'], 'succeeded')


class AdoptionRecoveryIntegrationTests(unittest.TestCase):
    setUp = HostTests.setUp
    run_systemctl = HostTests.run_systemctl

    def adoption_to_recovery(self, interrupt=False):
        import base64
        spec = importlib.util.spec_from_file_location('fixture_adopt', SOURCE/'adopt.py')
        adoption = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adoption)
        core = sys.modules['engine']
        packet = adoption.contract()
        policy = adoption.policy_for(packet)
        workspace_id = 'validator-integration-evidence'
        code_id = 'validator-worker-code'
        target, code = policy['targets'][workspace_id], policy['targets'][code_id]
        target['root'], code['root'] = str(h.WORKSPACE_ROOT), str(h.CODE_ROOT)
        peer = (os.getuid(), os.getgid())
        policy['peers'][0].update(uid=peer[0], gid=peer[1])
        store = self.base/'store'
        store.mkdir()
        h.WORKSPACE.mkdir(mode=0o700)
        originals = {name: ('failed fixture '+name).encode() for name in target['files']}
        for name, raw in originals.items():
            (h.WORKSPACE/name).write_bytes(raw)
            (h.WORKSPACE/name).chmod(0o600)
        # Run the actual adoption entry point in a mapped filesystem. Its real
        # record construction and sealing must carry pre-fence ingress into
        # Engine recovery, without fabricating a legacy operation in the test.
        self.sockets[h.SOCKETS[1]] = self.sockets[h.SOCKETS[4]] = 'active'
        with patch.dict(sys.modules, {'host':h}), patch.object(core, 'protected', lambda path,uid:None), patch.object(core.os, 'chown', lambda *args:None):
            engine = core.Engine(policy, store, self.manager, trusted_uid=os.getuid())
            before = self.manager.observe(code)
            self.apply_adoption_fixture(adoption, core, packet, policy, store, originals)
            legacy_path = store/'operations/legacy-02fee-retained.json'
            legacy_bytes = legacy_path.read_bytes()
            legacy = core.read(legacy_path)
            self.assertEqual(legacy['restore_ingress'], before)
            self.assertEqual(legacy['original_outcome'], packet['migration']['original_outcome'])
            self.assertFalse(legacy['original_outcome']['complete'])
            self.assertEqual(legacy['original_outcome']['original_transfer'], 'uncertain')
            self.assertTrue(all(state == 'inactive' for state in self.sockets.values()))

            def prepare(rid, linked):
                return engine.handle(dict(method='prepare', request_id=rid, target=workspace_id,
                                          action='recover', generation=engine.current(target)['generation'],
                                          recovery_of=linked), peer)['plan_id']
            def execute(pid, oid):
                return engine.handle(dict(method='execute', plan_id=pid, operation_id=oid), peer)
            worker_spec=importlib.util.spec_from_file_location('adopted_worker',h.BINDING/'validation/worker/runtime.py')
            worker=importlib.util.module_from_spec(worker_spec)
            worker_spec.loader.exec_module(worker)
            worker.ROOT_UID=os.getuid()
            with self.assertRaises(ValueError):
                worker.integration_intake(h.WORKSPACE.parent)
            pid = prepare('legacy-recovery', legacy['operation_id'])
            if interrupt:
                class Interrupted(BaseException): pass
                engine.fault = lambda point: (_ for _ in ()).throw(Interrupted()) if point == 'accepted' else None
                with self.assertRaises(Interrupted):
                    execute(pid, 'interrupted')
                accepted = core.read(store/'operations/interrupted.json')
                self.assertEqual(accepted['restore_ingress'], before)
                self.assertTrue(all(v['active'] == 'inactive' for v in accepted['before'].values()))
                engine = core.Engine(policy, store, self.manager, trusted_uid=os.getuid())
                pid = prepare('linked-recovery', 'interrupted')
            result = execute(pid, 'recovered')
            self.assertEqual(result['state'], 'succeeded', result)
            self.assertEqual(result['restore_ingress'], before)
            self.assertEqual(legacy_path.read_bytes(), legacy_bytes)
            self.assertEqual((h.WORKSPACE_ROOT/'evidence/0/original-operation.json').read_bytes(), legacy_bytes)
            for name, raw in originals.items():
                self.assertEqual((h.WORKSPACE_ROOT/'evidence/0/workspace'/name).read_bytes(), raw)
            self.assertEqual({p.name for p in h.WORKSPACE.iterdir()}, {'.rootops-fresh.json'})
            self.assertEqual(self.sockets[h.SOCKETS[1]], 'active')
            self.assertEqual(self.sockets[h.SOCKETS[4]], 'active')
            self.assertEqual(self.sockets[h.ORDINARY_SOCKET], 'inactive')

            # Actual next-worker intake consumes only the root allocation marker.
            worker.integration_intake(h.WORKSPACE.parent)
            self.assertFalse(h.WORKSPACE.exists())
            self.assertEqual((h.WORKSPACE_ROOT/'evidence/0/original-operation.json').read_bytes(),legacy_bytes)

            # A separately prepared publication preserves the restored ingress.
            pid = engine.handle(dict(method='prepare', request_id='next-code', target=code_id,
                                     action='publish', generation=0,
                                     artifact={name:base64.b64encode(b'fixture').decode() for name in code['files']}), peer)['plan_id']
            self.assertEqual(execute(pid, 'published')['state'], 'succeeded')
            self.assertEqual(self.sockets[h.SOCKETS[1]], 'active')
            self.assertEqual(self.sockets[h.SOCKETS[4]], 'active')
            self.assertEqual(self.sockets[h.ORDINARY_SOCKET], 'inactive')
            self.assertTrue(all(call[1] in h.SOCKETS for call in self.calls if call[0] == 'start'))

    def apply_adoption_fixture(self, adoption, core, packet, policy, store, originals):
        import copy
        import hashlib
        import types
        # Every inspected/mutated host path is mapped before entering apply().
        # No real privileged paths, services, users or protected state are read.
        spec = importlib.util.spec_from_file_location('fixture_package', SOURCE/'package.py')
        package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package)
        release = self.base/'adoption-package'
        package.prepare(SOURCE, release)
        packet = copy.deepcopy(packet)
        packet['installed_unit_definitions'] = []
        packet['installed_configs'] = []
        h.BINDING.mkdir()
        entries = []
        import base64
        artifact = package.decode((SOURCE/'worker-release.json').read_bytes())
        for name in h.FILES:
            path = h.BINDING/name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = ((SOURCE/'ordinary-runtime-baseline.py').read_bytes() if name == 'validation/worker/runtime.py' else (SOURCE/'integration-release-baseline.json').read_bytes() if name == 'integration-release.json' else base64.b64decode(artifact[name]))
            path.write_bytes(raw)
            entries.append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        packet['current_code']['fresh_files'] = entries
        old_workspace = h.SHARED_LOCK.parent/'last-integration'
        os.rename(h.WORKSPACE, old_workspace)
        h.WORKSPACE.parent.rmdir()
        packet['migration']['workspace'] = str(old_workspace)
        for name, raw in originals.items():
            info = (old_workspace/name).lstat()
            packet['migration']['observed_records']['files'][name] = dict(
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))
        # Adoption, rather than the test, must create the managed generations.
        h.CODE_ROOT.rmdir()
        h.WORKSPACE_ROOT.rmdir()
        paths = {
            '/var/lib/eqemu-resilient-ops': store,
            '/srv/eqemu-validator-code': h.BINDING,
            '/etc/eqemu-resilient-ops/policy.json': self.base/'configuration/policy.json',
            '/srv/eqemu-resilient-adoption': self.base/'backup',
            '/var/lib/eqemu-validator/ordinary/last-integration': h.WORKSPACE,
        }
        class RootPath(type(Path())):
            def lstat(path, *args, **kw):
                info = super().lstat(*args, **kw)
                # Simulate immutable root package custody only. Workspace byte
                # and ownership verification uses its actual fixture metadata.
                if path == release or release in path.parents or path in release.parents:
                    return types.SimpleNamespace(st_mode=info.st_mode & ~0o022, st_uid=0)
                return info
        def mapped_path(value):
            return RootPath(paths.get(str(value), value))
        real_engine = core.Engine
        operator = release/'adopt.py'
        import transition
        from contextlib import ExitStack
        h.SHARED_LOCK.parent.chmod(0o700)
        fixtures = {'PARENT':h.SHARED_LOCK.parent,'STATE':h.WORKSPACE.parent,
                    'OLD_WORKSPACE':old_workspace,'BACKUP':self.base/'backup',
                    'CONFIG':self.base/'configuration/config.json',
                    'UNIT':self.base/'units/ordinary.service','PROFILE':self.base/'profile',
                    'PUBLISHER_UNITS':(self.base/'units/legacy.socket',self.base/'units/legacy@.service'),
                    'TRUSTED_UID':os.getuid(),'WORKER_UID':os.getuid(),'WORKER_GID':os.getgid()}
        for path in (fixtures['CONFIG'],fixtures['UNIT'],fixtures['PROFILE'],*fixtures['PUBLISHER_UNITS']):
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((SOURCE/'ordinary-apparmor-baseline').read_bytes() if path==fixtures['PROFILE'] else b'original authority')
        selection={'version':1,'entries':sorted(p.name for p in h.SHARED_LOCK.parent.iterdir()),'records':{}}
        selection_path=self.base/'selection.json'
        selection_path.write_bytes(package.encode(selection))
        with ExitStack() as stack:
            for key,value in fixtures.items():
                stack.enter_context(patch.object(transition,key,value))
            stack.enter_context(patch.object(adoption,'__file__',str(operator)))
            stack.enter_context(patch.object(adoption,'Path',mapped_path))
            stack.enter_context(patch.object(adoption,'contract',return_value=packet))
            stack.enter_context(patch.object(adoption,'policy_for',return_value=policy))
            stack.enter_context(patch.object(adoption.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(core,'Engine',side_effect=lambda *a,**kw:real_engine(*a,**kw,trusted_uid=os.getuid())))
            stack.enter_context(patch.object(h,'HostManager',return_value=self.manager))
            result=adoption.apply(hashlib.sha256(operator.read_bytes()).hexdigest(),True,selection_path,hashlib.sha256(selection_path.read_bytes()).hexdigest())
        self.assertTrue(all(path.is_symlink() and os.readlink(path)=='/dev/null' for path in fixtures['PUBLISHER_UNITS']))
        self.assertEqual((fixtures['BACKUP']/'custody/legacy.socket').read_bytes(),b'original authority')
        self.assertEqual(stat.S_IMODE(h.SHARED_LOCK.parent.stat().st_mode),0o711)
        self.assertTrue(result['adopted'])
        self.assertFalse(result['activation_performed'])
        self.assertTrue((store/'host-adoption-result.json').is_file())

    def test_adoption_record_restores_original_ingress(self):
        self.adoption_to_recovery()

    def test_adoption_intent_survives_interrupted_first_recovery(self):
        self.adoption_to_recovery(interrupt=True)
