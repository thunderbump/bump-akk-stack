"""Actual known-baseline worker and finite bootstrap controls; no workload runs."""
import base64
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[2]/'validation/resilient_ops'
sys.path.insert(0,str(SOURCE))
import bootstrap
import transition
import package
import engine


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        artifact = json.loads((SOURCE/'worker-release.json').read_bytes())
        self.release = self.root/'managed/releases'/('a'*64)
        for name, raw in artifact.items():
            dest = self.release/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(base64.b64decode(raw))
            dest.chmod(0o644)
        for directory in self.root.rglob('*'):
            if directory.is_dir():directory.chmod(0o755)
        self.link = self.root/'code'
        self.link.symlink_to(self.release)
        (self.release.parent.parent/'current.json').write_text(json.dumps({'release':'a'*64}))
        spec = importlib.util.spec_from_file_location('proposed_ordinary',self.release/'validation/worker/runtime.py')
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)
        self.worker.ROOT_UID = 0
        self.worker.MANAGED_ROOT = self.release.parent.parent
        self.worker.MANAGED_LINK = self.link
        self.state = self.root/'ordinary'
        self.state.mkdir(mode=0o700)
        self.worker.ORDINARY_STATE = self.state
        self.lock = self.root/'worker.lock'
        self.lock.write_bytes(b'common')
        self.lock.chmod(0o600)
        self.worker.SHARED_LOCK = self.lock
        self.config = json.loads((SOURCE/'ordinary-config.json').read_bytes())
        self.config.update(state_dir=str(self.state),code_dir=str(self.link),shared_lock=str(self.lock),
                           worker_uid=os.getuid(),worker_gid=os.getgid())
        self.config_file = self.root/'config.json'
        self.config_file.write_text(json.dumps(self.config))
        account = type('Account',(),dict(pw_uid=os.getuid(),pw_gid=os.getgid()))
        # Simulate the protected /tmp ancestor and root configuration custody,
        # preserving actual worker state and code ancestor metadata checks.
        real_lstat = Path.lstat
        real_fstat = os.fstat
        code_inodes = {p.stat().st_ino for p in self.release.rglob('*') if p.is_file()}
        def root_stat(info):
            data=list(info);data[4]=0;data[5]=0
            return os.stat_result(data)
        def lstat(path,*a,**kw):
            info=real_lstat(path,*a,**kw)
            if path == self.state or self.state in path.parents or path == self.lock:
                return info
            result=root_stat(info)
            if path == Path('/tmp'):
                data=list(result);data[0]&=~0o022;result=os.stat_result(data)
            return result
        def fstat(fd):
            info=real_fstat(fd)
            return root_stat(info) if info.st_ino in code_inodes else info
        for subject,name,effect in ((Path,'lstat',lstat),(os,'fstat',fstat)):
            patcher=patch.object(subject,name,new=effect)
            patcher.start();self.addCleanup(patcher.stop)
        patcher=patch.object(self.worker,'root_file',side_effect=lambda p:Path(p))
        patcher.start();self.addCleanup(patcher.stop)
        patcher=patch.object(self.worker.pwd,'getpwnam',return_value=account)
        patcher.start();self.addCleanup(patcher.stop)

    def test_actual_worker_config_binding_and_shared_acquire(self):
        value=self.worker.config(self.config_file)
        fd=self.worker.acquire(value)
        try:
            with self.lock.open('rb') as other:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertFalse((self.state/'worker.lock').exists())
        finally: os.close(fd)
        self.assertEqual(self.lock.read_bytes(),b'common')
        self.lock.chmod(0o644)
        with self.assertRaises(ValueError):self.worker.acquire(value)

    def test_binding_refuses_arbitrary_symlink_stale_current_and_writable_root(self):
        (self.release.parent.parent/'current.json').write_text(json.dumps({'release':'b'*64}))
        with self.assertRaises(ValueError):self.worker.config(self.config_file)
        (self.release.parent.parent/'current.json').write_text(json.dumps({'release':'a'*64}))
        self.release.chmod(0o777)
        with self.assertRaises(ValueError):self.worker.config(self.config_file)
        self.release.chmod(0o755)
        self.worker.MANAGED_LINK=self.root/'different'
        with self.assertRaises(ValueError):self.worker.config(self.config_file)

    def test_managed_binding_rejects_indirect_link_even_to_same_release(self):
        alias=self.root/'alias'
        alias.symlink_to(self.release)
        self.link.unlink()
        self.link.symlink_to(alias)
        with self.assertRaisesRegex(ValueError,'Unexpected managed worker release'):
            self.worker.config(self.config_file)

    def test_root_allocated_slot_passes_actual_intake_and_dirty_slot_refuses(self):
        workspace=self.state/'last-integration'
        target=dict(service_uid=os.getuid(),host_contract='fixture')
        obj=object.__new__(engine.Engine);obj.uid=os.getuid()
        with patch.object(engine.os,'chown'):
            obj.allocate(workspace,target,1)
        marker=(workspace/self.worker.FRESH_MARKER).read_bytes()
        self.worker.ROOT_UID=os.getuid()
        self.worker.integration_intake(self.state)
        self.assertFalse(workspace.exists())
        self.assertEqual(json.loads(marker)['generation'],1)
        workspace.mkdir()
        with self.assertRaises(Exception):self.worker.integration_intake(self.state)
        (workspace/'dirty').write_text('unknown')
        with self.assertRaises(Exception):self.worker.integration_intake(self.state)

    def test_uncertain_retention_still_blocks_intake_and_bytes_unchanged(self):
        import integration_artifacts as ia
        directory=self.state/'last-integration'
        directory.mkdir(mode=0o700)
        # Construct genuine baseline pending/receipt through its public helpers.
        pending=ia.binding('a'*40,'b'*32)
        raw=b''
        receipt=dict(pending,bytes=0,sha256=hashlib.sha256(raw).hexdigest(),terminal=False,
                     complete=False,client_durable=False,original_transfer='uncertain',
                     error='integration-incomplete',execution=dict(workload_exit_code=2,
                     validator_exit_code=2,native_cleanup='not-run',database_cleanup=True,vm_cleanup=True))
        for name,data in ((ia.NAME,raw),('pending.json',ia.encoded(pending)),('receipt.json',ia.encoded(receipt))):
            (directory/name).write_bytes(data);(directory/name).chmod(0o600)
        prior={p.name:p.read_bytes() for p in directory.iterdir()}
        with self.assertRaisesRegex(ValueError,'integration-previous-transfer-uncertain'):
            self.worker.integration_intake(self.state)
        self.assertEqual(prior,{p.name:p.read_bytes() for p in directory.iterdir()})

    def test_exact_baseline_delta_and_release_closure(self):
        packet=json.loads((SOURCE/'enrollment-contract.json').read_bytes())
        result=transition.release_bytes(SOURCE,packet)
        self.assertEqual(len(result),19)
        baseline=(SOURCE/'ordinary-runtime-baseline.py').read_bytes()
        self.assertEqual(hashlib.sha256(baseline).hexdigest(),'37ceb3371e34e92917cb51609aba244d86191857f029bb71cc5f8b3603fa40f8')
        self.assertNotEqual(baseline,result['validation/worker/runtime.py'])
        # Exercise the actual identity reader across the full staged closure.
        identity=self.worker.implementation_identity(self.config)
        (self.release/'validation/actor.py').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.worker.implementation_identity(self.config)

    def test_bootstrap_real_stage_idempotency_mutations_and_links(self):
        output=self.root/'package'
        info=package.prepare(SOURCE,output)
        operators=self.root/'operators';operators.mkdir(mode=0o700)
        with patch.object(bootstrap,'ROOT',operators),patch.object(bootstrap,'TRUSTED_UID',0),patch.object(bootstrap,'protected',side_effect=lambda p:None):
            destination=bootstrap.stage(output,info['manifest_sha256'])
            self.assertEqual(destination.read_bytes(),(SOURCE/'package.py').read_bytes())
            self.assertEqual(bootstrap.stage(output,info['manifest_sha256']),destination)
            with patch.object(bootstrap.os,'fsync',side_effect=OSError('fixture durability failure')):
                with self.assertRaises(OSError):bootstrap.stage(output,info['manifest_sha256'])
            self.assertEqual(destination.read_bytes(),(SOURCE/'package.py').read_bytes())
            destination.unlink();destination.symlink_to(self.root/'outside')
            with self.assertRaises(ValueError):bootstrap.stage(output,info['manifest_sha256'])
            destination.unlink()
            original=(output/'package.py').read_bytes()
            (output/'package.py').write_bytes(original+b'changed')
            with self.assertRaises(ValueError):bootstrap.stage(output,info['manifest_sha256'])
            (output/'package.py').unlink();(output/'package.py').symlink_to(SOURCE/'package.py')
            with self.assertRaises((ValueError,OSError)):bootstrap.stage(output,info['manifest_sha256'])
            with self.assertRaises(ValueError):bootstrap.stage(output,'bad')


if __name__=='__main__':unittest.main()

class TransitionRefusalTests(unittest.TestCase):
    def test_manifest_hash_links_and_unknown_state_refuse_before_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            parent=base/'state';parent.mkdir(mode=0o700)
            (parent/'worker.lock').write_bytes(b'lock')
            (parent/'last-integration').mkdir()
            (parent/'active.json').write_bytes(b'uncertain')
            manifest={'version':1,'entries':sorted(p.name for p in parent.iterdir()),'records':{}}
            path=base/'selection.json';path.write_bytes(package.encode(manifest))
            expected=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(transition.manifest_data(path,expected),manifest)
            with self.assertRaises(ValueError):transition.manifest_data(path,'0'*64)
            linked=base/'linked';linked.symlink_to(path)
            with self.assertRaises((OSError,ValueError)):transition.manifest_data(linked,expected)
            manager=type('Fenced',(),{'_fenced':True})()
            with patch.object(transition,'PARENT',parent),patch.object(transition,'WORKER_UID',os.getuid()),patch.object(transition,'WORKER_GID',os.getgid()),patch.object(engine,'protected'):
                with self.assertRaisesRegex(ValueError,'unreviewed state entries'):
                    transition.prepare_state(manager,{},SOURCE,{}, {},manifest)
            self.assertEqual((parent/'active.json').read_bytes(),b'uncertain')
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode),0o700)
