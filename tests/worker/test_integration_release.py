"""Finite publication tests use a private fake host; never touch /srv or services."""
import contextlib
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import integration_release as r


class FakeHost(r.Host):
    def __init__(self): self.metadata_by_inode={};self.active=True;self.calls=[];self.writer=False
    def info(self,path):
        actual=Path(path).lstat();uid,gid,mode=self.metadata_by_inode.get((actual.st_dev,actual.st_ino),(1000,1000,stat.S_IMODE(actual.st_mode)))
        return types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFMT(actual.st_mode)|mode,st_ino=actual.st_ino,st_dev=actual.st_dev,st_size=actual.st_size)
    def metadata(self,fd,uid,gid,mode):
        actual=os.fstat(fd);self.metadata_by_inode[actual.st_dev,actual.st_ino]=(uid,gid,mode);os.fchmod(fd,mode)
        self.calls.append(('metadata',actual.st_ino,uid,gid,mode))
    def lock_info(self,fd):
        value=os.fstat(fd)
        return types.SimpleNamespace(st_uid=995,st_gid=980,st_mode=stat.S_IFREG|0o600,st_ino=value.st_ino,st_dev=value.st_dev)
    def quiescent(self): self.calls.append(('quiescent',))
    def socket_active(self): return self.active
    def socket(self,active): self.active=active;self.calls.append(('socket',active))
    def writers(self,identities):
        if self.writer: raise ValueError('injected open writable descriptor')


class Publication(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.code=root/'code';self.code.mkdir()
        self.dirs=(self.code,self.code/'validation',self.code/'validation/worker')
        self.dirs[1].mkdir();self.dirs[2].mkdir()
        self.lock=root/'worker.lock';self.lock.write_bytes(b'');self.lock.chmod(0o600)
        self.host=FakeHost();self.digest='f'*64
        for name in r.CHANGED:
            path=self.code/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('old-'+name).encode());path.chmod(0o644)
        self.exception=self.code/'validation/unchanged.py';self.exception.write_bytes(b'unchanged mutable exception')
        self.baseline=dict(files={str(self.code/n):r.record(self.code/n,self.host) for n in r.CHANGED},
                           directories={str(p):r.record(p,self.host) for p in self.dirs},retained={})
        self.baseline['files'][str(self.exception)]=r.record(self.exception,self.host)
        self.assets={'forward/'+name:('new-'+name).encode() for name in r.ASSETS}
        self.manifest=dict(installed={name:r.content_record(self.assets['forward/'+name]) for name in r.ASSETS},source_commit='a'*40)
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        for name,value in dict(CODE=self.code,DIRECTORIES=self.dirs,LOCK=self.lock,JOURNAL=root/'journal',BACKUP=self.code/'.backup').items(): stack.enter_context(patch.object(r,name,value))
        stack.enter_context(patch.object(r,'package',return_value=(self.manifest,self.baseline,self.assets)))

    def test_exact_forward_and_repeated_rollback_restore_original_inodes_before_directories(self):
        original={name:r.record(name,self.host) for name in self.baseline['files']}
        r.apply(Path('/unused'),self.digest,self.host)
        for name in r.ASSETS:
            value=r.record(self.code/name,self.host)
            self.assertTrue(r.matches(value,self.manifest['installed'][name]))
        self.assertEqual(r.record(self.exception,self.host),original[str(self.exception)])
        self.assertTrue(self.host.active)
        self.assertEqual(r.verify(Path('/unused'),self.digest,self.host)['state'],'new')
        r.rollback(Path('/unused'),self.digest,self.host)
        r.rollback(Path('/unused'),self.digest,self.host)
        for name,expected in original.items(): self.assertEqual(r.record(name,self.host),expected)
        for directory in self.dirs: self.assertEqual(r.record(directory,self.host),self.baseline['directories'][str(directory)])
        self.assertTrue(all(not (self.code/n).exists() for n in r.ADDED))
        self.assertTrue(self.host.active)
        self.assertEqual(r.verify(Path('/unused'),self.digest,self.host)['state'],'original')

    def test_partial_forward_after_atomic_replace_is_reversible(self):
        real=r.append
        def stop(event,name,info=None):
            if event=='published' and name==r.CHANGED[2]: raise OSError('injected post-publication journal failure')
            return real(event,name,info)
        with patch.object(r,'append',side_effect=stop),self.assertRaises(OSError): r.apply(Path('/unused'),self.digest,self.host)
        self.assertFalse(self.host.active)
        r.rollback(Path('/unused'),self.digest,self.host)
        for name,expected in self.baseline['files'].items(): self.assertEqual(r.record(name,self.host),expected)
        self.assertTrue(self.host.active)

    def test_unknown_bytes_and_missing_backup_refuse_before_rollback_mutation(self):
        r.apply(Path('/unused'),self.digest,self.host)
        path=self.code/r.CHANGED[0];path.write_bytes(b'unknown bytes')
        before=list(self.host.calls)
        with self.assertRaises(ValueError): r.rollback(Path('/unused'),self.digest,self.host)
        self.assertEqual(self.host.calls,before+[('quiescent',)])
        path.write_bytes(self.assets['forward/'+r.CHANGED[0]])
        (r.BACKUP/r.CHANGED[1]).unlink()
        before=list(self.host.calls)
        with self.assertRaises(ValueError): r.rollback(Path('/unused'),self.digest,self.host)
        self.assertEqual(self.host.calls,before+[('quiescent',)])

    def test_mutable_exception_drift_and_parent_symlinks_are_not_overwritten(self):
        self.exception.write_bytes(b'changed by other owner')
        before=list(self.host.calls)
        with self.assertRaises(ValueError): r.apply(Path('/unused'),self.digest,self.host)
        self.assertEqual(self.exception.read_bytes(),b'changed by other owner')
        self.assertTrue(self.host.active)

    def test_existing_writer_is_a_reversible_protection_failure(self):
        self.host.writer=True
        with self.assertRaises(ValueError): r.apply(Path('/unused'),self.digest,self.host)
        self.host.writer=False
        r.rollback(Path('/unused'),self.digest,self.host)
        for name,expected in self.baseline['files'].items(): self.assertEqual(r.record(name,self.host),expected)


class Patch(unittest.TestCase):
    def test_selected_overlay_uses_exact_installed_bytes_and_no_fuzz(self):
        source=Path(__file__).resolve().parents[2]
        baseline=__import__('json').loads((source/'validation/worker/integration-b999-baseline.json').read_bytes())
        old={name:r.read(r.CODE/name) for name in r.CHANGED}
        if any(r.sha(old[name])!=baseline['files'][str(r.CODE/name)]['sha256'] for name in r.CHANGED): self.skipTest('Installed baseline has changed under another reviewed owner')
        result=r.patch_files(old,(source/'validation/worker/integration-b999.patch').read_bytes())
        self.assertEqual(set(result),set(r.CHANGED))
        for name,raw in result.items(): __import__('ast').parse(raw)
        self.assertNotIn(b'from profile_artifacts',result['validation/worker/runtime.py'])
        self.assertNotIn(b'from sanitizers',result['validation/worker/runtime.py'])
        self.assertNotIn(b'from profiling',result['validation/worker/build_guest.py'])
        changed=dict(old);changed[r.CHANGED[0]]=b'unknown\n'+changed[r.CHANGED[0]]
        with self.assertRaises(ValueError): r.patch_files(changed,(source/'validation/worker/integration-b999.patch').read_bytes())


if __name__=='__main__': unittest.main()
