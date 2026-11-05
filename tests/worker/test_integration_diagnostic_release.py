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
import integration_diagnostic_release as r


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
        self.worker=self.code/'validation/worker/unchanged.py';self.worker.write_bytes(b'unchanged existing worker helper')
        self.exception=self.code/'validation/unchanged.py';self.exception.write_bytes(b'unchanged mutable exception')
        for path in (*self.dirs,*[self.code/n for n in r.CHANGED]):
            fd=os.open(path,os.O_RDONLY)
            try: self.host.metadata(fd,0,0,stat.S_IMODE(path.stat().st_mode))
            finally: os.close(fd)
        self.baseline=dict(files={str(self.code/n):r.record(self.code/n,self.host) for n in r.CHANGED},
                           directories={str(p):r.record(p,self.host) for p in self.dirs},retained={})
        self.baseline['files'][str(self.exception)]=r.record(self.exception,self.host)
        self.baseline['files'][str(self.worker)]=r.record(self.worker,self.host)
        self.assets={'forward/'+name:('new-'+name).encode() for name in r.ASSETS}
        self.manifest=dict(installed={name:r.content_record(self.assets['forward/'+name]) for name in r.ASSETS},source_commit='a'*40)
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(r,'PRIOR_PRIVATE',{}))
        stack.enter_context(patch.object(r,'PRIOR_BACKUPS',()))
        for name,value in dict(CODE=self.code,DIRECTORIES=self.dirs,LOCK=self.lock,JOURNAL=root/'journal',BACKUP=self.code/'.backup').items(): stack.enter_context(patch.object(r,name,value))
        stack.enter_context(patch.object(r,'package',return_value=(self.manifest,self.baseline,self.assets)))

    def test_fixture_partial_publication_restores_actual_cf11_bytes_and_inode(self):
        name='validation/actor-integration-fixture.json'
        self.assertEqual(len(r.CHANGED),2);self.assertIn(name,r.CHANGED);self.assertEqual(r.ADDED,())
        original=self.baseline['files'][str(self.code/name)];real=r.append
        def stop(event,target,info=None):
            value=real(event,target,info)
            if event=='published' and target==name:raise OSError('interrupted after fifth-source fixture publication')
            return value
        with patch.object(r,'append',side_effect=stop),self.assertRaises(OSError):r.apply(Path('/unused'),self.digest,self.host)
        r.rollback(Path('/unused'),self.digest,self.host);r.rollback(Path('/unused'),self.digest,self.host)
        self.assertEqual(r.record(self.code/name,self.host),original)

    def test_versioned_successor_paths_must_be_unapplied(self):
        with patch.object(r,'OPERATOR',self.code.parent/'operator'):
            r.unused_successor_paths()
            r.OPERATOR.write_bytes(b'existing historical operator')
            with self.assertRaises(ValueError):r.unused_successor_paths()
            r.OPERATOR.unlink();r.JOURNAL.write_bytes(b'existing transaction')
            with self.assertRaises(ValueError):r.unused_successor_paths()
            r.JOURNAL.unlink();r.BACKUP.mkdir()
            with self.assertRaises(ValueError):r.unused_successor_paths()

    def test_prior_admission_private_history_drift_refuses_without_overwrite(self):
        history=self.code.parent/'prior-journal';history.write_bytes(b'prior frozen history')
        expected=r.record(history,self.host)
        with patch.object(r,'PRIOR_PRIVATE',{str(history):expected}):
            history.write_bytes(b'unknown drift')
            before=list(self.host.calls)
            with self.assertRaises(ValueError):r.apply(Path('/unused'),self.digest,self.host)
            self.assertEqual(history.read_bytes(),b'unknown drift')
            self.assertEqual(self.host.calls,before+[('quiescent',)])

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
            if event=='published' and name==r.CHANGED[0]: raise OSError('injected post-publication journal failure')
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

    def test_rollback_rechecks_after_protection_before_deleting_unknown_new_inode(self):
        r.apply(Path('/unused'),self.digest,self.host)
        real=r.protect_directory;changed=[False];path=self.code/r.CHANGED[0]
        def replace(patharg,expected,host):
            real(patharg,expected,host)
            if not changed[0]:
                changed[0]=True;path.unlink();path.write_bytes(b'foreign replacement')
        with patch.object(r,'protect_directory',side_effect=replace),self.assertRaises(ValueError):
            r.rollback(Path('/unused'),self.digest,self.host)
        self.assertEqual(path.read_bytes(),b'foreign replacement');self.assertFalse(self.host.active)

    def test_rollback_recovers_interruption_between_chown_and_chmod(self):
        for phase in ('forward','rollback'):
            with self.subTest(phase=phase):
                # Original inode/bytes, but only the first metadata syscall committed.
                path=self.code/r.CHANGED[0];expected=self.baseline['files'][str(path)]
                fd=os.open(path,os.O_RDONLY)
                try:
                    self.host.metadata(fd,0 if phase=='forward' else expected['uid'],0 if phase=='forward' else expected['gid'],expected['mode'] if phase=='forward' else 0o600)
                finally: os.close(fd)
                if not r.JOURNAL.exists(): r.journal(self.digest,self.host,create=True)
                r.rollback(Path('/unused'),self.digest,self.host)
                self.assertEqual(r.record(path,self.host),expected)

    def test_syscall_boundary_failure_during_forward_and_rollback_is_recoverable(self):
        path=self.code/r.CHANGED[0];original=self.baseline['files'][str(path)];real=self.host.metadata
        def interrupt(fd,uid,gid,mode):
            actual=os.fstat(fd)
            if actual.st_ino==original['inode']:
                # fchown completed, fchmod did not. Preserve actual mode.
                self.host.metadata_by_inode[actual.st_dev,actual.st_ino]=(uid,gid,stat.S_IMODE(actual.st_mode))
                raise OSError('interrupted between fchown and fchmod')
            real(fd,uid,gid,mode)
        with patch.object(self.host,'metadata',side_effect=interrupt),self.assertRaises(OSError):
            r.apply(Path('/unused'),self.digest,self.host)
        r.rollback(Path('/unused'),self.digest,self.host)
        self.assertEqual(r.record(path,self.host),original)
        # A fresh fake journal permits a new independent forward transaction.
        r.JOURNAL.unlink();r.apply(Path('/unused'),self.digest,self.host)
        with patch.object(self.host,'metadata',side_effect=interrupt),self.assertRaises(OSError):
            r.rollback(Path('/unused'),self.digest,self.host)
        r.rollback(Path('/unused'),self.digest,self.host)
        self.assertEqual(r.record(path,self.host),original)

    def test_all_three_prior_histories_are_checked_before_new_journal_or_socket_change(self):
        priors=[];expected={}
        for suffix in ('v1','v2','v3'):
            directory=self.code/('.prior-'+suffix);directory.mkdir(mode=0o700)
            fd=os.open(directory,os.O_RDONLY)
            try:self.host.metadata(fd,0,0,0o700)
            finally:os.close(fd)
            path=directory/'old';path.write_bytes(('frozen-'+suffix).encode());expected[str(path)]=r.record(path,self.host);priors.append(directory)
        with patch.object(r,'PRIOR_BACKUPS',tuple(priors)),patch.object(r,'PRIOR_PRIVATE',expected):
            r.verify(Path('/unused'),self.digest,self.host)
            path=priors[2]/'old';path.write_bytes(b'unknown private history')
            before=list(self.host.calls)
            with self.assertRaises(ValueError):r.apply(Path('/unused'),self.digest,self.host)
            self.assertFalse(r.JOURNAL.exists());self.assertEqual(self.host.calls,before+[('quiescent',)])
            self.assertEqual(path.read_bytes(),b'unknown private history')

    def test_prior_history_unknown_file_and_parent_symlink_are_rejected(self):
        prior=self.code/'.prior';prior.mkdir(mode=0o700)
        fd=os.open(prior,os.O_RDONLY)
        try:self.host.metadata(fd,0,0,0o700)
        finally:os.close(fd)
        with patch.object(r,'PRIOR_BACKUPS',(prior,)):
            foreign=prior/'unknown';foreign.write_bytes(b'foreign history')
            with self.assertRaises(ValueError):r.verify(Path('/unused'),self.digest,self.host)
            foreign.unlink();prior.rmdir();prior.symlink_to(self.code,target_is_directory=True)
            with self.assertRaises(ValueError):r.verify(Path('/unused'),self.digest,self.host)
