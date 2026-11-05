"""Finite retirement uses real temporary directories and Linux no-replace rename."""
import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import integration_retirement as r


class FakeHost:
    prior_socket=True
    history={'fixed':'fake-host-only'}
    def __init__(self): self.stopped=False;self.calls=0;self.fail_at=None
    @contextlib.contextmanager
    def guard(self): yield
    def verify(self):
        self.calls+=1
        if self.calls==self.fail_at: raise ValueError('injected')
    def socket(self,value): self.stopped=not value
    def writers(self,identities): pass


class Retirement(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.state=self.root/'state';self.state.mkdir();self.archive=self.root/'archive'
        self.target=self.state/r.SLOT;self.target.mkdir()
        self.expected={'directory':r.metadata(self.target.stat()),'files':{}}
        for name,raw in [('central-cdau-integration-v1.json',b''),('pending.json',b'{"run":"known"}'),('receipt.json',b'{"uncertain":true,"ack":false}')]:
            f=self.target/name;f.write_bytes(raw);f.chmod(0o600)
            self.expected['files'][name]=dict(r.metadata(f.stat()),sha256=r.sha(raw))
        self.expected['directory']=r.metadata(self.target.stat())
        @contextlib.contextmanager
        def owned_directory(path,private=False):
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);before=os.fstat(fd)
            def check():
                current=path.lstat()
                if (current.st_dev,current.st_ino)!=(before.st_dev,before.st_ino): raise ValueError('changed')
            try: yield fd,check;check()
            finally: os.close(fd)
        self.enterContext(patch.object(r,'STATE',self.state));self.enterContext(patch.object(r,'ARCHIVE',self.archive))
        self.enterContext(patch.object(r,'directory',owned_directory))
        self.enterContext(patch.object(os,'fchown',return_value=None))
        def load(fd,name):
            child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            try:return json.loads(os.pread(child,4097,0))
            finally:os.close(child)
        self.enterContext(patch.object(r,'load_event',side_effect=load))
        self.host=FakeHost()
    def runop(self,op):return r.transaction(op,self.host,self.expected)
    def test_apply_verify_rollback_preserves_original_inodes_bytes_and_no_ack(self):
        self.assertEqual(self.runop('verify')['state'],'original')
        self.assertEqual(self.runop('apply')['state'],'retired');self.assertFalse(self.target.exists());self.assertFalse(self.host.stopped)
        self.assertEqual(self.runop('verify')['state'],'retired')
        self.assertEqual(self.runop('rollback')['state'],'original');self.assertFalse(self.host.stopped)
        fd=os.open(self.state,os.O_RDONLY|os.O_DIRECTORY)
        try:r.tree(fd,r.SLOT,self.expected)
        finally:os.close(fd)
        self.assertFalse(json.loads((self.archive/'retired.json').read_text())['ack'])
        with self.assertRaises(ValueError):self.runop('apply')
        with self.assertRaises(ValueError):self.runop('rollback')
    def test_unknown_or_symlink_archive_refuses_without_socket_change(self):
        for kind in ['directory','symlink']:
            if kind=='directory':self.archive.mkdir()
            else:self.archive.symlink_to(self.state)
            with self.assertRaises((ValueError,OSError)):self.runop('apply')
            self.assertFalse(self.host.stopped)
            if kind=='directory':self.archive.rmdir()
            else:self.archive.unlink()
    def test_wrong_inode_hash_mode_member_refuses_before_writes(self):
        f=self.target/'pending.json';original=f.read_bytes()
        for kind in ['hash','mode','member','inode']:
            with self.subTest(kind=kind):
                if kind=='hash':f.write_bytes(b'wrongrun')
                elif kind=='mode':f.chmod(0o644)
                elif kind=='member':(self.target/'unknown').touch()
                else:
                    f.rename(self.target/'saved');f.write_bytes(original);(self.target/'saved').unlink()
                with self.assertRaises(ValueError):self.runop('apply')
                self.assertFalse(self.archive.exists());self.assertFalse(self.host.stopped)
                f.write_bytes(original);f.chmod(0o600);(self.target/'unknown').unlink(missing_ok=True)
                self.expected['files']['pending.json']=dict(r.metadata(f.stat()),sha256=r.sha(original))
    def test_new_slot_prevents_rollback_and_preserves_both(self):
        self.runop('apply');self.target.mkdir()
        with self.assertRaises(ValueError):self.runop('rollback')
        self.assertTrue((self.archive/r.RETIRED).exists());self.assertTrue(self.target.exists())
    def test_noreplace_rename_never_overwrites_empty_destination(self):
        self.archive.mkdir();(self.archive/r.RETIRED).mkdir()
        a=os.open(self.state,os.O_RDONLY|os.O_DIRECTORY);b=os.open(self.archive,os.O_RDONLY|os.O_DIRECTORY)
        try:
            with self.assertRaises(FileExistsError):r.rename(a,r.SLOT,b,r.RETIRED)
        finally:os.close(a);os.close(b)
        self.assertTrue(self.target.exists())
    def test_failure_after_rename_keeps_socket_stopped_then_bounded_rollback(self):
        self.host.fail_at=4
        with self.assertRaises(ValueError):self.runop('apply')
        self.assertTrue(self.host.stopped);self.assertFalse(self.target.exists());self.assertTrue((self.archive/r.RETIRED).exists())
        self.host.fail_at=None
        with self.assertRaisesRegex(ValueError,'interrupted-disposition'):self.runop('verify')
        self.assertEqual(self.runop('rollback')['state'],'original')
        self.assertEqual(self.runop('verify')['state'],'original')
        self.assertFalse(self.host.stopped)
    def test_drift_in_installed_guard_leaves_original_untouched(self):
        self.host.fail_at=1
        with self.assertRaises(ValueError):self.runop('apply')
        self.assertTrue(self.target.exists());self.assertFalse(self.archive.exists());self.assertFalse(self.host.stopped)


class FrozenHelperLoading(unittest.TestCase):
    def test_replaced_package_helper_is_never_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'v6').mkdir()
            (p/'v6/operator.py').write_text("raise AssertionError('UNTRUSTED EXECUTED')")
            with self.assertRaisesRegex(ValueError,'helper-hash'):r.Host(p)
