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
    def socket_active(self): return not self.stopped
    def socket(self,value):
        if value and getattr(self,'start_failure',False):raise ValueError('socket-start')
        self.stopped=not value
    def writers(self,identities):
        if getattr(self,'writer',False): raise ValueError('preopened-writer')
    def state_metadata(self,fd): return self.parent
    def protect(self,fd):
        self.parent=dict(self.original_parent,uid=0,gid=0)
        if getattr(self,'half_protection',False): raise ValueError('half-protection')
    def restore(self,fd,old):self.parent=dict(old)
    def result(self,state):
        if getattr(self,'no_result',False):raise ValueError('result-unavailable')
        return dict(device=1,inode=10,sha256='fixed',mtime_ns=getattr(self,'workload',0))


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
        self.host.original_parent=r.metadata(self.state.stat());self.host.original_parent.pop('bytes')
        self.host.parent=dict(self.host.original_parent)
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
        with self.assertRaisesRegex(ValueError,'interrupted'):self.runop('verify')
        self.assertEqual(self.runop('rollback')['state'],'original')
        self.assertEqual(self.runop('verify')['state'],'original')
        self.assertFalse(self.host.stopped)
    def test_drift_in_installed_guard_leaves_original_untouched(self):
        self.host.fail_at=1
        with self.assertRaises(ValueError):self.runop('apply')
        self.assertTrue(self.target.exists());self.assertFalse(self.archive.exists());self.assertFalse(self.host.stopped)

    def test_completed_ordinary_workload_or_missing_result_refuses_rollback(self):
        self.runop('apply')
        self.host.workload=1
        with self.assertRaisesRegex(ValueError,'workload'):self.runop('rollback')
        self.host.workload=0;self.host.no_result=True
        with self.assertRaisesRegex(ValueError,'unavailable'):self.runop('rollback')
        self.assertFalse(self.target.exists());self.assertTrue((self.archive/r.RETIRED).exists())
    def test_half_protection_keeps_socket_stopped_and_explicit_rollback_restores_parent(self):
        self.host.half_protection=True
        with self.assertRaisesRegex(ValueError,'half-protection'):self.runop('apply')
        self.assertTrue(self.host.stopped);self.assertEqual(self.host.parent['uid'],0)
        with self.assertRaisesRegex(ValueError,'interrupted'):self.runop('verify')
        self.host.half_protection=False;self.runop('rollback')
        self.assertEqual(self.host.parent,self.host.original_parent);self.assertFalse(self.host.stopped)
    def test_preopened_writer_refuses_and_preserves_original(self):
        self.host.writer=True
        with self.assertRaisesRegex(ValueError,'writer'):self.runop('apply')
        self.assertTrue(self.target.exists());self.assertFalse(self.archive.exists())
        self.assertTrue(self.host.stopped)

    def test_socket_start_failure_cannot_verify_success(self):
        self.host.start_failure=True
        with self.assertRaisesRegex(ValueError,'socket-start'):self.runop('apply')
        self.assertEqual(self.host.parent,self.host.original_parent);self.assertTrue(self.host.stopped)
        with self.assertRaisesRegex(ValueError,'interrupted-socket'):self.runop('verify')


class FrozenHelperLoading(unittest.TestCase):
    def test_replaced_package_helper_is_never_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'v6').mkdir()
            (p/'v6/operator.py').write_text("raise AssertionError('UNTRUSTED EXECUTED')")
            with self.assertRaisesRegex(ValueError,'helper-hash'):r.Host(p)


class ResultGuard(unittest.TestCase):
    def test_actual_bounded_result_reads_bind_inode_timestamps_hash_without_raw_export(self):
        import types
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);f=path/'last-result.json';f.write_bytes(b'PRIVATE-RESULT-BYTES');f.chmod(0o600)
            state=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            host=object.__new__(r.Host);host.result_fd=None
            real_fstat=os.fstat;real_stat=os.stat
            def fixed(info):
                fields={k:getattr(info,k) for k in dir(info) if k.startswith('st_')}
                return types.SimpleNamespace(**dict(fields,st_uid=995,st_gid=980))
            try:
                with patch.object(os,'fstat',side_effect=lambda fd:fixed(real_fstat(fd))),patch.object(os,'stat',side_effect=lambda *a,**kw:fixed(real_stat(*a,**kw))):
                    first=host.result(state)
                    self.assertNotIn('PRIVATE-RESULT',str(first));self.assertIn('mtime_ns',first);self.assertIn('ctime_ns',first)
                    f.write_bytes(b'CHANGED-WORKLOAD')
                    self.assertNotEqual(first,host.result(state))
                    f.unlink();f.write_bytes(b'CHANGED-WORKLOAD');f.chmod(0o600)
                    with self.assertRaisesRegex(ValueError,'result-(changed|shape)'):host.result(state)
            finally:
                if host.result_fd is not None:os.close(host.result_fd)
                os.close(state)


class RetainedReferences(unittest.TestCase):
    def test_subprocess_readonly_directory_fd_is_rejected_before_openat_mutation(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);info=directory.stat()
            code="import os,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY);print('held',flush=True);sys.stdin.read(1)"
            child=subprocess.Popen([sys.executable,'-B','-c',code,str(directory)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'held')
                with self.assertRaisesRegex(ValueError,'retained-reference'):
                    r.reject_references({(info.st_dev,info.st_ino)},[Path('/proc')/str(child.pid)])
                self.assertEqual(list(directory.iterdir()),[])
            finally:
                child.communicate(input='x',timeout=5)
                self.assertEqual(child.returncode,0)
    def test_unrelated_reference_does_not_refuse(self):
        r.reject_references({(0,0)},[Path('/proc')/str(os.getpid())])


class RetainedMappings(unittest.TestCase):
    def test_shared_readonly_mapping_with_closed_fd_is_rejected(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'original';path.write_bytes(b'original bytes');info=path.stat()
            code="""import ctypes,os,sys
lib=ctypes.CDLL(None,use_errno=True)
lib.mmap.restype=ctypes.c_void_p
lib.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
fd=os.open(sys.argv[1],os.O_RDWR)
p=lib.mmap(None,4096,1,1,fd,0)
os.close(fd)
if p==ctypes.c_void_p(-1).value: raise SystemExit(2)
print('mapped',flush=True)
sys.stdin.read(1)
lib.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
lib.munmap(p,4096)
"""
            child=subprocess.Popen([sys.executable,'-B','-c',code,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'mapped')
                with self.assertRaisesRegex(ValueError,'retained-mapping'):
                    r.reject_references({(info.st_dev,info.st_ino)},[Path('/proc')/str(child.pid)])
                self.assertEqual(path.read_bytes(),b'original bytes')
            finally:
                child.communicate(input='x',timeout=5);self.assertEqual(child.returncode,0)


class ThreadReferences(unittest.TestCase):
    def test_unshared_thread_directory_fd_is_rejected(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);info=directory.stat()
            code="""import ctypes,os,sys,threading
ready=threading.Event();finish=threading.Event();failed=[]
def hold():
 lib=ctypes.CDLL(None,use_errno=True)
 # CLOSE_RANGE_UNSHARE clones only this thread's descriptor table.
 if lib.close_range(ctypes.c_uint(1000000),ctypes.c_uint(0xffffffff),ctypes.c_uint(2)):
  failed.append(ctypes.get_errno());ready.set();return
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
 ready.set();finish.wait();os.close(fd)
t=threading.Thread(target=hold);t.start();ready.wait()
print('failed' if failed else 'thread-held',flush=True)
sys.stdin.read(1);finish.set();t.join()
"""
            child=subprocess.Popen([sys.executable,'-B','-c',code,str(directory)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'thread-held')
                with self.assertRaisesRegex(ValueError,'retained-reference'):
                    r.reject_references({(info.st_dev,info.st_ino)},[Path('/proc')/str(child.pid)])
            finally:
                child.communicate(input='x',timeout=5);self.assertEqual(child.returncode,0)


class WorkerPrincipal(unittest.TestCase):
    def test_active_worker_uid_task_refuses_even_without_visible_target_fd(self):
        with tempfile.TemporaryDirectory() as tmp:
            process=Path(tmp)/'99999999';task=process/'task/99999999';task.mkdir(parents=True)
            (task/'status').write_text('Uid:\t995\t995\t995\t995\n')
            with self.assertRaisesRegex(ValueError,'worker-principal-active'):
                r.reject_references({(1,2)},[process])
