"""Audit filesystem/lock controls use temporary owned files, never real worker state."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, mock_open

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import integration_transfer_audit as audit


class HarmlessHost(audit.Host):
    def __init__(self, hook=None): self.calls=0;self.hook=hook
    def root(self): pass
    def parent(self, info): return stat.S_ISDIR(info.st_mode)
    def quiescent(self):
        self.calls+=1
        if self.hook: self.hook(self.calls)


class ReadOnlyAudit(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.target=self.state/'last-integration';self.target.mkdir(mode=0o700)
        (self.state/'worker.lock').touch(mode=0o600)
        for name,value in [(audit.NAME,b''),('pending.json',json.dumps(audit.BINDING).encode()),('receipt.json',json.dumps(audit.RECEIPT).encode())]:
            path=self.target/name;path.write_bytes(value);path.chmod(0o600)
            os.utime(path,ns=(1000000000,2000000000))
        for name,value in [('STATE',self.state),('WORKER_UID',os.getuid()),('WORKER_GID',os.getgid())]:
            self.enterContext(patch.object(audit,name,value))
        real_open=os.open
        def harmless_open(name,flags,*args,**kwargs):
            # Unprivileged tests cannot request NOATIME on public root ancestors.
            # No ancestor is enumerated; all observed owned fixture files keep NOATIME.
            if flags&os.O_DIRECTORY and flags&os.O_NOATIME:
                info=os.stat(name,dir_fd=kwargs.get('dir_fd'),follow_symlinks=False)
                if info.st_uid!=os.getuid(): flags &= ~os.O_NOATIME
            return real_open(name,flags,*args,**kwargs)
        self.enterContext(patch.object(os,'open',side_effect=harmless_open))

    def snapshot(self):
        result={}
        # The observer must not change directory atime while taking its own snapshots.
        for path in [self.state,self.target,self.state/'worker.lock',*[self.target/name for name in audit.LIMITS]]:
            data=None
            if path.is_file():
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME)
                try: data=os.pread(fd,900000,0)
                finally: os.close(fd)
            result[str(path)]=(audit.fingerprint(path.lstat()),data)
        return result

    def test_exact_readonly_output_keeps_all_bytes_metadata_and_external_provenance(self):
        before=self.snapshot();host=HarmlessHost();opens=[];original=os.open
        def opened(name,flags,*args,**kwargs):
            opens.append(flags);return original(name,flags,*args,**kwargs)
        with patch.object(os,'open',side_effect=opened): result=audit.audit(host)
        self.assertEqual(before,self.snapshot());self.assertEqual(host.calls,3)
        self.assertTrue(result['audit_complete']);self.assertFalse(result['qualification'])
        self.assertFalse(result['external_trusted_receipt_binding']['observed_in_protected_files'])
        self.assertNotIn('server_tree',result['protected_binding'])
        self.assertEqual(result['receipt_outcome']['original_transfer'],'uncertain')
        self.assertFalse(result['ack_sent']);self.assertFalse(result['state_mutated'])
        self.assertEqual(set(result['records']['files']),set(audit.LIMITS))
        self.assertLess(len(json.dumps(result).encode()),4096)
        self.assertTrue(all(not flags&(os.O_CREAT|os.O_TRUNC|os.O_WRONLY|os.O_RDWR) for flags in opens))

    def test_unknown_missing_symlink_mode_binding_duplicate_and_boolean_refuse(self):
        receipt=self.target/'receipt.json';original=receipt.read_bytes()
        for kind in ('unknown','missing','symlink','mode','binding','duplicate','boolean'):
            with self.subTest(kind=kind):
                extra=self.target/'PRIVATE-CREDENTIAL';outside=self.root/'outside';outside.write_bytes(b'PRIVATE-CREDENTIAL')
                receipt.unlink(missing_ok=True);receipt.write_bytes(original);receipt.chmod(0o600)
                if kind=='unknown': extra.write_text('PRIVATE-CREDENTIAL')
                elif kind=='missing': receipt.unlink()
                elif kind=='symlink': receipt.unlink();receipt.symlink_to(outside)
                elif kind=='mode': receipt.chmod(0o644)
                elif kind=='binding': receipt.write_text(json.dumps(dict(audit.RECEIPT,run_id='f'*32)))
                elif kind=='duplicate': receipt.write_bytes(original[:-1]+b',"run_id":"PRIVATE-CREDENTIAL"}')
                else: receipt.write_text(json.dumps(dict(audit.RECEIPT,version=True)))
                with self.assertRaises((audit.Refused,OSError)): audit.audit(HarmlessHost())
                extra.unlink(missing_ok=True)

    def test_reread_detects_content_and_inode_replacement_without_mutating_evidence(self):
        path=self.target/'receipt.json';original=path.read_bytes()
        for replacement in (False,True):
            with self.subTest(replacement=replacement):
                path.write_bytes(original);path.chmod(0o600)
                def change(calls):
                    if calls!=3:return
                    if replacement:
                        other=self.target/'new';other.write_bytes(original);other.chmod(0o600);os.replace(other,path)
                    else:path.write_bytes(original+b' ')
                with self.assertRaises(audit.Refused):audit.audit(HarmlessHost(change))
                self.assertEqual(path.read_bytes(),original if replacement else original+b' ')

    def test_busy_existing_lock_is_not_created_truncated_or_bypassed(self):
        path=self.state/'worker.lock';before=path.stat().st_ino;fd=os.open(path,os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(audit.Refused) as raised:audit.audit(HarmlessHost())
            self.assertEqual(raised.exception.reason,'lock');self.assertEqual(path.stat().st_ino,before)
        finally:os.close(fd)
        path.unlink()
        with self.assertRaises(FileNotFoundError):audit.audit(HarmlessHost())
        self.assertFalse(path.exists())

    def test_main_exports_only_fixed_error_and_no_arbitrary_operands(self):
        for args,error in [(['audit','--path','PRIVATE-CREDENTIAL'],None),(['audit'],OSError('PRIVATE-CREDENTIAL'))]:
            stream=io.StringIO()
            with patch.object(sys,'argv',args),patch.object(audit,'audit',side_effect=error) as call,contextlib.redirect_stdout(stream):
                self.assertEqual(audit.main(),2)
            value=json.loads(stream.getvalue());self.assertNotIn('PRIVATE',stream.getvalue())
            self.assertEqual(value['error'],'audit-refused');self.assertFalse(value['audit_complete'])
            if error is None:call.assert_not_called()

    def test_parent_replacement_and_unquiescent_guard_refuse(self):
        def replace(calls):
            if calls==3:
                self.target.rename(self.state/'original');self.target.mkdir(mode=0o700)
        with self.assertRaises(audit.Refused):audit.audit(HarmlessHost(replace))
        self.target.rmdir();(self.state/'original').rename(self.target)
        host=HarmlessHost(lambda _:(_ for _ in ()).throw(audit.Refused('quiescence')))
        with self.assertRaises(audit.Refused) as raised:audit.audit(host)
        self.assertEqual(raised.exception.reason,'quiescence')

    def test_real_guard_requires_root_protected_parents_and_no_new_privileges_off(self):
        host=audit.Host()
        for uid,gid,mode,allowed in [(0,0,stat.S_IFDIR|0o755,True),(1000,0,stat.S_IFDIR|0o755,False),
                                    (0,0,stat.S_IFDIR|0o777,False),(0,0,stat.S_IFLNK|0o755,False)]:
            self.assertEqual(host.parent(types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=mode)),allowed)
        with patch('os.geteuid',return_value=0),patch('os.getegid',return_value=0),patch.object(Path,'open',mock_open(read_data='NoNewPrivs:\t1\n')):
            with self.assertRaises(audit.Refused) as raised:host.root()
            self.assertEqual(raised.exception.reason,'root')


if __name__=='__main__':unittest.main()
