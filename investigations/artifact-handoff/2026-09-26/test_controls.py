import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
import shutil
import stat
from artifact import copy_blob, hash_file, validate_inventory, consume_files
from diagnostics import DiagnosticTail, utility_result


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.write_bytes(b'known\x00bytes' * 1000)
        self.size = self.source.stat().st_size
        self.sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.target = self.root / 'copy'

    def test_copy_hash_and_exact_identity(self):
        copy_blob(self.source, self.target, self.size, self.sha, time.monotonic()+5)
        self.assertEqual(hash_file(self.target, self.size, time.monotonic()+5), self.sha)

    def test_corruption_truncation_and_timeout_remove_partial_copy(self):
        for size, digest, deadline in [(self.size, '0'*64, time.monotonic()+5),
                                      (self.size+1, self.sha, time.monotonic()+5),
                                      (self.size, self.sha, time.monotonic()-1)]:
            with self.assertRaises((ValueError, TimeoutError)):
                copy_blob(self.source, self.target, size, digest, deadline)
            self.assertFalse(self.target.exists())

    def test_empty_file_and_interrupted_copy(self):
        self.source.write_bytes(b'')
        empty = hashlib.sha256(b'').hexdigest()
        copy_blob(self.source, self.target, 0, empty, time.monotonic()+5)
        self.assertEqual(self.target.read_bytes(), b'')
        self.target.unlink()
        with patch('artifact.os.fsync', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                copy_blob(self.source, self.target, 0, empty, time.monotonic()+5)
        self.assertFalse(self.target.exists())

    def test_symlink_and_existing_destination_are_never_followed_or_deleted(self):
        link = self.root/'link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            copy_blob(link, self.target, self.size, self.sha, time.monotonic()+5)
        self.target.write_text('preserve')
        with self.assertRaises(FileExistsError):
            copy_blob(self.source, self.target, self.size, self.sha, time.monotonic()+5)
        self.assertEqual(self.target.read_text(), 'preserve')

    def test_manifest_identity_paths_types_count_and_bytes(self):
        valid = {'version':1, 'identity':'expected','files':[{'path':'file','type':'file','bytes':1,'sha256':self.sha}]}
        self.assertEqual(len(validate_inventory(valid,'expected')),1)
        cases=[]
        for field,value in [('path','../escape'),('path','/absolute'),('path','a//b'),('type','symlink'),('bytes',True),('bytes',4*1024**3)]:
            item=json.loads(json.dumps(valid));item['files'][0][field]=value;cases.append(item)
        item=json.loads(json.dumps(valid));item['files']*=2;cases.append(item)
        item=json.loads(json.dumps(valid));item['identity']='other';cases.append(item)
        for item in cases:
            with self.assertRaises(ValueError): validate_inventory(item,'expected')
        with self.assertRaises(ValueError): validate_inventory(valid,'expected',max_files=0)

    def test_guest_copy_checks_actual_file_not_only_manifest(self):
        out=self.root/'out';out.mkdir()
        manifest={'version':1,'identity':'x','files':[{'path':'source','type':'file','bytes':self.size,'sha256':self.sha}]}
        self.assertEqual(consume_files(self.root,out,manifest,'x',time.monotonic()+5),1)
        (out/'source').unlink();self.source.write_bytes(b'changed')
        with self.assertRaises(ValueError):consume_files(self.root,out,manifest,'x',time.monotonic()+5)


class OutcomeTests(unittest.TestCase):
    def test_completed_work_and_exit_are_both_required(self):
        record={'version':1,'selected':2,'started':2,'completed':2,'failed':0,'finalized':True,'passed':True}
        line='EQEMU_TEST_RESULT '+json.dumps(record)
        self.assertEqual(utility_result(line,0)['completed'],2)
        for text,code in [('',0),(line+'\n'+line,0),(line,1),(line[:-3],0)]:
            with self.assertRaises(ValueError): utility_result(text,code)
        for field,value in [('selected',0),('completed',0),('failed',1),('finalized',False),('passed',False)]:
            wrong=dict(record);wrong[field]=value
            with self.assertRaises(ValueError):utility_result('EQEMU_TEST_RESULT '+json.dumps(wrong),0)

    def test_warning_is_data_and_secret_crosses_chunks(self):
        tail=DiagnosticTail(['synthetic-credential'],limit=128)
        tail.feed(b'[Warning] Aborted connection synthetic-')
        tail.feed(b'credential\n')
        self.assertIn('Aborted connection',tail.export()['text'])
        self.assertNotIn('synthetic-credential',tail.export()['text'])
        tail.feed(b'z'*100000)
        result=tail.export()
        self.assertEqual(len(result['text']),128)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(tail.data),150)

    def test_invalid_utf8_and_control_characters_stay_bounded(self):
        tail=DiagnosticTail(limit=16)
        tail.feed(b'\xff'*100+b'\xc2\x9b'+b'\x1b')
        result=tail.export()
        self.assertLessEqual(len(result['text'].encode()),16)
        self.assertEqual(result['retained_bytes'],len(result['text'].encode()))
        self.assertNotIn('\x9b',result['text'])
        self.assertNotIn('\x1b',result['text'])


class RescueTests(unittest.TestCase):
    def test_rescue_preserves_first_cleanup_failure_and_stays_failed(self):
        # Exercise the actual suite cleanup with external VM operations replaced.
        namespace={}
        exec(Path(__file__).with_name('suite_extension.py').read_text(),namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); evidence=root/'producer'/'evidence';evidence.mkdir(parents=True)
            def write(path,value):path.write_text(json.dumps(value))
            def read(path):return json.loads(path.read_text())
            first={'complete':False,'error':'original cleanup failure'}
            write(evidence/'cleanup.json',first)
            write(evidence/'report.json',{'cleanup':first,'ok':False})
            write(root/'custody.json',{'eligible':False})
            write(root/'leases.json',{'active':{}})
            write(root/'suite-result.json',{'cases_passed':True})
            ctl=root/'controller.slice';ctl.write_text('owned')
            def rescue(preserve_failed_outcome):
                self.assertTrue(preserve_failed_outcome)
                write(evidence/'cleanup.json',{'complete':True})
                write(evidence/'report.json',{'cleanup':{'complete':True},'ok':False})
                return 0
            worker=SimpleNamespace(ROOT=evidence.parent,EVIDENCE=evidence,UNIT='owned',
                                   state=lambda:{'uuid':'owned'},cleanup=rescue)
            namespace.update(ROOT=root,CASES=('producer',),module=lambda _:worker,
                             properties=lambda _: {},quiescent=lambda _:True,
                             absent=Mock(side_effect=[False,True]),ownership=lambda _:None,
                             read=read,write=write,shutil=shutil,stat=stat,time=time,os=os,
                             CTLFILE=ctl,CTLTEXT='owned',controller_budget=lambda:{},run=Mock())
            with patch.dict(os.environ,{'SERVICE_RESULT':'success'}):
                self.assertEqual(namespace['cleanup'](),0)
            self.assertEqual(read(evidence/'before-suite-rescue'/'cleanup.json'),first)
            self.assertFalse(read(evidence/'before-suite-rescue'/'custody.json')['eligible'])
            result=read(root/'suite-result.json')
            self.assertFalse(result['suite_passed'])
            self.assertEqual(result['cleanup']['rescued'],['producer'])

    def test_budget_failure_does_not_prevent_owned_slice_removal(self):
        for error in [RuntimeError('Controller pool OOM'), FileNotFoundError('cgroup absent')]:
            with self.subTest(error=str(error)), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                def write(path,value):path.write_text(json.dumps(value))
                def read(path):return json.loads(path.read_text())
                write(root/'leases.json',{'active':{}})
                write(root/'suite-result.json',{'cases_passed':True,'error':'original failure'})
                ctl=root/'controller.slice';ctl.write_text('owned')
                namespace={}
                exec(Path(__file__).with_name('suite_extension.py').read_text(),namespace)
                namespace.update(ROOT=root,CASES=(),read=read,write=write,time=time,os=os,
                    CTLFILE=ctl,CTLTEXT='owned',controller_budget=Mock(side_effect=error),run=Mock())
                with patch.dict(os.environ,{'SERVICE_RESULT':'success'}):
                    self.assertEqual(namespace['cleanup'](),0)
                self.assertFalse(ctl.exists())
                result=read(root/'suite-result.json')
                self.assertFalse(result['suite_passed'])
                self.assertEqual(result['error'],'original failure')
                self.assertEqual(result['cleanup']['controller_budget_error'],str(error))


if __name__=='__main__': unittest.main()
