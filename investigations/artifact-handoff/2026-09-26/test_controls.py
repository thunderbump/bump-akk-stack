import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
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


if __name__=='__main__': unittest.main()
