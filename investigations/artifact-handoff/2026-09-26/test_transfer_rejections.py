"""Small real byte/file fixtures exercise the existing transfer and receiver paths."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from artifact import copy_blob, hash_file, consume_files, validate_inventory


class TransferRejections(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'payload';self.target=self.root/'copy'
        self.source.write_bytes(b'original bytes')
        self.size=self.source.stat().st_size
        self.sha=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest={'version':1,'identity':'expected','files':[
            {'path':'payload','type':'file','bytes':self.size,'sha256':self.sha}]}

    def test_expired_empty_transfer_and_hash_fail(self):
        self.source.write_bytes(b'');digest=hashlib.sha256(b'').hexdigest()
        for operation in [lambda:copy_blob(self.source,self.target,0,digest,0),
                          lambda:hash_file(self.source,0,0)]:
            with self.assertRaises(TimeoutError):operation()
        self.assertFalse(self.target.exists())

    def test_final_flush_cannot_turn_expired_copy_into_success(self):
        now=[0]
        real_sync=os.fsync
        def late_sync(fd):
            real_sync(fd);now[0]=2
        with patch('artifact.time.monotonic',side_effect=lambda:now[0]),patch('artifact.os.fsync',side_effect=late_sync):
            with self.assertRaises(TimeoutError):copy_blob(self.source,self.target,self.size,self.sha,1)
        self.assertFalse(self.target.exists())
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.sha)

    def test_mid_copy_timeout_removes_partial_output(self):
        now=[0];real_fdopen=os.fdopen
        class ObservedReader:
            def __init__(self,stream):self.stream=stream;self.reads=0
            def __enter__(self):return self
            def __exit__(self,*args):self.stream.close()
            def read(self,n):
                data=self.stream.read(n);self.reads+=1
                if self.reads==2:now[0]=2
                return data
            def fileno(self):return self.stream.fileno()
        def fdopen(fd,mode):
            stream=real_fdopen(fd,mode)
            return ObservedReader(stream) if mode=='rb' else stream
        with patch('artifact.BLOCK',4),patch('artifact.os.fdopen',side_effect=fdopen),patch('artifact.time.monotonic',side_effect=lambda:now[0]):
            with self.assertRaises(TimeoutError):copy_blob(self.source,self.target,self.size,self.sha,1)
        self.assertFalse(self.target.exists())
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.sha)

    def test_mutation_truncation_and_real_special_files_refuse_consumption(self):
        output=self.root/'out';output.mkdir()
        reference=self.root/'reference';reference.write_bytes(b'original bytes')
        for kind in ['mutation','truncation','symlink','fifo']:
            with self.subTest(kind=kind):
                self.source.unlink()
                if kind=='mutation':self.source.write_bytes(b'X'+b'original bytes'[1:])
                elif kind=='truncation':self.source.write_bytes(b'short')
                elif kind=='symlink':self.source.symlink_to(reference)
                else:os.mkfifo(self.source)
                with self.assertRaises((ValueError,OSError)):
                    consume_files(self.root,output,self.manifest,'expected',time.monotonic()+5)
                self.assertEqual(list(output.iterdir()),[])

    def test_reduced_inventory_budgets_and_wrong_identity(self):
        entry=self.manifest['files'][0]
        for inventory,identity,limits in [
            (self.manifest,'other',{}),
            (dict(self.manifest,files=[entry,dict(entry,path='second')]),'expected',{'max_files':1}),
            (self.manifest,'expected',{'max_bytes':self.size-1}),
            (dict(self.manifest,files=[dict(entry,path='../escape')]),'expected',{}),
            (dict(self.manifest,files=[dict(entry,type='device')]),'expected',{})]:
            with self.assertRaises(ValueError):validate_inventory(inventory,identity,**limits)
        self.assertEqual(validate_inventory(self.manifest,'expected',max_files=1,max_bytes=self.size),[entry])


if __name__=='__main__':unittest.main()
